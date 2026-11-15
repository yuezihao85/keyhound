"""Filesystem walker and finding extraction for keyhound."""

from __future__ import annotations

import hashlib
import os
import re
from dataclasses import dataclass, field
from typing import Dict, Iterable, List, Optional, Tuple

from .config import Config
from .entropy import looks_like_random, shannon_entropy
from .ignore import IgnoreMatcher, to_posix
from .rules import SEVERITY_ORDER, Rule, RuleSet

BINARY_EXTENSIONS = frozenset((
    ".png", ".jpg", ".jpeg", ".gif", ".bmp", ".ico", ".webp", ".pdf",
    ".zip", ".gz", ".bz2", ".xz", ".7z", ".rar", ".tar", ".woff", ".woff2",
    ".ttf", ".eot", ".otf", ".mp3", ".mp4", ".mov", ".avi", ".mkv",
    ".exe", ".dll", ".so", ".dylib", ".o", ".a", ".pyc", ".class", ".jar",
    ".wasm", ".sqlite", ".db", ".parquet", ".pkl",
))

SELF_FILES = frozenset((".keyhound.json", ".keyhound-baseline.json"))


@dataclass
class Finding:
    path: str
    line: int
    column: int
    rule_id: str
    description: str
    severity: str
    masked: str
    fingerprint: str
    start: int = 0          # 0-based offset within the line
    end: int = 0            # exclusive
    generic: bool = False
    tags: Tuple[str, ...] = ()

    def to_dict(self) -> dict:
        return {
            "rule_id": self.rule_id,
            "description": self.description,
            "severity": self.severity,
            "path": self.path,
            "line": self.line,
            "column": self.column,
            "masked": self.masked,
            "fingerprint": self.fingerprint,
            "tags": list(self.tags),
        }


@dataclass
class ScanResult:
    base: str
    findings: List[Finding] = field(default_factory=list)
    suppressed: List[Finding] = field(default_factory=list)
    files_scanned: int = 0
    files_skipped: int = 0
    lines_scanned: int = 0
    errors: List[str] = field(default_factory=list)
    config: Optional[Config] = None

    @property
    def counts_by_severity(self) -> Dict[str, int]:
        counts = {name: 0 for name in SEVERITY_ORDER}
        for finding in self.findings:
            counts[finding.severity] = counts.get(finding.severity, 0) + 1
        return counts


def mask_secret(secret: str, safe_to_show: bool = False,
                limit: int = 120) -> str:
    """Redact a secret for reports; never return the raw value."""
    if safe_to_show:
        return secret[:limit]
    if len(secret) <= 8:
        redacted = "*" * len(secret)
    else:
        middle = "*" * min(12, len(secret) - 6)
        redacted = secret[:4] + middle + secret[-2:]
    return redacted[:limit]


def fingerprint(rule_id: str, path: str, secret: str) -> str:
    """Stable across line shifts: rule + path + hash of the secret value."""
    digest = hashlib.sha256(secret.encode("utf-8", "replace")).hexdigest()[:16]
    payload = "\x00".join((rule_id, to_posix(path), digest))
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()[:16]


def _compute_base(paths: List[str]) -> str:
    absolute = [os.path.abspath(p) for p in paths]
    if len(absolute) == 1:
        target = absolute[0]
        return target if os.path.isdir(target) else os.path.dirname(target)
    roots = [p if os.path.isdir(p) else os.path.dirname(p) for p in absolute]
    try:
        return os.path.commonpath(roots)
    except ValueError:  # different drives on Windows
        return os.getcwd()


class Scanner:
    def __init__(self, config: Config, rule_set: RuleSet,
                 baseline: Optional[set] = None,
                 severity: str = "low") -> None:
        self.config = config
        self.rule_set = rule_set
        self.baseline = baseline or set()
        self.min_severity = SEVERITY_ORDER.get(severity, 1)

    def scan_text(self, text: str, label: str = "stdin") -> ScanResult:
        """Scan an in-memory string (used for ``keyhound -`` / pre-commit).

        Nothing is written to disk, which matters when stdin itself contains a
        credential.
        """
        result = ScanResult(base="<stdin>", config=self.config)
        result.files_scanned = 1
        for line_number, line in enumerate(text.splitlines(), start=1):
            result.lines_scanned += 1
            result.findings.extend(
                self._scan_line(label, line_number, line.rstrip("\r"))
            )
        result.findings = self._dedupe(result.findings)
        result.findings = [
            f for f in result.findings
            if SEVERITY_ORDER.get(f.severity, 0) >= self.min_severity
        ]
        active, suppressed = [], []
        for finding in result.findings:
            (suppressed if finding.fingerprint in self.baseline else active).append(finding)
        result.findings, result.suppressed = active, suppressed
        return result

    def scan(self, paths: List[str]) -> ScanResult:
        base = _compute_base(paths)
        result = ScanResult(base=base, config=self.config)
        matcher = IgnoreMatcher(
            base,
            extra_patterns=self.config.exclude,
            include=self.config.include,
            use_gitignore=self.config.use_gitignore,
        )
        matcher.add_gitignore_file("", os.path.join(base, ".gitignore"))

        for target in paths:
            absolute = os.path.abspath(target)
            if os.path.isfile(absolute):
                self._scan_file(absolute, base, matcher, result)
            elif os.path.isdir(absolute):
                self._scan_dir(absolute, base, matcher, result)
            else:
                result.errors.append("path not found: %s" % target)

        result.findings = self._dedupe(result.findings)
        result.findings = [
            f for f in result.findings
            if SEVERITY_ORDER.get(f.severity, 0) >= self.min_severity
        ]
        active, suppressed = [], []
        for finding in result.findings:
            (suppressed if finding.fingerprint in self.baseline else active).append(finding)
        result.findings, result.suppressed = active, suppressed
        return result

    def _scan_dir(self, directory: str, base: str,
                  matcher: IgnoreMatcher, result: ScanResult) -> None:
        """Walk *directory*, keeping nested .gitignore rules scoped to their
        own subtree (a rule under a/vendor must not affect b/)."""
        def walk(current: str, rel_current: str,
                 local_patterns: list) -> None:
            own = matcher.parse_gitignore_file(
                rel_current, os.path.join(current, ".gitignore"))
            child_patterns = local_patterns + own
            try:
                entries = sorted(os.listdir(current))
            except OSError as exc:
                result.errors.append("%s: %s" % (rel_current or ".", exc))
                return
            dirs, files = [], []
            for name in entries:
                path = os.path.join(current, name)
                if os.path.islink(path):
                    continue
                (dirs if os.path.isdir(path) else files).append(name)
            for name in dirs:
                rel = to_posix(os.path.join(rel_current, name)) if rel_current else name
                if matcher.is_ignored(rel, is_dir=True, extra=child_patterns):
                    result.files_skipped += 1
                    continue
                walk(os.path.join(current, name), rel, child_patterns)
            for name in files:
                rel = to_posix(os.path.join(rel_current, name)) if rel_current else name
                if name in SELF_FILES:
                    continue
                if matcher.is_ignored(rel, is_dir=False, extra=child_patterns):
                    result.files_skipped += 1
                    continue
                if not matcher.included(rel):
                    continue
                self._scan_file(os.path.join(current, name), base, matcher, result,
                                rel_override=rel)

        walk(directory, to_posix(os.path.relpath(directory, base))
             if os.path.relpath(directory, base) != "." else "", [])

    def _scan_file(self, path: str, base: str, matcher: IgnoreMatcher,
                   result: ScanResult, rel_override: Optional[str] = None) -> None:
        rel = rel_override or to_posix(os.path.relpath(path, base))
        ext = os.path.splitext(rel)[1].lower()
        if ext in BINARY_EXTENSIONS:
            result.files_skipped += 1
            return
        try:
            size = os.path.getsize(path)
        except OSError as exc:
            result.errors.append("%s: %s" % (rel, exc))
            return
        if self.config.max_size_bytes and size > self.config.max_size_bytes:
            result.files_skipped += 1
            return
        try:
            with open(path, "rb") as handle:
                raw = handle.read()
        except OSError as exc:
            result.errors.append("%s: %s" % (rel, exc))
            return
        if b"\x00" in raw[:8192]:
            result.files_skipped += 1
            return
        text = raw.decode("utf-8", errors="replace")
        result.files_scanned += 1
        for line_number, line in enumerate(text.splitlines(), start=1):
            result.lines_scanned += 1
            result.findings.extend(
                self._scan_line(rel, line_number, line.rstrip("\r"))
            )

    def _scan_line(self, rel: str, line_number: int,
                   line: str) -> Iterable[Finding]:
        for rule in self.rule_set:
            pattern = self.rule_set.pattern(rule.id)
            for match in pattern.finditer(line):
                full = match.group(0)
                group = rule.secret_group
                secret = match.group(group) if group else full
                secret = secret.strip("\"'` \t")
                if not secret:
                    continue
                start = match.start(group) if group else match.start()
                end = start + len(secret)

                min_len = rule.min_length
                if rule.generic:
                    min_len = max(min_len, self.config.min_length)
                if len(secret) < min_len:
                    continue

                window = line[max(0, match.start() - 40): match.end() + 40]
                if (self.config.allowlist_re.search(secret)
                        or self.config.allowlist_re.search(full)
                        or self.config.context_re.search(window)):
                    continue

                threshold = max(rule.min_entropy,
                                self.config.min_entropy if rule.generic else 0.0)
                if threshold > 0 and shannon_entropy(secret) < threshold:
                    continue
                if rule.generic and not looks_like_random(
                        secret, self.config.min_entropy, self.config.min_length):
                    continue

                yield Finding(
                    path=rel,
                    line=line_number,
                    column=start + 1,
                    rule_id=rule.id,
                    description=rule.description,
                    severity=rule.severity,
                    masked=mask_secret(secret, rule.safe_to_show),
                    fingerprint=fingerprint(rule.id, rel, secret),
                    start=start,
                    end=end,
                    generic=rule.generic,
                    tags=rule.tags,
                )

    @staticmethod
    def _dedupe(findings: List[Finding]) -> List[Finding]:
        """Drop duplicate spans and generic hits covered by a specific rule."""
        ordered = sorted(
            findings,
            key=lambda f: (-SEVERITY_ORDER.get(f.severity, 0), f.path, f.line,
                           f.column, f.rule_id),
        )
        seen = set()
        kept: List[Finding] = []
        for finding in ordered:
            key = (finding.path, finding.line, finding.start, finding.end,
                   finding.fingerprint)
            if key in seen:
                continue
            if finding.generic:
                covered = any(
                    not other.generic
                    and other.path == finding.path
                    and other.line == finding.line
                    and other.start < finding.end
                    and finding.start < other.end
                    for other in kept
                )
                if covered:
                    continue
            seen.add(key)
            kept.append(finding)
        return sorted(kept, key=lambda f: (f.path, f.line, f.column, f.rule_id))
