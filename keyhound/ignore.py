"""Path filtering: default directory ignores, user globs and .gitignore."""

from __future__ import annotations

import fnmatch
import os
from typing import List, Optional

DEFAULT_IGNORE_DIRS = frozenset((
    ".git", ".hg", ".svn", "node_modules", ".venv", "venv", "__pycache__",
    ".idea", ".vscode", ".tox", ".pytest_cache", ".mypy_cache", ".ruff_cache",
    "dist", "build", "target", "coverage", ".next", ".nuxt", ".gradle",
    "site-packages", ".terraform",
))


def to_posix(path: str) -> str:
    return path.replace("\\", "/").replace(os.sep, "/")


class _Pattern:
    __slots__ = ("base", "pattern", "negated", "dir_only", "anchored")

    def __init__(self, base: str, pattern: str, negated: bool,
                 dir_only: bool, anchored: bool) -> None:
        self.base = base
        self.pattern = pattern
        self.negated = negated
        self.dir_only = dir_only
        self.anchored = anchored

    def matches(self, rel: str, is_dir: bool) -> bool:
        if self.dir_only and not is_dir:
            return False
        if self.base:
            prefix = self.base.rstrip("/") + "/"
            if not rel.startswith(prefix):
                return False
            sub = rel[len(prefix):]
        else:
            sub = rel
        if not sub:
            return False
        parts = sub.split("/")
        pattern = self.pattern

        if "/" not in pattern:
            if self.anchored:
                # A leading "/" anchors the pattern to the directory holding
                # this .gitignore; no deeper component may appear.
                return "/" not in sub and fnmatch.fnmatchcase(sub, pattern)
            # No separator in the pattern: gitignore matches it at ANY depth.
            return any(fnmatch.fnmatchcase(p, pattern) for p in parts)

        if self.anchored:
            return fnmatch.fnmatchcase(sub, pattern)
        # Approximate the leading "**/" that gitignore implies for patterns
        # containing a separator, by trying every suffix of the path.
        for index in range(len(parts)):
            if fnmatch.fnmatchcase("/".join(parts[index:]), pattern):
                return True
        return False


class IgnoreMatcher:
    """Decides whether a path (relative to the scan root) is ignored."""

    def __init__(self, root: str, extra_patterns: Optional[List[str]] = None,
                 include: Optional[List[str]] = None,
                 use_gitignore: bool = True) -> None:
        self.root = root
        self.use_gitignore = use_gitignore
        self.patterns: List[_Pattern] = []
        self.extra = list(extra_patterns or [])
        self.include = list(include or [])
        for pattern in self.extra:
            self.patterns.append(self._parse("", pattern, False))

    @staticmethod
    def _parse(base: str, raw: str, from_gitignore: bool) -> _Pattern:
        line = raw.strip()
        negated = line.startswith("!")
        if negated:
            line = line[1:]
        dir_only = line.endswith("/")
        if dir_only:
            line = line[:-1]
        anchored = line.startswith("/")
        if anchored:
            line = line[1:]
        if not line:
            line = "\x00NEVER_MATCH\x00"
        return _Pattern(base, line, negated, dir_only, anchored)

    def parse_gitignore(self, base_rel: str, lines: List[str]) -> List[_Pattern]:
        """Parse lines without installing them globally (scoped to a subtree)."""
        if not self.use_gitignore:
            return []
        base = to_posix(base_rel)
        base = "" if base in (".", "") else base
        parsed = []
        for line in lines:
            stripped = line.strip()
            if not stripped or stripped.startswith("#"):
                continue
            parsed.append(self._parse(base, stripped, True))
        return parsed

    def parse_gitignore_file(self, base_rel: str,
                             abs_path: str) -> List[_Pattern]:
        if not self.use_gitignore or not os.path.isfile(abs_path):
            return []
        try:
            with open(abs_path, "r", encoding="utf-8", errors="replace") as handle:
                return self.parse_gitignore(base_rel, handle.read().splitlines())
        except OSError:
            return []

    def add_gitignore(self, base_rel: str, lines: List[str]) -> None:
        self.patterns.extend(self.parse_gitignore(base_rel, lines))

    def add_gitignore_file(self, base_rel: str, abs_path: str) -> None:
        self.patterns.extend(self.parse_gitignore_file(base_rel, abs_path))

    def is_ignored(self, rel: str, is_dir: bool = False,
                   extra: Optional[List[_Pattern]] = None) -> bool:
        rel = to_posix(rel)
        if rel.startswith("../") or rel == "..":
            return True
        parts = rel.split("/")
        # Only directory components count: a *file* named "build" is fine,
        # anything living inside an ignored directory is not.
        dir_parts = parts if is_dir else parts[:-1]
        if any(part in DEFAULT_IGNORE_DIRS for part in dir_parts):
            return True
        ignored = False
        for pattern in self.patterns:
            if pattern.matches(rel, is_dir):
                ignored = not pattern.negated
        for pattern in (extra or ()):
            if pattern.matches(rel, is_dir):
                ignored = not pattern.negated
        return ignored

    def included(self, rel: str) -> bool:
        """Return True when --include globs are empty or the path matches one."""
        if not self.include:
            return True
        rel = to_posix(rel)
        parts = rel.split("/")
        for pattern in self.include:
            if "/" in pattern:
                if fnmatch.fnmatchcase(rel, pattern):
                    return True
                for index in range(len(parts)):
                    if fnmatch.fnmatchcase("/".join(parts[index:]), pattern):
                        return True
            elif any(fnmatch.fnmatchcase(p, pattern) for p in parts):
                return True
        return False
