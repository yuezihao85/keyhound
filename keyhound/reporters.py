"""Console / JSON / SARIF 2.1.0 renderers."""

from __future__ import annotations

import json
import os
import sys
from typing import Any, Dict, Iterable, List

from . import __version__
from .rules import SEVERITY_ORDER
from .scanner import Finding, ScanResult

LEVELS = {
    "low": "note",
    "medium": "warning",
    "high": "error",
    "critical": "error",
}

COLORS = {
    "low": "\x1b[36m",      # cyan
    "medium": "\x1b[33m",   # yellow
    "high": "\x1b[31m",     # red
    "critical": "\x1b[35m", # magenta
    "reset": "\x1b[0m",
    "dim": "\x1b[2m",
    "bold": "\x1b[1m",
}


def _use_color(color: str) -> bool:
    if color == "always":
        return True
    if color == "never":
        return False
    if os.environ.get("NO_COLOR"):
        return False
    try:
        return bool(sys.stdout.isatty())
    except Exception:
        return False


def _counted(n: int, word: str) -> str:
    return "%d %s%s" % (n, word, "" if n == 1 else "s")


def _scope(files: int, line_count: int) -> str:
    return "%s / %s scanned" % (_counted(files, "file"),
                                _counted(line_count, "line"))


def render_console(result: ScanResult, color: str = "auto",
                   show_suppressed: bool = False) -> str:
    use = _use_color(color)
    paint = lambda name: COLORS.get(name, "") if use else ""
    reset = COLORS["reset"] if use else ""
    lines: List[str] = []
    scope = _scope(result.files_scanned, result.lines_scanned)

    if not result.findings:
        # ASCII only: Windows consoles (cp936/cp1252) cannot render Unicode
        # markers, and CI logs should stay byte-clean everywhere.
        lines.append("%s[OK] no secrets found%s  %s%s%s"
                     % (paint("low"), reset, paint("dim"), scope, reset))
    else:
        lines.append("%s[!] %d potential secret%s found%s"
                     % (paint("critical"), len(result.findings),
                        "" if len(result.findings) == 1 else "s", reset))
        lines.append("")
        current_path = None
        for finding in result.findings:
            if finding.path != current_path:
                current_path = finding.path
                lines.append("%s%s%s" % (paint("bold"), current_path, reset))
            severity = "%s%-8s%s" % (paint(finding.severity),
                                     finding.severity, reset)
            lines.append(
                "  %s:%d:%d  %s  %s%s%s  %s"
                % (finding.path, finding.line, finding.column, severity,
                   paint("bold"), finding.rule_id, reset, finding.description)
            )
            lines.append("    %svalue: %s  fp: %s%s"
                         % (paint("dim"), finding.masked, finding.fingerprint,
                            reset))
        lines.append("")
        counts = result.counts_by_severity
        summary = ", ".join("%s=%d" % (k, counts[k])
                            for k in ("critical", "high", "medium", "low"))
        lines.append("%s%s  (%s)%s"
                     % (paint("dim"), scope, summary, reset))

    if result.suppressed:
        n = len(result.suppressed)
        lines.append("%s%d baseline-suppressed finding%s%s"
                     % (paint("dim"), n, "" if n == 1 else "s", reset))
        if show_suppressed:
            for finding in result.suppressed:
                lines.append("  %s:%d  %s  %s"
                             % (finding.path, finding.line, finding.rule_id,
                                finding.fingerprint))
    for error in result.errors:
        lines.append("%swarning: %s%s" % (paint("medium"), error, reset))
    return "\n".join(lines) + "\n"


def _finding_dict(finding: Finding) -> dict:
    return finding.to_dict()


def render_json(result: ScanResult) -> str:
    payload: Dict[str, Any] = {
        "version": 1,
        "tool": "keyhound",
        "tool_version": __version__,
        "scan_root": result.base.replace("\\", "/"),
        "summary": {
            "total": len(result.findings),
            "suppressed": len(result.suppressed),
            "files_scanned": result.files_scanned,
            "files_skipped": result.files_skipped,
            "lines_scanned": result.lines_scanned,
            "by_severity": result.counts_by_severity,
        },
        "findings": [_finding_dict(f) for f in result.findings],
        "errors": list(result.errors),
    }
    return json.dumps(payload, indent=2, ensure_ascii=False) + "\n"


def render_sarif(result: ScanResult) -> str:
    rules = []
    index_by_id: Dict[str, int] = {}
    for rule_id in sorted({f.rule_id for f in result.findings}):
        finding = next(f for f in result.findings if f.rule_id == rule_id)
        index_by_id[rule_id] = len(rules)
        rules.append({
            "id": rule_id,
            "name": rule_id,
            "shortDescription": {"text": finding.description},
            "defaultConfiguration": {
                "level": LEVELS.get(finding.severity, "warning")
            },
            "properties": {
                "severity": finding.severity,
                "tags": list(finding.tags),
            },
        })

    results = []
    for finding in result.findings:
        results.append({
            "ruleId": finding.rule_id,
            "ruleIndex": index_by_id[finding.rule_id],
            "level": LEVELS.get(finding.severity, "warning"),
            "message": {
                "text": "%s: %s (redacted %s)"
                        % (finding.description, finding.rule_id, finding.masked)
            },
            "locations": [{
                "physicalLocation": {
                    "artifactLocation": {"uri": finding.path},
                    "region": {
                        "startLine": finding.line,
                        "startColumn": finding.column,
                        "snippet": {"text": finding.masked},
                    },
                }
            }],
            "partialFingerprints": {
                "keyhoundSecretHash/v1": finding.fingerprint,
            },
            "properties": {
                "severity": finding.severity,
                "baseline_suppressed": False,
            },
        })

    payload = {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {
                "driver": {
                    "name": "keyhound",
                    "version": __version__,
                    "informationUri": "https://github.com/yuezihao85/keyhound",
                    "rules": rules,
                }
            },
            "results": results,
            "properties": {
                "filesScanned": result.files_scanned,
                "linesScanned": result.lines_scanned,
                "baselineSuppressed": len(result.suppressed),
            },
        }],
    }
    return json.dumps(payload, indent=2, ensure_ascii=False) + "\n"


def render(result: ScanResult, fmt: str, color: str = "auto") -> str:
    if fmt == "json":
        return render_json(result)
    if fmt == "sarif":
        return render_sarif(result)
    return render_console(result, color=color)
