"""Baseline file handling: suppress known findings without hiding new ones."""

from __future__ import annotations

import datetime
import json
import os
from typing import Iterable, List, Set

from .scanner import Finding

BASELINE_VERSION = 1
DEFAULT_BASELINE = ".keyhound-baseline.json"


def _utc_now() -> str:
    return datetime.datetime.utcnow().replace(microsecond=0).isoformat() + "Z"


def load(path: str) -> Set[str]:
    """Return the set of fingerprints in a baseline file.

    A missing file yields an empty set (callers decide whether that is fine).
    A malformed file raises ValueError so the CLI can exit with code 2.
    """
    if not os.path.isfile(path):
        return set()
    with open(path, "r", encoding="utf-8") as handle:
        try:
            raw = json.load(handle)
        except ValueError as exc:
            raise ValueError("invalid baseline JSON %s: %s" % (path, exc))
    if not isinstance(raw, dict) or "findings" not in raw:
        raise ValueError("baseline %s must be an object with 'findings'" % path)
    entries = raw["findings"]
    if not isinstance(entries, list):
        raise ValueError("baseline 'findings' must be a list")
    return {
        str(entry["fingerprint"]) for entry in entries
        if isinstance(entry, dict) and "fingerprint" in entry
    }


def dump(path: str, findings: Iterable[Finding], reason: str = "") -> int:
    """Write a baseline from findings; returns the number of entries written."""
    entries: List[dict] = []
    seen = set()
    for finding in findings:
        if finding.fingerprint in seen:
            continue
        seen.add(finding.fingerprint)
        entry = {
            "fingerprint": finding.fingerprint,
            "rule_id": finding.rule_id,
            "path": finding.path,
            "line": finding.line,
            "masked": finding.masked,
            "severity": finding.severity,
        }
        if reason:
            entry["reason"] = reason
        entries.append(entry)
    payload = {
        "version": BASELINE_VERSION,
        "tool": "keyhound",
        "generated_at": _utc_now(),
        "count": len(entries),
        "findings": entries,
    }
    directory = os.path.dirname(os.path.abspath(path))
    if directory and not os.path.isdir(directory):
        os.makedirs(directory)
    with open(path, "w", encoding="utf-8", newline="\n") as handle:
        json.dump(payload, handle, indent=2, ensure_ascii=False)
        handle.write("\n")
    return len(entries)
