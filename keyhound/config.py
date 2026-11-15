"""Configuration loading for keyhound (.keyhound.json, zero dependencies)."""

from __future__ import annotations

import json
import os
import re
from dataclasses import dataclass, field
from typing import List, Optional, Pattern

from .rules import DEFAULT_ALLOWLIST, Rule, rule_from_dict

CONFIG_FILENAME = ".keyhound.json"

DEFAULT_EXCLUDE = (
    "*.min.js", "*.map", "*.lock", "*.pdf", "*.png", "*.jpg", "*.jpeg",
    "*.gif", "*.ico", "*.woff*", "*.zip", "*.gz", "*.pyc",
)

# Scoped inline flags "(?i:...)" rather than a global "(?i)": allowlist
# patterns are joined with "|", and Python 3.11+ rejects global flags that
# are not at the very start of the combined expression.
DEFAULT_CONTEXT_ALLOWLIST = (
    r"(?i:os\.environ|process\.env|getenv|environ\.get|ENV\[|"
    r"System\.getenv|keyhound:allow|nosec\b)"
)

DEFAULT_TEMPLATE = {
    "exclude": list(DEFAULT_EXCLUDE),
    "include": [],
    "min_entropy": 3.5,
    "min_length": 16,
    "max_size_bytes": 2097152,
    "disabled_rules": [],
    "custom_rules": [],
    "allowlist": [],
    "use_gitignore": True,
    "fail_on": "low",
}

_LEADING_FLAGS = re.compile(r"^\(\?([imsx]+)\)")


def _scoped(pattern: str) -> str:
    """Make a leading global inline-flag group safe for alternation.

    ``(?i)foo`` becomes ``(?i:foo)``.  Global flags are only legal at the
    start of a whole expression, but every allowlist entry is embedded in a
    larger ``(?:a|b|c)`` group.
    """
    match = _LEADING_FLAGS.match(pattern)
    if not match:
        return pattern
    return "(?%s:%s)" % (match.group(1), pattern[match.end():])


@dataclass
class Config:
    exclude: List[str] = field(default_factory=lambda: list(DEFAULT_EXCLUDE))
    include: List[str] = field(default_factory=list)
    min_entropy: float = 3.5
    min_length: int = 16
    max_size_bytes: int = 2097152
    disabled_rules: List[str] = field(default_factory=list)
    custom_rules: List[Rule] = field(default_factory=list)
    allowlist: List[str] = field(default_factory=list)
    use_gitignore: bool = True
    fail_on: str = "low"
    config_path: Optional[str] = None
    allowlist_re: Pattern[str] = field(
        default_factory=lambda: re.compile(DEFAULT_ALLOWLIST))
    context_re: Pattern[str] = field(
        default_factory=lambda: re.compile(DEFAULT_CONTEXT_ALLOWLIST))

    def build_allowlist(self) -> None:
        # An allowlist entry is checked against the secret value, the full
        # regex match, and a +-40 character context window around the match.
        value_parts = [_scoped(DEFAULT_ALLOWLIST)]
        value_parts.extend(_scoped(p) for p in self.allowlist)
        context_parts = [_scoped(DEFAULT_CONTEXT_ALLOWLIST)]
        context_parts.extend(_scoped(p) for p in self.allowlist)
        try:
            self.allowlist_re = re.compile(
                "|".join("(?:%s)" % p for p in value_parts))
            self.context_re = re.compile(
                "|".join("(?:%s)" % p for p in context_parts))
        except re.error as exc:
            raise ValueError("invalid allowlist regex: %s" % exc)


def load_config(explicit_path: Optional[str] = None,
                root: Optional[str] = None) -> Config:
    """Load config from *explicit_path*, or discover .keyhound.json at *root*.

    An explicit path that does not exist is an error (exit code 2 territory);
    an absent implicit config simply yields defaults.
    """
    cfg = Config()
    path = explicit_path
    if path is None and root:
        candidate = os.path.join(root, CONFIG_FILENAME)
        if os.path.isfile(candidate):
            path = candidate
    if path is None:
        cfg.build_allowlist()
        return cfg

    if not os.path.isfile(path):
        raise IOError("config file not found: %s" % path)
    with open(path, "r", encoding="utf-8") as handle:
        try:
            raw = json.load(handle)
        except ValueError as exc:
            raise ValueError("invalid JSON in %s: %s" % (path, exc))
    if not isinstance(raw, dict):
        raise ValueError("config %s must contain a JSON object" % path)

    for key in ("exclude", "include", "disabled_rules", "allowlist"):
        if key in raw:
            value = raw[key]
            if not isinstance(value, list) or not all(isinstance(x, str) for x in value):
                raise ValueError("config field %r must be a list of strings" % key)
            setattr(cfg, key, list(value))
    for key in ("min_entropy",):
        if key in raw:
            cfg.min_entropy = float(raw[key])
    for key in ("min_length", "max_size_bytes"):
        if key in raw:
            setattr(cfg, key, int(raw[key]))
    if "use_gitignore" in raw:
        cfg.use_gitignore = bool(raw["use_gitignore"])
    if "fail_on" in raw:
        cfg.fail_on = str(raw["fail_on"]).lower()
    if "custom_rules" in raw:
        entries = raw["custom_rules"]
        if not isinstance(entries, list):
            raise ValueError("config field 'custom_rules' must be a list")
        cfg.custom_rules = [rule_from_dict(e) for e in entries]
    cfg.config_path = os.path.abspath(path)
    cfg.build_allowlist()
    return cfg


def write_template(path: str) -> bool:
    """Write the default config; returns False when the file already exists."""
    if os.path.exists(path):
        return False
    with open(path, "w", encoding="utf-8", newline="\n") as handle:
        json.dump(DEFAULT_TEMPLATE, handle, indent=2, ensure_ascii=False)
        handle.write("\n")
    return True
