"""Built-in detection rules for keyhound.

Every rule is a compiled regular expression plus metadata.  ``secret_group``
points at the capture group holding the actual secret (0 = whole match), so
reports can redact precisely the interesting part.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Pattern, Tuple

SEVERITY_ORDER = {"low": 1, "medium": 2, "high": 3, "critical": 4}


@dataclass(frozen=True)
class Rule:
    id: str
    description: str
    severity: str
    pattern: str
    secret_group: int = 0
    min_entropy: float = 0.0
    min_length: int = 0
    generic: bool = False
    safe_to_show: bool = False
    tags: Tuple[str, ...] = ()

    def compile(self) -> Pattern[str]:
        return re.compile(self.pattern)


_GENERIC_ASSIGNMENT = (
    r"(?i)(?<![A-Za-z0-9])(?:api[_.-]?key|secret|token|password|passwd|pwd|"
    r"access[_.-]?key|auth[_.-]?token|client[_.-]?secret|"
    r"private[_.-]?key|credential|bearer)\b"
    r"\s*[:=]\s*[\"'`]?([A-Za-z0-9+/=_\-.~]{16,})[\"'`]?"
)

BUILTIN_RULES: Tuple[Rule, ...] = (
    Rule("aws-access-key-id", "AWS access key ID (AKIA / ASIA)", "critical",
         r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b", tags=("cloud", "aws")),
    Rule("aws-secret-access-key", "AWS secret access key (40-char base64)",
         "critical",
         r"(?i)\baws.{0,40}?(?:secret|private)[_ .-]?(?:access)?[_ .-]?key"
         r".{0,20}?[:=]\s*[\"'`]?([A-Za-z0-9/+=]{40})[\"'`]?",
         secret_group=1, min_length=40, tags=("cloud", "aws")),
    Rule("github-pat", "GitHub personal access token (classic)", "critical",
         r"\b(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{36,255}\b",
         tags=("vcs", "github")),
    Rule("github-fine-grained-pat", "GitHub fine-grained PAT", "critical",
         r"\bgithub_pat_[A-Za-z0-9_]{50,255}\b", tags=("vcs", "github")),
    Rule("github-oauth", "GitHub OAuth app client secret", "high",
         r"\b[0-9a-f]{40}\b(?=.*github)", tags=("vcs", "github")),
    Rule("gitlab-pat", "GitLab personal access token", "critical",
         r"\bglpat-[A-Za-z0-9_\-]{20,}\b", tags=("vcs", "gitlab")),
    Rule("slack-token", "Slack bot / user / app token", "high",
         r"\bxox[abprs]-[A-Za-z0-9\-]{10,}\b", tags=("saas", "slack")),
    Rule("slack-webhook", "Slack incoming webhook URL", "high",
         r"https://hooks\.slack\.com/services/T[A-Za-z0-9_]+/B[A-Za-z0-9_]+"
         r"/[A-Za-z0-9]+", tags=("saas", "slack")),
    Rule("stripe-live-key", "Stripe live secret / restricted key", "critical",
         r"\b(?:sk|rk)_live_[A-Za-z0-9]{16,}\b", tags=("payment", "stripe")),
    Rule("google-api-key", "Google / Firebase API key", "high",
         r"\bAIza[0-9A-Za-z_\-]{35}\b", tags=("cloud", "gcp")),
    Rule("google-oauth-secret", "Google OAuth client secret (GOCSPX)", "high",
         r"\bGOCSPX-[A-Za-z0-9_\-]{20,}\b", tags=("cloud", "gcp")),
    Rule("private-key-block", "PEM / OpenSSH private key header", "critical",
         r"-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP )?PRIVATE KEY-----",
         safe_to_show=True, tags=("crypto",)),
    Rule("jwt", "JSON Web Token (header.payload.signature)", "medium",
         r"\beyJ[A-Za-z0-9_\-]{8,}\.eyJ[A-Za-z0-9_\-]{8,}\."
         r"[A-Za-z0-9_\-]{10,}\b", tags=("auth",)),
    Rule("npm-token", "npm automation / access token", "high",
         r"\bnpm_[A-Za-z0-9]{36}\b", tags=("registry",)),
    Rule("pypi-token", "PyPI / TestPyPI API token", "critical",
         r"\bpypi-[A-Za-z0-9_\-]{50,}\b", tags=("registry",)),
    Rule("sendgrid-api-key", "SendGrid API key", "high",
         r"\bSG\.[A-Za-z0-9_\-]{16,}\.[A-Za-z0-9_\-]{16,}\b",
         tags=("saas", "email")),
    Rule("mailgun-api-key", "Mailgun API key", "medium",
         r"\bkey-[0-9a-zA-Z]{32}\b", tags=("saas", "email")),
    Rule("twilio-api-key", "Twilio API key (SK...)", "high",
         r"\bSK[0-9a-fA-F]{32}\b", tags=("saas",)),
    Rule("openai-api-key", "OpenAI / Anthropic style sk- key", "high",
         r"\bsk-(?:proj-|ant-)?[A-Za-z0-9_\-]{20,}\b", tags=("ai",)),
    Rule("connection-string-password", "Password embedded in a DB URI",
         "critical",
         r"(?i)\b(?:postgres(?:ql)?|mysql|mongodb(?:\+srv)?|redis|amqps?|mssql)"
         r"://[^\s:/@\"']+:([^\s@/\"'<>]{4,})@",
         secret_group=1, min_length=4, tags=("database",)),
    Rule("generic-high-entropy-secret",
         "Assignment to a secret-like key with a high-entropy value",
         "medium", _GENERIC_ASSIGNMENT, secret_group=1, min_length=16,
         generic=True, tags=("heuristic",)),
)

# Deliberately conservative: bare words are anchored or word-bounded so a
# real random token that happens to contain the letters "true" is not dropped.
DEFAULT_ALLOWLIST = (
    r"(?i:"
    r"(?:"
    r"^(?:null|none|true|false|undefined|todo|fixme|changeme|placeholder|"
    r"example|dummy|redacted|test|fake|sample|secret|password|token|"
    r"your[_-].*|insert[_-]?here|replace[_-]?me|secret[_-]?here|"
    r"not[_-]?a[_-]?real|test[_-]?key|public[_-]?key|<[^>]*>|"
    r"\$\{[^}]*\}|\{\{[^}]*\}\}|\*{3,}|x{4,}|%[sd])$"
    r"|\b(?:example|placeholder|dummy|changeme|redacted|fake|sample|"
    r"your[_-]|insert[_-]?here|replace[_-]?me|not[_-]?a[_-]?real|"
    r"test[_-]?key|public[_-]?key)\b"
    r"|\$\{[^}]*\}|\{\{[^}]*\}\}|<[^>]*>|\*{3,}|%[sd]"
    r")"
    r")"
)


class RuleSet:
    """Compiled, filtered collection of rules."""

    def __init__(self, rules: Tuple[Rule, ...] = BUILTIN_RULES,
                 disabled: Optional[List[str]] = None,
                 custom: Optional[List[Rule]] = None) -> None:
        disabled_set = set(disabled or [])
        self.rules: List[Rule] = [r for r in rules if r.id not in disabled_set]
        self.rules.extend(r for r in (custom or []) if r.id not in disabled_set)
        self._compiled: Dict[str, Pattern[str]] = {}
        for rule in self.rules:
            try:
                compiled = rule.compile()
            except re.error as exc:
                raise ValueError("invalid regex in rule %r: %s" % (rule.id, exc))
            if rule.secret_group > compiled.groups:
                raise ValueError(
                    "rule %r references group %d but pattern has %d groups"
                    % (rule.id, rule.secret_group, compiled.groups))
            self._compiled[rule.id] = compiled

    def __iter__(self):
        return iter(self.rules)

    def __len__(self) -> int:
        return len(self.rules)

    def pattern(self, rule_id: str) -> Pattern[str]:
        return self._compiled[rule_id]

    def by_id(self, rule_id: str) -> Optional[Rule]:
        return next((r for r in self.rules if r.id == rule_id), None)


def rule_from_dict(data: dict) -> Rule:
    """Build a Rule from a ``custom_rules`` entry in .keyhound.json."""
    required = ("id", "description", "severity", "pattern")
    missing = [k for k in required if k not in data]
    if missing:
        raise ValueError("custom rule missing field(s): %s" % ", ".join(missing))
    severity = str(data["severity"]).lower()
    if severity not in SEVERITY_ORDER:
        raise ValueError("custom rule %r has unknown severity %r"
                         % (data["id"], severity))
    return Rule(
        id=str(data["id"]),
        description=str(data["description"]),
        severity=severity,
        pattern=str(data["pattern"]),
        secret_group=int(data.get("secret_group", 0)),
        min_entropy=float(data.get("min_entropy", 0.0)),
        min_length=int(data.get("min_length", 0)),
        generic=bool(data.get("generic", False)),
        safe_to_show=bool(data.get("safe_to_show", False)),
        tags=tuple(data.get("tags", ())),
    )
