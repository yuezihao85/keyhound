"""Entropy helpers used to separate real secrets from ordinary identifiers.

Pure standard library, Python 3.7+.
"""

from __future__ import annotations

import math
import re
import string
from collections import Counter
from typing import Iterable

_HEX = frozenset(string.hexdigits)
_B64 = frozenset(string.ascii_letters + string.digits + "+/=")
_B64URL = frozenset(string.ascii_letters + string.digits + "-_=")
_ALNUM = frozenset(string.ascii_letters + string.digits)

_REPEATED_CHAR = re.compile(r"^(.)\1+$")


def shannon_entropy(value: str) -> float:
    """Return the base-2 Shannon entropy of the characters in *value*.

    >>> round(shannon_entropy("aaaa"), 3)
    0.0
    >>> round(shannon_entropy("ab"), 3)
    1.0
    """
    if not value:
        return 0.0
    counts = Counter(value)
    length = float(len(value))
    return -sum(
        (n / length) * math.log(n / length, 2) for n in counts.values()
    )


def charset_of(value: str) -> str:
    """Classify the alphabet of *value*: hex, base64, base64url, alnum, mixed."""
    if not value:
        return "empty"
    if all(c in _HEX for c in value):
        return "hex"
    if all(c in _B64 for c in value):
        return "base64"
    if all(c in _B64URL for c in value):
        return "base64url"
    if all(c in _ALNUM for c in value):
        return "alnum"
    return "mixed"


def normalized_entropy(value: str) -> float:
    """Entropy divided by the theoretical maximum for the detected alphabet.

    Hex tops out at 4.0 bits/char, base64 at 6.0.  Use this when comparing
    values of different lengths / alphabets; ``shannon_entropy`` is the raw
    value exposed in reports.
    """
    maximum = {"hex": 4.0, "base64": 6.0, "base64url": 6.0,
               "alnum": 5.17, "mixed": 6.0, "empty": 1.0}[charset_of(value)]
    return shannon_entropy(value) / maximum if maximum else 0.0


def looks_like_random(value: str, min_entropy: float = 3.5,
                      min_length: int = 16) -> bool:
    """Heuristic gate for generic high-entropy assignments.

    Rejects repeated characters, low-entropy dictionary-ish strings, and
    short values before they ever become findings.
    """
    if len(value) < min_length:
        return False
    if _REPEATED_CHAR.match(value):
        return False
    if shannon_entropy(value) < min_entropy:
        return False
    # A random token should mix at least two character classes.  This kills
    # things like "production_env_prod" (high-ish entropy, all lowercase).
    classes = sum(bool(re.search(p, value)) for p in (
        r"[a-z]", r"[A-Z]", r"[0-9]", r"[^A-Za-z0-9]"
    ))
    return classes >= 2


def extract_candidates(text: str, min_length: int = 16) -> Iterable[str]:
    """Yield word-like tokens that could be standalone secrets in a line.

    Useful for custom rules that want to run their own entropy pass.
    """
    for match in re.finditer(r"[A-Za-z0-9+/=_\-.~]{%d,}" % min_length, text):
        yield match.group(0)
