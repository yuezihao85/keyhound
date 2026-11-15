"""Use keyhound as a library instead of a CLI (standard library only).

Run from the repository root:  python examples/library_usage.py
"""

from __future__ import annotations

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from keyhound import Config, RuleSet, Scanner
from keyhound.reporters import render_console, render_json, render_sarif


def main() -> int:
    config = Config(min_entropy=3.8, min_length=20, exclude=["*.min.js"])
    config.build_allowlist()  # required before constructing a Scanner

    rules = RuleSet(disabled=["jwt"])

    # 1. Scan files on disk.
    result = Scanner(config, rules).scan(["tests/fixtures/sample.env"])
    print(render_console(result, color="never"))

    # 2. Scan an in-memory string (stdin / diff / generated config).
    inline = Scanner(config, rules).scan_text(
        'api_key = "9fB3kQ7mZ1xP4vT8nR6wL2cY5sH0jD"\n', label="generated.env"
    )
    for finding in inline.findings:
        print("%s:%d %s -> %s" % (finding.path, finding.line,
                                  finding.rule_id, finding.masked))

    # 3. Machine-readable output, no raw secret is ever included.
    payload = render_json(result)
    assert "9fB3kQ7mZ1xP4vT8nR6wL2cY5sH0jD" not in payload
    sarif = render_sarif(result)
    assert '"version": "2.1.0"' in sarif
    print("json bytes=%d  sarif bytes=%d" % (len(payload), len(sarif)))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
