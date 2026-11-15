#!/usr/bin/env python3
"""Zero-install entry point: ``python keyhound-cli.py .`` works after clone.

The repository root itself is on sys.path, so the sibling ``keyhound/``
package is importable without pip install / editable install.
"""

from __future__ import annotations

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from keyhound.cli import main  # noqa: E402

if __name__ == "__main__":
    raise SystemExit(main())
