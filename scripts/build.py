#!/usr/bin/env python3
"""Convenience wrapper so the build runs from a checkout without installing.

Equivalent to `python -m glinet_rules build`, with src/ put on sys.path first.
"""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from glinet_rules.cli import main  # noqa: E402

if __name__ == "__main__":
    raise SystemExit(main(["build", *sys.argv[1:]]))
