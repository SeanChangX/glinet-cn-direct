#!/usr/bin/env python3
"""Compose the publication commit message / release notes from build metadata.

Kept as a script rather than inline workflow YAML so it can be run and reviewed
locally, and so the workflow stays readable.

    python scripts/release-notes.py --dist dist --audit audit/report.json
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path


def revision_of(metadata: dict, key: str) -> str:
    for source in metadata["sources"]:
        if source["key"] == key:
            return f"{source['name']}@{source['revision']}"
    return "unknown"


def movement(audit: dict, section: str) -> str:
    data = audit.get(section)
    if not data:
        return "n/a (no previous release)"
    return f"+{data['added']} / -{data['removed']} ({data['count_change_percent']:+.2f}%)"


def compose(metadata: dict, audit: dict) -> str:
    counts = metadata["counts"]
    ipv4 = metadata["ipv4"]
    lines = [
        f"chore(rules): update CN routing rules [{metadata['generated_on']}]",
        "",
        f"IPv4 source  : {revision_of(metadata, 'ipv4_primary')}",
        f"Domain source: {revision_of(metadata, 'domains_primary')}",
        "",
        f"IPv4 networks: {counts['ipv4_networks']:,}",
        f"Domains      : {counts['domains']:,}",
        f"Combined     : {counts['combined']:,}",
        f"IPv4 coverage: {ipv4['addresses']:,} addresses "
        f"({ipv4['coverage_percent_ipv4']}% of IPv4), broadest {ipv4['broadest_prefix']}",
        "",
        f"IPv4 change  : {movement(audit, 'ipv4')}",
        f"Domain change: {movement(audit, 'domains')}",
    ]
    warnings = metadata.get("warnings") or []
    if warnings:
        lines += ["", "Warnings:"]
        lines += [f"  - {w}" for w in warnings]
    return "\n".join(lines) + "\n"


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--dist", type=Path, default=Path("dist"))
    parser.add_argument("--audit", type=Path, default=Path("audit/report.json"))
    parser.add_argument("--output", type=Path, default=None)
    args = parser.parse_args(argv)

    metadata = json.loads((args.dist / "metadata.json").read_text(encoding="utf-8"))
    audit = json.loads(args.audit.read_text(encoding="utf-8")) if args.audit.is_file() else {}

    text = compose(metadata, audit)
    if args.output is None:
        sys.stdout.write(text)
    else:
        args.output.write_text(text, encoding="utf-8")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
