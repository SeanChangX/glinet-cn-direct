#!/usr/bin/env python3
"""One-off migration audit: generated cn-ipv4.txt vs a known-good baseline list.

This exists for the migration described in README ("Migrating from another
subscription"). It is deliberately NOT part of the build pipeline: the baseline
is a comparator, never a source, and the project must not acquire a runtime
dependency on someone else's moving list.

    python scripts/compare-baseline.py
    python scripts/compare-baseline.py --baseline-url https://.../ipv4.txt
    python scripts/compare-baseline.py --baseline-file previous/ipv4.txt

The output answers one question: would switching subscriptions change which
destinations bypass the VPN, and by how much?
"""

from __future__ import annotations

import argparse
import ipaddress
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from glinet_rules.config import load_config  # noqa: E402
from glinet_rules.diff import compare_coverage, diff_sets  # noqa: E402
from glinet_rules.fetch import http_get  # noqa: E402
from glinet_rules.ipv4 import normalize_network  # noqa: E402

DEFAULT_BASELINE_URL = (
    "https://raw.githubusercontent.com/carrnot/china-ip-list/release/ipv4.txt"
)


def parse_networks(text: str) -> list[ipaddress.IPv4Network]:
    networks = []
    for raw in text.splitlines():
        line = raw.split("#", 1)[0].strip()
        if not line:
            continue
        try:
            networks.append(normalize_network(line))
        except ValueError:
            continue
    return sorted(set(networks))


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--generated", type=Path, default=Path("dist/cn-ipv4.txt"))
    parser.add_argument("--baseline-url", default=DEFAULT_BASELINE_URL)
    parser.add_argument("--baseline-file", type=Path, default=None)
    parser.add_argument("--json", action="store_true", help="emit the report as JSON")
    args = parser.parse_args(argv)

    if not args.generated.is_file():
        parser.error(f"{args.generated} not found; run a build first")

    config = load_config()
    generated = parse_networks(args.generated.read_text(encoding="utf-8"))

    if args.baseline_file is not None:
        baseline_name = str(args.baseline_file)
        baseline_text = args.baseline_file.read_text(encoding="utf-8")
    else:
        baseline_name = args.baseline_url
        baseline_text = http_get(
            args.baseline_url,
            policy=config.policy,
            max_bytes=int(config.policy.value("fetch", "ipv4_max_bytes")),
        ).decode("utf-8")
    baseline = parse_networks(baseline_text)

    coverage = compare_coverage(
        baseline, generated, left_name=baseline_name, right_name=str(args.generated)
    )
    rules = diff_sets([str(n) for n in baseline], [str(n) for n in generated])

    report = {
        "baseline": baseline_name,
        "generated": str(args.generated),
        "rules": rules.as_metadata(),
        "coverage": coverage.as_metadata(),
        "shared_percent_of_baseline": round(
            coverage.shared_addresses / coverage.left_addresses * 100.0, 4
        )
        if coverage.left_addresses
        else 0.0,
    }

    if args.json:
        print(json.dumps(report, indent=2, sort_keys=True))
        return 0

    print(f"baseline : {baseline_name}")
    print(f"generated: {args.generated}")
    print()
    print(f"  networks   {coverage.left_networks:>12,}  ->  {coverage.right_networks:>12,}")
    print(f"  addresses  {coverage.left_addresses:>12,}  ->  {coverage.right_addresses:>12,}")
    print(f"  shared addresses            {coverage.shared_addresses:>12,} "
          f"({report['shared_percent_of_baseline']:.2f}% of baseline)")
    print(f"  address coverage change     {coverage.address_change_percent:>+11.2f}%")
    print(f"  network count change        {rules.count_change_percent:>+11.2f}%")
    print()
    print(f"  only in baseline : {len(coverage.only_left):,} networks")
    for network in coverage.only_left[:10]:
        print(f"      {network}  ({network.num_addresses:,} addresses)")
    print(f"  only in generated: {len(coverage.only_right):,} networks")
    for network in coverage.only_right[:10]:
        print(f"      {network}  ({network.num_addresses:,} addresses)")
    print()
    print("Interpretation: a small address-coverage change means the routing")
    print("policy is preserved even when the rule counts differ, because one")
    print("list may express the same space with fewer, larger CIDRs.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
