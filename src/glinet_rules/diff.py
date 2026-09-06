"""Change detection between the candidate build and the last published release.

Upstream data moves every day, and most of that movement is legitimate. The
gates here exist for the movement that is not: a source repository that gets
compromised, a build script upstream that breaks, a category that silently
empties out. When any of those happen the right answer is to keep serving the
previous known-good list, so every check in this module can only fail the build.
"""

from __future__ import annotations

import ipaddress
from dataclasses import dataclass, field
from pathlib import Path

from .config import Policy
from .errors import SecurityGateError
from .ipv4 import IPv4Network, coverage_addresses, normalize_network


def _percent_change(old: float, new: float) -> float:
    """Signed percentage change from `old` to `new`; 0 when there is no baseline."""
    if old == 0:
        return 0.0 if new == 0 else 100.0
    return (new - old) / old * 100.0


@dataclass
class SetDiff:
    """Added/removed entries between two rule sets."""

    added: list[str] = field(default_factory=list)
    removed: list[str] = field(default_factory=list)
    old_count: int = 0
    new_count: int = 0

    @property
    def count_change_percent(self) -> float:
        return _percent_change(self.old_count, self.new_count)

    @property
    def removed_percent(self) -> float:
        if self.old_count == 0:
            return 0.0
        return len(self.removed) / self.old_count * 100.0

    def as_metadata(self) -> dict:
        return {
            "old_count": self.old_count,
            "new_count": self.new_count,
            "added": len(self.added),
            "removed": len(self.removed),
            "count_change_percent": round(self.count_change_percent, 4),
            "removed_percent": round(self.removed_percent, 4),
        }


def diff_sets(old: list[str], new: list[str]) -> SetDiff:
    old_set, new_set = set(old), set(new)
    return SetDiff(
        added=sorted(new_set - old_set),
        removed=sorted(old_set - new_set),
        old_count=len(old_set),
        new_count=len(new_set),
    )


# --- address-space arithmetic -------------------------------------------------
# Networks are converted to half-open integer intervals so that coverage and
# overlap can be computed exactly, without materializing any addresses.

def _intervals(networks: list[IPv4Network]) -> list[tuple[int, int]]:
    raw = sorted((int(n.network_address), int(n.broadcast_address) + 1) for n in networks)
    merged: list[tuple[int, int]] = []
    for start, end in raw:
        if merged and start <= merged[-1][1]:
            merged[-1] = (merged[-1][0], max(merged[-1][1], end))
        else:
            merged.append((start, end))
    return merged


def _intersection_size(a: list[tuple[int, int]], b: list[tuple[int, int]]) -> int:
    total = i = j = 0
    while i < len(a) and j < len(b):
        start = max(a[i][0], b[j][0])
        end = min(a[i][1], b[j][1])
        if start < end:
            total += end - start
        if a[i][1] < b[j][1]:
            i += 1
        else:
            j += 1
    return total


@dataclass
class CoverageComparison:
    """Address-space comparison between two IPv4 network sets."""

    left_name: str
    right_name: str
    left_networks: int
    right_networks: int
    left_addresses: int
    right_addresses: int
    shared_addresses: int
    only_left: list[IPv4Network]
    only_right: list[IPv4Network]

    @property
    def address_change_percent(self) -> float:
        return _percent_change(self.left_addresses, self.right_addresses)

    @property
    def divergence_percent(self) -> float:
        """Share of the union that the two sets disagree about."""
        union = self.left_addresses + self.right_addresses - self.shared_addresses
        if union == 0:
            return 0.0
        return (union - self.shared_addresses) / union * 100.0

    def as_metadata(self) -> dict:
        return {
            "left": self.left_name,
            "right": self.right_name,
            "left_networks": self.left_networks,
            "right_networks": self.right_networks,
            "left_addresses": self.left_addresses,
            "right_addresses": self.right_addresses,
            "shared_addresses": self.shared_addresses,
            "address_change_percent": round(self.address_change_percent, 4),
            "divergence_percent": round(self.divergence_percent, 4),
            "only_left_networks": len(self.only_left),
            "only_right_networks": len(self.only_right),
            "largest_only_left": [str(n) for n in self.only_left[:10]],
            "largest_only_right": [str(n) for n in self.only_right[:10]],
        }


def compare_coverage(
    left: list[IPv4Network],
    right: list[IPv4Network],
    *,
    left_name: str,
    right_name: str,
) -> CoverageComparison:
    """Compare two IPv4 sets by address space as well as by rule count."""
    left_set, right_set = set(left), set(right)
    only_left = sorted(left_set - right_set, key=lambda n: (n.prefixlen, n))
    only_right = sorted(right_set - left_set, key=lambda n: (n.prefixlen, n))
    return CoverageComparison(
        left_name=left_name,
        right_name=right_name,
        left_networks=len(left),
        right_networks=len(right),
        left_addresses=coverage_addresses(left),
        right_addresses=coverage_addresses(right),
        shared_addresses=_intersection_size(_intervals(left), _intervals(right)),
        only_left=only_left,
        only_right=only_right,
    )


# --- fail-closed gates against the previous release ---------------------------

def check_ipv4_change(
    previous: list[IPv4Network],
    current: list[IPv4Network],
    *,
    policy: Policy,
) -> tuple[SetDiff, CoverageComparison]:
    """Compare against the last published IPv4 list and enforce the thresholds."""
    set_diff = diff_sets([str(n) for n in previous], [str(n) for n in current])
    coverage = compare_coverage(previous, current, left_name="previous", right_name="current")

    max_count = float(policy.value("ipv4", "max_rule_count_change_percent"))
    max_coverage = float(policy.value("ipv4", "max_coverage_change_percent"))
    max_removed = float(policy.value("ipv4", "max_removed_percent"))

    if abs(set_diff.count_change_percent) > max_count:
        raise SecurityGateError(
            "ipv4:rule-count-change",
            f"network count moved {set_diff.count_change_percent:+.2f}% "
            f"({set_diff.old_count} -> {set_diff.new_count}), limit is +/-{max_count}%",
        )
    if abs(coverage.address_change_percent) > max_coverage:
        raise SecurityGateError(
            "ipv4:coverage-change",
            f"address coverage moved {coverage.address_change_percent:+.2f}% "
            f"({coverage.left_addresses:,} -> {coverage.right_addresses:,}), "
            f"limit is +/-{max_coverage}%",
        )
    if set_diff.removed_percent > max_removed:
        raise SecurityGateError(
            "ipv4:removal-rate",
            f"{len(set_diff.removed)} of {set_diff.old_count} networks removed "
            f"({set_diff.removed_percent:.2f}%), limit is {max_removed}%",
        )
    return set_diff, coverage


def check_domain_change(
    previous: list[str],
    current: list[str],
    *,
    policy: Policy,
) -> SetDiff:
    """Compare against the last published domain list and enforce the thresholds."""
    set_diff = diff_sets(previous, current)

    max_count = float(policy.value("domains", "max_rule_count_change_percent"))
    max_removed = float(policy.value("domains", "max_removed_percent"))

    if abs(set_diff.count_change_percent) > max_count:
        raise SecurityGateError(
            "domains:rule-count-change",
            f"domain count moved {set_diff.count_change_percent:+.2f}% "
            f"({set_diff.old_count} -> {set_diff.new_count}), limit is +/-{max_count}%",
        )
    if set_diff.removed_percent > max_removed:
        raise SecurityGateError(
            "domains:removal-rate",
            f"{len(set_diff.removed)} of {set_diff.old_count} domains removed "
            f"({set_diff.removed_percent:.2f}%), limit is {max_removed}%",
        )
    return set_diff


# --- helpers for reading a previously published directory ---------------------

def read_ipv4_file(path: Path) -> list[IPv4Network]:
    if not path.is_file():
        return []
    networks = []
    for raw in path.read_text(encoding="utf-8").splitlines():
        line = raw.split("#", 1)[0].strip()
        if line:
            try:
                networks.append(normalize_network(line))
            except ValueError:
                continue
    return sorted(set(networks))


def read_domain_file(path: Path) -> list[str]:
    if not path.is_file():
        return []
    out = []
    for raw in path.read_text(encoding="utf-8").splitlines():
        line = raw.split("#", 1)[0].strip().lower()
        if line and not _looks_like_ip(line):
            out.append(line)
    return sorted(set(out))


def _looks_like_ip(line: str) -> bool:
    try:
        ipaddress.IPv4Network(line, strict=False)
    except ValueError:
        return False
    return True
