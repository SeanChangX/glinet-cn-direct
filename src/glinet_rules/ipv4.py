"""Parsing, normalization and safety analysis of IPv4 routing rules.

Nothing here repairs bad input. A line either normalizes cleanly to a canonical
IPv4 network or it is rejected with a reason, because in this project a wrongly
accepted network silently removes destinations from the VPN tunnel.
"""

from __future__ import annotations

import ipaddress
from dataclasses import dataclass, field

from .config import Policy
from .errors import SecurityGateError

IPv4Network = ipaddress.IPv4Network

#: Special-purpose IPv4 ranges that must never appear in a geographic routing
#: list. Defined explicitly rather than via `.is_private`, because the registry
#: semantics behind that property are broader than, and can drift from, this
#: project's policy (spec: reserved / special-use validation).
RESERVED_NETWORKS: tuple[IPv4Network, ...] = tuple(
    IPv4Network(cidr)
    for cidr in (
        "0.0.0.0/8",          # "this network"
        "10.0.0.0/8",         # RFC 1918 private
        "100.64.0.0/10",      # RFC 6598 carrier-grade NAT
        "127.0.0.0/8",        # loopback
        "169.254.0.0/16",     # link-local
        "172.16.0.0/12",      # RFC 1918 private
        "192.0.0.0/24",       # IETF protocol assignments
        "192.0.2.0/24",       # TEST-NET-1
        "192.88.99.0/24",     # deprecated 6to4 relay anycast
        "192.168.0.0/16",     # RFC 1918 private
        "198.18.0.0/15",      # benchmarking
        "198.51.100.0/24",    # TEST-NET-2
        "203.0.113.0/24",     # TEST-NET-3
        "224.0.0.0/4",        # multicast
        "240.0.0.0/4",        # reserved / limited broadcast
    )
)

TOTAL_IPV4_ADDRESSES = 2**32


@dataclass
class ParseReport:
    """What happened while turning upstream text into networks."""

    total_lines: int = 0
    content_lines: int = 0
    accepted: int = 0
    rejected: list[tuple[int, str, str]] = field(default_factory=list)

    @property
    def rejected_count(self) -> int:
        return len(self.rejected)

    @property
    def unparsable_percent(self) -> float:
        if self.content_lines == 0:
            return 0.0
        return self.rejected_count / self.content_lines * 100.0

    def as_metadata(self) -> dict:
        return {
            "lines_read": self.total_lines,
            "entries_read": self.content_lines,
            "entries_valid": self.accepted,
            "entries_rejected": self.rejected_count,
            "rejected_percent": round(self.unparsable_percent, 4),
            "rejected_samples": [
                {"line": lineno, "value": value, "reason": reason}
                for lineno, value, reason in self.rejected[:20]
            ],
        }


def normalize_network(value: str) -> IPv4Network:
    """Return the canonical IPv4 network for `value`, or raise ValueError.

    A bare address becomes a /32. Host bits are cleared (1.2.3.5/24 -> 1.2.3.0/24)
    so that identical ranges written differently deduplicate against each other.
    """
    text = value.strip()
    if not text:
        raise ValueError("empty value")
    if ":" in text:
        raise ValueError("looks like IPv6; IPv4 output must not contain it")
    if "/" not in text:
        # Reject a bare address early rather than letting IPv4Network guess.
        ipaddress.IPv4Address(text)
        return IPv4Network(f"{text}/32")
    return IPv4Network(text, strict=False)


def parse_ipv4_lines(text: str) -> tuple[list[IPv4Network], ParseReport]:
    """Parse an upstream IPv4 list into canonical networks plus a report."""
    report = ParseReport()
    networks: list[IPv4Network] = []
    for lineno, raw in enumerate(text.splitlines(), 1):
        report.total_lines += 1
        line = raw.split("#", 1)[0].strip()
        if not line:
            continue
        report.content_lines += 1
        try:
            networks.append(normalize_network(line))
        except ValueError as exc:
            report.rejected.append((lineno, line, str(exc)))
        else:
            report.accepted += 1
    return networks, report


def collapse(networks: list[IPv4Network]) -> list[IPv4Network]:
    """Deduplicate and merge adjacent/contained networks, deterministically."""
    return sorted(ipaddress.collapse_addresses(set(networks)))


def coverage_addresses(networks: list[IPv4Network]) -> int:
    """Total number of IPv4 addresses the (collapsed) set represents."""
    return sum(n.num_addresses for n in networks)


def coverage_percent(networks: list[IPv4Network]) -> float:
    return coverage_addresses(networks) / TOTAL_IPV4_ADDRESSES * 100.0


def reserved_overlaps(networks: list[IPv4Network]) -> list[tuple[IPv4Network, IPv4Network]]:
    """Every (network, reserved_range) pair that must block publication."""
    hits: list[tuple[IPv4Network, IPv4Network]] = []
    for net in networks:
        for reserved in RESERVED_NETWORKS:
            if net.overlaps(reserved):
                hits.append((net, reserved))
    return hits


def broad_networks(networks: list[IPv4Network], threshold: int) -> list[IPv4Network]:
    """Networks at or broader than /threshold (i.e. prefixlen <= threshold)."""
    return [n for n in networks if n.prefixlen <= threshold]


@dataclass(frozen=True)
class IPv4Result:
    """The validated CN IPv4 set plus the numbers the gates were judged on."""

    networks: list[IPv4Network]
    report: ParseReport
    raw_count: int

    @property
    def count(self) -> int:
        return len(self.networks)

    @property
    def addresses(self) -> int:
        return coverage_addresses(self.networks)

    @property
    def percent(self) -> float:
        return coverage_percent(self.networks)

    @property
    def broadest_prefixlen(self) -> int:
        return min((n.prefixlen for n in self.networks), default=32)

    def contains(self, address: ipaddress.IPv4Address) -> IPv4Network | None:
        """Return the matching network, or None. Linear scan; sets are small."""
        for net in self.networks:
            if address in net:
                return net
        return None

    def as_lines(self) -> list[str]:
        return [str(n) for n in self.networks]

    def as_metadata(self) -> dict:
        return {
            "networks": self.count,
            "networks_before_collapse": self.raw_count,
            "addresses": self.addresses,
            "coverage_percent_ipv4": round(self.percent, 4),
            "broadest_prefix": f"/{self.broadest_prefixlen}",
            "parse": self.report.as_metadata(),
        }


def build_ipv4_set(text: str, *, policy: Policy) -> IPv4Result:
    """Turn upstream IPv4 text into a validated, collapsed CN network set.

    Raises SecurityGateError for anything that is unsafe on its own terms,
    independent of any previous release. Cross-release diff gates live in
    diff.py; canary checks live in validate.py.
    """
    parsed, report = parse_ipv4_lines(text)

    max_unparsable = float(policy.value("fetch", "max_unparsable_percent"))
    if report.unparsable_percent > max_unparsable:
        raise SecurityGateError(
            "ipv4:source-quality",
            f"{report.rejected_count}/{report.content_lines} lines "
            f"({report.unparsable_percent:.2f}%) could not be parsed, limit is "
            f"{max_unparsable}% - upstream format may have changed",
        )
    if not parsed:
        raise SecurityGateError("ipv4:source-quality", "upstream produced no usable networks")

    networks = collapse(parsed)
    result = IPv4Result(networks=networks, report=report, raw_count=len(parsed))

    hard = int(policy.value("ipv4", "hard_reject_prefix_threshold"))
    review = int(policy.value("ipv4", "broad_prefix_review_threshold"))
    allowed = {IPv4Network(c) for c in policy.value("ipv4", "allowed_broad_networks")}

    too_broad = broad_networks(networks, hard)
    if too_broad:
        raise SecurityGateError(
            "ipv4:hard-prefix-limit",
            f"network(s) at or broader than /{hard} are never acceptable: "
            + ", ".join(str(n) for n in too_broad[:10]),
        )

    needs_review = [n for n in broad_networks(networks, review) if n not in allowed]
    if needs_review:
        raise SecurityGateError(
            "ipv4:broad-prefix-review",
            f"network(s) at or broader than /{review} require explicit entries in "
            f"policy.toml [ipv4].allowed_broad_networks: "
            + ", ".join(str(n) for n in needs_review[:10]),
        )

    overlaps = reserved_overlaps(networks)
    if overlaps:
        raise SecurityGateError(
            "ipv4:reserved-range",
            "network(s) overlap special-use ranges: "
            + ", ".join(f"{net} overlaps {res}" for net, res in overlaps[:10]),
        )

    min_networks = int(policy.value("ipv4", "min_networks"))
    max_networks = int(policy.value("ipv4", "max_networks"))
    if not (min_networks <= result.count <= max_networks):
        raise SecurityGateError(
            "ipv4:set-size",
            f"{result.count} networks is outside the sane range "
            f"[{min_networks}, {max_networks}]",
        )

    max_coverage = float(policy.value("ipv4", "max_coverage_percent"))
    if result.percent > max_coverage:
        raise SecurityGateError(
            "ipv4:coverage-ceiling",
            f"set covers {result.percent:.2f}% of IPv4, above the {max_coverage}% ceiling",
        )

    return result


# --- Experimental IPv6 support ------------------------------------------------
# GL.iNet's VPN policy parser is documented for domains and IPv4 only, so IPv6
# output is generated separately, never merged into production artifacts, and
# is not subject to the production gates above.

def parse_ipv6_lines(text: str) -> tuple[list[ipaddress.IPv6Network], ParseReport]:
    """Parse an upstream IPv6 list. Used only for experimental/cn-ipv6.txt."""
    report = ParseReport()
    networks: list[ipaddress.IPv6Network] = []
    for lineno, raw in enumerate(text.splitlines(), 1):
        report.total_lines += 1
        line = raw.split("#", 1)[0].strip()
        if not line:
            continue
        report.content_lines += 1
        try:
            networks.append(ipaddress.IPv6Network(line, strict=False))
        except ValueError as exc:
            report.rejected.append((lineno, line, str(exc)))
        else:
            report.accepted += 1
    return networks, report


def collapse_ipv6(networks: list[ipaddress.IPv6Network]) -> list[ipaddress.IPv6Network]:
    return sorted(ipaddress.collapse_addresses(set(networks)))
