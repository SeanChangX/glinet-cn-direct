"""Parsing, normalization and safety analysis of domain routing rules.

The hard rule here is that nothing is guessed at. V2Ray syntax that GL.iNet
cannot express (`keyword:`, `regexp:`, ...) is counted and reported, never
lossily converted, because an approximated regular expression would decide
routing for domains nobody reviewed.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field

from .config import Policy
from .errors import SecurityGateError

#: V2Ray/Xray prefixes that carry matching semantics GL.iNet cannot express.
#: These are dropped and counted, never converted.
UNSUPPORTED_PREFIXES = ("keyword:", "regexp:", "include:", "geosite:", "geoip:", "ext:")

#: Prefixes that are safely equivalent to a plain domain line for this target.
#: `domain:` is suffix matching, which is what a bare GL.iNet domain line does.
#: `full:` is exact matching; GL.iNet may also match subdomains, which is a
#: documented widening (see README "Semantic differences").
CONVERTIBLE_PREFIXES = ("domain:", "full:")

#: dnsmasq configuration line: server=/example.com/114.114.114.114
_DNSMASQ_RE = re.compile(r"^server=/([^/]+)/")

#: One label. Underscores appear in real DNS data (SRV-style names), so they are
#: allowed; a label may not start or end with a hyphen.
_LABEL_RE = re.compile(r"^(?!-)[a-z0-9_-]{1,63}(?<!-)$")

MAX_DOMAIN_LENGTH = 253
MAX_LABEL_LENGTH = 63


class DomainRejected(ValueError):
    """A line could not become a valid GL.iNet domain rule."""


@dataclass
class DomainParseReport:
    """What happened while turning upstream text into domain rules."""

    total_lines: int = 0
    content_lines: int = 0
    accepted: int = 0
    duplicates: int = 0
    redundant_subdomains: int = 0
    unsupported: dict[str, int] = field(default_factory=dict)
    rejected: list[tuple[int, str, str]] = field(default_factory=list)

    @property
    def rejected_count(self) -> int:
        return len(self.rejected)

    @property
    def unsupported_count(self) -> int:
        return sum(self.unsupported.values())

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
            "duplicates_removed": self.duplicates,
            "redundant_subdomains_removed": self.redundant_subdomains,
            "unsupported": dict(sorted(self.unsupported.items())),
            "rejected_samples": [
                {"line": lineno, "value": value, "reason": reason}
                for lineno, value, reason in self.rejected[:20]
            ],
        }


def _to_ascii(domain: str) -> str:
    """Convert a unicode domain to its Punycode (IDNA) form."""
    if domain.isascii():
        return domain
    labels = []
    for label in domain.split("."):
        if label.isascii():
            labels.append(label)
            continue
        try:
            labels.append(label.encode("idna").decode("ascii"))
        except UnicodeError as exc:
            raise DomainRejected(f"cannot encode internationalized label {label!r}: {exc}")
    return ".".join(labels)


def normalize_domain(value: str) -> str:
    """Return a canonical GL.iNet domain rule for `value`, or raise.

    Handles the upstream shapes this project actually consumes: bare domains,
    `domain:`/`full:` prefixed V2Ray entries, and dnsmasq `server=/x/y` lines.
    Anything with a scheme, path, query, wildcard or unsupported V2Ray prefix is
    rejected rather than reshaped.
    """
    text = value.strip()
    if not text:
        raise DomainRejected("empty value")

    dnsmasq = _DNSMASQ_RE.match(text)
    if dnsmasq:
        text = dnsmasq.group(1)

    lowered = text.lower()

    for prefix in UNSUPPORTED_PREFIXES:
        if lowered.startswith(prefix):
            raise DomainRejected(f"unsupported rule type {prefix!r}")
    for prefix in CONVERTIBLE_PREFIXES:
        if lowered.startswith(prefix):
            lowered = lowered[len(prefix) :]
            break

    # A V2Ray entry may carry an attribute suffix such as "example.com:@cn".
    lowered = lowered.split(":@", 1)[0].strip()

    if "://" in lowered:
        raise DomainRejected("contains a URL scheme")
    if lowered.startswith("*."):
        raise DomainRejected("wildcard rules are not converted; see README")
    for char in "/?#@ \t*!$%^&()[]{}<>\"'\\|,;+=~`":
        if char in lowered:
            raise DomainRejected(f"contains forbidden character {char!r}")
    if ":" in lowered:
        raise DomainRejected("contains ':' (port or unsupported rule syntax)")

    lowered = lowered.rstrip(".")
    if not lowered:
        raise DomainRejected("empty after normalization")

    ascii_domain = _to_ascii(lowered)

    if len(ascii_domain) > MAX_DOMAIN_LENGTH:
        raise DomainRejected(f"longer than {MAX_DOMAIN_LENGTH} characters")

    labels = ascii_domain.split(".")
    for label in labels:
        if not label:
            raise DomainRejected("contains an empty label")
        if len(label) > MAX_LABEL_LENGTH:
            raise DomainRejected(f"label {label!r} is longer than {MAX_LABEL_LENGTH} characters")
        if not _LABEL_RE.match(label):
            raise DomainRejected(f"invalid label {label!r}")
    if labels[-1].isdigit():
        raise DomainRejected("last label is numeric; looks like an IP address")

    return ascii_domain


def collapse_domains(domains: set[str]) -> tuple[list[str], int]:
    """Drop entries already covered by a shorter suffix rule in the same set.

    A GL.iNet domain line matches the domain and its subdomains, so if both
    `example.com` and `cdn.example.com` are present the second one decides
    nothing. Removing it is semantically neutral and meaningfully shrinks the
    file on a memory-constrained router.

    Returns the sorted survivors and the number of entries removed.
    """
    kept: list[str] = []
    removed = 0
    for domain in sorted(domains, key=lambda d: (d.count("."), d)):
        parts = domain.split(".")
        covered = any(".".join(parts[i:]) in domains for i in range(1, len(parts)))
        if covered:
            removed += 1
        else:
            kept.append(domain)
    return sorted(kept), removed


def parse_domain_lines(text: str) -> tuple[set[str], DomainParseReport]:
    """Parse upstream domain text into normalized rules plus a report."""
    report = DomainParseReport()
    domains: set[str] = set()
    for lineno, raw in enumerate(text.splitlines(), 1):
        report.total_lines += 1
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        report.content_lines += 1

        marker = next(
            (p for p in UNSUPPORTED_PREFIXES if line.lower().startswith(p)),
            None,
        )
        if marker is not None:
            key = marker.rstrip(":")
            report.unsupported[key] = report.unsupported.get(key, 0) + 1
            continue

        try:
            domain = normalize_domain(line)
        except DomainRejected as exc:
            report.rejected.append((lineno, line[:120], str(exc)))
            continue

        if domain in domains:
            report.duplicates += 1
        else:
            domains.add(domain)
            report.accepted += 1
    return domains, report


@dataclass(frozen=True)
class DomainResult:
    """The validated CN domain set plus the numbers the gates were judged on."""

    domains: list[str]
    report: DomainParseReport
    bare_tlds: tuple[str, ...]

    @property
    def count(self) -> int:
        return len(self.domains)

    def as_lines(self) -> list[str]:
        return list(self.domains)

    def as_metadata(self) -> dict:
        return {
            "domains": self.count,
            "bare_tld_rules": list(self.bare_tlds),
            "parse": self.report.as_metadata(),
        }


def build_domain_set(
    text: str,
    *,
    policy: Policy,
    allowed_tlds: frozenset[str],
) -> DomainResult:
    """Turn upstream domain text into a validated CN domain set.

    Raises SecurityGateError for anything unsafe on its own terms. Never-direct
    leak checks live in validate.py; cross-release diff gates live in diff.py.
    """
    domains, report = parse_domain_lines(text)

    max_unparsable = float(policy.value("fetch", "max_unparsable_percent"))
    if report.unparsable_percent > max_unparsable:
        raise SecurityGateError(
            "domains:source-quality",
            f"{report.rejected_count}/{report.content_lines} lines "
            f"({report.unparsable_percent:.2f}%) could not be parsed, limit is "
            f"{max_unparsable}% - upstream format may have changed",
        )
    if not domains:
        raise SecurityGateError("domains:source-quality", "upstream produced no usable domains")

    unsupported_fail = int(policy.value("domains", "unsupported_fail"))
    if report.unsupported_count > unsupported_fail:
        raise SecurityGateError(
            "domains:unsupported-entries",
            f"{report.unsupported_count} unsupported V2Ray-style entries "
            f"({dict(sorted(report.unsupported.items()))}) exceed the limit of "
            f"{unsupported_fail}; review the upstream format before publishing",
        )

    # A bare TLD line matches an entire top-level domain. Only ones explicitly
    # reviewed into config/allowed-tld-rules.txt may survive.
    found_bare = sorted(d for d in domains if "." not in d)
    unexpected = [t for t in found_bare if t not in allowed_tlds]
    if unexpected:
        raise SecurityGateError(
            "domains:unreviewed-tld",
            "bare top-level-domain rule(s) not present in config/allowed-tld-rules.txt: "
            + ", ".join(unexpected[:10])
            + " - each one would route an entire TLD around the VPN",
        )

    collapsed, redundant = collapse_domains(domains)
    report.redundant_subdomains = redundant

    min_domains = int(policy.value("domains", "min_domains"))
    max_domains = int(policy.value("domains", "max_domains"))
    if not (min_domains <= len(collapsed) <= max_domains):
        raise SecurityGateError(
            "domains:set-size",
            f"{len(collapsed)} domains is outside the sane range "
            f"[{min_domains}, {max_domains}]",
        )

    return DomainResult(
        domains=collapsed,
        report=report,
        bare_tlds=tuple(found_bare),
    )
