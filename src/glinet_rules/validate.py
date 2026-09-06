"""GL.iNet grammar validation and route-leak tripwires.

Two independent jobs live here:

1. `validate_lines` enforces the documented GL.iNet subscription grammar. A
   production file is published only if *every* line is a valid domain, IPv4
   address or IPv4 CIDR. There is no partially valid file.
2. The never-direct and canary checks catch upstream contamination that is
   syntactically perfect but would route traffic the user expects inside the
   VPN around it.
"""

from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass
from pathlib import Path

from .config import Canary
from .domains import MAX_DOMAIN_LENGTH, MAX_LABEL_LENGTH, _LABEL_RE
from .errors import SecurityGateError
from .ipv4 import IPv4Result

#: Anything a GL.iNet "Exclude Specified Domain / IP List" line may be.
LINE_KIND_DOMAIN = "domain"
LINE_KIND_IPV4 = "ipv4"
LINE_KIND_IPV4_CIDR = "ipv4_cidr"

_IPV4_TEXT = re.compile(r"^\d{1,3}(\.\d{1,3}){3}$")
_IPV4_CIDR_TEXT = re.compile(r"^\d{1,3}(\.\d{1,3}){3}/\d{1,2}$")


class InvalidLine(ValueError):
    """A production line does not satisfy the GL.iNet grammar."""


def classify_line(line: str) -> str:
    """Return the GL.iNet rule kind for `line`, or raise InvalidLine.

    Deliberately strict: the value must already be canonical, because these
    checks run on generated output, not on upstream input.
    """
    if line != line.strip():
        raise InvalidLine("has leading or trailing whitespace")
    if not line:
        raise InvalidLine("empty line")
    if any(c.isspace() for c in line):
        raise InvalidLine("contains whitespace")
    if not line.isascii():
        raise InvalidLine("contains non-ASCII characters; expected Punycode")
    if line != line.lower():
        raise InvalidLine("is not lowercase")

    if _IPV4_CIDR_TEXT.match(line):
        try:
            network = ipaddress.IPv4Network(line, strict=True)
        except ValueError as exc:
            raise InvalidLine(str(exc)) from exc
        if str(network) != line:
            raise InvalidLine(f"is not canonical; expected {network}")
        return LINE_KIND_IPV4_CIDR

    if _IPV4_TEXT.match(line):
        try:
            ipaddress.IPv4Address(line)
        except ValueError as exc:
            raise InvalidLine(str(exc)) from exc
        return LINE_KIND_IPV4

    if "/" in line or ":" in line:
        raise InvalidLine("looks like a malformed network or an IPv6 address")
    if len(line) > MAX_DOMAIN_LENGTH:
        raise InvalidLine(f"longer than {MAX_DOMAIN_LENGTH} characters")

    labels = line.split(".")
    for label in labels:
        if not label:
            raise InvalidLine("contains an empty label")
        if len(label) > MAX_LABEL_LENGTH:
            raise InvalidLine(f"label {label!r} exceeds {MAX_LABEL_LENGTH} characters")
        if not _LABEL_RE.match(label):
            raise InvalidLine(f"invalid label {label!r}")
    return LINE_KIND_DOMAIN


@dataclass
class LineValidationResult:
    """Outcome of validating one production artifact."""

    path: str
    counts: dict[str, int]
    problems: list[tuple[int, str, str]]

    @property
    def ok(self) -> bool:
        return not self.problems

    @property
    def total(self) -> int:
        return sum(self.counts.values())


def validate_lines(lines: list[str], *, path: str = "<memory>") -> LineValidationResult:
    """Validate every line against the GL.iNet grammar."""
    counts = {LINE_KIND_DOMAIN: 0, LINE_KIND_IPV4: 0, LINE_KIND_IPV4_CIDR: 0}
    problems: list[tuple[int, str, str]] = []
    for lineno, line in enumerate(lines, 1):
        try:
            counts[classify_line(line)] += 1
        except InvalidLine as exc:
            problems.append((lineno, line[:120], str(exc)))
    return LineValidationResult(path=path, counts=counts, problems=problems)


def validate_text_file(path: Path) -> LineValidationResult:
    """Validate a generated file on disk, including its byte-level shape."""
    raw = path.read_bytes()
    problems: list[tuple[int, str, str]] = []
    if raw.startswith(b"\xef\xbb\xbf"):
        problems.append((0, "<file>", "starts with a UTF-8 BOM"))
    if b"\r" in raw:
        problems.append((0, "<file>", "contains CR; output must use LF endings only"))
    if raw and not raw.endswith(b"\n"):
        problems.append((0, "<file>", "does not end with a final newline"))

    text = raw.decode("utf-8")
    lines = text.split("\n")
    if lines and lines[-1] == "":
        lines.pop()

    result = validate_lines(lines, path=str(path))
    result.problems = problems + result.problems
    return result


def encompassing_rules(domain: str, generated: set[str]) -> list[str]:
    """Every generated rule that would match `domain`, including via suffix.

    `example.com` in the generated set matches `api.example.com`, and a bare
    `com` line would match all of them. Both count as a leak.
    """
    parts = domain.split(".")
    return [
        candidate
        for i in range(len(parts))
        if (candidate := ".".join(parts[i:])) in generated
    ]


def check_never_direct(domains: list[str], never_direct: tuple[str, ...]) -> None:
    """Fail if any generated rule would route a never-direct domain around the VPN."""
    generated = set(domains)
    leaks: list[str] = []
    for protected in never_direct:
        matches = encompassing_rules(protected, generated)
        if matches:
            leaks.append(f"{protected} <- matched by {', '.join(matches)}")
    if leaks:
        raise SecurityGateError(
            "domains:never-direct",
            "generated rules would bypass the VPN for protected domains: " + "; ".join(leaks),
        )


def check_ip_canaries(
    result: IPv4Result,
    *,
    cn_canaries: tuple[Canary, ...],
    foreign_canaries: tuple[Canary, ...],
) -> None:
    """Fail if a known-CN address is missing, or a known-foreign address present."""
    missing = [c for c in cn_canaries if result.contains(c.address) is None]
    if missing:
        raise SecurityGateError(
            "ipv4:cn-canary",
            "known Mainland China address(es) are not covered by the generated set: "
            + ", ".join(f"{c.address} ({c.label})" for c in missing),
        )

    leaked: list[str] = []
    for canary in foreign_canaries:
        network = result.contains(canary.address)
        if network is not None:
            leaked.append(f"{canary.address} ({canary.label}) inside {network}")
    if leaked:
        raise SecurityGateError(
            "ipv4:foreign-canary",
            "known foreign address(es) fell inside the generated CN set: " + "; ".join(leaked),
        )


def check_artifact_limits(
    name: str,
    lines: list[str],
    data: bytes,
    *,
    max_lines_warn: int,
    max_bytes_warn: int,
) -> list[str]:
    """Report router-practicality warnings. These never block publication."""
    warnings: list[str] = []
    if len(lines) > max_lines_warn:
        warnings.append(
            f"{name}: {len(lines):,} lines exceeds the advisory limit of "
            f"{max_lines_warn:,}; smaller GL.iNet models may struggle"
        )
    if len(data) > max_bytes_warn:
        warnings.append(
            f"{name}: {len(data):,} bytes exceeds the advisory limit of "
            f"{max_bytes_warn:,}; smaller GL.iNet models may struggle"
        )
    return warnings
