"""The build pipeline: fetch -> normalize -> validate -> compare -> gates -> write.

`run_build` performs every check before it writes anything to the output
directory. If any gate raises, the caller has not been given a partially written
artifact set and the previously published release stays authoritative.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import date
from pathlib import Path

from . import GENERATOR_NAME, __version__
from .config import Config
from .diff import (
    SetDiff,
    check_domain_change,
    check_ipv4_change,
    compare_coverage,
    read_domain_file,
    read_ipv4_file,
)
from .domains import DomainResult, build_domain_set, parse_domain_lines
from .errors import FetchError, SecurityGateError
from .fetch import FetchResult, fetch_source
from .ipv4 import IPv4Result, build_ipv4_set, collapse_ipv6, parse_ipv6_lines
from .metadata import (
    ARTIFACT_ORDER,
    file_report,
    render_lines,
    utc_now_iso,
    write_artifact,
    write_checksums,
    write_json,
)
from .validate import (
    check_artifact_limits,
    check_ip_canaries,
    check_never_direct,
    validate_lines,
)


@dataclass
class BuildResult:
    """Everything a caller needs to report on, publish or audit a build."""

    output_dir: Path
    ipv4: IPv4Result
    domains: DomainResult
    metadata: dict
    audit: dict
    warnings: list[str] = field(default_factory=list)
    ipv4_diff: SetDiff | None = None
    domain_diff: SetDiff | None = None
    experimental_ipv6: int = 0

    @property
    def combined_count(self) -> int:
        return self.ipv4.count + self.domains.count

    def step_summary(self) -> str:
        """A GitHub-Actions-flavoured markdown summary of this build."""
        lines = [
            "# GL.iNet rules build",
            "",
            f"Generator: `{GENERATOR_NAME} {__version__}`",
            "",
            "## Sources",
            "",
            "| source | role | revision |",
            "| --- | --- | --- |",
        ]
        for source in self.metadata["sources"]:
            revision = source["revision"]
            short = revision[:12] if source["revision_kind"] == "commit" else revision
            lines.append(f"| `{source['name']}` | {source['role']} | `{short}` |")

        lines += [
            "",
            "## Counts",
            "",
            f"- IPv4 networks: **{self.ipv4.count:,}**",
            f"- IPv4 coverage: **{self.ipv4.addresses:,}** addresses "
            f"({self.ipv4.percent:.2f}% of IPv4)",
            f"- Domains: **{self.domains.count:,}**",
            f"- Combined: **{self.combined_count:,}**",
            "",
            "## Change vs previous release",
            "",
        ]
        if self.ipv4_diff is None:
            lines.append("- No previous release available; diff gates skipped.")
        else:
            lines += [
                f"- IPv4 additions: {len(self.ipv4_diff.added):,} / "
                f"removals: {len(self.ipv4_diff.removed):,} "
                f"({self.ipv4_diff.count_change_percent:+.2f}%)",
                f"- Domain additions: {len(self.domain_diff.added):,} / "
                f"removals: {len(self.domain_diff.removed):,} "
                f"({self.domain_diff.count_change_percent:+.2f}%)",
            ]

        lines += ["", "## Safety checks", ""]
        for label in (
            "GL.iNet grammar",
            "Reserved ranges",
            "Broad prefixes",
            "Never-direct domains",
            "IP canaries",
            "Coverage anomaly",
            "Diff thresholds",
        ):
            lines.append(f"- {label}: **PASS**")

        if self.warnings:
            lines += ["", "## Warnings", ""]
            lines += [f"- {w}" for w in self.warnings]
        return "\n".join(lines) + "\n"


def _fetch_all(
    config: Config,
    *,
    include_experimental: bool,
    overrides: dict[str, FetchResult] | None,
) -> tuple[dict[str, FetchResult], list[str]]:
    """Download every configured source, honouring test overrides."""
    overrides = overrides or {}
    warnings: list[str] = []
    fetched: dict[str, FetchResult] = {}

    wanted = ["ipv4_primary", "domains_primary"]
    if config.policy.section("secondary").get("enabled", False):
        wanted.append("domains_secondary")
    if include_experimental and "ipv6_experimental" in config.sources:
        wanted.append("ipv6_experimental")

    for key in wanted:
        if key in overrides:
            fetched[key] = overrides[key]
            continue
        spec = config.sources.get(key)
        if spec is None:
            continue
        try:
            fetched[key] = fetch_source(spec, policy=config.policy)
        except FetchError as exc:
            optional = spec.role in {"comparator", "experimental"}
            required = bool(config.policy.section("secondary").get("required", False))
            if optional and not (spec.role == "comparator" and required):
                warnings.append(f"optional source {key!r} unavailable: {exc}")
                continue
            raise
    return fetched, warnings


def _check_secondary_domains(
    primary: DomainResult,
    secondary: FetchResult,
    *,
    config: Config,
) -> dict:
    """Cross-check the primary domain set against an independent comparator.

    The comparator is never merged into published output. It exists so that a
    single compromised or broken upstream cannot move the rules unnoticed.
    """
    other, _ = parse_domain_lines(secondary.text)
    primary_set = set(primary.domains)
    # Membership is tested by suffix, so this project's own subdomain collapsing
    # does not register as upstream drift: a collapsed entry is still "covered"
    # by the parent rule that replaced it.
    covered = {
        d
        for d in other
        if any(".".join(d.split(".")[i:]) in primary_set for i in range(len(d.split("."))))
    }
    only_secondary = sorted(other - covered)
    only_primary = sorted(primary_set - other)
    union = len(other | primary_set)
    divergence = (len(only_secondary) + len(only_primary)) / union * 100.0 if union else 0.0

    limit = float(config.policy.value("secondary", "max_domain_divergence_percent"))
    if divergence > limit:
        raise SecurityGateError(
            "domains:secondary-divergence",
            f"primary source diverges from comparator {secondary.slug} by "
            f"{divergence:.2f}%, limit is {limit}% - one of the two upstreams "
            "may have changed unexpectedly",
        )
    return {
        "comparator": secondary.slug,
        "revision": secondary.revision,
        "comparator_domains": len(other),
        "only_in_primary": len(only_primary),
        "only_in_comparator": len(only_secondary),
        "divergence_percent": round(divergence, 4),
        "limit_percent": limit,
        "sample_only_in_comparator": only_secondary[:20],
    }


def run_build(
    config: Config,
    *,
    output_dir: Path,
    previous_dir: Path | None = None,
    audit_dir: Path | None = None,
    include_experimental: bool = True,
    sources_override: dict[str, FetchResult] | None = None,
    generated_on: date | None = None,
) -> BuildResult:
    """Run the full pipeline. Raises SecurityGateError instead of publishing junk."""
    output_dir = Path(output_dir)
    warnings = list(config.warnings)

    # 1. fetch (pinned, size-limited, no upstream code executed)
    fetched, fetch_warnings = _fetch_all(
        config, include_experimental=include_experimental, overrides=sources_override
    )
    warnings += fetch_warnings

    # 2. normalize + per-set safety gates
    ipv4 = build_ipv4_set(fetched["ipv4_primary"].text, policy=config.policy)
    domains = build_domain_set(
        fetched["domains_primary"].text,
        policy=config.policy,
        allowed_tlds=config.allowed_tlds,
    )

    # 3. route-leak tripwires
    check_never_direct(domains.domains, config.never_direct)
    check_ip_canaries(
        ipv4,
        cn_canaries=config.cn_canaries,
        foreign_canaries=config.foreign_canaries,
    )

    # 4. GL.iNet grammar: every published line, or nothing is published
    ipv4_lines = ipv4.as_lines()
    domain_lines = domains.as_lines()
    combined_lines = domain_lines + ipv4_lines
    for name, lines in (
        ("cn-ipv4.txt", ipv4_lines),
        ("cn-domains.txt", domain_lines),
        ("cn-direct.txt", combined_lines),
    ):
        result = validate_lines(lines, path=name)
        if not result.ok:
            detail = "; ".join(f"line {n}: {v!r} {r}" for n, v, r in result.problems[:10])
            raise SecurityGateError(
                "output:glinet-grammar",
                f"{name} contains {len(result.problems)} invalid line(s): {detail}",
            )

    # 5. independent comparator (anomaly detection only, never merged)
    secondary_report: dict | None = None
    if "domains_secondary" in fetched:
        secondary_report = _check_secondary_domains(
            domains, fetched["domains_secondary"], config=config
        )

    # 6. change detection against the last published release
    ipv4_diff: SetDiff | None = None
    domain_diff: SetDiff | None = None
    coverage_report: dict | None = None
    if previous_dir is not None:
        previous_dir = Path(previous_dir)
        previous_ipv4 = read_ipv4_file(previous_dir / "cn-ipv4.txt")
        previous_domains = read_domain_file(previous_dir / "cn-domains.txt")
        if previous_ipv4:
            ipv4_diff, coverage = check_ipv4_change(
                previous_ipv4, ipv4.networks, policy=config.policy
            )
            coverage_report = coverage.as_metadata()
        else:
            warnings.append("no previous cn-ipv4.txt found; IPv4 diff gates skipped")
        if previous_domains:
            domain_diff = check_domain_change(
                previous_domains, domains.domains, policy=config.policy
            )
        else:
            warnings.append("no previous cn-domains.txt found; domain diff gates skipped")

    # 7. router-practicality advisories (never blocking)
    artifacts = config.policy.section("artifacts")
    for name, lines in (
        ("cn-ipv4.txt", ipv4_lines),
        ("cn-domains.txt", domain_lines),
        ("cn-direct.txt", combined_lines),
    ):
        warnings += check_artifact_limits(
            name,
            lines,
            render_lines(lines),
            max_lines_warn=int(artifacts["max_lines_warn"]),
            max_bytes_warn=int(artifacts["max_bytes_warn"]),
        )

    # 8. everything passed: write the artifacts
    output_dir.mkdir(parents=True, exist_ok=True)
    write_artifact(output_dir / "cn-ipv4.txt", ipv4_lines)
    write_artifact(output_dir / "cn-domains.txt", domain_lines)
    write_artifact(output_dir / "cn-direct.txt", combined_lines)

    experimental_count = 0
    if "ipv6_experimental" in fetched:
        networks, _ = parse_ipv6_lines(fetched["ipv6_experimental"].text)
        collapsed = collapse_ipv6(networks)
        experimental_count = len(collapsed)
        write_artifact(
            output_dir / "experimental" / "cn-ipv6.txt",
            [str(n) for n in collapsed],
        )

    source_metadata = []
    for key in ("ipv4_primary", "domains_primary", "domains_secondary", "ipv6_experimental"):
        if key not in fetched:
            continue
        entry = fetched[key].as_metadata()
        spec = config.sources[key]
        entry["role"] = spec.role
        entry["license"] = spec.license
        entry["path"] = spec.path
        if key == "ipv4_primary":
            entry.update(fetched[key].as_metadata())
            entry["parse"] = ipv4.report.as_metadata()
        if key == "domains_primary":
            entry["parse"] = domains.report.as_metadata()
        source_metadata.append(entry)

    document = {
        "generated_at": utc_now_iso(),
        "generated_on": (generated_on or date.today()).isoformat(),
        "generator": GENERATOR_NAME,
        "generator_version": config.generator_version,
        "sources": source_metadata,
        "counts": {
            "domains": domains.count,
            "ipv4_networks": ipv4.count,
            "combined": len(combined_lines),
            "experimental_ipv6_networks": experimental_count,
        },
        "ipv4": ipv4.as_metadata(),
        "domains": domains.as_metadata(),
        "files": {},
        "warnings": warnings,
    }
    write_json(output_dir / "metadata.json", document)

    write_checksums(output_dir, list(ARTIFACT_ORDER))
    document["files"] = file_report(output_dir, [*ARTIFACT_ORDER, "checksums.txt"])
    write_json(output_dir / "metadata.json", document)

    audit = {
        "generated_at": document["generated_at"],
        "ipv4": ipv4_diff.as_metadata() if ipv4_diff else None,
        "domains": domain_diff.as_metadata() if domain_diff else None,
        "ipv4_coverage_vs_previous": coverage_report,
        "secondary_comparison": secondary_report,
        "warnings": warnings,
    }
    if audit_dir is not None:
        _write_audit(Path(audit_dir), audit, ipv4_diff, domain_diff)

    return BuildResult(
        output_dir=output_dir,
        ipv4=ipv4,
        domains=domains,
        metadata=document,
        audit=audit,
        warnings=warnings,
        ipv4_diff=ipv4_diff,
        domain_diff=domain_diff,
        experimental_ipv6=experimental_count,
    )


def _write_audit(
    audit_dir: Path,
    audit: dict,
    ipv4_diff: SetDiff | None,
    domain_diff: SetDiff | None,
) -> None:
    audit_dir.mkdir(parents=True, exist_ok=True)
    write_artifact(audit_dir / "ipv4-added.txt", ipv4_diff.added if ipv4_diff else [])
    write_artifact(audit_dir / "ipv4-removed.txt", ipv4_diff.removed if ipv4_diff else [])
    write_artifact(audit_dir / "domains-added.txt", domain_diff.added if domain_diff else [])
    write_artifact(audit_dir / "domains-removed.txt", domain_diff.removed if domain_diff else [])
    write_json(audit_dir / "report.json", audit)


def compare_directories(new_dir: Path, old_dir: Path) -> dict:
    """Report-only comparison between two generated directories (CLI `diff`)."""
    new_ipv4 = read_ipv4_file(Path(new_dir) / "cn-ipv4.txt")
    old_ipv4 = read_ipv4_file(Path(old_dir) / "cn-ipv4.txt")
    new_domains = read_domain_file(Path(new_dir) / "cn-domains.txt")
    old_domains = read_domain_file(Path(old_dir) / "cn-domains.txt")
    from .diff import diff_sets

    return {
        "ipv4": diff_sets([str(n) for n in old_ipv4], [str(n) for n in new_ipv4]).as_metadata(),
        "ipv4_coverage": compare_coverage(
            old_ipv4, new_ipv4, left_name=str(old_dir), right_name=str(new_dir)
        ).as_metadata(),
        "domains": diff_sets(old_domains, new_domains).as_metadata(),
    }
