"""End-to-end pipeline tests, run entirely offline against committed fixtures."""

from __future__ import annotations

import json

import pytest

from glinet_rules.build import compare_directories, run_build
from glinet_rules.errors import SecurityGateError
from glinet_rules.metadata import release_version, render_lines, write_artifact

from conftest import make_fetch_result, read_fixture

ARTIFACTS = ("cn-ipv4.txt", "cn-domains.txt", "cn-direct.txt")


def build(tmp_path, config, sources, **kwargs):
    return run_build(
        config,
        output_dir=tmp_path / "dist",
        include_experimental=False,
        sources_override=sources,
        **kwargs,
    )


def with_extra(sources, key, extra_lines):
    """Copy the fixture sources with extra upstream lines appended."""
    patched = dict(sources)
    original = patched[key]
    patched[key] = make_fetch_result(
        key, original.text + "\n".join(extra_lines) + "\n", slug=original.slug
    )
    return patched


class TestFixtureBuild:
    def test_matches_the_committed_expected_output(self, tmp_path, fixture_config, fixture_sources):
        result = build(tmp_path, fixture_config, fixture_sources)

        assert (tmp_path / "dist" / "cn-ipv4.txt").read_text(encoding="utf-8") == read_fixture(
            "expected-cn-ipv4.txt"
        )
        assert (tmp_path / "dist" / "cn-domains.txt").read_text(encoding="utf-8") == read_fixture(
            "expected-cn-domains.txt"
        )
        assert result.ipv4.count == 10
        assert result.domains.count == 6

    def test_combined_file_is_domains_then_ipv4(self, tmp_path, fixture_config, fixture_sources):
        build(tmp_path, fixture_config, fixture_sources)
        combined = (tmp_path / "dist" / "cn-direct.txt").read_text(encoding="utf-8")
        expected = read_fixture("expected-cn-domains.txt") + read_fixture("expected-cn-ipv4.txt")
        assert combined == expected

    def test_normalizes_messy_upstream_input(self, tmp_path, fixture_config, fixture_sources):
        result = build(tmp_path, fixture_config, fixture_sources)
        lines = result.ipv4.as_lines()
        assert "1.2.3.0/24" in lines  # host bits cleared
        assert "203.208.60.1/32" in lines  # bare address became a /32
        assert lines.count("1.0.1.0/24") == 1  # duplicate removed
        assert result.ipv4.report.rejected_count == 1  # "not-an-ip-address"

    def test_accounts_for_unsupported_rules_without_converting_them(
        self, tmp_path, fixture_config, fixture_sources
    ):
        result = build(tmp_path, fixture_config, fixture_sources)
        assert result.domains.report.unsupported == {"keyword": 1, "regexp": 1}
        assert not any("example" in d for d in result.domains.domains)

    def test_collapses_redundant_subdomains(self, tmp_path, fixture_config, fixture_sources):
        result = build(tmp_path, fixture_config, fixture_sources)
        assert "baidu.com" in result.domains.domains
        assert "www.baidu.com" not in result.domains.domains
        assert result.domains.report.redundant_subdomains == 1

    def test_writes_checksums_for_every_artifact(self, tmp_path, fixture_config, fixture_sources):
        build(tmp_path, fixture_config, fixture_sources)
        lines = (tmp_path / "dist" / "checksums.txt").read_text(encoding="utf-8").splitlines()
        assert [line.split("  ")[1] for line in lines] == sorted(ARTIFACTS)
        for line in lines:
            digest, name = line.split("  ")
            assert len(digest) == 64
            import hashlib

            assert digest == hashlib.sha256((tmp_path / "dist" / name).read_bytes()).hexdigest()

    def test_metadata_records_provenance(self, tmp_path, fixture_config, fixture_sources):
        build(tmp_path, fixture_config, fixture_sources)
        document = json.loads((tmp_path / "dist" / "metadata.json").read_text(encoding="utf-8"))
        assert document["counts"] == {
            "domains": 6,
            "ipv4_networks": 10,
            "combined": 16,
            "experimental_ipv6_networks": 0,
        }
        for source in document["sources"]:
            assert len(source["source_sha256"]) == 64
            assert source["revision"]
        assert document["files"]["cn-direct.txt"]["lines"] == 16


class TestDeterminism:
    def test_repeated_builds_produce_identical_bytes(
        self, tmp_path, fixture_config, fixture_sources
    ):
        first = tmp_path / "a"
        second = tmp_path / "b"
        run_build(
            fixture_config,
            output_dir=first,
            include_experimental=False,
            sources_override=fixture_sources,
        )
        run_build(
            fixture_config,
            output_dir=second,
            include_experimental=False,
            sources_override=fixture_sources,
        )
        for name in (*ARTIFACTS, "checksums.txt"):
            assert (first / name).read_bytes() == (second / name).read_bytes()

    def test_input_order_does_not_affect_output(self, tmp_path, fixture_config, fixture_sources):
        baseline = build(tmp_path / "one", fixture_config, fixture_sources)
        shuffled = dict(fixture_sources)
        ipv4 = shuffled["ipv4_primary"]
        reordered = "\n".join(reversed(ipv4.text.splitlines())) + "\n"
        shuffled["ipv4_primary"] = make_fetch_result("ipv4_primary", reordered, slug=ipv4.slug)
        other = build(tmp_path / "two", fixture_config, shuffled)
        assert baseline.ipv4.as_lines() == other.ipv4.as_lines()

    def test_rendered_bytes_are_lf_utf8_without_bom(self):
        data = render_lines(["baidu.com", "1.2.3.0/24"])
        assert data == b"baidu.com\n1.2.3.0/24\n"
        assert not data.startswith(b"\xef\xbb\xbf")
        assert b"\r" not in data
        assert data.endswith(b"\n")

    def test_empty_rule_list_renders_as_empty_bytes(self):
        assert render_lines([]) == b""


class TestSecurityGatesBlockPublication:
    """Nothing may be written when a gate fires."""

    @pytest.mark.parametrize(
        ("key", "line", "gate"),
        [
            ("ipv4_primary", "0.0.0.0/0", "ipv4:hard-prefix-limit"),
            # Narrow enough to clear the prefix gates, so this isolates the
            # reserved-range check rather than re-testing broad-prefix review.
            ("ipv4_primary", "192.168.0.0/16", "ipv4:reserved-range"),
            ("ipv4_primary", "127.0.0.0/24", "ipv4:reserved-range"),
            ("ipv4_primary", "13.0.0.0/8", "ipv4:broad-prefix-review"),
            ("ipv4_primary", "8.8.8.0/24", "ipv4:foreign-canary"),
            ("domains_primary", "com", "domains:unreviewed-tld"),
            ("domains_primary", "google.com", "domains:never-direct"),
            ("domains_primary", "github.com", "domains:never-direct"),
        ],
    )
    def test_dangerous_upstream_entry_fails_the_build(
        self, tmp_path, fixture_config, fixture_sources, key, line, gate
    ):
        with pytest.raises(SecurityGateError) as exc:
            build(tmp_path, fixture_config, with_extra(fixture_sources, key, [line]))
        assert exc.value.gate == gate

    def test_no_artifacts_are_written_when_a_gate_fires(
        self, tmp_path, fixture_config, fixture_sources
    ):
        with pytest.raises(SecurityGateError):
            build(tmp_path, fixture_config, with_extra(fixture_sources, "ipv4_primary", ["0.0.0.0/0"]))
        assert not (tmp_path / "dist").exists()

    def test_a_previous_release_survives_a_failed_build(
        self, tmp_path, fixture_config, fixture_sources
    ):
        good = build(tmp_path, fixture_config, fixture_sources)
        before = (good.output_dir / "cn-ipv4.txt").read_bytes()
        with pytest.raises(SecurityGateError):
            build(tmp_path, fixture_config, with_extra(fixture_sources, "ipv4_primary", ["0.0.0.0/0"]))
        assert (good.output_dir / "cn-ipv4.txt").read_bytes() == before


class TestDiffAgainstPrevious:
    def test_first_build_skips_diff_gates(self, tmp_path, fixture_config, fixture_sources):
        result = run_build(
            fixture_config,
            output_dir=tmp_path / "dist",
            previous_dir=tmp_path / "empty",
            include_experimental=False,
            sources_override=fixture_sources,
        )
        assert result.ipv4_diff is None
        assert any("diff gates skipped" in w for w in result.warnings)

    def test_an_unchanged_rebuild_reports_no_change(
        self, tmp_path, fixture_config, fixture_sources
    ):
        first = build(tmp_path / "one", fixture_config, fixture_sources)
        result = run_build(
            fixture_config,
            output_dir=tmp_path / "two",
            previous_dir=first.output_dir,
            include_experimental=False,
            sources_override=fixture_sources,
        )
        assert result.ipv4_diff.added == []
        assert result.ipv4_diff.removed == []

    def test_a_wild_swing_against_the_previous_release_fails(
        self, tmp_path, fixture_config, fixture_sources
    ):
        first = build(tmp_path / "one", fixture_config, fixture_sources)
        extra = [f"{n}.0.0.0/24" for n in range(20, 40)]
        with pytest.raises(SecurityGateError) as exc:
            run_build(
                fixture_config,
                output_dir=tmp_path / "two",
                previous_dir=first.output_dir,
                include_experimental=False,
                sources_override=with_extra(fixture_sources, "ipv4_primary", extra),
            )
        assert exc.value.gate == "ipv4:rule-count-change"

    def test_audit_files_are_written(self, tmp_path, fixture_config, fixture_sources):
        first = build(tmp_path / "one", fixture_config, fixture_sources)
        run_build(
            fixture_config,
            output_dir=tmp_path / "two",
            previous_dir=first.output_dir,
            audit_dir=tmp_path / "audit",
            include_experimental=False,
            sources_override=with_extra(fixture_sources, "ipv4_primary", ["77.0.0.0/24"]),
        )
        assert (tmp_path / "audit" / "ipv4-added.txt").read_text(encoding="utf-8") == "77.0.0.0/24\n"
        assert (tmp_path / "audit" / "ipv4-removed.txt").read_bytes() == b""
        assert json.loads((tmp_path / "audit" / "report.json").read_text(encoding="utf-8"))


class TestCompareDirectories:
    def test_reports_both_rule_and_address_differences(self, tmp_path):
        old, new = tmp_path / "old", tmp_path / "new"
        write_artifact(old / "cn-ipv4.txt", ["1.0.0.0/24"])
        write_artifact(new / "cn-ipv4.txt", ["1.0.0.0/24", "2.0.0.0/24"])
        write_artifact(old / "cn-domains.txt", ["a.com"])
        write_artifact(new / "cn-domains.txt", ["a.com", "b.com"])
        report = compare_directories(new, old)
        assert report["ipv4"]["added"] == 1
        assert report["domains"]["added"] == 1
        assert report["ipv4_coverage"]["right_addresses"] == 512


class TestReleaseVersion:
    def test_uses_a_plain_date_when_the_day_is_free(self):
        assert release_version("2026-09-06", []) == "v2026.09.06"

    def test_suffixes_subsequent_builds_on_the_same_day(self):
        tags = ["v2026.09.06"]
        assert release_version("2026-09-06", tags) == "v2026.09.06.1"
        assert release_version("2026-09-06", tags + ["v2026.09.06.1"]) == "v2026.09.06.2"


class TestStepSummary:
    def test_includes_counts_and_source_revisions(self, tmp_path, fixture_config, fixture_sources):
        summary = build(tmp_path, fixture_config, fixture_sources).step_summary()
        assert "# GL.iNet rules build" in summary
        assert "IPv4 networks: **10**" in summary
        assert "fixture/ipv4" in summary
        assert "Never-direct domains: **PASS**" in summary
