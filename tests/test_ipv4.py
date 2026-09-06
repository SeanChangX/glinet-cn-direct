"""IPv4 parsing, normalization and the standalone safety gates."""

from __future__ import annotations

import ipaddress

import pytest

from glinet_rules.errors import SecurityGateError
from glinet_rules.ipv4 import (
    RESERVED_NETWORKS,
    build_ipv4_set,
    collapse,
    coverage_addresses,
    coverage_percent,
    normalize_network,
    parse_ipv4_lines,
    reserved_overlaps,
)


class TestNormalizeNetwork:
    @pytest.mark.parametrize(
        ("value", "expected"),
        [
            ("1.2.3.0/24", "1.2.3.0/24"),
            ("1.2.3.4", "1.2.3.4/32"),
            ("  1.2.3.0/24  ", "1.2.3.0/24"),
            ("1.2.3.5/24", "1.2.3.0/24"),  # host bits are cleared
            ("10.0.0.0/8", "10.0.0.0/8"),  # parsing succeeds; the gate rejects it later
            ("0.0.0.0/0", "0.0.0.0/0"),
        ],
    )
    def test_accepts_and_canonicalizes(self, value, expected):
        assert str(normalize_network(value)) == expected

    @pytest.mark.parametrize(
        "value",
        [
            "",
            "   ",
            "999.2.3.4",
            "1.2.3",
            "1.2.3.4/33",
            "1.2.3.4/-1",
            "example.com",
            "2001:db8::/32",
            "::1",
            "1.2.3.4 5.6.7.8",
        ],
    )
    def test_rejects_invalid(self, value):
        with pytest.raises(ValueError):
            normalize_network(value)


class TestParsing:
    def test_skips_comments_and_blanks(self):
        text = "# comment\n\n1.2.3.0/24\n  \n4.5.6.0/24  # trailing\n"
        networks, report = parse_ipv4_lines(text)
        assert [str(n) for n in networks] == ["1.2.3.0/24", "4.5.6.0/24"]
        assert report.content_lines == 2
        assert report.rejected_count == 0

    def test_records_rejections_with_line_numbers(self):
        networks, report = parse_ipv4_lines("1.2.3.0/24\nnope\n")
        assert len(networks) == 1
        assert report.rejected[0][0] == 2
        assert report.rejected[0][1] == "nope"
        assert report.unparsable_percent == pytest.approx(50.0)


class TestCollapse:
    def test_deduplicates_and_merges_adjacent(self):
        networks = [
            ipaddress.IPv4Network(c)
            for c in ("1.2.3.0/25", "1.2.3.128/25", "1.2.3.0/25", "9.9.9.0/24")
        ]
        assert [str(n) for n in collapse(networks)] == ["1.2.3.0/24", "9.9.9.0/24"]

    def test_absorbs_contained_networks(self):
        networks = [ipaddress.IPv4Network(c) for c in ("1.0.0.0/16", "1.0.5.0/24")]
        assert [str(n) for n in collapse(networks)] == ["1.0.0.0/16"]

    def test_is_deterministic(self):
        a = [ipaddress.IPv4Network(c) for c in ("9.9.9.0/24", "1.2.3.0/24")]
        assert collapse(a) == collapse(list(reversed(a)))


class TestCoverage:
    def test_counts_addresses(self):
        networks = [ipaddress.IPv4Network(c) for c in ("1.2.3.0/24", "4.5.6.7/32")]
        assert coverage_addresses(networks) == 257

    def test_percent_of_full_space(self):
        assert coverage_percent([ipaddress.IPv4Network("0.0.0.0/0")]) == pytest.approx(100.0)


class TestReservedRanges:
    @pytest.mark.parametrize(
        "cidr",
        ["10.0.0.0/8", "127.0.0.1/32", "192.168.1.0/24", "169.254.0.0/16", "224.0.0.1/32"],
    )
    def test_detects_overlap(self, cidr):
        assert reserved_overlaps([ipaddress.IPv4Network(cidr)])

    def test_ignores_public_networks(self):
        assert not reserved_overlaps([ipaddress.IPv4Network("1.2.3.0/24")])

    def test_reserved_list_is_canonical(self):
        for network in RESERVED_NETWORKS:
            assert network == ipaddress.IPv4Network(str(network))


class TestBuildGates:
    """Each gate must block publication on its own, without a previous release."""

    def _build(self, policy, lines):
        return build_ipv4_set("\n".join(lines) + "\n", policy=policy)

    def _ok_lines(self):
        # Public, non-adjacent networks, so nothing collapses into something
        # broader than what the test is actually asserting about.
        return [f"{n}.0.0.0/16" for n in (1, 3, 5, 7, 9)]

    def test_accepts_a_sane_set(self, fixture_config):
        result = self._build(fixture_config.policy, self._ok_lines())
        assert result.count == 5
        assert result.broadest_prefixlen == 16

    @pytest.mark.parametrize("cidr", ["0.0.0.0/0", "0.0.0.0/1", "128.0.0.0/1", "64.0.0.0/4"])
    def test_hard_rejects_very_broad_prefixes(self, fixture_config, cidr):
        with pytest.raises(SecurityGateError) as exc:
            self._build(fixture_config.policy, [*self._ok_lines(), cidr])
        assert exc.value.gate in {"ipv4:hard-prefix-limit", "ipv4:reserved-range"}

    def test_broad_prefix_needs_explicit_allowlisting(self, fixture_config):
        with pytest.raises(SecurityGateError) as exc:
            self._build(fixture_config.policy, [*self._ok_lines(), "13.0.0.0/8"])
        assert exc.value.gate == "ipv4:broad-prefix-review"

    def test_allowlisted_broad_prefix_is_accepted(self, fixture_config):
        fixture_config.policy.raw["ipv4"]["allowed_broad_networks"] = ["13.0.0.0/8"]
        result = self._build(fixture_config.policy, [*self._ok_lines(), "13.0.0.0/8"])
        assert "13.0.0.0/8" in result.as_lines()

    @pytest.mark.parametrize("cidr", ["10.0.0.0/16", "192.168.0.0/24", "127.0.0.0/24"])
    def test_rejects_reserved_ranges(self, fixture_config, cidr):
        with pytest.raises(SecurityGateError) as exc:
            self._build(fixture_config.policy, [*self._ok_lines(), cidr])
        assert exc.value.gate == "ipv4:reserved-range"

    def test_rejects_an_empty_set(self, fixture_config):
        with pytest.raises(SecurityGateError) as exc:
            build_ipv4_set("# nothing here\n", policy=fixture_config.policy)
        assert exc.value.gate == "ipv4:source-quality"

    def test_rejects_too_many_unparsable_lines(self, fixture_config):
        text = "\n".join(["1.2.3.0/24", *["garbage"] * 10]) + "\n"
        with pytest.raises(SecurityGateError) as exc:
            build_ipv4_set(text, policy=fixture_config.policy)
        assert exc.value.gate == "ipv4:source-quality"

    def test_rejects_a_set_below_the_size_floor(self, fixture_config):
        fixture_config.policy.raw["ipv4"]["min_networks"] = 100
        with pytest.raises(SecurityGateError) as exc:
            self._build(fixture_config.policy, self._ok_lines())
        assert exc.value.gate == "ipv4:set-size"

    def test_rejects_excessive_coverage(self, fixture_config):
        # 14 non-adjacent /6 blocks cover 21.9% of IPv4: individually allowed by
        # the prefix gates, collectively far too much to be a country.
        fixture_config.policy.raw["ipv4"]["broad_prefix_review_threshold"] = 5
        blocks = [f"{n}.0.0.0/6" for n in range(16, 128, 8)]
        with pytest.raises(SecurityGateError) as exc:
            self._build(fixture_config.policy, blocks)
        assert exc.value.gate == "ipv4:coverage-ceiling"


class TestRealUpstreamShape:
    """Guards on the shipped config, so a bad edit to policy.toml is caught."""

    def test_production_policy_hard_rejects_default_routes(self, repo_config):
        assert int(repo_config.policy.value("ipv4", "hard_reject_prefix_threshold")) >= 4
        assert int(repo_config.policy.value("ipv4", "broad_prefix_review_threshold")) >= 8
        assert repo_config.policy.value("ipv4", "allowed_broad_networks") == []
