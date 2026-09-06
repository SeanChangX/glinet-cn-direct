"""Change detection against the previous release."""

from __future__ import annotations

import ipaddress

import pytest

from glinet_rules.diff import (
    check_domain_change,
    check_ipv4_change,
    compare_coverage,
    diff_sets,
    read_domain_file,
    read_ipv4_file,
)
from glinet_rules.errors import SecurityGateError
from glinet_rules.metadata import write_artifact


def nets(*cidrs: str) -> list[ipaddress.IPv4Network]:
    return sorted(ipaddress.IPv4Network(c) for c in cidrs)


class TestDiffSets:
    def test_reports_additions_and_removals(self):
        diff = diff_sets(["a", "b", "c"], ["b", "c", "d"])
        assert diff.added == ["d"]
        assert diff.removed == ["a"]
        assert diff.old_count == 3
        assert diff.new_count == 3

    def test_percentages(self):
        diff = diff_sets(["a"] * 1 + ["b", "c", "d"], ["a", "b"])
        assert diff.count_change_percent == pytest.approx(-50.0)
        assert diff.removed_percent == pytest.approx(50.0)

    def test_handles_an_empty_baseline(self):
        diff = diff_sets([], ["a"])
        assert diff.count_change_percent == 100.0
        assert diff.removed_percent == 0.0


class TestCompareCoverage:
    def test_identical_sets_do_not_diverge(self):
        left = nets("1.0.0.0/24", "2.0.0.0/24")
        comparison = compare_coverage(left, left, left_name="a", right_name="b")
        assert comparison.divergence_percent == pytest.approx(0.0)
        assert comparison.shared_addresses == 512

    def test_disjoint_sets_diverge_completely(self):
        comparison = compare_coverage(
            nets("1.0.0.0/24"), nets("2.0.0.0/24"), left_name="a", right_name="b"
        )
        assert comparison.shared_addresses == 0
        assert comparison.divergence_percent == pytest.approx(100.0)

    def test_partial_overlap_is_measured_by_address_space(self):
        comparison = compare_coverage(
            nets("1.0.0.0/24"), nets("1.0.0.0/25"), left_name="a", right_name="b"
        )
        assert comparison.shared_addresses == 128
        assert comparison.address_change_percent == pytest.approx(-50.0)

    def test_overlapping_inputs_are_not_double_counted(self):
        left = nets("1.0.0.0/24", "1.0.0.128/25")  # deliberately overlapping input
        comparison = compare_coverage(left, left, left_name="a", right_name="b")
        assert comparison.shared_addresses == 256


class TestIPv4ChangeGates:
    def test_accepts_a_small_change(self, fixture_config):
        previous = nets(*[f"{n}.0.0.0/24" for n in range(1, 21)])
        current = nets(*[f"{n}.0.0.0/24" for n in range(1, 22)])
        diff, coverage = check_ipv4_change(previous, current, policy=fixture_config.policy)
        assert diff.added == ["21.0.0.0/24"]
        assert coverage.address_change_percent == pytest.approx(5.0)

    def test_rejects_a_large_count_change(self, fixture_config):
        previous = nets(*[f"{n}.0.0.0/24" for n in range(1, 21)])
        current = nets(*[f"{n}.0.0.0/24" for n in range(1, 31)])
        with pytest.raises(SecurityGateError) as exc:
            check_ipv4_change(previous, current, policy=fixture_config.policy)
        assert exc.value.gate == "ipv4:rule-count-change"

    def test_rejects_a_large_coverage_change(self, fixture_config):
        # Same rule count, wildly different address space.
        previous = nets(*[f"{n}.0.0.0/24" for n in range(1, 21)])
        current = nets(*[f"{n}.0.0.0/16" for n in range(1, 21)])
        with pytest.raises(SecurityGateError) as exc:
            check_ipv4_change(previous, current, policy=fixture_config.policy)
        assert exc.value.gate == "ipv4:coverage-change"

    def test_rejects_a_high_removal_rate(self, fixture_config):
        # Count stays inside the limit, but a fifth of the entries were replaced.
        previous = nets(*[f"{n}.0.0.0/24" for n in range(1, 21)])
        current = nets(*[f"{n}.0.0.0/24" for n in range(5, 25)])
        with pytest.raises(SecurityGateError) as exc:
            check_ipv4_change(previous, current, policy=fixture_config.policy)
        assert exc.value.gate == "ipv4:removal-rate"


class TestDomainChangeGates:
    def test_accepts_a_small_change(self, fixture_config):
        previous = [f"d{n}.com" for n in range(20)]
        current = previous + ["new.com"]
        assert check_domain_change(previous, current, policy=fixture_config.policy).added == [
            "new.com"
        ]

    def test_rejects_a_large_count_change(self, fixture_config):
        previous = [f"d{n}.com" for n in range(20)]
        current = previous + [f"n{n}.com" for n in range(10)]
        with pytest.raises(SecurityGateError) as exc:
            check_domain_change(previous, current, policy=fixture_config.policy)
        assert exc.value.gate == "domains:rule-count-change"

    def test_rejects_a_high_removal_rate(self, fixture_config):
        previous = [f"d{n}.com" for n in range(20)]
        current = [f"d{n}.com" for n in range(4, 24)]
        with pytest.raises(SecurityGateError) as exc:
            check_domain_change(previous, current, policy=fixture_config.policy)
        assert exc.value.gate == "domains:removal-rate"


class TestReadingPreviousArtifacts:
    def test_reads_a_generated_ipv4_file(self, tmp_path):
        write_artifact(tmp_path / "cn-ipv4.txt", ["1.2.3.0/24", "4.5.6.7"])
        assert [str(n) for n in read_ipv4_file(tmp_path / "cn-ipv4.txt")] == [
            "1.2.3.0/24",
            "4.5.6.7/32",
        ]

    def test_missing_file_reads_as_empty(self, tmp_path):
        assert read_ipv4_file(tmp_path / "nope.txt") == []
        assert read_domain_file(tmp_path / "nope.txt") == []

    def test_domain_reader_ignores_ip_lines(self, tmp_path):
        write_artifact(tmp_path / "cn-direct.txt", ["baidu.com", "1.2.3.0/24", "qq.com"])
        assert read_domain_file(tmp_path / "cn-direct.txt") == ["baidu.com", "qq.com"]
