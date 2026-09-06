"""GL.iNet grammar enforcement and the route-leak tripwires."""

from __future__ import annotations

import ipaddress

import pytest

from glinet_rules.config import Canary
from glinet_rules.errors import SecurityGateError
from glinet_rules.ipv4 import IPv4Result, ParseReport
from glinet_rules.metadata import render_lines
from glinet_rules.validate import (
    LINE_KIND_DOMAIN,
    LINE_KIND_IPV4,
    LINE_KIND_IPV4_CIDR,
    InvalidLine,
    check_ip_canaries,
    check_never_direct,
    classify_line,
    encompassing_rules,
    validate_lines,
    validate_text_file,
)


def make_result(cidrs: list[str]) -> IPv4Result:
    networks = sorted(ipaddress.IPv4Network(c) for c in cidrs)
    return IPv4Result(networks=networks, report=ParseReport(), raw_count=len(networks))


def canary(address: str, label: str = "test") -> Canary:
    return Canary(address=ipaddress.IPv4Address(address), label=label, review_by=None)


class TestClassifyLine:
    @pytest.mark.parametrize(
        ("line", "kind"),
        [
            ("baidu.com", LINE_KIND_DOMAIN),
            ("www.example.com", LINE_KIND_DOMAIN),
            ("xn--fiqs8s", LINE_KIND_DOMAIN),
            ("cn", LINE_KIND_DOMAIN),
            ("1.2.3.4", LINE_KIND_IPV4),
            ("1.2.3.0/24", LINE_KIND_IPV4_CIDR),
            ("0.0.0.0/0", LINE_KIND_IPV4_CIDR),  # syntax is fine; the IPv4 gate rejects it
        ],
    )
    def test_accepts_documented_rule_types(self, line, kind):
        assert classify_line(line) == kind

    @pytest.mark.parametrize(
        "line",
        [
            "",
            " baidu.com",
            "baidu.com ",
            "bai du.com",
            "Baidu.com",
            "中国.cn",
            "domain:baidu.com",
            "full:baidu.com",
            "keyword:baidu",
            "regexp:.*",
            "geosite:cn",
            "geoip:cn",
            "include:foo",
            "https://baidu.com",
            "*.baidu.com",
            "baidu.com/path",
            "# a comment",
            "{",
            "2001:db8::/32",
            "1.2.3.4/33",
            "1.2.3.5/24",  # non-canonical: host bits set
            "999.1.1.1",
        ],
    )
    def test_rejects_everything_else(self, line):
        with pytest.raises(InvalidLine):
            classify_line(line)


class TestValidateLines:
    def test_counts_each_rule_kind(self):
        result = validate_lines(["baidu.com", "1.2.3.4", "1.2.3.0/24"])
        assert result.ok
        assert result.counts == {
            LINE_KIND_DOMAIN: 1,
            LINE_KIND_IPV4: 1,
            LINE_KIND_IPV4_CIDR: 1,
        }

    def test_reports_the_offending_line_number(self):
        result = validate_lines(["baidu.com", "keyword:x", "1.2.3.0/24"])
        assert not result.ok
        assert result.problems[0][0] == 2


class TestValidateTextFile:
    def _write(self, tmp_path, data: bytes):
        path = tmp_path / "rules.txt"
        path.write_bytes(data)
        return path

    def test_accepts_a_well_formed_file(self, tmp_path):
        path = self._write(tmp_path, render_lines(["baidu.com", "1.2.3.0/24"]))
        assert validate_text_file(path).ok

    def test_rejects_a_bom(self, tmp_path):
        path = self._write(tmp_path, b"\xef\xbb\xbfbaidu.com\n")
        assert "BOM" in validate_text_file(path).problems[0][2]

    def test_rejects_crlf_endings(self, tmp_path):
        path = self._write(tmp_path, b"baidu.com\r\n")
        assert any("CR" in reason for _, _, reason in validate_text_file(path).problems)

    def test_rejects_a_missing_final_newline(self, tmp_path):
        path = self._write(tmp_path, b"baidu.com")
        assert any("final newline" in reason for _, _, reason in validate_text_file(path).problems)


class TestNeverDirect:
    def test_passes_when_no_protected_domain_is_matched(self):
        check_never_direct(["baidu.com", "qq.com"], ("google.com", "github.com"))

    def test_fails_on_an_exact_match(self):
        with pytest.raises(SecurityGateError) as exc:
            check_never_direct(["baidu.com", "google.com"], ("google.com",))
        assert exc.value.gate == "domains:never-direct"

    @pytest.mark.parametrize("rule", ["com", "example.com"])
    def test_fails_on_a_parent_domain(self, rule):
        with pytest.raises(SecurityGateError):
            check_never_direct(["baidu.com", rule], ("api.example.com",))

    def test_encompassing_rules_lists_every_match(self):
        generated = {"com", "example.com", "api.example.com"}
        assert encompassing_rules("api.example.com", generated) == [
            "api.example.com",
            "example.com",
            "com",
        ]

    def test_a_subdomain_rule_does_not_encompass_its_parent(self):
        check_never_direct(["mail.google.com"], ("google.com",))


class TestIPCanaries:
    def test_passes_when_cn_is_covered_and_foreign_is_not(self):
        result = make_result(["114.114.114.0/24"])
        check_ip_canaries(
            result,
            cn_canaries=(canary("114.114.114.114"),),
            foreign_canaries=(canary("8.8.8.8"),),
        )

    def test_fails_when_a_cn_canary_is_missing(self):
        with pytest.raises(SecurityGateError) as exc:
            check_ip_canaries(
                make_result(["1.2.3.0/24"]),
                cn_canaries=(canary("114.114.114.114", "114DNS"),),
                foreign_canaries=(),
            )
        assert exc.value.gate == "ipv4:cn-canary"
        assert "114DNS" in exc.value.detail

    def test_fails_when_a_foreign_canary_leaks_into_the_cn_set(self):
        with pytest.raises(SecurityGateError) as exc:
            check_ip_canaries(
                make_result(["8.8.8.0/24"]),
                cn_canaries=(),
                foreign_canaries=(canary("8.8.8.8", "Google DNS"),),
            )
        assert exc.value.gate == "ipv4:foreign-canary"
        assert "Google DNS" in exc.value.detail


class TestShippedArtifacts:
    """A local build's output must survive the same validator users would run.

    `dist/` is not tracked in the repository — the `release` branch is the
    published copy — so this skips unless someone has run a build here. CI
    always has, because the workflow builds before it validates.
    """

    def test_generated_artifacts_are_valid(self, tmp_path):
        from pathlib import Path

        dist = Path(__file__).resolve().parents[1] / "dist"
        for name in ("cn-ipv4.txt", "cn-domains.txt", "cn-direct.txt"):
            path = dist / name
            if not path.is_file():
                pytest.skip(f"{name} not built in this checkout; run a build first")
            result = validate_text_file(path)
            assert result.ok, result.problems[:5]
