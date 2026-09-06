"""Domain normalization, unsupported-rule accounting and the domain gates."""

from __future__ import annotations

import pytest

from glinet_rules.domains import (
    DomainRejected,
    build_domain_set,
    collapse_domains,
    normalize_domain,
    parse_domain_lines,
)
from glinet_rules.errors import SecurityGateError


class TestNormalizeDomain:
    @pytest.mark.parametrize(
        ("value", "expected"),
        [
            ("baidu.com", "baidu.com"),
            ("Baidu.COM", "baidu.com"),
            ("  baidu.com  ", "baidu.com"),
            ("baidu.com.", "baidu.com"),
            ("domain:baidu.com", "baidu.com"),
            ("full:www.example.com", "www.example.com"),
            ("DOMAIN:Baidu.Com.", "baidu.com"),
            ("server=/qq.com/114.114.114.114", "qq.com"),
            ("server=/WWW.QQ.COM./223.5.5.5", "www.qq.com"),
            ("xn--fiqs8s", "xn--fiqs8s"),
            ("cn", "cn"),
            ("a-b_c.example.com", "a-b_c.example.com"),
            ("example.com:@cn", "example.com"),
        ],
    )
    def test_accepts_and_canonicalizes(self, value, expected):
        assert normalize_domain(value) == expected

    def test_converts_internationalized_names_to_punycode(self):
        assert normalize_domain("中国.cn") == "xn--fiqs8s.cn"

    @pytest.mark.parametrize(
        "value",
        [
            "",
            "   ",
            "https://baidu.com",
            "http://baidu.com",
            "*.baidu.com",
            "baidu.com/path",
            "baidu.com?foo=bar",
            "baidu.com#frag",
            "baidu.com:8080",
            "user@baidu.com",
            "bai du.com",
            "keyword:google",
            "regexp:^foo",
            "geosite:cn",
            "geoip:cn",
            "include:china-list",
            "..baidu.com",
            "baidu..com",
            "-bad.example.com",
            "bad-.example.com",
            "1.2.3.4",
        ],
    )
    def test_rejects_invalid(self, value):
        with pytest.raises(DomainRejected):
            normalize_domain(value)

    def test_rejects_overlong_domain(self):
        with pytest.raises(DomainRejected):
            normalize_domain(".".join(["a" * 60] * 5))

    def test_rejects_overlong_label(self):
        with pytest.raises(DomainRejected):
            normalize_domain("a" * 64 + ".com")


class TestParsing:
    def test_counts_unsupported_rules_by_type(self):
        text = "keyword:a\nkeyword:b\nregexp:c\nbaidu.com\n"
        domains, report = parse_domain_lines(text)
        assert domains == {"baidu.com"}
        assert report.unsupported == {"keyword": 2, "regexp": 1}
        assert report.unsupported_count == 3

    def test_never_converts_unsupported_rules(self):
        domains, _ = parse_domain_lines("keyword:google\nregexp:.*google.*\n")
        assert domains == set()

    def test_counts_duplicates_separately_from_rejections(self):
        domains, report = parse_domain_lines("baidu.com\nBAIDU.COM\nbaidu.com.\n")
        assert domains == {"baidu.com"}
        assert report.duplicates == 2
        assert report.rejected_count == 0

    def test_skips_comments_and_blanks(self):
        _, report = parse_domain_lines("# note\n\n   \nbaidu.com\n")
        assert report.content_lines == 1


class TestCollapseDomains:
    def test_drops_subdomains_covered_by_a_parent_rule(self):
        kept, removed = collapse_domains({"example.com", "cdn.example.com", "a.b.example.com"})
        assert kept == ["example.com"]
        assert removed == 2

    def test_keeps_unrelated_subdomains(self):
        kept, _ = collapse_domains({"www.jd.com", "baidu.com"})
        assert kept == ["baidu.com", "www.jd.com"]

    def test_a_bare_tld_absorbs_everything_under_it(self):
        kept, removed = collapse_domains({"cn", "taobao.cn", "a.b.cn", "qq.com"})
        assert kept == ["cn", "qq.com"]
        assert removed == 2

    def test_output_is_sorted_and_deterministic(self):
        entries = {"z.com", "a.com", "m.com"}
        assert collapse_domains(entries)[0] == ["a.com", "m.com", "z.com"]


class TestBuildGates:
    def _build(self, config, lines):
        return build_domain_set(
            "\n".join(lines) + "\n",
            policy=config.policy,
            allowed_tlds=config.allowed_tlds,
        )

    def test_accepts_a_sane_set(self, fixture_config):
        result = self._build(fixture_config, ["baidu.com", "qq.com", "cn"])
        assert result.domains == ["baidu.com", "cn", "qq.com"]
        assert result.bare_tlds == ("cn",)

    @pytest.mark.parametrize("tld", ["com", "net", "org", "io", "top"])
    def test_rejects_a_bare_tld_that_was_not_reviewed(self, fixture_config, tld):
        with pytest.raises(SecurityGateError) as exc:
            self._build(fixture_config, ["baidu.com", tld])
        assert exc.value.gate == "domains:unreviewed-tld"

    def test_accepts_a_reviewed_bare_tld(self, fixture_config):
        result = self._build(fixture_config, ["baidu.com", "cn"])
        assert "cn" in result.domains

    def test_rejects_an_empty_set(self, fixture_config):
        with pytest.raises(SecurityGateError) as exc:
            build_domain_set(
                "# nothing\n",
                policy=fixture_config.policy,
                allowed_tlds=fixture_config.allowed_tlds,
            )
        assert exc.value.gate == "domains:source-quality"

    def test_rejects_too_many_unparsable_lines(self, fixture_config):
        with pytest.raises(SecurityGateError) as exc:
            self._build(fixture_config, ["baidu.com", *["https://x"] * 10])
        assert exc.value.gate == "domains:source-quality"

    def test_rejects_an_unsupported_rule_flood(self, fixture_config):
        fixture_config.policy.raw["domains"]["unsupported_fail"] = 3
        with pytest.raises(SecurityGateError) as exc:
            self._build(fixture_config, ["baidu.com", *[f"keyword:k{i}" for i in range(4)]])
        assert exc.value.gate == "domains:unsupported-entries"

    def test_rejects_a_set_below_the_size_floor(self, fixture_config):
        fixture_config.policy.raw["domains"]["min_domains"] = 10
        with pytest.raises(SecurityGateError) as exc:
            self._build(fixture_config, ["baidu.com", "qq.com"])
        assert exc.value.gate == "domains:set-size"


class TestShippedConfig:
    def test_allowed_tlds_are_bare_and_lowercase(self, repo_config):
        for tld in repo_config.allowed_tlds:
            assert "." not in tld
            assert tld == tld.lower()
            assert normalize_domain(tld) == tld

    def test_no_allowed_tld_encompasses_a_never_direct_domain(self, repo_config):
        for tld in repo_config.allowed_tlds:
            for protected in repo_config.never_direct:
                assert protected != tld
                assert not protected.endswith("." + tld)
