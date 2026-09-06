"""Configuration loading, cross-validation and discovery."""

from __future__ import annotations

import pytest

from glinet_rules import config as config_module
from glinet_rules.config import default_config_dir, load_config
from glinet_rules.errors import ConfigError

from conftest import FIXTURE_CONFIG, REPO_CONFIG


def make_checkout(root, *, with_pyproject: bool = True):
    """A directory that looks enough like a checkout to be discovered."""
    (root / "config").mkdir(parents=True, exist_ok=True)
    (root / "config" / "policy.toml").write_text("[general]\n", encoding="utf-8")
    if with_pyproject:
        (root / "pyproject.toml").write_text("[project]\n", encoding="utf-8")
    return root / "config"


class TestDiscovery:
    """Regression cover for config/ being resolved from the installed package.

    `Path(__file__).parents[2]` is the repository root only while the package is
    imported straight from src/. Once pip installs it normally the same
    expression lands in site-packages' parent, and every command fails with
    "config directory not found". Discovery must follow the working tree.
    """

    def test_finds_config_in_the_current_directory(self, tmp_path, monkeypatch):
        expected = make_checkout(tmp_path)
        monkeypatch.chdir(tmp_path)
        assert default_config_dir() == expected

    def test_prefers_the_working_tree_over_the_package_location(self, tmp_path, monkeypatch):
        expected = make_checkout(tmp_path)
        monkeypatch.chdir(tmp_path)
        found = default_config_dir()
        assert found == expected
        assert found != REPO_CONFIG

    def test_finds_config_from_a_subdirectory_of_the_checkout(self, tmp_path, monkeypatch):
        expected = make_checkout(tmp_path)
        nested = tmp_path / "a" / "b"
        nested.mkdir(parents=True)
        monkeypatch.chdir(nested)
        assert default_config_dir() == expected

    def test_ignores_an_unrelated_ancestor_without_a_pyproject(self, tmp_path, monkeypatch):
        # A bare config/policy.toml further up the filesystem must not be
        # mistaken for this project's configuration.
        make_checkout(tmp_path, with_pyproject=False)
        nested = tmp_path / "somewhere" / "else"
        nested.mkdir(parents=True)
        monkeypatch.chdir(nested)
        assert default_config_dir() != tmp_path / "config"

    def test_reports_a_recognizable_path_when_nothing_is_found(self, tmp_path, monkeypatch):
        # The package-relative fallback finds the real repository whenever the
        # package is imported from a source checkout, so it has to be stubbed
        # out to reach the not-found path at all.
        monkeypatch.setattr(config_module, "_PACKAGE_RELATIVE_ROOT", tmp_path / "nowhere")
        monkeypatch.chdir(tmp_path)
        with pytest.raises(ConfigError) as exc:
            load_config()
        assert str(tmp_path) in str(exc.value)
        assert "--config" in str(exc.value)

    def test_falls_back_to_the_package_location_outside_a_checkout(self, tmp_path, monkeypatch):
        # Running from an unrelated directory while working in a source
        # checkout should still find that checkout's config.
        elsewhere = tmp_path / "unrelated"
        elsewhere.mkdir()
        monkeypatch.chdir(elsewhere)
        assert default_config_dir() == REPO_CONFIG


class TestCrossValidation:
    """Two config files can each be valid and still combine into a hole."""

    def _copy_config(self, src, dst):
        dst.mkdir(parents=True, exist_ok=True)
        for path in src.iterdir():
            if path.is_file():
                (dst / path.name).write_text(path.read_text(encoding="utf-8"), encoding="utf-8")
        return dst

    def test_loads_the_shipped_config(self):
        config = load_config(REPO_CONFIG)
        assert config.sources
        assert config.allowed_tlds
        assert config.never_direct

    def test_rejects_an_allowed_tld_that_covers_a_protected_domain(self, tmp_path):
        directory = self._copy_config(FIXTURE_CONFIG, tmp_path / "config")
        (directory / "allowed-tld-rules.txt").write_text("com\n", encoding="utf-8")
        with pytest.raises(ConfigError, match="would encompass"):
            load_config(directory)

    def test_rejects_a_tld_entry_containing_a_dot(self, tmp_path):
        directory = self._copy_config(FIXTURE_CONFIG, tmp_path / "config")
        (directory / "allowed-tld-rules.txt").write_text("com.cn\n", encoding="utf-8")
        with pytest.raises(ConfigError, match="not a bare TLD"):
            load_config(directory)

    def test_rejects_an_address_listed_as_both_cn_and_foreign(self, tmp_path):
        directory = self._copy_config(FIXTURE_CONFIG, tmp_path / "config")
        (directory / "foreign-ip-canaries.txt").write_text(
            "114.114.114.114  # also a CN canary | review: 2099-01-01\n", encoding="utf-8"
        )
        with pytest.raises(ConfigError, match="both CN and foreign"):
            load_config(directory)

    def test_rejects_a_missing_file(self, tmp_path):
        directory = self._copy_config(FIXTURE_CONFIG, tmp_path / "config")
        (directory / "never-direct-domains.txt").unlink()
        with pytest.raises(ConfigError, match="missing config file"):
            load_config(directory)

    def test_rejects_an_unparsable_canary_line(self, tmp_path):
        directory = self._copy_config(FIXTURE_CONFIG, tmp_path / "config")
        (directory / "cn-ip-canaries.txt").write_text("not-an-address\n", encoding="utf-8")
        with pytest.raises(ConfigError):
            load_config(directory)

    def test_warns_about_a_canary_past_its_review_date(self, tmp_path):
        directory = self._copy_config(FIXTURE_CONFIG, tmp_path / "config")
        (directory / "foreign-ip-canaries.txt").write_text(
            "8.8.8.8  # Google DNS | review: 2001-01-01\n", encoding="utf-8"
        )
        config = load_config(directory)
        assert any("review date" in w for w in config.warnings)
