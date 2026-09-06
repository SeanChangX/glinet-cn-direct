"""Loading and validation of everything under config/."""

from __future__ import annotations

import ipaddress
import json
import re
import tomllib
from dataclasses import dataclass, field
from datetime import date
from pathlib import Path

from .errors import ConfigError

REPO_ROOT = Path(__file__).resolve().parents[2]
DEFAULT_CONFIG_DIR = REPO_ROOT / "config"

_CANARY_RE = re.compile(
    r"^(?P<ip>\S+)\s*(?:#\s*(?P<label>.*?)\s*(?:\|\s*review:\s*(?P<review>\d{4}-\d{2}-\d{2}))?\s*)?$"
)


def _strip_comment(line: str) -> str:
    """Drop a trailing '#' comment and surrounding whitespace."""
    return line.split("#", 1)[0].strip()


def _read_list_file(path: Path) -> list[str]:
    if not path.is_file():
        raise ConfigError(f"missing config file: {path}")
    out: list[str] = []
    for raw in path.read_text(encoding="utf-8").splitlines():
        value = _strip_comment(raw)
        if value:
            out.append(value)
    return out


@dataclass(frozen=True)
class Canary:
    """A single IP tripwire plus the date its ownership was last checked."""

    address: ipaddress.IPv4Address
    label: str
    review_by: date | None

    def is_stale(self, today: date) -> bool:
        return self.review_by is not None and self.review_by < today


def _parse_canaries(path: Path) -> list[Canary]:
    canaries: list[Canary] = []
    for lineno, raw in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        match = _CANARY_RE.match(line)
        if not match:
            raise ConfigError(f"{path}:{lineno}: cannot parse canary line: {raw!r}")
        try:
            address = ipaddress.IPv4Address(match.group("ip"))
        except ValueError as exc:
            raise ConfigError(f"{path}:{lineno}: {exc}") from exc
        review = match.group("review")
        canaries.append(
            Canary(
                address=address,
                label=(match.group("label") or "").strip() or str(address),
                review_by=date.fromisoformat(review) if review else None,
            )
        )
    if not canaries:
        raise ConfigError(f"{path}: contains no canaries")
    return canaries


@dataclass(frozen=True)
class SourceSpec:
    """One entry from expected-sources.json.

    fetch.py will not download anything that is not described by one of these,
    so a source can only be changed by editing a reviewed config file.
    """

    key: str
    role: str
    kind: str
    owner: str
    repo: str
    ref: str
    path: str
    license: str
    max_bytes_key: str
    description: str

    @property
    def slug(self) -> str:
        return f"{self.owner}/{self.repo}"


@dataclass(frozen=True)
class Policy:
    """Parsed config/policy.toml, kept as plain nested dicts plus accessors."""

    raw: dict

    def section(self, name: str) -> dict:
        try:
            return self.raw[name]
        except KeyError as exc:
            raise ConfigError(f"policy.toml: missing [{name}] section") from exc

    def value(self, section: str, key: str):
        sec = self.section(section)
        if key not in sec:
            raise ConfigError(f"policy.toml: missing {section}.{key}")
        return sec[key]


@dataclass(frozen=True)
class Config:
    """Everything the build needs from disk, validated once at load time."""

    config_dir: Path
    policy: Policy
    sources: dict[str, SourceSpec]
    never_direct: tuple[str, ...]
    allowed_tlds: frozenset[str]
    foreign_canaries: tuple[Canary, ...]
    cn_canaries: tuple[Canary, ...]
    warnings: tuple[str, ...] = field(default=())

    @property
    def generator_version(self) -> str:
        return self.policy.value("general", "generator_version")


def load_config(config_dir: Path | str = DEFAULT_CONFIG_DIR) -> Config:
    """Load and cross-validate config/. Raises ConfigError on any problem."""
    config_dir = Path(config_dir)
    if not config_dir.is_dir():
        raise ConfigError(f"config directory not found: {config_dir}")

    policy_path = config_dir / "policy.toml"
    if not policy_path.is_file():
        raise ConfigError(f"missing config file: {policy_path}")
    try:
        policy = Policy(tomllib.loads(policy_path.read_text(encoding="utf-8")))
    except tomllib.TOMLDecodeError as exc:
        raise ConfigError(f"{policy_path}: {exc}") from exc

    sources_path = config_dir / "expected-sources.json"
    if not sources_path.is_file():
        raise ConfigError(f"missing config file: {sources_path}")
    try:
        sources_doc = json.loads(sources_path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise ConfigError(f"{sources_path}: {exc}") from exc

    sources: dict[str, SourceSpec] = {}
    for key, entry in sources_doc.get("sources", {}).items():
        try:
            sources[key] = SourceSpec(key=key, **entry)
        except TypeError as exc:
            raise ConfigError(f"{sources_path}: source {key!r}: {exc}") from exc
    for required in ("ipv4_primary", "domains_primary"):
        if required not in sources:
            raise ConfigError(f"{sources_path}: missing required source {required!r}")

    never_direct = tuple(d.lower() for d in _read_list_file(config_dir / "never-direct-domains.txt"))
    allowed_tlds = frozenset(_read_list_file(config_dir / "allowed-tld-rules.txt"))

    warnings: list[str] = []
    for tld in sorted(allowed_tlds):
        if "." in tld:
            raise ConfigError(f"allowed-tld-rules.txt: {tld!r} is not a bare TLD")
        for domain in never_direct:
            if domain == tld or domain.endswith("." + tld):
                raise ConfigError(
                    f"config conflict: allowed TLD rule {tld!r} would encompass "
                    f"never-direct domain {domain!r}"
                )

    foreign = tuple(_parse_canaries(config_dir / "foreign-ip-canaries.txt"))
    cn = tuple(_parse_canaries(config_dir / "cn-ip-canaries.txt"))

    overlap = {c.address for c in foreign} & {c.address for c in cn}
    if overlap:
        raise ConfigError(
            "config conflict: address(es) listed as both CN and foreign canaries: "
            + ", ".join(str(a) for a in sorted(overlap))
        )

    today = date.today()
    for canary in foreign + cn:
        if canary.is_stale(today):
            warnings.append(
                f"canary {canary.address} ({canary.label}) passed its review date "
                f"{canary.review_by}; re-verify ownership"
            )

    return Config(
        config_dir=config_dir,
        policy=policy,
        sources=sources,
        never_direct=never_direct,
        allowed_tlds=allowed_tlds,
        foreign_canaries=foreign,
        cn_canaries=cn,
        warnings=tuple(warnings),
    )
