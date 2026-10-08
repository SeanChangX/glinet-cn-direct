**English** · [繁體中文](README.zh-TW.md)

# glinet-cn-direct

[![build](https://img.shields.io/github/actions/workflow/status/SeanChangX/glinet-cn-direct/release.yml?label=build)](https://github.com/SeanChangX/glinet-cn-direct/actions/workflows/release.yml)
[![release](https://img.shields.io/github/v/release/SeanChangX/glinet-cn-direct?label=release)](https://github.com/SeanChangX/glinet-cn-direct/releases/latest)
[![license](https://img.shields.io/github/license/SeanChangX/glinet-cn-direct)](LICENSE)

Mainland China IP and domain lists for VPN split tunneling, rebuilt daily from
established upstream datasets and published only after automated safety checks
pass.

The lists are formatted for the GL.iNet VPN policy feature, and as plain
one-rule-per-line text they also work with other routers and tools that accept
CIDR or domain lists.

```text
Mainland China destinations  ->  direct
everything else              ->  VPN tunnel
```

## Files

| File | Contents | Size |
| --- | --- | --- |
| `cn-ipv4.txt` | Mainland China IPv4 networks (CIDR) — **recommended** | ~6,200 lines, ~95 KiB |
| `cn-domains.txt` | Mainland China domains | ~110,000 lines, ~1.3 MiB |
| `cn-direct.txt` | `cn-domains.txt` followed by `cn-ipv4.txt` | ~117,000 lines, ~1.4 MiB |
| `checksums.txt` | SHA-256 of the three lists | |
| `metadata.json` | Upstream revisions, per-file counts and validation results | |

Exact figures for every build are recorded in its `metadata.json`.

## Download

Each file is available at two URLs. Both serve identical content and always
point at the latest build.

**Release asset**

```text
https://github.com/SeanChangX/glinet-cn-direct/releases/latest/download/cn-ipv4.txt
https://github.com/SeanChangX/glinet-cn-direct/releases/latest/download/cn-domains.txt
https://github.com/SeanChangX/glinet-cn-direct/releases/latest/download/cn-direct.txt
```

**Raw file on the `release` branch**

```text
https://raw.githubusercontent.com/SeanChangX/glinet-cn-direct/release/cn-ipv4.txt
https://raw.githubusercontent.com/SeanChangX/glinet-cn-direct/release/cn-domains.txt
https://raw.githubusercontent.com/SeanChangX/glinet-cn-direct/release/cn-direct.txt
```

Routers usually fetch subscriptions over their own WAN connection rather than
through the VPN. From networks in mainland China, `raw.githubusercontent.com` is
frequently unreachable; the release-asset URL tends to be more reliable, though
neither is guaranteed.

Previous builds are kept as
[GitHub Releases](https://github.com/SeanChangX/glinet-cn-direct/releases).

## Usage

### GL.iNet

1. Open **VPN Dashboard**, edit the tunnel, and go to **Target Destination**.
2. Select **Exclude Specified Domain / IP List** and set the mode to
   **Subscription URL**.
3. Enter the URL of `cn-ipv4.txt`, press **Detect**, check that the detected
   count is plausible, then apply.

Destinations on the list leave through the local WAN; everything else stays in
the tunnel. `cn-direct.txt` adds domain rules for China-oriented services that
resolve to non-Chinese infrastructure. It is about fifteen times the size of
`cn-ipv4.txt` and may be too large for some models.

### Other routers and tools

- `cn-ipv4.txt` holds one CIDR per line and can populate ipset or nftables
  sets, or any policy-routing setup that takes a CIDR list.
- Each line of `cn-domains.txt` is meant to match the domain and all of its
  subdomains. The list includes six bare top-level-domain rules, such as `cn`,
  that match entire TLDs; check how your tool treats single-label entries.
- All files are UTF-8 with LF line endings, one rule per line, and no comments.

IPv6 is not part of the production lists. An experimental
`experimental/cn-ipv6.txt` is published on the `release` branch and is not
covered by the safety checks.

## How it works

A scheduled GitHub Actions workflow rebuilds the lists daily and publishes a new
release only when the content changes.

- **Sources:** IPv4 comes from
  [`gaoyifan/china-operator-ip`](https://github.com/gaoyifan/china-operator-ip),
  the same data behind `geoip:cn` in the V2Ray ecosystem. Domains come from
  [`felixonmars/dnsmasq-china-list`](https://github.com/felixonmars/dnsmasq-china-list).
  Every build pins both to a commit SHA. See [SOURCES.md](SOURCES.md).
- **Validation:** every line must be a valid domain, IPv4 address or IPv4 CIDR.
- **Safety checks:** a build is rejected if it contains overly broad prefixes or
  reserved address ranges, matches a protected foreign domain, misclassifies a
  known address, disagrees with an independent second source, or changes too
  much from the previous release.
- **Fail closed:** if any check fails, nothing is published and the previous
  release stays in place.
- **Reproducible:** output is deterministic, and every release records the
  upstream revisions and file hashes it was built from.

Thresholds and policy live in [`config/`](config/).

## Building from source

Requires Python 3.11 or later. The generator has no runtime dependencies.

```bash
python -m glinet_rules build --output dist
python -m glinet_rules validate dist/cn-ipv4.txt dist/cn-domains.txt dist/cn-direct.txt
```

Development setup:

```bash
python -m venv venv
source venv/bin/activate        # Windows: venv\Scripts\activate
pip install -r requirements-dev.txt -e .
python -m pytest
```

## Contributing

Issues and pull requests are welcome. Please read
[CONTRIBUTING.md](CONTRIBUTING.md) first, in particular the rules on generated
files and safety thresholds.

## Security

Please report security issues through
[private vulnerability reporting](https://github.com/SeanChangX/glinet-cn-direct/security/advisories/new)
rather than a public issue. The threat model and reporting process are described
in [SECURITY.md](SECURITY.md).

## Acknowledgements

- [`gaoyifan/china-operator-ip`](https://github.com/gaoyifan/china-operator-ip):
  IPv4 data
- [`felixonmars/dnsmasq-china-list`](https://github.com/felixonmars/dnsmasq-china-list):
  domain data
- [`Loyalsoldier/v2ray-rules-dat`](https://github.com/Loyalsoldier/v2ray-rules-dat):
  independent cross-check

## Disclaimer

No geolocation dataset is perfectly accurate; verify the routing on your own
network. This project is not affiliated with GL.iNet, v2rayN, V2Ray, Xray or any
upstream data project, and it is not a VPN or a censorship circumvention
service.

## License

The code is released under the [MIT License](LICENSE). The published lists are
derived from upstream data licensed under MIT and WTFPL; see
[THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md).
