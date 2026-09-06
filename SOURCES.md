# Upstream sources

This project does not maintain its own geolocation database. It consumes
established upstream datasets, normalizes them into GL.iNet's rule grammar, and
refuses to publish when anything looks wrong.

The authoritative machine-readable list lives in
[`config/expected-sources.json`](config/expected-sources.json). The build will
not download anything that is not described there.

License texts are reproduced in [THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md).

---

## Selected sources

### IPv4 — `gaoyifan/china-operator-ip`

| | |
| --- | --- |
| **Purpose** | Mainland China IPv4 CIDR ranges |
| **URL** | <https://github.com/gaoyifan/china-operator-ip> |
| **License** | MIT |
| **File consumed** | `ip-lists/china.txt` (branch `ip-lists`) |
| **Produces** | `cn-ipv4.txt`, the IPv4 half of `cn-direct.txt` |
| **Pinning** | branch resolved to a commit SHA, then downloaded from a SHA-pinned raw URL |

**Why this one.** It is not merely a popular China IP list — it is *the* list
behind `geoip:cn` in the V2Ray/Xray rules ecosystem this project aligns with.
[`Loyalsoldier/geoip`](https://github.com/Loyalsoldier/geoip) builds its `cn`
category by taking MaxMind GeoLite2, **removing** its `cn` entries, and adding
`gaoyifan/china-operator-ip`'s `china.txt` (IPv4) and `china6.txt` (IPv6). That
`geoip.dat` is what `Loyalsoldier/v2ray-rules-dat` ships, and what a v2rayN
profile written against `geoip:cn` actually resolves to.

Consuming it directly therefore minimizes transformations rather than
introducing a new opinion about what "China" means.

Verify the claim yourself:

```bash
curl -s https://raw.githubusercontent.com/Loyalsoldier/geoip/master/config.json | grep -A3 china-operator-ip
```

### Domains — `felixonmars/dnsmasq-china-list`

| | |
| --- | --- |
| **Purpose** | Mainland China domain names |
| **URL** | <https://github.com/felixonmars/dnsmasq-china-list> |
| **License** | WTFPL |
| **File consumed** | `accelerated-domains.china.conf` (branch `master`) |
| **Produces** | `cn-domains.txt`, the domain half of `cn-direct.txt` |
| **Pinning** | branch resolved to a commit SHA, then downloaded from a SHA-pinned raw URL |

**Why this one rather than Loyalsoldier's `china-list.txt`.** They are the same
data. `Loyalsoldier/v2ray-rules-dat` generates its `china-list.txt` release
asset by running exactly this transformation on exactly this file:

```bash
curl -sSL $CHINA_DOMAINS_URL | perl -ne '/^server=\/([^\/]+)\// && print "$1\n"' > china-list.txt
```

(from `.github/workflows/run.yml` in that repository, where `CHINA_DOMAINS_URL`
is `accelerated-domains.china.conf`.)

Taking the upstream file directly buys three things:

1. **True commit pinning.** `china-list.txt` exists only as a GitHub *release
   asset*, which can be pinned to a release tag but not to a commit. The source
   `.conf` file is in a repository tree, so every build can record the exact
   immutable commit it read.
2. **Simpler licensing.** WTFPL rather than GPL-3.0, so republishing derived
   rule files raises no questions.
3. **One less intermediary** between the data and the published rules.

The equivalence is re-verified on every build: Loyalsoldier's `china-list.txt`
is still downloaded as an independent comparator (see below), and the build
fails if the two sources drift apart by more than the configured threshold.

---

## Comparator — `Loyalsoldier/v2ray-rules-dat`

| | |
| --- | --- |
| **Purpose** | independent anomaly detection, never a source of rules |
| **URL** | <https://github.com/Loyalsoldier/v2ray-rules-dat> |
| **License** | GPL-3.0 |
| **File consumed** | `china-list.txt` (latest release asset) |
| **Produces** | nothing — its content is never merged or republished |

If the primary domain source and this comparator diverge by more than
`[secondary].max_domain_divergence_percent` in `config/policy.toml`, the build
fails. That means a single compromised or broken upstream cannot silently move
the rules: two independently maintained pipelines would have to break the same
way at the same time.

Set `[secondary].enabled = false` to drop this download entirely.

---

## Evaluated and not used

### `v2fly/domain-list-community`

The upstream community domain database (MIT) behind `geosite:*`. Its `cn`
category is assembled from `include:` directives across many files and carries
`keyword:` and `regexp:` entries that GL.iNet cannot express.

Not used, because reproducing `geosite:cn` faithfully would mean implementing
the `include:` resolution and attribute semantics of the V2Ray data format —
significant complexity for a result whose Mainland-China core is
`china-list`, which this project already consumes directly and losslessly.

### `Loyalsoldier` `direct-list.txt`

Explicitly **rejected** as a `cn-domains.txt` substitute.

`direct-list.txt` expresses a broader *direct-routing policy*, not "Mainland
China domains". It merges `china-list` with `Loyalsoldier/domain-list-custom`'s
`cn.txt`, which contains routing decisions made for reasons other than
geography. Using it here would send domains that have nothing to do with China
around the VPN tunnel.

This project's rule is narrower and deliberate:

```text
cn-domains.txt = Mainland-China-focused domains
             not = every domain someone upstream decided should be direct
```

### `carrnot/china-ip-list`

A perfectly reasonable China IPv4 list, and the baseline this deployment
migrated *from*. Kept as a one-off migration comparator only
(`scripts/compare-baseline.py`); it is not a runtime dependency and is never
merged with the primary source.

See [README](README.md#migrating-from-another-subscription) for the measured
migration difference.

### Multiple unioned GeoIP databases

Deliberately avoided. Merging several China IP databases maximizes coverage at
the cost of predictability: a false positive becomes untraceable, and every
upstream gets a veto over your routing. One clearly documented authoritative
source per rule category is the design choice here, and
[README](README.md#design-principles) explains why false positives are the
dangerous direction in this project.

---

## Semantic mapping to the reference client

This project's routing intent is aligned with a v2rayN whitelist profile:

```text
v2rayN                          this project
------------------------------  --------------------------------------------
geoip:cn   -> direct            cn-ipv4.txt
geosite:cn -> direct            cn-domains.txt  (approximation, see below)
final      -> proxy             GL.iNet: anything unmatched stays in the tunnel
```

`cn-ipv4.txt` is a close match: it is the same data `geoip:cn` is built from.

`cn-domains.txt` is an **approximation** of `geosite:cn`. The differences are:

| | `geosite:cn` | `cn-domains.txt` |
| --- | --- | --- |
| `china-list` domains | yes | yes |
| `apple-cn`, `google-cn` | yes | no |
| `keyword:` / `regexp:` rules | yes | no — counted and reported, never converted |
| `full:` exact-match semantics | preserved | flattened to suffix matching |
| custom `domain-list-custom` additions | yes | no |

This project claims **routing-policy alignment**, not identical rule-engine
behavior. GL.iNet's matcher is not V2Ray or Xray, and no claim of byte-for-byte
or engine-level equivalence is made.

---

## Adding or changing a source

1. Edit `config/expected-sources.json`. The build refuses any URL not described
   there, and only allows the `github_raw` and `github_release_asset` kinds on
   an allowlisted host.
2. Record the license here and reproduce its text in `THIRD_PARTY_NOTICES.md`.
3. Explain *why* — this file is the record of routing-policy decisions, not just
   a bibliography.
4. Expect the diff gates to fail on the first build if the new source moves the
   rules materially. That is the system working; review the audit report before
   raising a threshold.
