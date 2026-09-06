**English** · [繁體中文](README.zh-TW.md)

# glinet-cn-direct

**Auditable, fail-closed GL.iNet routing rules built from established upstream datasets.**

Automatically generated Mainland China direct-routing rules for the GL.iNet VPN
policy feature, so that:

```text
Mainland China destinations  ->  DIRECT / bypass the VPN
everything else              ->  stays inside the VPN tunnel
```

This is an independent compatibility project. It is **not** affiliated with
GL.iNet, v2rayN, V2Ray, Xray, or any of the upstream data projects it consumes.

---

## Subscription URLs

Paste one of these into your GL.iNet router. See [Setup](#setup) below.

| File | Use it when | URL |
| --- | --- | --- |
| **`cn-ipv4.txt`** *(recommended)* | you want predictable, GeoIP-based routing | `https://raw.githubusercontent.com/SeanChangX/glinet-cn-direct/release/cn-ipv4.txt` |
| `cn-direct.txt` *(advanced)* | you want behavior closer to `geoip:cn + geosite:cn` | `https://raw.githubusercontent.com/SeanChangX/glinet-cn-direct/release/cn-direct.txt` |
| `cn-domains.txt` *(specialized)* | you only want domain rules | `https://raw.githubusercontent.com/SeanChangX/glinet-cn-direct/release/cn-domains.txt` |

The `release` branch is a moving pointer that your router follows automatically.
For auditing, every published build is also tagged as an immutable
[GitHub Release](../../releases) with checksums and full provenance metadata.

> **Start with `cn-ipv4.txt`.** It has the clearest semantics and the lowest
> false-positive risk, and in practice it already routes most Chinese services
> correctly — see [Why IP-only usually suffices](#why-ip-only-usually-suffices).

---

## What makes this different from mirroring a list

This repository does not simply re-host an upstream file. Every build:

1. resolves each upstream branch to an **immutable commit SHA** and downloads
   from a SHA-pinned URL;
2. normalizes entries into GL.iNet's grammar, rejecting rather than repairing;
3. validates every generated line, and publishes nothing if even one fails;
4. compares the result against the previous release and against an
   **independent second upstream**;
5. blocks publication on any anomaly — a broad prefix, a reserved range, a
   protected domain, a coverage jump, an unexplained mass removal;
6. records checksums, source revisions and source hashes in `metadata.json`.

If anything looks wrong, **nothing is published and the previous known-good list
stays live.** A stale correct list is safer than a fresh suspicious one.

Never any upstream code execution: the pipeline downloads *data*, never clones
an upstream repository and never runs an upstream build script.

---

## Setup

On the GL.iNet admin panel:

```text
VPN Dashboard
  -> edit your tunnel
  -> Target Destination
  -> Exclude Specified Domain / IP List
  -> Subscription URL
```

Paste the `cn-ipv4.txt` URL, press **Detect**, and confirm the detected entry
count is plausible (see [Current output](#current-output)). Then apply.

Expected routing afterwards:

```text
Mainland China IPv4  ->  local WAN
other IPv4           ->  VPN tunnel
```

With `cn-direct.txt` instead:

```text
CN domains           ->  local WAN
CN IPv4              ->  local WAN
everything else      ->  VPN tunnel
```

---

## Current output

<!-- These figures are from the build committed in dist/; each release records
     its own exact numbers in metadata.json. -->

| Artifact | Rules | Size |
| --- | ---: | ---: |
| `cn-ipv4.txt` | 6,234 IPv4 networks | 95 KiB |
| `cn-domains.txt` | 110,433 domains | 1.3 MiB |
| `cn-direct.txt` | 116,667 rules | 1.4 MiB |
| `experimental/cn-ipv6.txt` | 3,395 IPv6 networks | not for production |

IPv4 coverage is 344,250,112 addresses — **8.02% of the IPv4 space** — with the
broadest single network being a `/10`.

### Router limits

`cn-ipv4.txt` is small and safe on any model. `cn-direct.txt` is over a hundred
thousand lines, and how well that loads depends on your router's memory and
firmware. Syntactic validity is not a compatibility promise: **no claim of
universal compatibility is made.** Every release records per-file line counts
and byte sizes in `metadata.json` so you can judge before subscribing.

If the GL.iNet UI struggles with the combined list, use `cn-ipv4.txt`.

---

## Why IP-only usually suffices

GL.iNet matches on the *destination* of a connection, so a DNS answer that lands
in a Chinese network is enough:

```text
bilibili.com
   |  DNS
   v
8.134.50.24
   |
   v
destination matches a CN IPv4 network
   |
   v
GL.iNet excludes the connection from the tunnel  ->  local WAN
```

and conversely:

```text
google.com
   |  DNS
   v
142.250.x.x
   |
   v
matches nothing in the CN set
   |
   v
stays in the tunnel  ->  VPN exit
```

Domain rules only add value where a China-oriented service resolves to non-CN or
CDN infrastructure. That is why `cn-ipv4.txt` is the default recommendation and
`cn-direct.txt` is the advanced option.

---

## Semantic differences from v2rayN

The intent is aligned with a common v2rayN whitelist profile:

```text
v2rayN                        GL.iNet + this project
--------------------------    ------------------------------------------
geoip:cn   -> direct          cn-ipv4.txt      -> bypasses the tunnel
geosite:cn -> direct          cn-domains.txt   -> bypasses the tunnel
final      -> proxy           anything unmatched stays in the Primary Tunnel
```

`cn-ipv4.txt` is built from the same data `geoip:cn` resolves to.
`cn-domains.txt` is an approximation of `geosite:cn`;
[SOURCES.md](SOURCES.md#semantic-mapping-to-the-reference-client) lists exactly
what differs.

**This project claims routing-policy alignment, not identical rule-engine
behavior.** GL.iNet's matcher is not V2Ray or Xray.

Two consequences worth knowing:

- **`full:` becomes suffix matching.** V2Ray's exact-match entries are emitted
  as plain domain lines, which GL.iNet may also match on subdomains. This
  widens a handful of rules.
- **`keyword:` and `regexp:` are dropped.** They are counted per type and
  reported in `metadata.json`, never approximated. A sudden change in their
  count blocks the build for review.

### Bare TLD rules

The domain output contains six single-label rules, each of which matches an
entire top-level domain:

```text
cn            .cn         China country-code TLD
xn--fiqs8s    .中国
xn--55qx5d    .公司
xn--io0a7i    .网络
top           .top        generic TLD, Chinese registry, open registration
wang          .wang       generic TLD, Chinese registry, open registration
```

`cn` is load-bearing: upstream contains **zero** explicit `.cn` entries because
it relies on this one rule, so dropping it would send all of `.cn` through the
tunnel.

`top` and `wang` are a deliberate trade-off. Their registries are Chinese, but
registration is open worldwide, so some non-Chinese sites under them will
bypass the VPN. They are kept to match upstream `geosite:cn` semantics. To drop
them, remove the lines from
[`config/allowed-tld-rules.txt`](config/allowed-tld-rules.txt) and rebuild.

Any bare TLD *not* in that file fails the build. A stray `com` line from a
compromised upstream would be catastrophic, so it is treated as such.

---

## Migrating from another subscription

Follow this order, and do not delete your old subscription URL until the last
step.

1. Build and validate the new `cn-ipv4.txt`.
2. Compare it against your current list:
   ```bash
   python scripts/compare-baseline.py --baseline-url <your current URL>
   ```
3. Review the additions and removals it reports.
4. Paste the new raw URL into GL.iNet and press **Detect**.
5. Confirm the detected count is plausible.
6. Apply the rule.
7. Run the [verification checks](#verifying-your-deployment) below.
8. Confirm CN destinations are still direct.
9. Confirm foreign destinations still use the VPN.
10. Only then make the new URL your long-term subscription.

**Rollback:** if any check fails, put your previous subscription URL back in
GL.iNet and press Detect again. Nothing else needs undoing — this project never
touches your router.

### Measured result for one real migration

Migrating from `carrnot/china-ip-list`'s `ipv4.txt`:

| | baseline | this project |
| --- | ---: | ---: |
| networks | 7,833 | 6,234 |
| addresses | 357,858,401 | 344,250,112 |

The rule count fell 20% while address coverage fell only **3.8%**, because the
upstream here expresses the same space in fewer, larger CIDRs. Every address in
the generated set is also in the baseline — it is a strict subset, so the change
can only move traffic *into* the VPN, never out of it. That is the safe
direction; see [Design principles](#design-principles).

---

## Verifying your deployment

CI cannot reproduce your physical network, so these checks are manual. Run them
from a client that uses the router as its DNS server.

```powershell
nslookup baidu.com
nslookup bilibili.com
nslookup qq.com
nslookup google.com
nslookup youtube.com
nslookup chatgpt.com
```

```powershell
tracert baidu.com
tracert bilibili.com
tracert qq.com
tracert google.com
tracert youtube.com
```

```powershell
curl.exe https://api.ipify.org
```

> On Windows PowerShell, use `curl.exe` explicitly. Older versions alias `curl`
> to `Invoke-WebRequest`, which behaves differently.

What you are looking for is the *shape* of the path, not specific hops:

```text
CN sites:
  your PC -> router -> local ISP upstream

Foreign sites:
  your PC -> router -> VPN-side private hop -> the VPN exit's ISP
```

CN sites should show low latency to a local upstream within the first couple of
hops. Foreign sites should show the private address of your VPN peer before
reaching any public network.

Do not treat exact public IPs, intermediate hops or latency numbers as
acceptance criteria — they change legitimately.

### What CI does check

Automatically, on every build:

- known Mainland China addresses fall **inside** the generated set
  ([`config/cn-ip-canaries.txt`](config/cn-ip-canaries.txt));
- known foreign addresses fall **outside** it
  ([`config/foreign-ip-canaries.txt`](config/foreign-ip-canaries.txt));
- no rule matches a protected domain
  ([`config/never-direct-domains.txt`](config/never-direct-domains.txt));
- no reserved or special-use IPv4 range enters the set;
- every published line is valid GL.iNet grammar.

Each canary carries a review date, because IP ownership is not permanent.

---

## Building it yourself

Python 3.11+ and no runtime dependencies at all — the generator uses only the
standard library.

```bash
python -m glinet_rules build --output dist
python -m glinet_rules validate dist/cn-ipv4.txt
python -m glinet_rules diff dist/ previous/
```

Or without installing:

```bash
python scripts/build.py --output dist
```

Development:

```bash
python -m venv venv
source venv/Scripts/activate      # Windows: .\venv\Scripts\Activate.ps1
pip install -r requirements-dev.txt
python -m pytest
```

### Reproducing a published build

Builds are deterministic: identical upstream input plus an identical generator
version produce identical bytes — UTF-8, LF, no BOM, one rule per line, final
newline, deterministic ordering, and no timestamps inside any `.txt`.

Every release records the exact commit SHA and SHA-256 of each upstream file it
read, so you can fetch the same inputs and check that you get the same output:

```bash
# what a given release was built from
curl -s https://raw.githubusercontent.com/SeanChangX/glinet-cn-direct/release/metadata.json \
  | python -m json.tool

# verify the files you downloaded
sha256sum -c checksums.txt
```

---

## Configuration

Everything that decides routing lives in [`config/`](config/) and is reviewable:

| File | Controls |
| --- | --- |
| `policy.toml` | every safety threshold and network limit |
| `expected-sources.json` | which upstreams may be downloaded at all |
| `never-direct-domains.txt` | domains that must never be routed direct |
| `allowed-tld-rules.txt` | which bare TLD rules are permitted |
| `cn-ip-canaries.txt` | addresses that must be inside the CN set |
| `foreign-ip-canaries.txt` | addresses that must not be |

---

## Design principles

**Prefer predictable and auditable rules over more rules.** In this project a
false positive is far more dangerous than a false negative: a false positive
routes traffic you expected to be inside the VPN around it, silently. A false
negative merely sends Chinese traffic through the tunnel, which is slow but
safe. So:

```text
uncertain destination  ->  VPN
```

**One documented authoritative source per rule category.** Unioning many GeoIP
databases maximizes coverage while destroying traceability.

**Fail closed.** If upstream data, parser behavior, coverage or diff metrics look
suspicious, keep the last known-good release and block publication.

---

## Safety

> This project controls routing policy. A malformed or compromised list could
> cause traffic that was expected to use the VPN to bypass it. For this reason,
> generated lists undergo validation, anomaly detection and historical diff
> checks. No third-party routing database can guarantee perfect geolocation
> accuracy.

> This project is not a censorship circumvention service, VPN provider, GL.iNet
> project, v2rayN project, V2Ray project, or Xray project.

See [SECURITY.md](SECURITY.md) for the threat model and for how to report a
problem.

---

## IPv6

**IPv4 only in production.** GL.iNet's documentation for this VPN filtering
feature lists domains, IPv4 addresses and IPv4 CIDRs; IPv6 support for this
particular parser is not documented and must not be assumed just because an
upstream dataset offers IPv6 ranges.

`experimental/cn-ipv6.txt` is generated for anyone who wants to test it. It is
**EXPERIMENTAL — not included in the default GL.iNet subscription**, is not
merged into `cn-direct.txt`, and is not covered by the production safety gates.

---

## Non-goals

This project is not a firewall, a VPN, a DNS resolver, a GFW detector, an
anonymity product, or a guaranteed GeoIP authority. It generates routing rules
compatible with GL.iNet. That is all.

---

## Credits and licenses

Rule data comes from [`gaoyifan/china-operator-ip`](https://github.com/gaoyifan/china-operator-ip)
(MIT) and [`felixonmars/dnsmasq-china-list`](https://github.com/felixonmars/dnsmasq-china-list)
(WTFPL). See [SOURCES.md](SOURCES.md) for why, and
[THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md) for their license texts.

This project's own code is [MIT](LICENSE) licensed.
