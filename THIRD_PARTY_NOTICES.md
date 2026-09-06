# Third-party notices

The rule files published by this project (`dist/`, the `release` branch and
GitHub Release assets) are derived from third-party datasets. Their licenses and
copyright notices are reproduced below, as those licenses require.

This project's own source code is licensed separately; see [LICENSE](LICENSE).

For why each source was selected and exactly which file is consumed, see
[SOURCES.md](SOURCES.md).

---

## gaoyifan/china-operator-ip

Consumed file: `ip-lists/china.txt` (and `ip-lists/china6.txt` for the
experimental IPv6 artifact).
Used to produce: `cn-ipv4.txt`, the IPv4 portion of `cn-direct.txt`, and
`experimental/cn-ipv6.txt`.

Upstream: <https://github.com/gaoyifan/china-operator-ip>

```text
MIT License

Copyright (c) 2017 Yifan Gao

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
```

---

## felixonmars/dnsmasq-china-list

Consumed file: `accelerated-domains.china.conf`.
Used to produce: `cn-domains.txt` and the domain portion of `cn-direct.txt`.

Upstream: <https://github.com/felixonmars/dnsmasq-china-list>

```text
Copyright © 2013 Felix Yan <felixonmars@archlinux.org>
This work is free. You can redistribute it and/or modify it under the
terms of the Do What The Fuck You Want To Public License, Version 2,
as published by Sam Hocevar. See below for more details.

            DO WHAT THE FUCK YOU WANT TO PUBLIC LICENSE
                    Version 2, December 2004

 Copyright (C) 2004 Sam Hocevar <sam@hocevar.net>

 Everyone is permitted to copy and distribute verbatim or modified
 copies of this license document, and changing it is allowed as long
 as the name is changed.

            DO WHAT THE FUCK YOU WANT TO PUBLIC LICENSE
   TERMS AND CONDITIONS FOR COPYING, DISTRIBUTION AND MODIFICATION

  0. You just DO WHAT THE FUCK YOU WANT TO.
```

---

## Loyalsoldier/v2ray-rules-dat — comparator only, not redistributed

`china-list.txt` from this project is downloaded during a build and compared
against the primary domain source purely to detect anomalies. **None of its
content is merged into, or republished as part of, any artifact this project
produces.** No part of it is redistributed here.

It is listed because the project's routing semantics are deliberately aligned
with the Geo data this project publishes, and because a reader auditing the
build will see it fetched.

Upstream: <https://github.com/Loyalsoldier/v2ray-rules-dat> (GPL-3.0)

Setting `enabled = false` under `[secondary]` in `config/policy.toml` removes
this download from the build entirely.
