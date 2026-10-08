[English](README.md) · **繁體中文**

# glinet-cn-direct

[![build](https://img.shields.io/github/actions/workflow/status/SeanChangX/glinet-cn-direct/release.yml?label=build)](https://github.com/SeanChangX/glinet-cn-direct/actions/workflows/release.yml)
[![release](https://img.shields.io/github/v/release/SeanChangX/glinet-cn-direct?label=release)](https://github.com/SeanChangX/glinet-cn-direct/releases/latest)
[![license](https://img.shields.io/github/license/SeanChangX/glinet-cn-direct)](LICENSE)

用於 VPN 分流的中國大陸 IP 與網域清單。每天根據成熟的上游資料集重新建置，並且只在自動安全檢查全部通過後才發布。

清單格式以 GL.iNet 的 VPN 政策功能為主，但因為是一行一條規則的純文字，其他接受 CIDR 或網域清單的路由器與工具也能使用。

```text
中國大陸目的地  ->  直連
其他所有目的地  ->  VPN 隧道
```

## 檔案

| 檔案 | 內容 | 大小 |
| --- | --- | --- |
| `cn-ipv4.txt` | 中國大陸 IPv4 網段（CIDR）—— **推薦** | 約 6,200 行，約 95 KiB |
| `cn-domains.txt` | 中國大陸網域 | 約 110,000 行，約 1.3 MiB |
| `cn-direct.txt` | `cn-domains.txt` 接著 `cn-ipv4.txt` | 約 117,000 行，約 1.4 MiB |
| `checksums.txt` | 三份清單的 SHA-256 | |
| `metadata.json` | 上游版本、各檔案條目數與驗證結果 | |

每一次建置的確切數字都記錄在該版的 `metadata.json`。

## 下載

每個檔案都有兩種網址，內容完全相同，也都永遠指向最新一次建置。

**Release 附檔**

```text
https://github.com/SeanChangX/glinet-cn-direct/releases/latest/download/cn-ipv4.txt
https://github.com/SeanChangX/glinet-cn-direct/releases/latest/download/cn-domains.txt
https://github.com/SeanChangX/glinet-cn-direct/releases/latest/download/cn-direct.txt
```

**`release` 分支上的 Raw 檔案**

```text
https://raw.githubusercontent.com/SeanChangX/glinet-cn-direct/release/cn-ipv4.txt
https://raw.githubusercontent.com/SeanChangX/glinet-cn-direct/release/cn-domains.txt
https://raw.githubusercontent.com/SeanChangX/glinet-cn-direct/release/cn-direct.txt
```

路由器通常是透過自己的 WAN 下載訂閱清單，而不是經由 VPN。從中國大陸的網路連 `raw.githubusercontent.com` 經常連不上；Release 附檔網址通常比較穩定，但兩者都沒有保證。

歷次建置都保留在 [GitHub Releases](https://github.com/SeanChangX/glinet-cn-direct/releases)。

## 使用方式

### GL.iNet

1. 打開 **VPN Dashboard**，編輯隧道，進入 **Target Destination**。
2. 選擇 **Exclude Specified Domain / IP List**，模式設為 **Subscription URL**。
3. 填入 `cn-ipv4.txt` 的網址，按 **Detect**，確認偵測到的數量合理後套用。

清單裡的目的地會走本地 WAN，其他流量留在隧道內。`cn-direct.txt` 另外加入網域規則，涵蓋那些解析到非中國基礎設施的中國服務。它的大小約是 `cn-ipv4.txt` 的十五倍，部分機型可能載入不了。

### 其他路由器與工具

- `cn-ipv4.txt` 每行一個 CIDR，可以用來填入 ipset、nftables set，或任何接受 CIDR 清單的政策路由設定。
- `cn-domains.txt` 的每一行，設計上要比對該網域及其所有子網域。清單中有六條裸頂級網域規則（例如 `cn`），會比對整個頂級網域；請確認你的工具如何處理單一標籤的條目。
- 所有檔案都是 UTF-8、LF 換行、一行一條規則、不含註解。

IPv6 不在正式清單之內。實驗性的 `experimental/cn-ipv6.txt` 發布在 `release` 分支上，不受安全檢查保護。

## 運作方式

GitHub Actions 排程每天重新建置清單，內容有變動時才發布新的 release。

- **來源：** IPv4 來自 [`gaoyifan/china-operator-ip`](https://github.com/gaoyifan/china-operator-ip)，與 V2Ray 生態系中 `geoip:cn` 使用的是同一份資料。網域來自 [`felixonmars/dnsmasq-china-list`](https://github.com/felixonmars/dnsmasq-china-list)。每次建置都會把兩者釘選到特定 commit SHA。詳見 [SOURCES.md](SOURCES.md)。
- **驗證：** 每一行都必須是合法的網域、IPv4 位址或 IPv4 CIDR。
- **安全檢查：** 只要出現過寬的前綴或保留網段、命中受保護的國外網域、把已知位址判錯、與獨立的第二來源不一致，或相對上一版變動過大，該次建置就會被拒絕。
- **失敗即不發布（fail closed）：** 任何一項檢查失敗都不會發布，上一版維持不變。
- **可重現：** 輸出是決定性的，每個 release 都記錄了它所依據的上游版本與檔案雜湊值。

閾值與政策設定在 [`config/`](config/)。

## 從原始碼建置

需要 Python 3.11 以上。產生器沒有任何執行期相依套件。

```bash
python -m glinet_rules build --output dist
python -m glinet_rules validate dist/cn-ipv4.txt dist/cn-domains.txt dist/cn-direct.txt
```

開發環境：

```bash
python -m venv venv
source venv/bin/activate        # Windows: venv\Scripts\activate
pip install -r requirements-dev.txt -e .
python -m pytest
```

## 參與貢獻

歡迎提交 issue 與 pull request。開始之前請先閱讀 [CONTRIBUTING.md](CONTRIBUTING.md)，特別是關於產出檔案與安全閾值的規定。

## 安全性

如果發現安全問題，請透過 [私密漏洞回報](https://github.com/SeanChangX/glinet-cn-direct/security/advisories/new) 告知，不要開公開 issue。威脅模型與回報流程見 [SECURITY.md](SECURITY.md)。

## 致謝

- [`gaoyifan/china-operator-ip`](https://github.com/gaoyifan/china-operator-ip)：IPv4 資料來源
- [`felixonmars/dnsmasq-china-list`](https://github.com/felixonmars/dnsmasq-china-list)：網域資料來源
- [`Loyalsoldier/v2ray-rules-dat`](https://github.com/Loyalsoldier/v2ray-rules-dat)：作為獨立的交叉比對來源

## 免責聲明

沒有任何地理定位資料是完全準確的，請在自己的網路上確認路由結果。本專案與 GL.iNet、v2rayN、V2Ray、Xray 及任何上游資料專案均無隸屬關係，也不是 VPN 或翻牆服務。

## 授權

程式碼採用 [MIT License](LICENSE)。發布的清單衍生自以 MIT 與 WTFPL 授權的上游資料，詳見 [THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md)。
