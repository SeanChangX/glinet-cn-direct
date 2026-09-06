[English](README.md) · **繁體中文**

# glinet-cn-direct

**可稽核、fail-closed 的 GL.iNet 路由規則，建構自成熟的上游資料集。**

自動產生給 GL.iNet VPN 政策功能使用的中國大陸直連規則，達成：

```text
中國大陸目的地  ->  直連 / 繞過 VPN
其他所有目的地  ->  留在 VPN 隧道內
```

本專案是獨立的相容性專案，與 GL.iNet、v2rayN、V2Ray、Xray 以及它所取用的任何上游資料
專案**均無隸屬關係**。

---

## 訂閱網址

把其中一個貼進你的 GL.iNet 路由器，設定步驟見下方[設定](#設定)。

| 檔案 | 什麼時候用 | 網址 |
| --- | --- | --- |
| **`cn-ipv4.txt`** *（推薦）* | 想要可預測的 GeoIP 路由 | `https://raw.githubusercontent.com/SeanChangX/glinet-cn-direct/release/cn-ipv4.txt` |
| `cn-direct.txt` *（進階）* | 想要接近 `geoip:cn + geosite:cn` 的行為 | `https://raw.githubusercontent.com/SeanChangX/glinet-cn-direct/release/cn-direct.txt` |
| `cn-domains.txt` *（特殊用途）* | 只要網域規則 | `https://raw.githubusercontent.com/SeanChangX/glinet-cn-direct/release/cn-domains.txt` |

`release` 分支是一個會移動的指標，你的路由器會自動跟隨。
為了稽核，每一次發布也會同時打上不可變的
[GitHub Release](../../releases) 標籤，附帶 checksum 與完整溯源資訊。

> **從 `cn-ipv4.txt` 開始。** 它的語意最清楚、偽陽性風險最低，
> 而且實務上它已經能正確路由絕大多數中國服務 ——
> 見[為什麼只靠 IP 規則通常就夠](#為什麼只靠-ip-規則通常就夠)。

---

## 這跟鏡像一份清單有什麼不同

這個倉庫並不是單純轉發上游檔案。每一次 build 都會：

1. 把每個上游分支解析成**不可變的 commit SHA**，再從釘選了 SHA 的網址下載；
2. 把條目規範化成 GL.iNet 的文法，遇到無法表達的就拒絕，而不是修補；
3. 驗證產出的每一行，只要有一行不過就什麼都不發布；
4. 與上一版發布、以及一份**獨立的第二份上游**比對；
5. 遇到任何異常就阻擋發布 —— 過寬的前綴、保留網段、受保護網域、覆蓋率暴增、
   無法解釋的大量移除；
6. 把 checksum、來源版本、來源檔案的雜湊值都寫進 `metadata.json`。

只要有任何地方看起來不對，**就什麼都不發布，上一版已知良好的清單繼續服務。**
一份過期但正確的清單，比一份新鮮但可疑的清單安全。

而且永遠不會執行上游程式碼：這條管線只下載*資料*，
從不 clone 上游倉庫、也從不執行上游的 build script。

---

## 設定

在 GL.iNet 管理介面：

```text
VPN Dashboard
  -> 編輯你的 tunnel
  -> Target Destination
  -> Exclude Specified Domain / IP List
  -> Subscription URL
```

貼上 `cn-ipv4.txt` 的網址，按 **Detect**，確認偵測到的條目數合理
（見[目前的產出](#目前的產出)），然後套用。

套用後預期的路由行為：

```text
中國大陸 IPv4  ->  本地 WAN
其他 IPv4      ->  VPN 隧道
```

如果改用 `cn-direct.txt`：

```text
中國網域       ->  本地 WAN
中國 IPv4      ->  本地 WAN
其他所有目的地  ->  VPN 隧道
```

---

## 目前的產出

| 產物 | 規則數 | 大小 |
| --- | ---: | ---: |
| `cn-ipv4.txt` | 6,234 個 IPv4 網段 | 95 KiB |
| `cn-domains.txt` | 110,433 個網域 | 1.3 MiB |
| `cn-direct.txt` | 116,667 條規則 | 1.4 MiB |
| `experimental/cn-ipv6.txt` | 3,395 個 IPv6 網段 | 非生產用途 |

IPv4 覆蓋 344,250,112 個位址 —— **整個 IPv4 空間的 8.02%** ——
最寬的單一網段是一個 `/10`。

### 路由器的限制

`cn-ipv4.txt` 很小，任何機型都沒問題。`cn-direct.txt` 超過十一萬行，
能不能順利載入取決於你路由器的記憶體與韌體。
**語法合法並不等於相容性保證**，本專案不宣稱任何普遍相容性。
每一版發布都會在 `metadata.json` 記錄每個檔案的行數與位元組數，
讓你在訂閱前就能自行判斷。

如果 GL.iNet 介面吃不下合併清單，請改用 `cn-ipv4.txt`。

---

## 為什麼只靠 IP 規則通常就夠

GL.iNet 是比對連線的*目的地*，所以只要 DNS 回答落在中國網段裡就足夠了：

```text
bilibili.com
   |  DNS
   v
8.134.50.24
   |
   v
目的地命中某個中國 IPv4 網段
   |
   v
GL.iNet 把這條連線排除出隧道  ->  本地 WAN
```

反過來也一樣：

```text
google.com
   |  DNS
   v
142.250.x.x
   |
   v
不在中國網段集合裡
   |
   v
留在隧道內  ->  VPN 出口
```

網域規則只有在「一個面向中國的服務解析到非中國或 CDN 基礎設施」時才派得上用場。
這就是為什麼 `cn-ipv4.txt` 是預設推薦，而 `cn-direct.txt` 是進階選項。

---

## 與 v2rayN 的語意差異

設計意圖是對齊常見的 v2rayN 白名單設定檔：

```text
v2rayN                        GL.iNet + 本專案
--------------------------    ------------------------------------------
geoip:cn   -> direct          cn-ipv4.txt      -> 繞過隧道
geosite:cn -> direct          cn-domains.txt   -> 繞過隧道
final      -> proxy           任何未命中的目的地留在 Primary Tunnel
```

`cn-ipv4.txt` 建構自 `geoip:cn` 實際解析到的同一份資料。
`cn-domains.txt` 則是 `geosite:cn` 的**近似**；
確切差異列在 [SOURCES.md](SOURCES.md#semantic-mapping-to-the-reference-client)。

**本專案主張的是路由策略對齊，不是規則引擎行為相同。**
GL.iNet 的比對器不是 V2Ray、也不是 Xray。

有兩個後果值得知道：

- **`full:` 會變成後綴比對。** V2Ray 的精確比對條目會被輸出成普通網域行，
  而 GL.iNet 可能也會比對其子網域。這放寬了少數幾條規則。
- **`keyword:` 與 `regexp:` 會被丟棄。** 它們按類型計數並記錄在 `metadata.json`，
  絕不做近似轉換。這類條目的數量若突變，會擋下 build 等待人工檢視。

### 裸 TLD 規則

網域產出中含有六條單一標籤的規則，每一條都會比對一整個頂級網域：

```text
cn            .cn         中國國碼 TLD
xn--fiqs8s    .中国
xn--55qx5d    .公司
xn--io0a7i    .网络
top           .top        通用 TLD，中國註冊局，開放註冊
wang          .wang       通用 TLD，中國註冊局，開放註冊
```

`cn` 是承重結構：上游**沒有任何一條**明確的 `.cn` 條目，因為它完全依賴這條規則，
所以拿掉它等於把整個 `.cn` 送進隧道。

`top` 與 `wang` 是刻意的取捨。它們的註冊局在中國，但開放全球註冊，
所以底下部分非中國的網站會繞過 VPN。保留它們是為了對齊上游的 `geosite:cn` 語意。
想拿掉的話，從 [`config/allowed-tld-rules.txt`](config/allowed-tld-rules.txt)
刪掉那兩行再重新 build 即可。

任何*不在*那個檔案裡的裸 TLD 都會讓 build 失敗。
一條來自被入侵上游的 `com` 會是災難性的，所以它被當成災難來處理。

---

## 從其他訂閱遷移過來

依照這個順序，而且在最後一步之前都不要刪掉舊的訂閱網址。

1. 建置並驗證新的 `cn-ipv4.txt`。
2. 跟你目前的清單比對：
   ```bash
   python scripts/compare-baseline.py --baseline-url <你目前的網址>
   ```
3. 檢視它報告的新增與移除。
4. 把新的 raw 網址貼進 GL.iNet 並按 **Detect**。
5. 確認偵測到的數字合理。
6. 套用規則。
7. 跑下面的[驗證步驟](#驗證你的部署)。
8. 確認中國目的地仍然直連。
9. 確認國外目的地仍然走 VPN。
10. 到這一步才把新網址設為長期訂閱。

**回滾：** 任何一項檢查失敗，就把先前的訂閱網址貼回 GL.iNet 再按一次 Detect。
不需要復原任何其他東西 —— 本專案從不碰你的路由器。

### 一次真實遷移的實測結果

從 `carrnot/china-ip-list` 的 `ipv4.txt` 遷移過來：

| | 舊基準 | 本專案 |
| --- | ---: | ---: |
| 網段數 | 7,833 | 6,234 |
| 位址數 | 357,858,401 | 344,250,112 |

規則數少了 20%，但位址覆蓋只少了 **3.8%**，
因為這裡的上游用更少、更大的 CIDR 表達同一片空間。
產出集合中的每一個位址也都在舊基準裡 —— 它是一個嚴格子集，
所以這次改動只可能把流量推*進* VPN，不可能推出去。
那是安全的方向，理由見[設計原則](#設計原則)。

---

## 驗證你的部署

CI 無法重現你的實體網路，所以這些檢查必須手動做。
請從一台以路由器作為 DNS 伺服器的用戶端執行。

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

> 在 Windows PowerShell 上請明確使用 `curl.exe`。
> 舊版本會把 `curl` 別名成 `Invoke-WebRequest`，行為並不相同。

你要看的是路徑的*形狀*，不是特定的 hop：

```text
中國網站：
  你的電腦 -> 路由器 -> 本地 ISP 上游

國外網站：
  你的電腦 -> 路由器 -> VPN 側的私有 hop -> VPN 出口所在的 ISP
```

中國網站應該在頭一兩個 hop 內就看到延遲很低的本地上游。
國外網站則應該在抵達任何公網之前，先出現你 VPN 對端的私有位址。

不要把確切的公網 IP、中間 hop 或延遲數字當成驗收標準 —— 這些都會合理地變動。

### CI 會自動檢查什麼

每一次 build 都會自動確認：

- 已知的中國大陸位址落在產出集合**內**
  （[`config/cn-ip-canaries.txt`](config/cn-ip-canaries.txt)）；
- 已知的國外位址落在集合**外**
  （[`config/foreign-ip-canaries.txt`](config/foreign-ip-canaries.txt)）；
- 沒有任何規則命中受保護網域
  （[`config/never-direct-domains.txt`](config/never-direct-domains.txt)）；
- 沒有任何保留或特殊用途的 IPv4 網段進入集合；
- 產出的每一行都是合法的 GL.iNet 文法。

每個 canary 都帶有 review date，因為 IP 歸屬不是永久的。

---

## 自己建置

需要 Python 3.11+，而且完全沒有執行期相依 —— 產生器只用標準函式庫。

```bash
python -m glinet_rules build --output dist
python -m glinet_rules validate dist/cn-ipv4.txt
python -m glinet_rules diff dist/ previous/
```

或者不安裝直接跑：

```bash
python scripts/build.py --output dist
```

開發環境：

```bash
python -m venv venv
source venv/Scripts/activate      # Windows: .\venv\Scripts\Activate.ps1
pip install -r requirements-dev.txt
python -m pytest
```

### 重現一次已發布的 build

建置是決定性的：相同的上游輸入加上相同的產生器版本，會產生完全相同的位元組 ——
UTF-8、LF、無 BOM、一行一條規則、結尾有換行、排序固定，
而且任何 `.txt` 裡都沒有時間戳。

每一版發布都記錄了它讀取的每個上游檔案的確切 commit SHA 與 SHA-256，
所以任何人都能抓同樣的輸入、確認自己得到同樣的輸出：

```bash
# 查看某一版是從什麼建置出來的
curl -s https://raw.githubusercontent.com/SeanChangX/glinet-cn-direct/release/metadata.json \
  | python -m json.tool

# 驗證你下載到的檔案
sha256sum -c checksums.txt
```

---

## 設定檔

所有決定路由行為的東西都在 [`config/`](config/) 裡，而且都是可審閱的：

| 檔案 | 控制什麼 |
| --- | --- |
| `policy.toml` | 所有安全閾值與網段限制 |
| `expected-sources.json` | 允許被下載的上游來源 |
| `never-direct-domains.txt` | 絕不可直連的網域 |
| `allowed-tld-rules.txt` | 允許哪些裸 TLD 規則 |
| `cn-ip-canaries.txt` | 必須落在中國集合內的位址 |
| `foreign-ip-canaries.txt` | 必須落在集合外的位址 |

---

## 設計原則

**寧可規則可預測、可稽核，也不要規則多。**
在這個專案裡，偽陽性遠比偽陰性危險：偽陽性會**靜默地**把你以為在 VPN 裡的流量
移出 VPN；偽陰性只是把中國流量送進隧道，慢但安全。所以：

```text
不確定的目的地  ->  走 VPN
```

**每個規則類別只用一個有文件記載的權威來源。**
聯集多個 GeoIP 資料庫可以最大化覆蓋率，代價是徹底摧毀可追溯性。

**Fail closed。** 只要上游資料、解析行為、覆蓋率或 diff 指標看起來可疑，
就保留上一版已知良好的發布並阻擋發布。

---

## 安全性

> 本專案控制路由策略。一份格式錯誤或被入侵的清單，可能導致你預期走 VPN 的流量繞過它。
> 因此產出的清單都會經過驗證、異常偵測與歷史 diff 檢查。
> 沒有任何第三方路由資料庫能保證完美的地理定位準確度。

> 本專案不是翻牆服務、不是 VPN 供應商，也不是 GL.iNet、v2rayN、V2Ray 或 Xray 的官方專案。

威脅模型與問題回報方式見 [SECURITY.md](SECURITY.md)。

---

## IPv6

**生產環境只支援 IPv4。** GL.iNet 針對這個 VPN 過濾功能的文件列出的是網域、
IPv4 位址與 IPv4 CIDR；這個特定解析器對 IPv6 的支援沒有文件記載，
不能因為上游資料集提供 IPv6 範圍就逕自假設它支援。

`experimental/cn-ipv6.txt` 是產生給想測試的人用的。它標示為
**EXPERIMENTAL —— 不包含在預設的 GL.iNet 訂閱裡**，
不會被合併進 `cn-direct.txt`，也不受生產安全閘門保護。

---

## 明確的非目標

本專案不是防火牆、不是 VPN、不是 DNS 解析器、不是 GFW 偵測器、不是匿名產品，
也不是有保證的 GeoIP 權威。它只產生與 GL.iNet 相容的路由規則，僅此而已。

---

## 致謝與授權

規則資料來自 [`gaoyifan/china-operator-ip`](https://github.com/gaoyifan/china-operator-ip)
（MIT）與 [`felixonmars/dnsmasq-china-list`](https://github.com/felixonmars/dnsmasq-china-list)
（WTFPL）。選擇理由見 [SOURCES.md](SOURCES.md)，
授權原文見 [THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md)。

本專案自己的程式碼採用 [MIT](LICENSE) 授權。
