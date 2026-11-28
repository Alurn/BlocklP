# BlocklP — AbuseIPDB 自動化 IPv4 黑名單

透過 GitHub Actions 每 **6 小時**自動抓取 [AbuseIPDB](https://www.abuseipdb.com/) 高風險惡意 IP，經白名單與保留網段（Bogons）過濾、同日多次抓取聯集累加（突破單次 10,000 筆限制），以及跨日視窗聚合後發布。

所有輸出清單皆為 **IPv4 格式（每行單一 `A.B.C.D`、不含任何 `#` 註解與 CIDR 合併）**，可直接供嚴格解析器的防火牆、WAF 或外部動態清單（EDL / Alias）訂閱使用。

## 清單狀態統計

<!-- STATS:START -->
> 最後更新時間：`2026-11-28 08:12:31 UTC`

| 清單檔案 | 時間視窗 | 有效 IP 筆數 | 適用場景 |
| :--- | :--- | ---: | :--- |
| `blocklist-1d.ipv4` | 近 1 天（2 日歸檔） | **20,705** | 防火牆／WAF 預設防護（低誤擋） |
| `blocklist-7d.ipv4` | 近 7 天累積 | **43,843** | 中強度持續性威脅防護 |
| `blocklist-30d.ipv4` | 近 30 天累積 | **57,792** | 高強度防護（需留意誤擋風險） |
<!-- STATS:END -->

## 訂閱連結（GitHub Raw URL）

* **1 天清單**：`https://raw.githubusercontent.com/Alurn/BlocklP/main/blocklist-1d.ipv4`
* **7 天清單**：`https://raw.githubusercontent.com/Alurn/BlocklP/main/blocklist-7d.ipv4`
* **30 天清單**：`https://raw.githubusercontent.com/Alurn/BlocklP/main/blocklist-30d.ipv4`

## 運作機制與設定

1. **排程與配額**：每 6 小時執行一次（`00:26`、`06:26`、`12:26`、`18:26` UTC），每日消耗 4 次免費額度（上限 5 次／天），保留 1 次餘裕；若超過上限收到 `HTTP 429` 將自動跳過，不清空既有清單。
2. **聯集累加**：同日多次抓取結果會於 `db/YYYY-MM-DD.ipv4`（UTC 時區）取聯集並去重，使單日即可累積超過 10,000 筆不重複 IP；超過 30 天的歸檔將自動刪除。
3. **白名單與保留網段**：
   * [config/bogons.ipv4](config/bogons.ipv4)：排除 RFC1918 / IANA 保留與無效網段。
   * [config/whitelist.txt](config/whitelist.txt)：預設排除常用公共 DNS（如 `1.1.1.1`、`8.8.8.8`、`9.9.9.9`、`168.95.1.1`），可自行加入需要放行的 IP 或 CIDR 網段。每次執行 `scripts/aggregate.sh` 時皆會對近 30 天歸檔進行二次過濾，修改白名單後立即生效。
4. **GitHub Actions 設定**：
   * 至儲存庫 **Settings → Secrets and variables → Actions** 新增 `ABUSEIPDB_TOKEN`。
   * 至 **Settings → Actions → General → Workflow permissions** 確認已啟用 **Read and write permissions**。

## 本機測試

```bash
# 1. 設定本機測試用 API Token（.env 已被 .gitignore 忽略）
echo 'ABUSEIPDB_TOKEN=your_api_key_here' > .env

# 2. 抓取並寫入當日 UTC 歸檔（4 小時內重跑會使用 .cache/ 不扣配額）
./scripts/fetch.sh

# 3. 產生 1d / 7d / 30d 清單並更新 README 統計
./scripts/aggregate.sh
```

## 資料來源與合規提醒

* 本清單惡意 IP 情資來源為 [AbuseIPDB](https://www.abuseipdb.com/)。
* **誤擋風險提醒**：動態撥號或共用 NAT IP 可能在數週後重新分配給正常用戶，`blocklist-30d.ipv4` 存在較高誤擋（False Positive）機率，建議一般服務優先採用 `blocklist-1d.ipv4` 或 `blocklist-7d.ipv4`。
