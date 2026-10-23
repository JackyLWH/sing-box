# sing-box 1.14.3：完全本機 DoH3／WireGuard MTU 重現

本套件用本機 WireGuard 與固定答案的 HTTP/3 DNS server，檢查 QUIC 起始封包超出路徑 MTU 時，userspace WireGuard 的 DoH3 連線是否逾時。**不需要 Surfshark 帳戶、既有私鑰、外部 DNS 或執行期間的互聯網連線。** 實際結果以執行後的 `results/summary.json` 為準。

本套件於 Debian／Linux amd64 實測，10 個樣本全部符合預期，原始結果保留在 `evidence/`。原版 MTU1500 成功 4/4（含恢復控制）、原版 MTU1290 成功 0/3、修補版 MTU1290 成功 3/3；三個失敗樣本共30個ICMP引用地址與port皆正確。失敗指查詢器等待8秒沒有收到回覆，未等到QUIC自身握手終止。修補版握手後仍可能有較大的MTU probe被拒，DNS已先成功。

## 需求與執行

- Linux Docker host，核心支援 WireGuard、veth 與 network namespace。
- 可以執行 Docker 的使用者；測試容器需要 `NET_ADMIN`、`SYS_ADMIN` capabilities，安全設定須允許 `unshare`／`nsenter`。
- 建置需要網路下載 Go／Debian 基底映像、套件及公開 Go modules。測試以 `--network none` 執行，所有測試連線留在容器內。

解壓後進入含有 `run.sh` 的目錄執行：

```sh
bash run.sh
```

腳本會建置映像、啟動一次性容器，將結果寫入 `results/`。若該目錄已有內容，會拒絕覆用；再次執行前先將舊結果搬到另一個目錄。**結束碼 0 表示全部預期結果及封包檢查符合，包含預期的逾時案例；不代表每次 DNS 查詢都成功。** 非 0 請查看 `results/summary.json`、各樣本日誌及 Docker 輸出。

## 隔離拓撲

```text
Docker 容器：--network none
  sing-box userspace WG（10.77.0.2，WG MTU 1408）
       │ 外層 WireGuard UDP，僅經容器 loopback
       ▼
  核心 WG server（10.77.0.1，WG MTU 1408）
       │ 轉送解密後 IPv4 封包
       ▼
  veth（192.0.2.254；MTU 1500 或 1290）
       │
       ▼ 獨立 child network namespace
  veth（192.0.2.1；同一 MTU）→ HTTP/3 DNS :443
```

每輪自動產生測試用 WireGuard 與 TLS 金鑰。DoH3 server 只回覆本地合成資料：`example.com A 192.0.2.123`、TTL 60，不轉送查詢。server 固定 QUIC 起始 UDP payload 1200 bytes 並停用向上 MTU 探測，以隔離客戶端起始封包的影響。

兩個客戶端均由 sing-box 1.14.3 原始碼 commit `7054cac5124465ffdb145870d7c01885566711b1` 建置，使用相同 Go 與 `with_quic,with_wireguard,with_gvisor` tags。`stock` 沒有修補；`fixed` 只在 DNS HTTP/3 Dial callback 加入 `initial1200.patch` 的兩行：

```go
cfg = cfg.Clone()
cfg.InitialPacketSize = 1200
```

## 預期結果與證據

每個樣本重新啟動 sing-box，關閉 DNS cache；固定 WG MTU 1408，只改 WG 出口後的 veth MTU。

| 順序 | 客戶端 | 出口後 MTU | 次數 | 預期 DNS 結果 |
|---|---|---:|---:|---|
| 1 | stock | 1500 | 3 | 成功 |
| 2 | stock | 1290 | 3 | 逾時／失敗 |
| 3 | fixed | 1290 | 3 | 成功 |
| 4 | stock | 1500 | 1 | 恢復成功 |

`stock` 起始 UDP payload 1280 加上 IPv4／UDP 標頭後為 **1308 bytes**，超出 MTU 1290；`fixed` 為 1200 + 28 = **1228 bytes**。腳本另檢查實際起始尺寸，以及瓶頸失敗案例的 ICMP type 3/code 4、MTU 1290、引用來源／目的 IP 與 UDP port 是否正確。

- `results/RESULTS.txt`：簡要結果。
- `results/summary.json`、各樣本 `.json`：版本、binary SHA-256、答案、封包與 ICMP 證據。
- 各樣本 `.pcap`、`.sing-box.log`、`h3-server.log`：合成測試流量及日誌。結果不包含 WG 私鑰或產生的 sing-box 設定。

PCAP 在核心 WG server 介面擷取內層流量，可證明正確的 ICMP 回報已送入 WG 回程；**不等同在 sing-box／gVisor 函式內追蹤到錯誤處理。** 此案例不模擬 Surfshark 曾出現的 ICMP 引用來源地址異常，也不證明原 issue 每一種失敗均有相同原因。

## 清理

正常完成或收到終止訊號時，容器腳本會清理自己建立的介面、子程序與臨時金鑰，Docker `--rm` 會刪除容器。結果保留於主機 `results/`；正式 sing-box 不參與本測試。

Docker 映像、建置快取及可能由核心自動載入的 WireGuard／veth 模組不會由通用腳本全域清除。不要在有其他 Docker 工作的主機直接全域 prune。需要刪除本套件映像時可執行：

```sh
docker image rm sb4027-local-133601:repro
```

基底映像與快取按主機既有用途另行處理；核心模組只有在確認測試前未載入、且目前沒有其他使用者時才應卸載。若強制終止 Docker 或主機，請先確認 `sb4027-local-133601-run` 容器已停止並移除。
