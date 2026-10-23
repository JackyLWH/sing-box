# 本機 DoH3 測試伺服器

只監聽 UDP HTTP/3，不提供 HTTP/1.1、HTTP/2 或對外 DNS 轉送。`example.com. IN A` 固定回覆 `192.0.2.123`、TTL 60；同名稱其他類型回覆 NOERROR 空答案，其他名稱回覆 NXDOMAIN。

依賴固定為 sing-box 1.14.3 使用的 `github.com/sagernet/quic-go v0.61.0-sing-box-mod.9`，DNS 解析使用 `github.com/miekg/dns v1.1.72`。需要 Go 1.25.5 或以上及可以下載這些公開模組的建置環境；執行時不需要互聯網。

建置：

```sh
cd server
go mod tidy
CGO_ENABLED=0 go build -trimpath -o doh3-server .
```

產生只供此測試使用的 TLS 憑證，私鑰留在測試工作目錄，勿上傳：

```sh
umask 077
openssl req -x509 -newkey rsa:2048 -sha256 -nodes -days 2 \
  -keyout server.key -out server.crt -subj '/CN=doh.lab.test' \
  -addext 'subjectAltName=DNS:doh.lab.test,IP:192.0.2.1'
```

由上層隔離網路套件在測試 namespace／容器內啟動：

```sh
./doh3-server -addr 192.0.2.1:443 -cert server.crt -key server.key
```

預設伺服器 QUIC 起始 UDP payload 為 1200 bytes，並停用伺服器向上 MTU 探測，以隔離客戶端起始封包問題。可用 `-packet-size` 及 `-disable-pmtud=false` 覆寫。客戶端應信任測試憑證並使用 `doh.lab.test` 作為 TLS server name。
