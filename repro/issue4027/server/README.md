# Deterministic local HTTP/3 DNS server

This server has no TCP listener and never forwards DNS queries. It returns `example.com A 192.0.2.123`, TTL 60; unknown names receive NXDOMAIN.

The main Dockerfile builds it with pinned quic-go and DNS dependencies. For a separate build:

```sh
go mod tidy
CGO_ENABLED=0 go build -trimpath -o doh3-server .
./doh3-server -addr 192.0.2.1:443 -cert server.crt -key server-tls.key
```

Use a certificate with SAN `doh.lab.test` (and optionally `192.0.2.1`); the client trusts that generated certificate explicitly. The main setup creates it automatically.

Server QUIC defaults are `-packet-size 1200 -disable-pmtud=true`. These control the return path so only the client's initial-size difference is tested. The server exposes `/dns-query` over HTTP/3 and validates standard DNS GET/POST requests.
