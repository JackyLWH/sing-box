# syntax=docker/dockerfile:1
FROM golang:1.26.8 AS build
LABEL codex.lab="sb4027-local-133601"
ENV CGO_ENABLED=0 GOTOOLCHAIN=local
WORKDIR /src
COPY sing-box-source.tar.gz initial1200.patch ./
RUN tar -xzf sing-box-source.tar.gz
WORKDIR /src/sing-box
RUN go build -trimpath -tags with_quic,with_wireguard,with_gvisor -ldflags '-s -w -X github.com/sagernet/sing-box/constant.Version=1.14.3' -o /out/sing-box-stock ./cmd/sing-box
RUN git apply --check --ignore-space-change /src/initial1200.patch && git apply --ignore-space-change /src/initial1200.patch
RUN go build -trimpath -tags with_quic,with_wireguard,with_gvisor -ldflags '-s -w -X github.com/sagernet/sing-box/constant.Version=1.14.3' -o /out/sing-box-fixed ./cmd/sing-box
WORKDIR /src/server
COPY server/ ./
RUN go mod tidy && go build -trimpath -ldflags '-s -w' -o /out/doh3-server .

FROM debian:trixie-slim
LABEL codex.lab="sb4027-local-133601"
RUN apt-get update && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
    python3 iproute2 wireguard-tools tcpdump util-linux openssl ca-certificates \
    && rm -rf /var/lib/apt/lists/*
COPY --from=build /out/ /usr/local/bin/
COPY --from=build /src/server/go.mod /src/server/go.sum /lab/build-info/
COPY runtime/ /lab/runtime/
RUN chmod 0755 /lab/runtime/setup.sh && bash -n /lab/runtime/setup.sh && python3 -m py_compile /lab/runtime/run.py
ENTRYPOINT ["/bin/bash", "/lab/runtime/setup.sh"]
