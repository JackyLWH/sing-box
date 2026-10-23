# Offline DoH3 / WireGuard low-MTU reproducer

No Surfshark account, existing VPN keys, external DNS server or runtime Internet connection is required. The container generates temporary WireGuard/TLS keys and returns only `example.com A 192.0.2.123`.

Tested on Debian Linux/amd64 with sing-box **1.14.3**: all 10 expected outcomes and packet assertions passed. See `evidence/summary.json` and the accompanying pcaps/logs.

## Run

Requires a Linux Docker host with kernel WireGuard, veth and network namespace support. The disposable container uses `NET_ADMIN` and `SYS_ADMIN`; its security profile must allow `unshare`/`nsenter`. Docker Desktop has not been validated.

```sh
bash run.sh
```

Building downloads public Go/Debian images, packages and Go modules. The actual experiment runs with `--network none` and has no connection to the Docker host network or the Internet. A synthetic default route terminates at the local server namespace so sing-box's interface monitor can operate.

Results are written to `results/`. A non-empty directory is rejected: move previous results before rerunning. Exit 0 means every **expected** outcome and packet assertion matched, including intentional failures.

## Topology and controls

```text
One network-none Docker container
  sing-box userspace WG client 10.77.0.2
    -> outer WG UDP over container loopback
    -> kernel WG server 10.77.0.1 (WG MTU 1408)
    -> veth router 192.0.2.254 (MTU 1500 or 1290)
    -> child network namespace: local HTTP/3 DNS 192.0.2.1:443
```

Both clients are built from sing-box commit `7054cac5124465ffdb145870d7c01885566711b1` (1.14.3), using Go 1.26.8, identical dependencies and `with_quic,with_wireguard,with_gvisor`. The patched binary adds only:

```go
cfg = cfg.Clone()
cfg.InitialPacketSize = 1200
```

The H3 server starts at 1200-byte UDP payload and disables its own PMTU probing to control return-path packet sizes. Client PMTU probing remains enabled. DNS caching is disabled and each sample starts a fresh client process.

| Client / downstream MTU | Expected result | Measured successes |
|---|---|---:|
| Unpatched / 1500 | success | 3/3 |
| Unpatched / 1290 | no DNS reply within 8 seconds | 0/3 |
| Patched / 1290 | success | 3/3 |
| Unpatched / restored 1500 | recovery success | 1/1 |

The initial UDP/IP sizes are 1280/1308 bytes unpatched and 1200/1228 patched, with DF set. Failed samples captured 30 ICMP fragmentation-needed messages advertising MTU 1290, with matching addresses and per-run UDP ports. There is no NAT or provider-specific ICMP quote rewriting.

`summary.json`, per-sample JSON, pcaps and logs contain synthetic traffic and answers, not generated private keys/configuration. `SOURCE.txt` records source checksums; the source archive includes upstream licenses.

## Scope and cleanup

Failure means the harness observed no DNS reply within 8 seconds, then stopped its own client; it did not wait for quic-go's terminal handshake timeout. Captures are on the kernel WG server: they show correct ICMP entering the return tunnel, not a gVisor function trace. Patched clients may still receive ICMP for later oversized PMTU probes after DNS has already succeeded.

This reproduces the initial-size/handshake problem without Surfshark. It does not reproduce the provider's mismatched ICMP quotes or establish that every symptom of #4027 has the same cause. IPv6, other platforms and performance are untested.

Normal completion or termination cleans up owned interfaces, child processes and temporary keys; Docker `--rm` removes the container. Results remain on the host. No production sing-box service is involved.

The generic runner retains its image/build cache and any kernel modules auto-loaded by the host. Remove the image with `docker image rm sb4027-local-133601:repro` if desired. Do not run a global prune or unload modules used by other workloads. For this investigation, all experiment resources were separately removed and verified against the host baseline.
