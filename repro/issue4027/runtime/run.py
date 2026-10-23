#!/usr/bin/env python3
"""Offline sing-box 1.14.3 userspace-WireGuard/DoH3 MTU experiment.

Run only inside the disposable lab container prepared by setup.sh. Generated
WireGuard configuration and unredacted debug output stay in STATE_DIR. Results
contain packet headers, DNS answers, and redacted logs, but no lab private key.
"""
from __future__ import annotations

import datetime as dt
import hashlib
import ipaddress
import json
import os
from pathlib import Path
import signal
import socket
import struct
import subprocess
import sys
import time
import traceback
from typing import Any


STATE = Path(os.environ.get("STATE_DIR", "/run/sb4027-local"))
RESULTS = Path(os.environ.get("RESULTS_DIR", "/results"))
WG_INTERFACE = os.environ.get("WG_INTERFACE", "repro-wg")
H3_PID = os.environ.get("H3_NS_PID", "")
ROOT_VETH = os.environ.get("ROOT_VETH", "")
PEER_VETH = os.environ.get("PEER_VETH", "")
BINARIES = {
    "stock": Path("/usr/local/bin/sing-box-stock"),
    "fixed": Path("/usr/local/bin/sing-box-fixed"),
}
DOMAIN = "example.com"
EXPECTED_ADDRESS = "192.0.2.123"
CLIENT_ADDRESS = "10.77.0.2"
SERVER_ADDRESS = "192.0.2.1"
DNS_PORT = 15353
PRIVATE_VALUES: list[str] = []


def redact(value: str) -> str:
    for private in PRIVATE_VALUES:
        value = value.replace(private, "[REDACTED]")
    return value


def json_write(path: Path, value: Any) -> None:
    path.write_text(json.dumps(value, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")


def command(argv: list[str], timeout: float = 10) -> str:
    completed = subprocess.run(argv, text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=timeout)
    if completed.returncode:
        raise RuntimeError(redact(f"Command failed ({completed.returncode}): {argv!r}\n{completed.stderr}"))
    return completed.stdout


def digest(path: Path) -> str:
    result = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            result.update(chunk)
    return result.hexdigest()


def config() -> dict[str, Any]:
    private = (STATE / "client.key").read_text(encoding="ascii").strip()
    PRIVATE_VALUES.append(private)
    public = (STATE / "server.pub").read_text(encoding="ascii").strip()
    return {
        "log": {"level": "debug", "timestamp": True},
        "dns": {
            "servers": [{
                "type": "h3", "tag": "doh", "server": SERVER_ADDRESS,
                "server_port": 443, "path": "/dns-query", "method": "POST", "detour": "wg",
                "tls": {"enabled": True, "server_name": "doh.lab.test", "certificate_path": str(STATE / "server.crt")},
            }],
            "final": "doh", "disable_cache": True, "timeout": "5s",
        },
        "inbounds": [{
            "type": "direct", "tag": "dns-in", "listen": "127.0.0.1", "listen_port": DNS_PORT,
            "network": "udp",
        }],
        "outbounds": [{"type": "direct", "tag": "direct", "bind_interface": "lo"}],
        "endpoints": [{
            "type": "wireguard", "tag": "wg", "system": False, "mtu": 1408,
            "address": [f"{CLIENT_ADDRESS}/24"], "private_key": private, "bind_interface": "lo",
            "peers": [{
                "address": "127.0.0.1", "port": 51820, "public_key": public,
                # Include ICMP router sources as well as the H3 server.
                "allowed_ips": ["0.0.0.0/0"],
            }],
        }],
        "route": {"rules": [{"inbound": ["dns-in"], "action": "hijack-dns"}], "final": "direct"},
    }


def set_mtu(mtu: int) -> None:
    if not (H3_PID.isdecimal() and ROOT_VETH and PEER_VETH):
        raise RuntimeError("setup.sh must export H3_NS_PID, ROOT_VETH and PEER_VETH")
    command(["ip", "link", "set", "dev", ROOT_VETH, "mtu", str(mtu)])
    command(["nsenter", "-t", H3_PID, "-n", "ip", "link", "set", "dev", PEER_VETH, "mtu", str(mtu)])
    # Replace the two lab-only host routes via netlink. Unlike `ip route flush
    # cache`, this works with Docker's read-only /proc/sys mount and keeps all
    # changes inside these disposable namespaces.
    command(["ip", "route", "replace", f"{SERVER_ADDRESS}/32", "dev", ROOT_VETH,
             "src", "192.0.2.254", "mtu", str(mtu)])
    command(["nsenter", "-t", H3_PID, "-n", "ip", "route", "replace",
             f"{CLIENT_ADDRESS}/32", "via", "192.0.2.254", "dev", PEER_VETH,
             "mtu", str(mtu)])


def dns_query(ident: int) -> bytes:
    qname = b"".join(bytes([len(label)]) + label.encode("ascii") for label in DOMAIN.split(".")) + b"\0"
    return struct.pack("!HHHHHH", ident, 0x0100, 1, 0, 0, 0) + qname + struct.pack("!HH", 1, 1)


def read_name(packet: bytes, offset: int) -> tuple[str, int]:
    labels: list[str] = []
    resume: int | None = None
    visited: set[int] = set()
    while True:
        if offset >= len(packet) or offset in visited:
            raise ValueError("Truncated or cyclic DNS name")
        visited.add(offset)
        length = packet[offset]
        if length & 0xC0 == 0xC0:
            if offset + 1 >= len(packet):
                raise ValueError("Truncated DNS pointer")
            if resume is None:
                resume = offset + 2
            offset = ((length & 0x3F) << 8) | packet[offset + 1]
            continue
        if length & 0xC0:
            raise ValueError("Unsupported DNS label")
        offset += 1
        if length == 0:
            return ".".join(labels).lower(), resume if resume is not None else offset
        if offset + length > len(packet):
            raise ValueError("Truncated DNS label")
        labels.append(packet[offset:offset + length].decode("ascii"))
        offset += length


def parse_dns(packet: bytes, ident: int) -> dict[str, Any]:
    if len(packet) < 12:
        raise ValueError("Truncated DNS response")
    received_id, flags, qd, an, ns, ar = struct.unpack_from("!HHHHHH", packet)
    if received_id != ident or not flags & 0x8000:
        raise ValueError("DNS response ID/QR mismatch")
    offset = 12
    for _ in range(qd):
        _, offset = read_name(packet, offset)
        offset += 4
    answers = []
    for _ in range(an):
        name, offset = read_name(packet, offset)
        rtype, rclass, ttl, length = struct.unpack_from("!HHIH", packet, offset)
        offset += 10
        rdata = packet[offset:offset + length]
        if len(rdata) != length:
            raise ValueError("Truncated DNS answer")
        if rtype == 1 and rclass == 1 and length == 4:
            answers.append({"name": name, "type": "A", "address": socket.inet_ntop(socket.AF_INET, rdata), "ttl": ttl})
        offset += length
    rcode = flags & 15
    return {
        "rcode": rcode, "rcode_name": {0: "NOERROR", 2: "SERVFAIL", 3: "NXDOMAIN"}.get(rcode, str(rcode)),
        "answers": answers, "response_bytes": len(packet),
        "query_success": rcode == 0 and any(a["name"] == DOMAIN and a["address"] == EXPECTED_ADDRESS for a in answers),
    }


def query(ident: int) -> dict[str, Any]:
    started = time.monotonic()
    result: dict[str, Any] = {"query_success": False, "rcode": None, "answers": []}
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as client:
        client.settimeout(8)
        try:
            client.sendto(dns_query(ident), ("127.0.0.1", DNS_PORT))
            packet, source = client.recvfrom(65535)
            result.update(parse_dns(packet, ident))
            result["response_source"] = list(source)
            if not result["query_success"]:
                result["failure_kind"] = "dns_error_or_unexpected_answer"
        except socket.timeout:
            result.update(failure_kind="udp_dns_timeout", error="No DNS response within 8 seconds")
        except (OSError, ValueError, struct.error) as error:
            result.update(failure_kind=type(error).__name__, error=redact(str(error)))
    result["query_seconds"] = round(time.monotonic() - started, 6)
    return result


def stop_child(child: subprocess.Popen[Any] | None, sig: int = signal.SIGTERM) -> None:
    if child is None or child.poll() is not None:
        return
    child.send_signal(sig)
    try:
        child.wait(timeout=3)
    except subprocess.TimeoutExpired:
        child.kill()
        child.wait(timeout=3)


def ipv4(packet: bytes) -> dict[str, Any] | None:
    if len(packet) < 20 or packet[0] >> 4 != 4:
        return None
    ihl = (packet[0] & 15) * 4
    if ihl < 20 or len(packet) < ihl:
        return None
    total, ident, fragment = struct.unpack_from("!HHH", packet, 2)
    result: dict[str, Any] = {
        "source": str(ipaddress.IPv4Address(packet[12:16])),
        "destination": str(ipaddress.IPv4Address(packet[16:20])),
        "ip_bytes": total, "ip_header_bytes": ihl, "ip_id": ident,
        "df": bool(fragment & 0x4000), "more_fragments": bool(fragment & 0x2000),
        "fragment_offset": (fragment & 0x1FFF) * 8, "protocol": packet[9],
    }
    payload = packet[ihl:]
    if packet[9] == 17 and len(payload) >= 8 and not fragment & 0x1FFF:
        sport, dport, length = struct.unpack_from("!HHH", payload)
        result.update(source_port=sport, destination_port=dport, udp_bytes=length, udp_payload_bytes=max(0, length - 8))
    elif packet[9] == 1 and len(payload) >= 8:
        result.update(icmp_type=payload[0], icmp_code=payload[1])
        if payload[0:2] == b"\x03\x04":
            result["next_hop_mtu"] = struct.unpack_from("!H", payload, 6)[0]
        quote = ipv4(payload[8:])
        if quote is not None:
            result["quoted_packet"] = quote
    return result


def parse_pcap(path: Path) -> dict[str, Any]:
    packets: list[dict[str, Any]] = []
    errors: list[str] = []
    with path.open("rb") as stream:
        header = stream.read(24)
        if len(header) != 24:
            return {"error": "Missing pcap header", "packets": []}
        magic = header[:4]
        if magic in (b"\xd4\xc3\xb2\xa1", b"\x4d\x3c\xb2\xa1"):
            order = "<"
        elif magic in (b"\xa1\xb2\xc3\xd4", b"\xa1\xb2\x3c\x4d"):
            order = ">"
        else:
            return {"error": f"Unsupported capture magic {magic.hex()}", "packets": []}
        link_type = struct.unpack_from(order + "I", header, 20)[0] & 0xFFFF
        while record := stream.read(16):
            if len(record) != 16:
                errors.append("Truncated pcap record header")
                break
            seconds, fraction, captured, original = struct.unpack(order + "IIII", record)
            frame = stream.read(captured)
            if len(frame) != captured:
                errors.append("Truncated pcap frame")
                break
            if link_type in (12, 101, 228):
                raw = frame
            elif link_type == 1 and len(frame) >= 14:
                offset = 14
                protocol = struct.unpack_from("!H", frame, 12)[0]
                while protocol in (0x8100, 0x88A8) and len(frame) >= offset + 4:
                    protocol = struct.unpack_from("!H", frame, offset + 2)[0]
                    offset += 4
                if protocol != 0x0800:
                    continue
                raw = frame[offset:]
            elif link_type == 113 and len(frame) >= 16:
                if frame[14:16] != b"\x08\x00":
                    continue
                raw = frame[16:]
            elif link_type == 276 and len(frame) >= 20:
                if frame[:2] != b"\x08\x00":
                    continue
                raw = frame[20:]
            elif link_type in (0, 108) and len(frame) >= 4:
                raw = frame[4:]
            else:
                errors.append(f"Unsupported link type {link_type}")
                break
            parsed = ipv4(raw)
            if parsed is not None:
                parsed.update(timestamp_seconds=seconds, timestamp_fraction=fraction)
                packets.append(parsed)
    outbound = [p for p in packets if p.get("source") == CLIENT_ADDRESS and p.get("destination") == SERVER_ADDRESS and p.get("destination_port") == 443]
    incoming = [p for p in packets if p.get("source") == SERVER_ADDRESS and p.get("source_port") == 443]
    ptbs = [p for p in packets if p.get("icmp_type") == 3 and p.get("icmp_code") == 4]
    return {
        "link_type": link_type, "ipv4_packet_count": len(packets), "outbound_udp443_count": len(outbound),
        "inbound_udp443_count": len(incoming), "icmp_packet_too_big_count": len(ptbs),
        "first_outbound_udp443": outbound[0] if outbound else None,
        "outbound_udp_payload_sizes": sorted({p["udp_payload_bytes"] for p in outbound}),
        "outbound_ip_sizes": sorted({p["ip_bytes"] for p in outbound}),
        "icmp_packet_too_big": ptbs[:20], "errors": errors,
    }


def run_sample(binary: str, mtu: int, index: int, expected_success: bool, ordinal: int) -> dict[str, Any]:
    name = f"mtu{mtu}-{binary}-{index:02d}"
    result: dict[str, Any] = {
        "case": name, "binary": binary, "path_mtu": mtu, "wireguard_mtu": 1408,
        "expected_success": expected_success, "cold_start": True, "query_success": False,
    }
    started = time.monotonic()
    raw_log = STATE / f"{name}.log"
    config_path = STATE / "client.json"
    capture_path = RESULTS / f"{name}.pcap"
    process: subprocess.Popen[Any] | None = None
    capture: subprocess.Popen[Any] | None = None
    try:
        set_mtu(mtu)
        with raw_log.open("wb") as log, (RESULTS / f"{name}.tcpdump.log").open("wb") as caplog:
            capture = subprocess.Popen(
                ["tcpdump", "--immediate-mode", "-U", "-n", "-s", "0", "-i", WG_INTERFACE, "-w", str(capture_path), "ip"],
                stdout=subprocess.DEVNULL, stderr=caplog,
            )
            time.sleep(0.2)
            if capture.poll() is not None:
                raise RuntimeError("tcpdump exited before the sample started")
            process = subprocess.Popen(
                [str(BINARIES[binary]), "run", "-c", str(config_path)],
                stdout=log, stderr=subprocess.STDOUT,
            )
            startup_deadline = time.monotonic() + 3
            while time.monotonic() < startup_deadline:
                if process.poll() is not None:
                    raise RuntimeError(f"sing-box exited during startup: status {process.returncode}")
                if b"sing-box started" in raw_log.read_bytes():
                    break
                time.sleep(0.05)
            else:
                raise RuntimeError("sing-box did not report startup within 3 seconds")
            result.update(query(0x4027 + ordinal))
            time.sleep(0.15)
    except Exception as error:
        result.update(error=redact(str(error)), failure_kind="sample_harness_error")
    finally:
        stop_child(process)
        stop_child(capture, signal.SIGINT)
        if raw_log.exists():
            clean_log = redact(raw_log.read_text(encoding="utf-8", errors="replace"))
            (RESULTS / f"{name}.sing-box.log").write_text(clean_log, encoding="utf-8")
            result["log_has_timeout"] = "timeout" in clean_log.lower() or "deadline exceeded" in clean_log.lower()
            raw_log.unlink()
        result["process_exit_code"] = process.returncode if process else None
        result["capture_exit_code"] = capture.returncode if capture else None
        if capture_path.exists():
            try:
                result["packet_evidence"] = parse_pcap(capture_path)
            except Exception as error:
                result["packet_evidence"] = {"error": redact(str(error))}
        evidence = result.get("packet_evidence", {})
        initial = evidence.get("first_outbound_udp443") or {}
        wanted_payload = 1200 if binary == "fixed" else 1280
        result["expected_match"] = (
            result.get("query_success", False) == expected_success
            and result.get("failure_kind") != "sample_harness_error"
        )
        result["initial_size_matches_expected"] = initial.get("udp_payload_bytes") == wanted_payload
        if mtu == 1290 and binary == "stock":
            ptbs = evidence.get("icmp_packet_too_big", [])
            result["received_matching_mtu_feedback"] = any(
                p.get("next_hop_mtu") == 1290
                and p.get("destination") == CLIENT_ADDRESS
                and p.get("quoted_packet", {}).get("source") == CLIENT_ADDRESS
                and p.get("quoted_packet", {}).get("destination") == SERVER_ADDRESS
                and p.get("quoted_packet", {}).get("destination_port") == 443
                and p.get("quoted_packet", {}).get("udp_payload_bytes") == 1280
                and p.get("quoted_packet", {}).get("source_port") == initial.get("source_port")
                and initial.get("df") is True
                and initial.get("ip_bytes") == 1308
                for p in ptbs
            )
        result["sample_seconds"] = round(time.monotonic() - started, 6)
        json_write(RESULTS / f"{name}.json", result)
        print(json.dumps({key: result.get(key) for key in ("case", "query_success", "expected_match", "initial_size_matches_expected", "received_matching_mtu_feedback", "query_seconds", "error")}), flush=True)
    return result


def main() -> int:
    def interrupted(signum: int, _frame: Any) -> None:
        raise SystemExit(128 + signum)
    signal.signal(signal.SIGTERM, interrupted)
    RESULTS.mkdir(parents=True, exist_ok=True)
    os.umask(0o077)
    cfg = config()
    config_path = STATE / "client.json"
    config_path.write_text(json.dumps(cfg), encoding="utf-8")
    config_path.chmod(0o600)
    summary: dict[str, Any] = {
        "experiment": "sing-box-1.14.3-offline-userspace-wireguard-doh3-mtu",
        "started_utc": dt.datetime.now(dt.timezone.utc).isoformat(),
        "external_network_required": False, "provider_credentials_required": False,
        "domain": DOMAIN, "expected_A": EXPECTED_ADDRESS,
        "wireguard_interface": WG_INTERFACE, "wireguard_mtu": 1408,
        "stock_initial_udp_payload": 1280, "fixed_initial_udp_payload": 1200,
        "binaries": {}, "samples": [],
    }
    try:
        for name, path in BINARIES.items():
            summary["binaries"][name] = {"sha256": digest(path), "version": command([str(path), "version"]).strip()}
            if "1.14.3" not in summary["binaries"][name]["version"]:
                raise RuntimeError(f"{name} binary is not sing-box 1.14.3")
            command([str(path), "check", "-c", str(config_path)])
        cases = [("stock", 1500, 3, True), ("stock", 1290, 3, False), ("fixed", 1290, 3, True), ("stock", 1500, 1, True)]
        ordinal = 0
        for binary, mtu, repeats, expected in cases:
            for index in range(1, repeats + 1):
                ordinal += 1
                # The final recovery control has a distinct index/file name.
                sample_index = index + 3 if ordinal == 10 else index
                summary["samples"].append(run_sample(binary, mtu, sample_index, expected, ordinal))
                json_write(RESULTS / "summary.json", summary)
        summary["all_expected_outcomes"] = all(s["expected_match"] for s in summary["samples"])
        summary["all_expected_initial_sizes"] = all(s["initial_size_matches_expected"] for s in summary["samples"])
        feedback = [s for s in summary["samples"] if s["binary"] == "stock" and s["path_mtu"] == 1290]
        summary["all_bottleneck_failures_have_correct_icmp_feedback"] = all(s.get("received_matching_mtu_feedback", False) for s in feedback)
        summary["passed"] = all(summary[key] for key in (
            "all_expected_outcomes", "all_expected_initial_sizes", "all_bottleneck_failures_have_correct_icmp_feedback",
        ))
    except Exception as error:
        summary.update(passed=False, fatal_error=redact(str(error)), traceback=redact(traceback.format_exc()))
    finally:
        # setup.sh handles the disposable namespaces/interfaces and all ephemeral keys.
        config_path.unlink(missing_ok=True)
        summary["completed_utc"] = dt.datetime.now(dt.timezone.utc).isoformat()
        json_write(RESULTS / "summary.json", summary)
        lines = [
            "sing-box 1.14.3 完全本機 DoH3 / userspace WireGuard MTU 重現結果",
            "",
            "測試無需 Surfshark 帳戶、外部 DNS 或外部網路。",
            "WireGuard 1408；本機 H3 回覆 example.com A 192.0.2.123。",
            "stock 預期 QUIC UDP payload 1280 / IPv4 1308；fixed 預期 1200 / 1228。",
            "",
        ]
        for sample in summary["samples"]:
            lines.append(f"{sample['case']}: DNS成功={sample['query_success']}，符合預期={sample['expected_match']}，初始尺寸符合={sample['initial_size_matches_expected']}")
        lines.extend(["", f"整體驗證通過：{summary.get('passed', False)}", "詳細版本、SHA-256、封包尺寸及 ICMP 引用來源請看 summary.json 與各樣本 JSON。", "pcap 為實驗內層明文流量；全部位址、DNS 問題及回覆均為合成測試資料。", "結果不包含 WireGuard 私鑰或生成的 sing-box 設定。"])
        (RESULTS / "RESULTS.txt").write_text("\n".join(lines) + "\n", encoding="utf-8")
    return 0 if summary.get("passed") else 1


if __name__ == "__main__":
    sys.exit(main())
