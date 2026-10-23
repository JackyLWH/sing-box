#!/bin/bash
# Run only as the entrypoint of the isolated, --network none repro container.
set -Eeuo pipefail
umask 077

readonly STATE_DIR=/run/sb4027-local
readonly RESULTS_DIR=${RESULTS_DIR:-/results}
readonly WG_INTERFACE=repro-wg
readonly ROOT_VETH=repro-h3
readonly PEER_VETH=repro-doh
readonly WG_PORT=51820
readonly OWN_NETNS_ID=$(readlink /proc/self/ns/net)
readonly OWNERSHIP_TAG="sb4027-local-$$"
H3_NS_PID=
H3_SERVER_PID=
RUNNER_PID=
STATE_CREATED=0
WG_CREATED=0
VETH_CREATED=0
FORWARD_CHANGED=0
OLD_FORWARD=

die() {
    printf 'setup: %s\n' "$*" >&2
    exit 1
}

kill_child() {
    local pid=${1:-} parent
    [[ "$pid" =~ ^[0-9]+$ ]] || return 0
    [[ -r "/proc/$pid/status" ]] || return 0
    parent=$(awk '$1 == "PPid:" { print $2 }' "/proc/$pid/status" 2>/dev/null || true)
    if [[ "$parent" == "$$" ]]; then
        kill "$pid" 2>/dev/null || true
        for ((wait_attempt=0; wait_attempt<50; wait_attempt++)); do
            kill -0 "$pid" 2>/dev/null || break
            sleep 0.1
        done
        parent=$(awk '$1 == "PPid:" { print $2 }' "/proc/$pid/status" 2>/dev/null || true)
        if [[ "$parent" == "$$" ]]; then
            kill -KILL "$pid" 2>/dev/null || true
        fi
        wait "$pid" 2>/dev/null || true
    fi
}

cleanup() {
    local result=$?
    trap - EXIT INT TERM
    # Never run networking cleanup after an unexpected namespace transition.
    if [[ "$(readlink /proc/self/ns/net)" != "$OWN_NETNS_ID" || "$OWN_NETNS_ID" == "${HOST_NETNS_ID:-}" ]]; then
        printf 'cleanup: namespace guard failed; refusing network mutations\n' >&2
        exit 1
    fi
    kill_child "$RUNNER_PID"
    kill_child "$H3_SERVER_PID"
    if [[ "$VETH_CREATED" == 1 ]] && ip link show dev "$ROOT_VETH" >/dev/null 2>&1; then
        if [[ "$(cat "/sys/class/net/$ROOT_VETH/ifalias")" == "$OWNERSHIP_TAG" ]]; then
            ip link del dev "$ROOT_VETH" || result=1
        else
            printf 'cleanup: veth ownership guard failed\n' >&2
            result=1
        fi
    fi
    if [[ "$WG_CREATED" == 1 ]] && ip link show dev "$WG_INTERFACE" >/dev/null 2>&1; then
        if [[ "$(cat "/sys/class/net/$WG_INTERFACE/ifalias")" == "$OWNERSHIP_TAG" ]]; then
            ip link del dev "$WG_INTERFACE" || result=1
        else
            printf 'cleanup: WireGuard ownership guard failed\n' >&2
            result=1
        fi
    fi
    kill_child "$H3_NS_PID"
    if [[ "$FORWARD_CHANGED" == 1 ]]; then
        printf '%s\n' "$OLD_FORWARD" > /proc/sys/net/ipv4/ip_forward || result=1
    fi
    # This exact path was absent before this process created it. It is never a
    # host bind mount; only non-secret result files are written to /results.
    if [[ "$STATE_CREATED" == 1 && "$STATE_DIR" == /run/sb4027-local && ! -L "$STATE_DIR" ]]; then
        rm -rf -- "$STATE_DIR" || result=1
    fi
    printf 'cleanup: container interfaces, child processes and ephemeral keys removed; ip_forward restored\n' >&2
    exit "$result"
}

[[ "${HOST_NETNS_ID:-}" =~ ^net:\[[0-9]+\]$ ]] || die 'HOST_NETNS_ID must contain the Docker host network namespace ID'
[[ "$OWN_NETNS_ID" != "$HOST_NETNS_ID" ]] || die 'host network namespace detected; --network none is required'
[[ -f /.dockerenv ]] || die 'this entrypoint must run inside Docker'
[[ "$(id -u)" == 0 ]] || die 'container root is required for private namespace setup'
[[ ! -e "$STATE_DIR" && ! -L "$STATE_DIR" ]] || die "$STATE_DIR already exists; refusing to overwrite it"
for name in "$WG_INTERFACE" "$ROOT_VETH" "$PEER_VETH"; do
    if ip link show dev "$name" >/dev/null 2>&1; then
        die "interface $name already exists; refusing to reuse it"
    fi
done
# The runtime requires only loopback. A connected Docker interface indicates a
# launch command different from the documented isolated setup.
if ip -o link show | awk -F ': ' '{ print $2 }' | cut -d@ -f1 | grep -qvx lo; then
    die 'unexpected initial network interface; use docker run --network none'
fi

mkdir -m 700 -- "$STATE_DIR"
STATE_CREATED=1
mkdir -p -- "$RESULTS_DIR"
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

wg genkey > "$STATE_DIR/server.key"
wg pubkey < "$STATE_DIR/server.key" > "$STATE_DIR/server.pub"
wg genkey > "$STATE_DIR/client.key"
wg pubkey < "$STATE_DIR/client.key" > "$STATE_DIR/client.pub"
openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 \
    -nodes -days 1 -subj /CN=doh.lab.test \
    -addext 'subjectAltName=DNS:doh.lab.test,IP:192.0.2.1' \
    -addext 'basicConstraints=critical,CA:TRUE' \
    -addext 'keyUsage=critical,digitalSignature,keyCertSign' \
    -addext 'extendedKeyUsage=serverAuth' \
    -keyout "$STATE_DIR/server-tls.key" -out "$STATE_DIR/server.crt" \
    > /dev/null 2>&1

ip link set dev lo up
ip link add dev "$WG_INTERFACE" type wireguard
WG_CREATED=1
ip link set dev "$WG_INTERFACE" alias "$OWNERSHIP_TAG"
wg set "$WG_INTERFACE" private-key "$STATE_DIR/server.key" listen-port "$WG_PORT" \
    peer "$(cat "$STATE_DIR/client.pub")" allowed-ips 10.77.0.2/32
ip address add 10.77.0.1/24 dev "$WG_INTERFACE"
ip link set dev "$WG_INTERFACE" mtu 1408 up

# Keep the child namespace alive without ip-netns bind mounts or changes to
# mount propagation. Only this container's CAP_SYS_ADMIN is used by unshare.
unshare --net sleep infinity &
H3_NS_PID=$!
namespace_ready=0
for ((attempt=0; attempt<100; attempt++)); do
    kill -0 "$H3_NS_PID" 2>/dev/null || die 'child namespace process exited (check container capabilities/seccomp)'
    child_netns=$(readlink "/proc/$H3_NS_PID/ns/net" 2>/dev/null || true)
    if [[ "$child_netns" =~ ^net:\[[0-9]+\]$ && "$child_netns" != "$OWN_NETNS_ID" && "$child_netns" != "$HOST_NETNS_ID" ]]; then
        namespace_ready=1
        break
    fi
    sleep 0.05
done
[[ "$namespace_ready" == 1 ]] || die 'child network namespace was not created'
nsenter -t "$H3_NS_PID" -n ip link set dev lo up

ip link add dev "$ROOT_VETH" type veth peer name "$PEER_VETH"
VETH_CREATED=1
ip link set dev "$ROOT_VETH" alias "$OWNERSHIP_TAG"
ip link set dev "$PEER_VETH" netns "$H3_NS_PID"
ip address add 192.0.2.254/24 dev "$ROOT_VETH"
ip link set dev "$ROOT_VETH" mtu 1500 up
nsenter -t "$H3_NS_PID" -n ip address add 192.0.2.1/24 dev "$PEER_VETH"
nsenter -t "$H3_NS_PID" -n ip link set dev "$PEER_VETH" mtu 1500 up
nsenter -t "$H3_NS_PID" -n ip route add 10.77.0.0/24 via 192.0.2.254 dev "$PEER_VETH"
# sing-box pauses its endpoints when no default interface is detected. This
# synthetic default route terminates at the local H3 namespace; neither side
# has any connection to the Docker host or an external network.
ip route add default via 192.0.2.1 dev "$ROOT_VETH"
OLD_FORWARD=$(cat /proc/sys/net/ipv4/ip_forward)
if [[ "$OLD_FORWARD" != 1 ]]; then
    printf '1\n' > /proc/sys/net/ipv4/ip_forward
    FORWARD_CHANGED=1
fi

export STATE_DIR RESULTS_DIR WG_INTERFACE WG_PORT ROOT_VETH PEER_VETH H3_NS_PID
nsenter -t "$H3_NS_PID" -n /usr/local/bin/doh3-server \
    -addr 192.0.2.1:443 -cert "$STATE_DIR/server.crt" -key "$STATE_DIR/server-tls.key" \
    -packet-size 1200 -disable-pmtud=true > "$RESULTS_DIR/h3-server.log" 2>&1 &
H3_SERVER_PID=$!
server_ready=0
for ((attempt=0; attempt<100; attempt++)); do
    kill -0 "$H3_SERVER_PID" 2>/dev/null || die 'local HTTP/3 server exited; see h3-server.log'
    if [[ -n "$(nsenter -t "$H3_NS_PID" -n ss -H -lun 'sport = :443')" ]]; then
        server_ready=1
        break
    fi
    sleep 0.05
done
[[ "$server_ready" == 1 ]] || die 'local HTTP/3 server did not listen on UDP 443'

printf 'setup: isolated WG 10.77.0.2 -> router -> local DoH3 192.0.2.1 ready\n' >&2
# A shell wait builtin lets PID 1 handle Docker SIGTERM promptly. Waiting on a
# foreground external command would delay the trap until that command ended.
python3 /lab/runtime/run.py &
RUNNER_PID=$!
wait "$RUNNER_PID"
