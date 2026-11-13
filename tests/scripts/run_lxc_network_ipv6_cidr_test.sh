#!/bin/bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_DIR="$(dirname "$(dirname "$SCRIPT_DIR")")"
LXC_EXEC="$REPO_DIR/src/target/release/lxc-exec"

if [ ! -f "$LXC_EXEC" ]; then
    LXC_EXEC="$REPO_DIR/src/target/debug/lxc-exec"
fi

SKIP_EXIT=77
skip()
{
    echo "SKIP: $1"
    exit "$SKIP_EXIT"
}

[ "$(id -u)" -eq 0 ] || skip "requires root for iptables/ip6tables and LXC."
command -v iptables >/dev/null 2>&1 || skip "iptables is not installed."
command -v ip6tables >/dev/null 2>&1 || skip "ip6tables is not installed."
command -v lxc-create >/dev/null 2>&1 || skip "LXC (lxc-create) is not installed."
command -v lxc-info >/dev/null 2>&1 || skip "LXC (lxc-info) is not installed."
command -v nsenter >/dev/null 2>&1 || skip "nsenter is not installed."
command -v ip >/dev/null 2>&1 || skip "iproute2 (ip) is not installed."
command -v python3 >/dev/null 2>&1 || skip "python3 is not installed."
[ -f "$LXC_EXEC" ] || skip "lxc-exec binary not built; run build.sh first."

fail()
{
    echo "FAIL: $1"
    exit 1
}

# shellcheck source=lib/lxc_peer_listener.sh
. "$SCRIPT_DIR/lib/lxc_peer_listener.sh"

WORK_DIR="$REPO_DIR/.lxc-ipv6-cidr-$$"
PEER_NETNS="mxc-cidr-$$"
PEER_VETH="cidrpeer0"
CONTAINER_VETH="cidrprobe0"
CONTAINER="mxc-ipv6-cidr-$$"
LISTENER_PID=""
RUN_PID=""

cleanup()
{
    if [ -n "$RUN_PID" ]; then
        kill -TERM "$RUN_PID" 2>/dev/null || true
        wait "$RUN_PID" 2>/dev/null || true
    fi
    "$LXC_EXEC" --delete --containername "$CONTAINER" >/dev/null 2>&1 || true
    if [ -n "$LISTENER_PID" ]; then
        kill "$LISTENER_PID" 2>/dev/null || true
        wait "$LISTENER_PID" 2>/dev/null || true
    fi
    ip netns del "$PEER_NETNS" >/dev/null 2>&1 || true
    rm -rf "$WORK_DIR"
}
trap cleanup EXIT

mkdir "$WORK_DIR"
printf 'CIDR_PEER\n' >"$WORK_DIR/response"

python3 - "$WORK_DIR" "$CONTAINER" <<'PY'
import json
import pathlib
import shlex
import sys

directory = pathlib.Path(sys.argv[1])
allow = ["140.82.112.0/20", "2606:50c0::/32", "2606:50c0:8000::153/128"]
deny = ["10.0.0.0/8", "2001:db8::/32", "fe80::1/128"]
egress = {
    "default": "deny",
    "allow": [{"to": [{"cidr": cidr}]} for cidr in allow],
    "deny": [{"to": [{"cidr": cidr}]} for cidr in deny],
}
cases = [
    ("control", {"default": "allow"}, [
        ("10.0.0.1", "allowed"),
        ("2001:db8::1", "allowed"),
        ("fe80::1", "allowed"),
    ]),
    ("deny", {**egress, "default": "allow"}, [
        ("10.0.0.1", "blocked"),
        ("11.0.0.1", "allowed"),
        ("2001:db8::1", "blocked"),
        ("2001:db9::1", "allowed"),
        ("fe80::1", "blocked"),
        ("fe80::2", "allowed"),
        ("140.82.128.1", "allowed"),
        ("2606:50c1::1", "allowed"),
    ]),
    ("cidr", egress, [
        ("140.82.127.254", "allowed"),
        ("140.82.128.1", "blocked"),
        ("2606:50c0:8000::152", "allowed"),
        ("2606:50c1::1", "blocked"),
    ]),
    ("single", {"default": "deny", "allow": [{"to": [{"cidr": allow[2]}]}]}, [
        ("2606:50c0:8000::153", "allowed"),
        ("2606:50c0:8000::152", "blocked"),
    ]),
]
for name, policy, probes in cases:
    command = [
        "until [ -e /tmp/cidr-ready ]; do sleep 0.1; done",
    ]
    for target, expected in probes:
        host = target
        if ":" in host:
            if host.startswith("fe80:"):
                host += "%cidrprobe0"
            host = f"[{host}]"
        command.extend([
            f"if body=$(wget -Y off -qO- -T 3 'http://{host}:8080/response'); then",
            '  [ "$body" = CIDR_PEER ] || { echo "FAIL: unexpected HTTP response"; exit 1; }',
            "  observed=allowed",
            "else",
            "  observed=blocked",
            "fi",
            f'[ "$observed" = {expected} ] || {{ echo "FAIL: {name}: {target} expected {expected}, got $observed"; exit 1; }}',
        ])
    config = {
        "version": "0.9.0-alpha",
        "containerId": sys.argv[2],
        "containment": "lxc",
        "process": {"commandLine": "sh -c " + shlex.quote("\n".join(command))},
        "lifecycle": {"destroyOnExit": True},
        "lxc": {"distribution": "alpine", "release": "3.23"},
        "network": {"egress": policy},
    }
    (directory / f"{name}.json").write_text(json.dumps(config))
targets = {target for _, _, probes in cases for target, _ in probes}
(directory / "targets").write_text("\n".join(sorted(targets)) + "\n")
PY

ip netns add "$PEER_NETNS"
ip -n "$PEER_NETNS" link set lo up
ip netns exec "$PEER_NETNS" python3 -m http.server 8080 --bind :: --directory "$WORK_DIR" \
    >"$WORK_DIR/peer.log" 2>&1 &
LISTENER_PID=$!
if ! ip netns exec "$PEER_NETNS" bash -c '. "$1"; await_peer_tcp 127.0.0.1 8080' \
    bash "$SCRIPT_DIR/lib/lxc_peer_listener.sh"; then
    cat "$WORK_DIR/peer.log"
    fail "the local HTTP peer did not accept a connection."
fi

for case in control deny cidr single; do
    echo "--- IPv4/IPv6 CIDR traffic: $case ---"
    timeout 300 "$LXC_EXEC" "$WORK_DIR/$case.json" >"$WORK_DIR/run.log" 2>&1 &
    RUN_PID=$!
    until NETNS_PID="$(lxc-info -n "$CONTAINER" -pH 2>/dev/null)" \
        && [[ "$NETNS_PID" =~ ^[1-9][0-9]*$ ]]; do
        if ! kill -0 "$RUN_PID" 2>/dev/null; then
            cat "$WORK_DIR/run.log"
            fail "$case: the workload did not reach its network probe."
        fi
        sleep 1
    done
    ip -n "$PEER_NETNS" link add "$PEER_VETH" type veth peer name "$CONTAINER_VETH"
    ip -n "$PEER_NETNS" link set "$CONTAINER_VETH" netns "$NETNS_PID"
    ip -n "$PEER_NETNS" link set "$PEER_VETH" up
    nsenter -t "$NETNS_PID" -n ip addr add 198.18.77.1/32 dev "$CONTAINER_VETH"
    nsenter -t "$NETNS_PID" -n ip -6 addr add fd00:77:88::1/128 dev "$CONTAINER_VETH" nodad
    nsenter -t "$NETNS_PID" -n ip link set "$CONTAINER_VETH" up
    PEER_MAC="$(ip -n "$PEER_NETNS" -o link show "$PEER_VETH" \
        | sed -n 's/.*link\/ether \([^ ]*\).*/\1/p')"
    CONTAINER_MAC="$(nsenter -t "$NETNS_PID" -n ip -o link show "$CONTAINER_VETH" \
        | sed -n 's/.*link\/ether \([^ ]*\).*/\1/p')"
    ip -n "$PEER_NETNS" route add 198.18.77.1/32 dev "$PEER_VETH"
    ip -n "$PEER_NETNS" -6 route add fd00:77:88::1/128 dev "$PEER_VETH"
    ip -n "$PEER_NETNS" -6 neigh add fd00:77:88::1 lladdr "$CONTAINER_MAC" \
        dev "$PEER_VETH" nud permanent

    while IFS= read -r target; do
        if [[ "$target" == *:* ]]; then
            ip -n "$PEER_NETNS" -6 addr add "$target/128" dev "$PEER_VETH" nodad
            nsenter -t "$NETNS_PID" -n ip -6 route add "$target/128" \
                dev "$CONTAINER_VETH" src fd00:77:88::1

            # Keep neighbor discovery from becoming an unrelated default-deny failure.
            nsenter -t "$NETNS_PID" -n ip -6 neigh add "$target" lladdr "$PEER_MAC" \
                dev "$CONTAINER_VETH" nud permanent
        else
            ip -n "$PEER_NETNS" addr add "$target/32" dev "$PEER_VETH"
            nsenter -t "$NETNS_PID" -n ip route add "$target/32" \
                dev "$CONTAINER_VETH" src 198.18.77.1
        fi
    done <"$WORK_DIR/targets"

    lxc-attach -n "$CONTAINER" -- touch /tmp/cidr-ready
    STATUS=0
    wait "$RUN_PID" || STATUS=$?
    RUN_PID=""
    cat "$WORK_DIR/run.log"
    if [ "$STATUS" -ne 0 ]; then
        fail "$case: the packet probes exited with status $STATUS."
    fi
done

echo "PASS: IPv4/IPv6 CIDRs enforced allowed, denied, and single-address traffic."
