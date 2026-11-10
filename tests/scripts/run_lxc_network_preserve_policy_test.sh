#!/bin/bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_DIR="$(dirname "$(dirname "$SCRIPT_DIR")")"
LXC_EXEC="${LXC_EXEC:-$REPO_DIR/src/target/release/lxc-exec}"
if [ "$LXC_EXEC" = "$REPO_DIR/src/target/release/lxc-exec" ] && [ ! -f "$LXC_EXEC" ]; then
    LXC_EXEC="$REPO_DIR/src/target/debug/lxc-exec"
fi

fail() {
    echo "FAIL: $1"
    exit 1
}

# shellcheck source=lib/lxc_peer_listener.sh
. "$SCRIPT_DIR/lib/lxc_peer_listener.sh"

CONTAINER="mxc-policy-lifecycle-$$"
CONFIG="$REPO_DIR/tests/configs/.lxc-policy-lifecycle-$$.json"
RUN_LOG="$REPO_DIR/tests/configs/.lxc-policy-lifecycle-$$.log"
LISTENER_LOG="$REPO_DIR/tests/configs/.lxc-policy-listener-$$.log"
CONTROL_LOG="$REPO_DIR/tests/configs/.lxc-policy-control-$$.log"
LISTENER_PID=""
CONTROL_PID=""
RUN_PID=""
cleanup() {
    local status=$?
    if [ -n "$RUN_PID" ]; then
        kill -TERM "$RUN_PID" 2>/dev/null || true
        wait "$RUN_PID" 2>/dev/null || true
    fi
    if [ -n "$LISTENER_PID" ]; then
        kill "$LISTENER_PID" 2>/dev/null || true
        wait "$LISTENER_PID" 2>/dev/null || true
    fi
    if [ -n "$CONTROL_PID" ]; then
        kill "$CONTROL_PID" 2>/dev/null || true
        wait "$CONTROL_PID" 2>/dev/null || true
    fi
    if lxc-info -n "$CONTAINER" >/dev/null 2>&1; then
        python3 - "$CONFIG" <<'PY'
import json, sys
path = sys.argv[1]
config = json.load(open(path))
config["process"]["commandLine"] = "true"
config["lifecycle"] = {"destroyOnExit": True, "preservePolicy": False}
with open(path, "w") as stream:
    json.dump(config, stream)
PY
        "$LXC_EXEC" "$CONFIG" >/dev/null 2>&1 || { echo "FAIL: MXC could not clean up the policy fixture."; status=1; }
    fi
    rm -f "$CONFIG" "$RUN_LOG" "$LISTENER_LOG" "$CONTROL_LOG"
    exit "$status"
}
trap cleanup EXIT

# Reserve a static guest address in the bridge's subnet; DHCP is not exempted.
read -r HOST_IP GUEST_CIDR < <(
    ip -j -4 address show dev lxcbr0 | python3 -c '
import ipaddress, json, sys
address = json.load(sys.stdin)[0]["addr_info"][0]
network = ipaddress.ip_network(f"{address['\''local'\'']}/{address['\''prefixlen'\'']}", strict=False)
print(address["local"], f"{network.broadcast_address - 2}/{network.prefixlen}")
')
[ -n "$HOST_IP" ] && [ -n "$GUEST_CIDR" ] || fail "could not address the test guest."
DENIED_PORT=$((20000 + $$ % 10000))
ALLOWED_PORT=$((DENIED_PORT + 1))

python3 -m http.server "$DENIED_PORT" --bind "$HOST_IP" >"$LISTENER_LOG" 2>&1 &
LISTENER_PID=$!
python3 -m http.server "$ALLOWED_PORT" --bind "$HOST_IP" >"$CONTROL_LOG" 2>&1 &
CONTROL_PID=$!
await_peer_tcp "$HOST_IP" "$DENIED_PORT" || fail "the denied-port listener is unreachable."
await_peer_tcp "$HOST_IP" "$ALLOWED_PORT" || fail "the allowed-port listener is unreachable."
peer_listener_running "$LISTENER_PID" && peer_listener_running "$CONTROL_PID" \
    || fail "a test listener did not start."

for dhcp in allow deny; do
    BEFORE_NFT="$(nft -s list ruleset)"
    python3 - "$CONTAINER" "$dhcp" >"$CONFIG" <<'PY'
import json, sys
egress = {"default": "allow"}
if sys.argv[2] == "deny":
    egress["deny"] = [{"ports": [{"protocol": "udp", "port": 67}]}]
print(json.dumps({
    "version": "1.0.0",
    "containerId": sys.argv[1],
    "containment": "lxc",
    "process": {"commandLine": "true"},
    "lifecycle": {"destroyOnExit": False, "preservePolicy": True},
    "lxc": {"distribution": "alpine", "release": "3.23"},
    "network": {"egress": egress, "ingress": {"default": "deny"}}
}))
PY
    if ! "$LXC_EXEC" "$CONFIG" >"$RUN_LOG" 2>&1; then
        cat "$RUN_LOG"
        fail "the fresh DHCP=$dhcp container did not start."
    fi
    INIT_PID="$(lxc-info -n "$CONTAINER" -p -H)"

    # Stop an image-started client before clearing its lease.
    lxc-attach -n "$CONTAINER" -- sh -c 'killall udhcpc; status=$?; [ "$status" -le 1 ]' \
        >>"$RUN_LOG" 2>&1 || { cat "$RUN_LOG"; fail "could not stop the image DHCP client."; }
    nsenter -t "$INIT_PID" -n ip -4 address flush dev eth0
    if lxc-attach -n "$CONTAINER" -- udhcpc -i eth0 -n -q -t 3 -T 2 >>"$RUN_LOG" 2>&1; then
        DHCP_EXIT=0
    else
        DHCP_EXIT=$?
    fi
    LEASE="$(nsenter -t "$INIT_PID" -n ip -o -4 address show dev eth0 scope global)"
    if [ "$dhcp" = allow ]; then
        if [ "$DHCP_EXIT" -ne 0 ] || [ -z "$LEASE" ]; then
            cat "$RUN_LOG"
            fail "permitted DHCP did not acquire an IPv4 lease with ingress default deny."
        fi
    elif [ "$DHCP_EXIT" -ne 1 ] || [ -n "$LEASE" ]; then
        cat "$RUN_LOG"
        fail "explicitly denied DHCP must fail to lease and leave eth0 without IPv4; client exit=$DHCP_EXIT, address=$LEASE."
    fi

    python3 - "$CONFIG" <<'PY'
import json, sys
path = sys.argv[1]
config = json.load(open(path))
config["lifecycle"] = {"destroyOnExit": True, "preservePolicy": False}
with open(path, "w") as stream:
    json.dump(config, stream)
PY
    if ! "$LXC_EXEC" "$CONFIG" >"$RUN_LOG" 2>&1; then
        cat "$RUN_LOG"
        fail "MXC could not destroy the DHCP=$dhcp container."
    fi
    CONTAINERS="$(lxc-ls -1)"
    grep -Fxq "$CONTAINER" <<<"$CONTAINERS" && fail "DHCP=$dhcp cleanup left the container defined."
    [ "$(nft -s list ruleset)" = "$BEFORE_NFT" ] \
        || fail "DHCP=$dhcp left host filtering after destruction."
    echo "PASS: DHCP=$dhcp acquired the expected IPv4 lease state."
done

for preserve in false true; do
    for destroy in false true; do
        BEFORE_V4="$(iptables-save)"
        BEFORE_V6="$(ip6tables-save)"
        BEFORE_NFT="$(nft -s list ruleset)"
        python3 - "$CONTAINER" "$preserve" "$destroy" "$HOST_IP" "$DENIED_PORT" >"$CONFIG" <<'PY'
import json, sys
container, preserve, destroy, host, port = sys.argv[1:]
print(json.dumps({
    "version": "1.0.0",
    "containerId": container,
    "containment": "lxc",
    "process": {"commandLine": "sh -c 'cat /proc/self/status; echo MXC_POLICY_READY; while [ ! -f /mxc-policy-finish ]; do sleep 1; done'"},
    "lifecycle": {"preservePolicy": preserve == "true", "destroyOnExit": destroy == "true"},
    "lxc": {"distribution": "alpine", "release": "3.23"},
    "network": {"egress": {
        "default": "allow",
        "deny": [{"to": [{"cidr": host + "/32"}], "ports": [{"protocol": "tcp", "port": int(port)}]}]
    }}
}))
PY
        : >"$RUN_LOG"
        "$LXC_EXEC" "$CONFIG" >"$RUN_LOG" 2>&1 &
        RUN_PID=$!
        for ((attempt = 0; attempt < 600; attempt++)); do
            grep -Fq MXC_POLICY_READY "$RUN_LOG" && break
            kill -0 "$RUN_PID" 2>/dev/null || { cat "$RUN_LOG"; fail "the policy workload exited before readiness."; }
            sleep 0.5
        done
        grep -Fq MXC_POLICY_READY "$RUN_LOG" || fail "the policy workload never became ready."
        INIT_PID="$(lxc-info -n "$CONTAINER" -p -H)"
        STARTUP_COMMAND="$(sed -n 's/^lxc\.net\.0\.script\.up[[:space:]]*=[[:space:]]*//p' "/var/lib/lxc/$CONTAINER/config")"
        SCRIPT="$(python3 -c 'import shlex, sys; args = shlex.split(sys.argv[1]); print(args[-1] if args else "")' "$STARTUP_COMMAND")"
        ATTACH_STATUS="$(lxc-attach -n "$CONTAINER" -- cat /proc/self/status)"
        for status in "$(<"/proc/$INIT_PID/status")" "$ATTACH_STATUS" "$(<"$RUN_LOG")"; do
            MASK="$(awk '$1 == "CapEff:" { print $2; exit }' <<<"$status" | tr -d '\r')"
            [ -n "$MASK" ] || fail "init, attachment, or workload reported no effective capability mask."
            (( (16#$MASK & 0x3000) == 0x3000 )) \
                || fail "init, attachment, or workload lost effective CAP_NET_ADMIN or CAP_NET_RAW."
        done

        # Enter init's network namespace without depending on guest-installed tools.
        nsenter -t "$INIT_PID" -n ip address replace "$GUEST_CIDR" dev eth0
        nsenter -t "$INIT_PID" -n ip link set eth0 up
        nsenter -t "$INIT_PID" -n ip route replace default via "$HOST_IP"
        nsenter -t "$INIT_PID" -n iptables -F
        nsenter -t "$INIT_PID" -n iptables -X
        nsenter -t "$INIT_PID" -n iptables -P OUTPUT ACCEPT
        nsenter -t "$INIT_PID" -n ip6tables -F
        nsenter -t "$INIT_PID" -n ip6tables -X
        nsenter -t "$INIT_PID" -n ip6tables -P OUTPUT ACCEPT

        nsenter -t "$INIT_PID" -n timeout 3 bash -c "exec 3<>/dev/tcp/$HOST_IP/$ALLOWED_PORT" \
            || fail "the guest cannot reach the allowed listener; a denied connection would prove nothing."
        if nsenter -t "$INIT_PID" -n timeout 3 bash -c "exec 3<>/dev/tcp/$HOST_IP/$DENIED_PORT"; then
            fail "flushing the guest firewall bypassed the configured egress deny."
        fi

        lxc-attach -n "$CONTAINER" -- touch /mxc-policy-finish
        if ! wait "$RUN_PID"; then
            cat "$RUN_LOG"
            fail "the lifecycle run failed."
        fi
        RUN_PID=""

        if [ "$destroy" = true ]; then
            CONTAINERS="$(lxc-ls -1)"
            grep -Fxq "$CONTAINER" <<<"$CONTAINERS" && fail "destroyOnExit left the test container defined."
        else
            [ "$(lxc-info -n "$CONTAINER" -s -H)" = RUNNING ] \
                || fail "destroyOnExit=false did not leave the container running."
            INIT_PID="$(lxc-info -n "$CONTAINER" -p -H)"
            nsenter -t "$INIT_PID" -n timeout 3 bash -c "exec 3<>/dev/tcp/$HOST_IP/$ALLOWED_PORT" \
                || fail "the surviving container lost its allowed route."
            if nsenter -t "$INIT_PID" -n timeout 3 bash -c "exec 3<>/dev/tcp/$HOST_IP/$DENIED_PORT"; then
                [ "$preserve" = false ] || fail "preservePolicy=true removed the surviving container's deny."
            else
                [ "$preserve" = true ] || fail "preservePolicy=false retained the surviving container's deny."
            fi
            if [ "$preserve" = true ] && [ -n "$SCRIPT" ]; then
                [ -f "$SCRIPT" ] || fail "preservePolicy=true removed the surviving container's startup script."
            fi
        fi

        if [ "$preserve" = false ] || [ "$destroy" = true ]; then
            # iptables-save includes timestamps; compare only kernel rules.
            [ "$(iptables-save | sed '/^#/d')" = "$(sed '/^#/d' <<<"$BEFORE_V4")" ] \
                || fail "IPv4 host rules survived policy teardown."
            [ "$(ip6tables-save | sed '/^#/d')" = "$(sed '/^#/d' <<<"$BEFORE_V6")" ] \
                || fail "IPv6 host rules survived policy teardown."
            [ "$(nft -s list ruleset)" = "$BEFORE_NFT" ] \
                || fail "host nftables rules survived policy teardown."
            [ -z "$SCRIPT" ] || [ ! -e "$SCRIPT" ] || fail "the retired startup script still exists."
            if [ "$destroy" = false ] && [ -n "$SCRIPT" ]; then
                if grep -Fq "$STARTUP_COMMAND" "/var/lib/lxc/$CONTAINER/config"; then
                    fail "preservePolicy=false left the retired startup hook registered."
                fi
            fi
        fi

        if [ "$destroy" = false ]; then
            python3 - "$CONFIG" <<'PY'
import json, sys
path = sys.argv[1]
config = json.load(open(path))
config["process"]["commandLine"] = "sh -c 'rm -f /mxc-policy-finish; echo MXC_POLICY_REUSED'"
config["lifecycle"] = {"destroyOnExit": True, "preservePolicy": False}
with open(path, "w") as stream:
    json.dump(config, stream)
PY
            OUTPUT=$("$LXC_EXEC" "$CONFIG") || fail "MXC could not reuse and destroy its surviving container."
            grep -Fq MXC_POLICY_REUSED <<<"$OUTPUT" || fail "the reused workload did not run."
            CONTAINERS="$(lxc-ls -1)"
            grep -Fxq "$CONTAINER" <<<"$CONTAINERS" && fail "reuse cleanup left the container defined."
            [ "$(iptables-save | sed '/^#/d')" = "$(sed '/^#/d' <<<"$BEFORE_V4")" ] \
                || fail "IPv4 host rules leaked after reuse cleanup."
            [ "$(ip6tables-save | sed '/^#/d')" = "$(sed '/^#/d' <<<"$BEFORE_V6")" ] \
                || fail "IPv6 host rules leaked after reuse cleanup."
            [ "$(nft -s list ruleset)" = "$BEFORE_NFT" ] \
                || fail "host nftables rules leaked after reuse cleanup."
            [ -z "$SCRIPT" ] || [ ! -e "$SCRIPT" ] || fail "reuse cleanup left the old startup script."
        fi
        echo "PASS: preservePolicy=$preserve destroyOnExit=$destroy."
    done
done
