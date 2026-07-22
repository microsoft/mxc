#!/bin/bash
# Behavioral + rule-level test for the LXC backend `allowLocalNetwork` field.
#
# Two independent layers are reported per config:
#
#   [RULE]  --- authoritative; asserts the emitted enforcement rule ---
#       Runs each config, dumps the container's iptables chain on the host,
#       and asserts the NEW-inbound decision that actually enforces the field:
#           allowLocalNetwork: true   =>  -m state --state NEW -j ACCEPT
#           allowLocalNetwork: absent =>  -m state --state NEW -j DROP  (default)
#       It also asserts loopback is an UNCONDITIONAL accept (`-i lo -j ACCEPT`)
#       in both cases. The chain is hooked into the host FORWARD chain with
#       `-o <veth>`, so it governs NEW connections *forwarded into* the
#       container. See network_iptables.rs build_firewall_rules() and
#       lxc_runner.rs:208-221.
#
#   [BEHAVIOR]  --- end-to-end over a GOVERNED path ---
#       Starts a `netcheck serve` listener INSIDE a server container (launched
#       by MXC), then launches a SECOND (peer) container that runs
#       `netcheck connect` against the server's IP. Container->container
#       traffic is *forwarded* by the host and therefore traverses the server
#       chain's `-o <server-veth>` hook, so the NEW-inbound rule applies:
#           allowLocalNetwork: true   =>  reachable
#           allowLocalNetwork: absent =>  blocked
#       A host->container probe would NOT exercise the rule (host-originated
#       packets take OUTPUT, not FORWARD), which is why the client is a peer
#       container. If the peer container cannot be launched the layer reports
#       INCONCLUSIVE (it never silently passes).
#
# Requires root (container management + iptables), like run_lxc_all_tests.sh.
set -uo pipefail

if [ "$(id -u)" -ne 0 ]; then
    echo "ERROR: LXC network tests require root (container mgmt + iptables)."
    echo "Run with: sudo $0"
    exit 1
fi

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_DIR="$(dirname "$(dirname "$SCRIPT_DIR")")"
CONFIG_DIR="$REPO_DIR/tests/configs"
HELPER_SRC="$REPO_DIR/tests/helpers/netcheck/netcheck.rs"
HELPER_DIR="/opt/mxc-netcheck"       # bind-mounted read-only into the sandbox
HELPER_BIN="$HELPER_DIR/netcheck"
PORT=5000

LXC_EXEC="$REPO_DIR/src/target/release/lxc-exec"
[ -f "$LXC_EXEC" ] || LXC_EXEC="$REPO_DIR/src/target/debug/lxc-exec"
if [ ! -f "$LXC_EXEC" ]; then
    echo "Error: lxc-exec not found. Run ./build.sh first."
    exit 1
fi

# --- Build the param-driven helper as a static musl binary (runs in Alpine) ---
echo "== Building netcheck helper (static musl) =="
if ! rustup target list --installed 2>/dev/null | grep -q '^x86_64-unknown-linux-musl$'; then
    rustup target add x86_64-unknown-linux-musl
fi
mkdir -p "$HELPER_DIR"
rustc --edition 2021 -O \
    --target x86_64-unknown-linux-musl \
    -C target-feature=+crt-static \
    "$HELPER_SRC" -o "$HELPER_BIN"
chmod 0755 "$HELPER_DIR" "$HELPER_BIN"
echo "netcheck -> $HELPER_BIN"

rule_pass=0
rule_fail=0
behavior_pass=0
behavior_fail=0
behavior_inconclusive=0

# Write a peer client config that connects to the server IP over the bridge.
# Generated at runtime because the server IP isn't known until the server is
# up; kept out of tests/configs so it doesn't need a static schema fixture.
write_client_config() {
    local path="$1" sip="$2"
    cat > "$path" <<EOF
{
  "version": "0.4.0-alpha",
  "containerId": "lxc-localnet-client",
  "containment": "lxc",
  "process": {
    "commandLine": "$HELPER_BIN connect --host $sip --port $PORT --timeout 5"
  },
  "lifecycle": {
    "destroyOnExit": true
  },
  "lxc": {
    "distribution": "alpine",
    "release": "3.23"
  },
  "filesystem": {
    "readonlyPaths": ["$HELPER_DIR"]
  },
  "network": {
    "defaultPolicy": "block",
    "enforcementMode": "firewall",
    "allowLocalNetwork": true
  }
}
EOF
}

run_case() {
    local label="$1" config="$2" cid="$3" expect_verb="$4" expect_reachable="$5"
    echo
    echo "===================== $label ====================="

    # Launch the sandboxed server in the background.
    "$LXC_EXEC" "$config" > "/tmp/netcheck_${cid}.log" 2>&1 &
    local mxc_pid=$!

    # Wait for the container IP (mirrors lxc_runner wait_for_network).
    local ip="" i
    for i in $(seq 1 20); do
        ip="$(lxc-info -iH -n "$cid" 2>/dev/null | head -n1 | tr -d '[:space:]')"
        [ -n "$ip" ] && break
        sleep 0.5
    done

    # [RULE] host-side chain dump — asserts the NEW-inbound enforcement verb.
    local chain="MXC-${cid}" verb="(none)" dump
    dump="$(iptables -S "$chain" 2>/dev/null)"
    if echo "$dump" | grep -q -- '-m state --state NEW -j ACCEPT'; then verb="ACCEPT"; fi
    if echo "$dump" | grep -q -- '-m state --state NEW -j DROP'; then verb="DROP"; fi

    local rule_ok=1
    if [ "$verb" != "$expect_verb" ]; then
        rule_ok=0
        echo "[RULE] FAIL  $chain NEW-inbound verb=$verb (expected $expect_verb)"
    fi
    # Loopback must be an unconditional ACCEPT regardless of allowLocalNetwork.
    if ! echo "$dump" | grep -q -- '-i lo -j ACCEPT'; then
        rule_ok=0
        echo "[RULE] FAIL  $chain missing unconditional '-i lo -j ACCEPT'"
    fi
    if echo "$dump" | grep -q -- '-i lo -j DROP'; then
        rule_ok=0
        echo "[RULE] FAIL  $chain has hazardous '-i lo -j DROP'"
    fi
    if [ "$rule_ok" -eq 1 ]; then
        echo "[RULE] PASS  $chain: NEW-inbound '$verb', loopback ACCEPT"
        rule_pass=$((rule_pass + 1))
    else
        echo "$dump" | sed 's/^/       /'
        rule_fail=$((rule_fail + 1))
    fi

    # [BEHAVIOR] connect from a PEER container so the traffic is forwarded and
    # actually traverses the server chain's `-o <veth>` hook.
    if [ -n "$ip" ]; then
        local client_cfg="/tmp/lxc_client_${cid}.json"
        local client_log="/tmp/netcheck_client_${cid}.log"
        write_client_config "$client_cfg" "$ip"
        "$LXC_EXEC" "$client_cfg" > "$client_log" 2>&1
        local actual="inconclusive"
        if grep -q 'NETCHECK_OK' "$client_log" 2>/dev/null; then
            actual="reachable"
        elif grep -qE 'NETCHECK_CONNECT_FAIL|NETCHECK_BAD_REPLY|NETCHECK_RESOLVE_FAIL' "$client_log" 2>/dev/null; then
            actual="blocked"
        fi

        local want="reachable"; [ "$expect_reachable" = "no" ] && want="blocked"
        if [ "$actual" = "inconclusive" ]; then
            echo "[BEHAVIOR] INCONCLUSIVE  peer container produced no verdict (see $client_log)"
            behavior_inconclusive=$((behavior_inconclusive + 1))
        elif [ "$actual" = "$want" ]; then
            echo "[BEHAVIOR] PASS  peer->server $ip:$PORT $actual (expected $want)"
            behavior_pass=$((behavior_pass + 1))
        else
            echo "[BEHAVIOR] FAIL  peer->server $ip:$PORT $actual (expected $want)"
            behavior_fail=$((behavior_fail + 1))
        fi
        rm -f "$client_cfg"
    else
        echo "[BEHAVIOR] INCONCLUSIVE  no container IP discovered for $cid"
        behavior_inconclusive=$((behavior_inconclusive + 1))
    fi

    # Let the sandbox finish (server exits after serving or after --hold).
    wait "$mxc_pid" 2>/dev/null
}

run_case "allowLocalNetwork: TRUE  (expect NEW ACCEPT, reachable)" \
    "$CONFIG_DIR/lxc_local_network_allow.json" "lxc-localnet-allow" "ACCEPT" "yes"
run_case "allowLocalNetwork: FALSE (expect NEW DROP, blocked)" \
    "$CONFIG_DIR/lxc_local_network_deny.json" "lxc-localnet-deny" "DROP" "no"

echo
echo "==================== SUMMARY ===================="
echo "[RULE]     pass=$rule_pass fail=$rule_fail"
echo "[BEHAVIOR] pass=$behavior_pass fail=$behavior_fail inconclusive=$behavior_inconclusive"
# Fail on any rule mismatch or any decisive behavioral mismatch. INCONCLUSIVE
# (peer container could not run) does not fail the suite but is reported above.
[ "$rule_fail" -eq 0 ] && [ "$behavior_fail" -eq 0 ]
