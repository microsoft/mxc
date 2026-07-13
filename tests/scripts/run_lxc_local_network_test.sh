#!/bin/bash
# Manual test for the LXC backend `allowLocalNetwork` schema field.
#
# Two independent layers are reported per config:
#
#   [RULE]  --- authoritative for the CURRENT code ---
#       Runs each config, then dumps the container's iptables chain on the
#       host and asserts the loopback rule's verb:
#           allowLocalNetwork: true   =>  -i lo -j ACCEPT
#           allowLocalNetwork: absent =>  -i lo -j DROP   (default false)
#       This is the only signal the current implementation makes observable,
#       because apply_firewall_rules emits the rule into the HOST FORWARD
#       chain (hooked with `-o <veth>`), not the container's inbound path.
#       See network_iptables.rs:157-173,257-261 and lxc_runner.rs:208-221.
#
#   [BEHAVIOR]  --- forward-looking ---
#       Starts a `netcheck serve` listener INSIDE the sandbox (launched by
#       MXC) and connects to it with `netcheck connect` from the host,
#       expecting reachable when allowed and blocked when denied.
#       NOTE: with the rule as written (`-i lo` in the host FORWARD chain) a
#       host->container connection does NOT traverse that path, so this layer
#       will report REACHABLE for BOTH configs until the inbound rule is
#       placed in the container INPUT path. It is wired here so it starts
#       distinguishing allow/deny automatically once that change lands.
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

run_case() {
    local label="$1" config="$2" cid="$3" expect_verb="$4"
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

    # [RULE] host-side chain dump — authoritative for the current code.
    local chain="MXC-${cid}" verb="(none)" dump
    dump="$(iptables -S "$chain" 2>/dev/null)"
    if echo "$dump" | grep -q -- '-i lo -j ACCEPT'; then verb="ACCEPT"; fi
    if echo "$dump" | grep -q -- '-i lo -j DROP'; then verb="DROP"; fi
    if [ "$verb" = "$expect_verb" ]; then
        echo "[RULE] PASS  $chain has '-i lo -j $verb' (expected $expect_verb)"
        rule_pass=$((rule_pass + 1))
    else
        echo "[RULE] FAIL  $chain '-i lo' verb=$verb (expected $expect_verb)"
        echo "$dump" | sed 's/^/       /'
        rule_fail=$((rule_fail + 1))
    fi

    # [BEHAVIOR] connect from the host to the sandboxed listener.
    if [ -n "$ip" ]; then
        if "$HELPER_BIN" connect --host "$ip" --port "$PORT" --timeout 5; then
            echo "[BEHAVIOR] reachable  (host reached $ip:$PORT)"
        else
            echo "[BEHAVIOR] blocked    (host could not reach $ip:$PORT)"
        fi
    else
        echo "[BEHAVIOR] SKIP  no container IP discovered for $cid"
    fi

    # Let the sandbox finish (server exits after serving or after --hold).
    wait "$mxc_pid" 2>/dev/null
}

run_case "allowLocalNetwork: TRUE  (expect -i lo ACCEPT)" \
    "$CONFIG_DIR/lxc_local_network_allow.json" "lxc-localnet-allow" "ACCEPT"
run_case "allowLocalNetwork: FALSE (expect -i lo DROP)" \
    "$CONFIG_DIR/lxc_local_network_deny.json" "lxc-localnet-deny" "DROP"

echo
echo "==================== SUMMARY ===================="
echo "[RULE]     pass=$rule_pass fail=$rule_fail   (authoritative for current code)"
echo "[BEHAVIOR] informational — distinguishes allow/deny only once the inbound"
echo "           rule is placed in the container INPUT path."
[ "$rule_fail" -eq 0 ]
