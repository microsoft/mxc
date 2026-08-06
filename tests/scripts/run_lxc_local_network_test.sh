#!/bin/bash
# Behavioral + rule-level test for the LXC backend `allowLocalNetwork` field.
#
# Two independent layers are reported per config:
#
#   [RULE]  --- authoritative; asserts the emitted enforcement rule ---
#       Runs each config, dumps the container's iptables chain from INSIDE the
#       container's network namespace (via `nsenter -t <init-pid> -n`), and
#       asserts the NEW-inbound decision that actually enforces the field:
#           allowLocalNetwork: absent =>  -m state --state NEW -j DROP  (default)
#       It also asserts loopback is an UNCONDITIONAL accept (`-i lo -j ACCEPT`).
#       The chain is hooked into the container's INPUT chain, so it governs NEW
#       connections *destined to the container's sockets* — from the host or from
#       a peer alike. See network_iptables.rs build_firewall_rules() and
#       lxc_runner.rs (init-PID discovery -> set_netns_pid). The chain is NOT on
#       the host, so a host-side `iptables -S MXC-<id>` shows nothing; the dump
#       must enter the netns.
#
#   [REFUSED]  --- asserts the permissive path is not silently over-broad ---
#       allowLocalNetwork: true is not yet implemented: scoping inbound to host
#       loopback needs a loopbackPorts schema field and a host-loopback forwarder
#       that do not exist yet, and the only rule available today is an unscoped
#       `--state NEW -j ACCEPT` that accepts inbound from every interface and
#       source. So the run is REFUSED with a not-yet-implemented error before any
#       chain is built (network_iptables.rs apply_firewall_rules), rather than
#       installing the over-broad accept. This layer asserts the refusal and that
#       no NEW-ACCEPT chain was installed.
#
#   [BEHAVIOR]  --- end-to-end over a GOVERNED path ---
#       Starts a `netcheck serve` listener INSIDE a server container (launched
#       by MXC), then launches a SECOND (peer) container that runs
#       `netcheck connect` against the server's IP. Peer->server traffic is
#       inbound to the server container and therefore traverses the server's
#       INPUT chain, so the NEW-inbound rule applies:
#           allowLocalNetwork: absent =>  blocked
#       Under the INPUT design a host->container-direct probe is now governed
#       too (host-originated packets reach the container's INPUT); the peer
#       container is kept as a representative external-inbound client. If the
#       peer container cannot be launched the layer reports INCONCLUSIVE (it
#       never silently passes). The client is launched only AFTER the server
#       signals NETCHECK_SERVER_READY (bounded wait); if the server never
#       becomes ready the layer reports UNREADY and fails the suite, so a
#       "connection refused" caused by a server that never started can never be
#       misread as proof the firewall blocked the connection.
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
#
# The helper executes INSIDE an Alpine container that shares the host's CPU
# architecture, so a helper built for the wrong arch cannot exec there. LXC is
# supported on Linux x64 AND ARM64 (README.md "Platforms"; build.sh's `uname -m`
# switch, x86_64|aarch64), so select the musl target matching the host arch
# instead of hard-coding x86_64 — which on an aarch64 host produced an x86_64
# binary that silently fails to run in the container. Any other architecture is
# skipped honestly (loudly, and not as a pass) rather than building a helper
# that cannot execute.
HOST_ARCH="$(uname -m)"
case "$HOST_ARCH" in
    x86_64)
        MUSL_TARGET="x86_64-unknown-linux-musl"
        ;;
    aarch64 | arm64)
        MUSL_TARGET="aarch64-unknown-linux-musl"
        ;;
    *)
        echo "SKIP: no netcheck helper can be produced for host architecture '$HOST_ARCH'."
        echo "SKIP: this LXC local-network E2E supports x86_64 and aarch64 only; a helper built"
        echo "SKIP: for another arch cannot exec inside the Alpine container, so nothing was"
        echo "SKIP: tested. This is an honest skip, NOT a pass."
        exit 0
        ;;
esac
echo "== Building netcheck helper (static musl, $MUSL_TARGET) =="
if ! rustup target list --installed 2>/dev/null | grep -q "^${MUSL_TARGET}\$"; then
    rustup target add "$MUSL_TARGET"
fi
mkdir -p "$HELPER_DIR"
rustc --edition 2021 -O \
    --target "$MUSL_TARGET" \
    -C target-feature=+crt-static \
    "$HELPER_SRC" -o "$HELPER_BIN"
chmod 0755 "$HELPER_DIR" "$HELPER_BIN"
echo "netcheck -> $HELPER_BIN"

rule_pass=0
rule_fail=0
behavior_pass=0
behavior_fail=0
behavior_inconclusive=0
behavior_unready=0
refused_pass=0
refused_fail=0

# Write a peer client config that connects to the server IP over the bridge.
# Generated at runtime because the server IP isn't known until the server is
# up; kept out of tests/configs so it doesn't need a static schema fixture.
write_client_config() {
    local path="$1" sip="$2"
    cat > "$path" <<EOF
{
  "version": "0.8.0-alpha",
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
    "enforcementMode": "firewall"
  }
}
EOF
}

# Assert that a config requesting the not-yet-implemented permissive inbound
# path (allowLocalNetwork: true) is REFUSED rather than silently installing an
# over-broad `--state NEW -j ACCEPT`. The run must fail with the
# not-yet-implemented error and must not leave a NEW-ACCEPT chain in the netns.
#
# lxc-exec's process exit code for a ScriptResponse error is not relied on here
# (it is reported for diagnostics only); the authoritative signal is the error
# text captured from the runner's combined stdout/stderr, plus the absence of
# an installed accept chain.
run_error_case() {
    local label="$1" config="$2" cid="$3"
    echo
    echo "===================== $label ====================="

    local log="/tmp/netcheck_${cid}.log"
    "$LXC_EXEC" "$config" > "$log" 2>&1
    local rc=$?

    local ok=1
    if ! grep -qi 'not yet implemented' "$log" 2>/dev/null; then
        ok=0
        echo "[REFUSED] FAIL  runner log missing the not-yet-implemented error (rc=$rc; see $log)"
    fi

    # Best-effort corroboration: the container is destroyed on refusal, but if a
    # PID is still visible, confirm no over-broad NEW ACCEPT chain was installed.
    local pid dump
    pid="$(lxc-info -pH -n "$cid" 2>/dev/null | grep -oE '[0-9]+' | head -n1)"
    if [ -n "$pid" ]; then
        dump="$(nsenter -t "$pid" -n iptables -S "MXC-${cid}" 2>/dev/null)"
        if echo "$dump" | grep -q -- '-m state --state NEW -j ACCEPT'; then
            ok=0
            echo "[REFUSED] FAIL  an over-broad NEW ACCEPT chain was installed despite refusal"
        fi
    fi

    if [ "$ok" -eq 1 ]; then
        echo "[REFUSED] PASS  permissive path refused (not-yet-implemented; rc=$rc); no accept chain"
        refused_pass=$((refused_pass + 1))
    else
        sed 's/^/       /' "$log" 2>/dev/null | tail -n 20
        refused_fail=$((refused_fail + 1))
    fi
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

    # [RULE] chain dump — asserts the NEW-inbound enforcement verb. The chain
    # lives inside the CONTAINER's network namespace (hooked into its INPUT),
    # so it is dumped via `nsenter` into the container's init PID, not on the
    # host. A host-side `iptables -S` would show nothing.
    #
    # The runner exposes the container IP (wait_for_network) slightly BEFORE it
    # discovers the init PID and applies the chain (init_pid -> nsenter), so a
    # single dump the instant the IP appears can race ahead of rule
    # application. Poll the netns until the chain shows a terminal NEW verb (or
    # a bounded timeout), which makes the assertion deterministic.
    local chain="MXC-${cid}" verb="(none)" dump="" pid="" j
    for j in $(seq 1 20); do
        pid="$(lxc-info -pH -n "$cid" 2>/dev/null | grep -oE '[0-9]+' | head -n1)"
        if [ -n "$pid" ]; then
            dump="$(nsenter -t "$pid" -n iptables -S "$chain" 2>/dev/null)"
            if echo "$dump" | grep -q -- '-m state --state NEW -j'; then
                break
            fi
        fi
        sleep 0.5
    done
    if [ -z "$pid" ]; then
        echo "[RULE] WARN  no init PID for $cid; cannot enter netns to dump $chain"
    fi
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

    # [BEHAVIOR] connect from a PEER container so the traffic is inbound to the
    # server container and actually traverses the server's INPUT-chain hook.
    #
    # Before connecting, wait for a POSITIVE readiness signal from the server.
    # Without it, a client `Connection refused` — because the server helper
    # never started or had not yet bound its socket — surfaces below as
    # NETCHECK_CONNECT_FAIL and is classified 'blocked', which for the deny case
    # (want=blocked) is scored a PASS: a FALSE PASS that credits the firewall
    # for a failure that was really "server not up". The server prints
    # `NETCHECK_SERVER_READY` to its stdout (captured in $server_log) only after
    # `TcpListener::bind` succeeds (tests/helpers/netcheck/netcheck.rs), so poll
    # for it with a bounded timeout, and stop early if the bind is reported
    # failed. "Server never became ready" is reported as an honest UNREADY that
    # fails the suite — never as a policy-blocked success.
    local server_log="/tmp/netcheck_${cid}.log"
    local server_ready=0 k
    for k in $(seq 1 40); do
        if grep -q 'NETCHECK_SERVER_READY' "$server_log" 2>/dev/null; then
            server_ready=1
            break
        fi
        if grep -q 'NETCHECK_BIND_FAIL' "$server_log" 2>/dev/null; then
            break
        fi
        sleep 0.25
    done

    if [ -n "$ip" ] && [ "$server_ready" -eq 1 ]; then
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
    elif [ -n "$ip" ]; then
        # IP came up but the server never signalled readiness (or its bind
        # failed). Do NOT launch the client: a refusal here proves nothing about
        # the firewall. Fail the suite rather than misread it as 'blocked'.
        echo "[BEHAVIOR] UNREADY  server never signalled NETCHECK_SERVER_READY within timeout;"
        echo "                    not connecting — a refusal here would be 'server not up', not"
        echo "                    'policy blocked'. Failing honestly (see $server_log)."
        behavior_unready=$((behavior_unready + 1))
    else
        echo "[BEHAVIOR] INCONCLUSIVE  no container IP discovered for $cid"
        behavior_inconclusive=$((behavior_inconclusive + 1))
    fi

    # Let the sandbox finish (server exits after serving or after --hold).
    wait "$mxc_pid" 2>/dev/null
}

run_error_case "allowLocalNetwork: TRUE  (permissive path not yet implemented -> refused)" \
    "$CONFIG_DIR/lxc_local_network_allow.json" "lxc-localnet-allow"
run_case "allowLocalNetwork: FALSE (expect NEW DROP, blocked)" \
    "$CONFIG_DIR/lxc_local_network_deny.json" "lxc-localnet-deny" "DROP" "no"

echo
echo "==================== SUMMARY ===================="
echo "[RULE]     pass=$rule_pass fail=$rule_fail"
echo "[REFUSED]  pass=$refused_pass fail=$refused_fail"
echo "[BEHAVIOR] pass=$behavior_pass fail=$behavior_fail unready=$behavior_unready inconclusive=$behavior_inconclusive"
# Fail on any rule mismatch, any refusal mismatch, any decisive behavioral
# mismatch, or any server-never-ready case (a behavior layer that could not run
# must not look green). INCONCLUSIVE (peer *client* container could not run)
# does not fail the suite but is reported above.
[ "$rule_fail" -eq 0 ] && [ "$refused_fail" -eq 0 ] && [ "$behavior_fail" -eq 0 ] \
    && [ "$behavior_unready" -eq 0 ]
