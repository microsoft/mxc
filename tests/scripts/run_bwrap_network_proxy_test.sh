#!/bin/bash
# Bubblewrap network-proxy sandbox tests.
#
# These tests do NOT require root. Proxy mode uses a private network namespace
# with rootless slirp4netns routing to a host-side proxy named by
# `runtimeConfig.networkProxy`.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_DIR="$(dirname "$(dirname "$SCRIPT_DIR")")"
# CI builds to a target-triple subdirectory, so allow the caller to point at a
# specific binary instead of guessing. An explicitly set LXC_EXEC is taken
# literally: falling back from it would silently exercise a different binary
# than the caller named -- a stale debug build passing while release is broken.
if [ -n "${LXC_EXEC:-}" ]; then
    if [ ! -f "$LXC_EXEC" ]; then
        echo "Error: LXC_EXEC is set to '$LXC_EXEC', which does not exist."
        exit 1
    fi
else
    LXC_EXEC="$REPO_DIR/src/target/release/lxc-exec"
    if [ ! -f "$LXC_EXEC" ]; then
        LXC_EXEC="$REPO_DIR/src/target/debug/lxc-exec"
    fi

    if [ ! -f "$LXC_EXEC" ]; then
        echo "Error: lxc-exec not found. Run build.sh first."
        exit 1
    fi
fi

# CI builds to a target-triple subdirectory, so prefer the directory holding
# LXC_EXEC before the repo-relative fallbacks.
resolve_test_proxy() {
    local candidate
    for candidate in "$(dirname "$LXC_EXEC")/unix-test-proxy" \
        "$REPO_DIR/src/target/release/unix-test-proxy" \
        "$REPO_DIR/src/target/debug/unix-test-proxy"; do
        if [ -x "$candidate" ]; then
            printf '%s\n' "$candidate"
            return 0
        fi
    done
    return 1
}

# A host-side listener on a port the proxy policy does not allow: proxy mode
# accepts only the proxy's own port on slirp's gateway (EgressPlan::for_proxy).
# Direct-egress assertions aim at it rather than an internet address, so a
# refusal is evidence of the drop and not of a runner with no outbound route.
# It doubles as the CONNECT target below, which is what proves it was live.
PROXY_BIN="$(resolve_test_proxy)" || {
    echo "Error: unix-test-proxy not found. Run build.sh first."
    exit 1
}
CONTROL_DIR="$(mktemp -d)"
CONTROL_PID=""
PROXY_ENDPOINT_PID=""
cleanup_control() {
    local pid
    for pid in "$CONTROL_PID" "$PROXY_ENDPOINT_PID"; do
        if [ -n "$pid" ]; then
            kill "$pid" 2>/dev/null || true
            wait "$pid" 2>/dev/null || true
        fi
    done
    # This runs once explicitly and again from the EXIT trap. A reaped PID can
    # be reused by an unrelated process before then, so forget it once reaped.
    CONTROL_PID=""
    PROXY_ENDPOINT_PID=""
    exec 7>&- 2>/dev/null || true
    exec 8>&- 2>/dev/null || true
    rm -rf "$CONTROL_DIR"
}
trap cleanup_control EXIT

# The listener exits when its stdin reaches EOF; the fifo is opened read-write
# so the open does not block and the script holding it keeps the listener up.
mkfifo "$CONTROL_DIR/parent.pipe"
exec 8<>"$CONTROL_DIR/parent.pipe"
# 8>&- keeps the listener from inheriting the write end: holding one itself
# would mean its stdin never reports EOF, orphaning it if this script is killed.
"$PROXY_BIN" --ready-file "$CONTROL_DIR/ready.port" --bind-address 127.0.0.1 \
    <"$CONTROL_DIR/parent.pipe" >"$CONTROL_DIR/listener.log" 2>&1 8>&- &
CONTROL_PID=$!
for _ in $(seq 1 100); do
    [ -s "$CONTROL_DIR/ready.port" ] && break
    if ! kill -0 "$CONTROL_PID" 2>/dev/null; then
        cat "$CONTROL_DIR/listener.log"
        echo "FAIL: the control listener exited before publishing its port."
        exit 1
    fi
    sleep 0.1
done
CONTROL_PORT="$(cat "$CONTROL_DIR/ready.port" 2>/dev/null || true)"
if [ -z "$CONTROL_PORT" ]; then
    cat "$CONTROL_DIR/listener.log"
    echo "FAIL: the control listener did not publish a port."
    exit 1
fi
echo "  control listener on 127.0.0.1:$CONTROL_PORT (10.0.2.2:$CONTROL_PORT from the sandbox)"

# Schema 0.9 removed `network.proxy` entirely, so `builtinTestServer` has no
# 0.9 spelling: a proxy is a real endpoint named by
# `runtimeConfig.networkProxy`, which the parser accepts only on loopback. This
# second listener is that endpoint, and the backend translates it to slirp's
# gateway on the way in. It serves `http://mxc-test.invalid/`, so the 0.9
# workloads assert the same sentinels the builtin server used to produce.
mkfifo "$CONTROL_DIR/proxy.pipe"
exec 7<>"$CONTROL_DIR/proxy.pipe"
# 7>&- and 8>&- keep this listener from holding either fifo's write end open,
# which would stop its own stdin from ever reporting EOF.
"$PROXY_BIN" --ready-file "$CONTROL_DIR/proxy.port" --bind-address 127.0.0.1 \
    <"$CONTROL_DIR/proxy.pipe" >"$CONTROL_DIR/proxy.log" 2>&1 7>&- 8>&- &
PROXY_ENDPOINT_PID=$!
for _ in $(seq 1 100); do
    [ -s "$CONTROL_DIR/proxy.port" ] && break
    if ! kill -0 "$PROXY_ENDPOINT_PID" 2>/dev/null; then
        cat "$CONTROL_DIR/proxy.log"
        echo "FAIL: the proxy endpoint exited before publishing its port."
        exit 1
    fi
    sleep 0.1
done
PROXY_PORT="$(cat "$CONTROL_DIR/proxy.port" 2>/dev/null || true)"
if [ -z "$PROXY_PORT" ]; then
    cat "$CONTROL_DIR/proxy.log"
    echo "FAIL: the proxy endpoint did not publish a port."
    exit 1
fi
echo "  proxy endpoint on 127.0.0.1:$PROXY_PORT (10.0.2.2:$PROXY_PORT from the sandbox)"

# Both ports are assigned by the OS per run, so configs carry placeholders and
# are rendered into the run's scratch directory.
render_config() {
    sed -e "s/{{CONTROL_PORT}}/$CONTROL_PORT/g" -e "s/{{PROXY_PORT}}/$PROXY_PORT/g" \
        "$REPO_DIR/tests/configs/$1" >"$CONTROL_DIR/$1"
    printf '%s\n' "$CONTROL_DIR/$1"
}

# Every sentinel named must appear. A workload that reports only its deny leg
# would pass while its allowed request was silently failing, which is the class
# of false result these tests exist to catch.
run_one() {
    local label="$1"
    local config="$2"
    shift 2
    echo "Running Bubblewrap network proxy test: $label..."
    local out sentinel
    if ! out=$("$LXC_EXEC" --experimental "$(render_config "$config")" 2>&1); then
        echo "$out"
        echo "FAIL: $label (lxc-exec returned non-zero)"
        return 1
    fi
    for sentinel in "$@"; do
        if ! grep -q "$sentinel" <<<"$out"; then
            echo "$out"
            echo "FAIL: $label (sentinel '$sentinel' not found in output)"
            return 1
        fi
    done
    echo "PASS: $label"
}

run_one "runtime proxy" "bubblewrap_network_proxy_builtin.json" "PROXY_OK"

# A hostname in a CIDR rule cannot express a legacy host allow/block list.
# Refuse it before launching rather than broadening proxy-only confinement.
run_rejected() {
    local label="$1" config="$2" marker="$3" sentinel="$4"
    local out rc=0
    echo "Running Bubblewrap proxy migration rejection: $label..."
    out=$("$LXC_EXEC" --experimental \
        "$(render_config "$config")" 2>&1) || rc=$?
    if [ "$rc" -eq 0 ] || ! grep -qF "$marker" <<<"$out" ||
        grep -qF "$sentinel" <<<"$out"; then
        echo "$out"
        echo "FAIL: $label (expected a pre-execution rejection of $marker, exit=$rc)"
        exit 1
    fi
    echo "PASS: $label"
}

run_rejected "hostname allowlist" "bubblewrap_network_proxy_allowlist.json" \
    "must be a valid network CIDR" "SENTINEL_OK"
run_rejected "hostname blocklist" "bubblewrap_network_proxy_blocklist.json" \
    "must be a valid network CIDR" "SENTINEL_OK"
run_rejected "hostname host rules" "bubblewrap_network_proxy_host_rules.json" \
    "must be a valid network CIDR" "DIRECT_EGRESS_BLOCKED_OK"

echo "Running Bubblewrap private proxy namespace test (schema 0.9)..."
HOST_NETNS="$(readlink /proc/self/ns/net)"
NAMESPACE_CONFIG="$(render_config bubblewrap_network_proxy_namespace.json)"
if ! NAMESPACE_OUT=$("$LXC_EXEC" --experimental "$NAMESPACE_CONFIG" 2>&1); then
    echo "$NAMESPACE_OUT"
    echo "FAIL: private proxy namespace (lxc-exec returned non-zero)"
    exit 1
fi
SANDBOX_NETNS="$(sed -n 's/^SANDBOX_NETNS=//p' <<<"$NAMESPACE_OUT" | tail -n 1)"
if [ -z "$SANDBOX_NETNS" ]; then
    echo "$NAMESPACE_OUT"
    echo "FAIL: private proxy namespace (namespace identity not reported)"
    exit 1
fi
if [ "$SANDBOX_NETNS" = "$HOST_NETNS" ]; then
    echo "$NAMESPACE_OUT"
    echo "FAIL: private proxy namespace (sandbox shares host network namespace)"
    exit 1
fi
if ! grep -q "PROXY_NAMESPACE_OK" <<<"$NAMESPACE_OUT"; then
    echo "$NAMESPACE_OUT"
    echo "FAIL: private proxy namespace (proxy request did not complete)"
    exit 1
fi
echo "PASS: private proxy namespace"

# Proxy mode has bwrap join the supervisor's user namespace instead of creating
# its own, and that namespace descriptor stays open in the workload (bwrap keeps
# it across its own fork+exec and upstream offers no way to close it). Re-entering
# it via setns requires CAP_SYS_ADMIN, so containment rests entirely on bwrap
# emptying the capability sets before exec. Assert that here: if a future bwrap
# ever leaves a non-empty bounding set, proxy mode must stop sharing the
# supervisor's user namespace, and this test is what catches it.
echo "Running Bubblewrap proxy-namespace capability drop test..."
for cap_field in CAPBND CAPEFF CAPPRM; do
    cap_value="$(sed -n "s/^SANDBOX_${cap_field}=//p" <<<"$NAMESPACE_OUT" | tail -n 1)"
    if [ -z "$cap_value" ]; then
        echo "$NAMESPACE_OUT"
        echo "FAIL: capability drop ($cap_field not reported by the sandbox)"
        exit 1
    fi
    if [ "$cap_value" != "0000000000000000" ]; then
        echo "$NAMESPACE_OUT"
        echo "FAIL: capability drop ($cap_field is $cap_value, expected 0000000000000000)"
        exit 1
    fi
done
echo "PASS: proxy-namespace capability drop"

# The supervisor blocks on a parent-owned pipe waiting for the sandbox PID. If
# the executor dies in that window the read must hit EOF and the supervisor must
# exit; the earlier file-polling loop had no exit condition and leaked a process
# holding a live user namespace.
#
# bwrap is shadowed with a stub that never reports a PID, which holds the
# executor in its startup wait and widens that window from microseconds to
# seconds so the kill lands inside it deterministically.
echo "Running Bubblewrap supervisor orphan-reaping test..."
BWRAP_STUB_DIR="$(mktemp -d)"
trap 'cleanup_control; rm -rf "$BWRAP_STUB_DIR"' EXIT
cat > "$BWRAP_STUB_DIR/bwrap" <<STUB
#!/bin/sh
case "\$*" in
    *--version*) echo "bubblewrap 0.11.0"; exit 0 ;;
esac
echo \$\$ > "$BWRAP_STUB_DIR/stub.pid"
exec sleep 300
STUB
chmod +x "$BWRAP_STUB_DIR/bwrap"

SUPERVISOR_PATTERN="mxc-bwrap-proxy-supervisor"
PATH="$BWRAP_STUB_DIR:$PATH" "$LXC_EXEC" --experimental \
    "$NAMESPACE_CONFIG" >/dev/null 2>&1 &
ORPHAN_EXEC_PID=$!

SUPERVISOR_SEEN=0
for _ in $(seq 1 100); do
    if pgrep -f "$SUPERVISOR_PATTERN" >/dev/null 2>&1; then
        SUPERVISOR_SEEN=1
        break
    fi
    sleep 0.05
done

if [ "$SUPERVISOR_SEEN" -ne 1 ]; then
    kill -9 "$ORPHAN_EXEC_PID" 2>/dev/null || true
    wait "$ORPHAN_EXEC_PID" 2>/dev/null || true
    pkill -f "$SUPERVISOR_PATTERN" 2>/dev/null || true
    echo "FAIL: supervisor orphan reaping (the supervisor never started)"
    exit 1
fi

kill -9 "$ORPHAN_EXEC_PID" 2>/dev/null || true
wait "$ORPHAN_EXEC_PID" 2>/dev/null || true

SUPERVISOR_REAPED=0
for _ in $(seq 1 100); do
    if ! pgrep -f "$SUPERVISOR_PATTERN" >/dev/null 2>&1; then
        SUPERVISOR_REAPED=1
        break
    fi
    sleep 0.05
done

# The stub bwrap outlives the SIGKILLed executor by design; the real backend
# runs it as pid 1 of a pid namespace, so only this stub needs reaping. It
# records its own pid because it `exec`s sleep, leaving nothing for pkill to
# match on its command line.
if [ -f "$BWRAP_STUB_DIR/stub.pid" ]; then
    kill -9 "$(cat "$BWRAP_STUB_DIR/stub.pid")" 2>/dev/null || true
fi

if [ "$SUPERVISOR_REAPED" -ne 1 ]; then
    pkill -f "$SUPERVISOR_PATTERN" 2>/dev/null || true
    echo "FAIL: supervisor orphan reaping (the supervisor survived the executor)"
    exit 1
fi
echo "PASS: supervisor orphan reaping"

echo "Running Bubblewrap proxy-only egress enforcement test (schema 0.9)..."
if ! EGRESS_OUT=$("$LXC_EXEC" --experimental \
    "$(render_config bubblewrap_network_proxy_egress_denied.json)" 2>&1); then
    echo "$EGRESS_OUT"
    echo "FAIL: proxy-only egress (lxc-exec returned non-zero)"
    exit 1
fi
for sentinel in CONTROL_PROXY_REACHABLE_OK DIRECT_EGRESS_BLOCKED_OK LOOPBACK_EXEMPT_OK \
    CAP_NET_ADMIN_DROPPED_OK TAMPER_REFUSED_OK TAMPER_INEFFECTIVE_OK PROXY_STILL_OK; do
    if ! grep -q "$sentinel" <<<"$EGRESS_OUT"; then
        echo "$EGRESS_OUT"
        echo "FAIL: proxy-only egress (sentinel '$sentinel' not found in output)"
        exit 1
    fi
done
echo "PASS: proxy-only egress enforcement"

# Every other proxied request here is plain HTTP, so without this the tunnel
# path could regress while the suite stayed green. The target is the control
# listener, so the sentinel coming back proves both that the tunnel carried
# bytes and that the endpoint refused above was live.
echo "Running Bubblewrap proxy CONNECT tunnel test (schema 0.9)..."
if ! CONNECT_OUT=$("$LXC_EXEC" --experimental \
    "$(render_config bubblewrap_network_proxy_connect.json)" 2>&1); then
    echo "$CONNECT_OUT"
    echo "FAIL: proxy CONNECT tunnel (lxc-exec returned non-zero)"
    exit 1
fi
for sentinel in CONNECT_DIRECT_BLOCKED_OK CONNECT_TUNNEL_ESTABLISHED_OK CONNECT_TUNNEL_BODY_OK; do
    if ! grep -q "$sentinel" <<<"$CONNECT_OUT"; then
        echo "$CONNECT_OUT"
        echo "FAIL: proxy CONNECT tunnel (sentinel '$sentinel' not found in output)"
        exit 1
    fi
done
echo "PASS: proxy CONNECT tunnel"

# A non-loopback proxy address cannot be enforced by the supported runtime
# proxy policy. Its former /etc/hosts pinning path was specific to retired
# contracts, so keep a fail-closed migration check rather than a false positive.
run_rejected "remote hostname proxy" "bubblewrap_network_proxy_hostname.json" \
    "runtimeConfig.networkProxy" "PIN_PRESENT_OK"

echo "Bubblewrap network proxy tests complete."
