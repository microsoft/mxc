#!/bin/bash
# Bubblewrap network-proxy sandbox tests.
#
# These tests do NOT require root. Proxy mode uses a private network namespace
# with rootless slirp4netns routing to the host-side builtin proxy.
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

run_one() {
    local label="$1"
    local config="$2"
    local sentinel="$3"
    echo "Running Bubblewrap network proxy test: $label..."
    local out
    if ! out=$("$LXC_EXEC" --experimental --allow-testing-features "$REPO_DIR/tests/configs/$config" 2>&1); then
        echo "$out"
        echo "FAIL: $label (lxc-exec returned non-zero)"
        return 1
    fi
    if ! grep -q "$sentinel" <<<"$out"; then
        echo "$out"
        echo "FAIL: $label (sentinel '$sentinel' not found in output)"
        return 1
    fi
    echo "PASS: $label"
}

run_one "builtin proxy"    "bubblewrap_network_proxy_builtin.json"    "PROXY_OK"
run_one "proxy allowlist"  "bubblewrap_network_proxy_allowlist.json"  "BLOCKED_OK"
run_one "proxy blocklist"  "bubblewrap_network_proxy_blocklist.json"  "BLOCKED_OK"

echo "Running Bubblewrap private proxy namespace test..."
HOST_NETNS="$(readlink /proc/self/ns/net)"
if ! NAMESPACE_OUT=$("$LXC_EXEC" --experimental --allow-testing-features \
    "$REPO_DIR/tests/configs/bubblewrap_network_proxy_namespace.json" 2>&1); then
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

# Schema <= 0.7 must keep the pre-0.8 proxy behavior: GHCP consumes Bubblewrap
# proxy mode on 0.6/0.7, so the private-namespace work must be invisible there.
# The unit tests only inspect generated arguments; this runs the legacy path for
# real and asserts all three properties that make it compatible.
#
# slirp4netns is deliberately shadowed with a failing stub for this case: the
# legacy path must neither probe nor use it, so the run succeeding with a broken
# slirp4netns is what proves the dependency is 0.8-only.
echo "Running Bubblewrap legacy (schema 0.7) proxy compatibility test..."
STUB_DIR="$(mktemp -d)"
trap 'rm -rf "$STUB_DIR"' EXIT
printf '#!/bin/sh\necho "slirp4netns must not be used on the legacy proxy path" >&2\nexit 1\n' \
    > "$STUB_DIR/slirp4netns"
chmod +x "$STUB_DIR/slirp4netns"

if ! LEGACY_OUT=$(PATH="$STUB_DIR:$PATH" "$LXC_EXEC" --experimental --allow-testing-features \
    "$REPO_DIR/tests/configs/bubblewrap_network_proxy_legacy.json" 2>&1); then
    echo "$LEGACY_OUT"
    echo "FAIL: legacy proxy (lxc-exec returned non-zero)"
    exit 1
fi

LEGACY_NETNS="$(sed -n 's/^SANDBOX_NETNS=//p' <<<"$LEGACY_OUT" | tail -n 1)"
if [ "$LEGACY_NETNS" != "$HOST_NETNS" ]; then
    echo "$LEGACY_OUT"
    echo "FAIL: legacy proxy (expected the host network namespace $HOST_NETNS, got $LEGACY_NETNS)"
    exit 1
fi

LEGACY_PROXY="$(sed -n 's/^SANDBOX_PROXY=//p' <<<"$LEGACY_OUT" | tail -n 1)"
case "$LEGACY_PROXY" in
    *127.0.0.1*) ;;
    *)
        echo "$LEGACY_OUT"
        echo "FAIL: legacy proxy (proxy address was rewritten away from loopback: $LEGACY_PROXY)"
        exit 1
        ;;
esac

if ! grep -q "LEGACY_PROXY_OK" <<<"$LEGACY_OUT"; then
    echo "$LEGACY_OUT"
    echo "FAIL: legacy proxy (proxied request did not complete)"
    exit 1
fi
echo "PASS: legacy (schema 0.7) proxy compatibility"

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
trap 'rm -rf "$STUB_DIR" "$BWRAP_STUB_DIR"' EXIT
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
PATH="$BWRAP_STUB_DIR:$PATH" "$LXC_EXEC" --experimental --allow-testing-features \
    "$REPO_DIR/tests/configs/bubblewrap_network_proxy_namespace.json" >/dev/null 2>&1 &
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

echo "Bubblewrap network proxy tests complete."
