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

echo "Running Bubblewrap proxy-only egress enforcement test..."
if ! EGRESS_OUT=$("$LXC_EXEC" --experimental --allow-testing-features \
    "$REPO_DIR/tests/configs/bubblewrap_network_proxy_egress_denied.json" 2>&1); then
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

# Hostname proxy endpoints. The endpoint is resolved on the host and pinned
# into the sandbox's /etc/hosts, because DNS is closed inside the sandbox.
echo "Running Bubblewrap hostname proxy pin test..."
PROXY_HOST="$(hostname)"
# The host's own name is used because it resolves everywhere without editing
# /etc/hosts (which would need root). Where it points is not fixed, though: a
# workstation maps it to loopback, a cloud runner to a routable address. Both
# are cases the pin must handle, so the proxy is bound to whatever the name
# actually resolves to rather than assuming loopback -- binding 127.0.0.1 while
# the name resolves routably leaves the sandbox dialing a closed port.
PROXY_BIND="$(getent ahostsv4 "$PROXY_HOST" 2>/dev/null | awk 'NR==1 {print $1}')"
if [ -z "$PROXY_BIND" ]; then
    echo "FAIL: hostname proxy pin (host name '$PROXY_HOST' does not resolve to an IPv4 address)"
    exit 1
fi
# A loopback answer is redirected to slirp's gateway, and the gateway lands on
# the host's 127.0.0.1 -- not on the exact loopback address the name carries
# (Ubuntu maps the machine name to 127.0.1.1). Binding there is what the
# sandbox can actually reach, and is where a real proxy would listen.
case "$PROXY_BIND" in
    127.*) PROXY_BIND=127.0.0.1 ;;
esac
echo "  host name '$PROXY_HOST' resolves to $PROXY_BIND"
# The proxy lives beside lxc-exec, wherever that came from: CI overrides
# LXC_EXEC with a --target build under src/target/<triple>/release, which the
# repo-relative fallbacks below do not cover. Every other case in this file
# reaches the proxy through the coordinator, which already resolves it that
# way -- this is the one that spawns it directly.
TEST_PROXY="$(dirname "$LXC_EXEC")/unix-test-proxy"
if [ ! -x "$TEST_PROXY" ]; then
    TEST_PROXY="$REPO_DIR/src/target/release/unix-test-proxy"
fi
if [ ! -x "$TEST_PROXY" ]; then
    TEST_PROXY="$REPO_DIR/src/target/debug/unix-test-proxy"
fi
if [ ! -x "$TEST_PROXY" ]; then
    echo "FAIL: hostname proxy pin (unix-test-proxy not built)"
    exit 1
fi

PIN_DIR="$(mktemp -d)"
PIN_PROXY_PID=""
cleanup_pin() {
    if [ -n "$PIN_PROXY_PID" ]; then
        kill "$PIN_PROXY_PID" 2>/dev/null || true
        wait "$PIN_PROXY_PID" 2>/dev/null || true
    fi
    exec 9>&- 2>/dev/null || true
    rm -rf "$PIN_DIR"
}
trap cleanup_pin EXIT

# The proxy exits when its stdin reaches EOF, which is how the coordinator
# stops an orphan. Driving it from a script means supplying that pipe here:
# the fifo is opened read-write so the open does not block, and the script
# holding it keeps the proxy alive for the run.
mkfifo "$PIN_DIR/parent.pipe"
exec 9<>"$PIN_DIR/parent.pipe"

# The proxy binds an OS-assigned port and publishes it, so the config is
# generated per run rather than committed with a fixed port.
"$TEST_PROXY" --ready-file "$PIN_DIR/ready.port" --bind-address "$PROXY_BIND" \
    <"$PIN_DIR/parent.pipe" >"$PIN_DIR/proxy.log" 2>&1 &
PIN_PROXY_PID=$!
for _ in $(seq 1 100); do
    [ -s "$PIN_DIR/ready.port" ] && break
    if ! kill -0 "$PIN_PROXY_PID" 2>/dev/null; then
        cat "$PIN_DIR/proxy.log"
        echo "FAIL: hostname proxy pin (test proxy exited before publishing its port)"
        exit 1
    fi
    sleep 0.1
done
PROXY_PORT="$(cat "$PIN_DIR/ready.port" 2>/dev/null || true)"
if [ -z "$PROXY_PORT" ]; then
    cat "$PIN_DIR/proxy.log"
    echo "FAIL: hostname proxy pin (test proxy did not publish a port)"
    exit 1
fi

sed -e "s/{{PROXY_HOST}}/$PROXY_HOST/g" -e "s/{{PROXY_PORT}}/$PROXY_PORT/g" \
    "$REPO_DIR/tests/configs/bubblewrap_network_proxy_hostname.json" \
    >"$PIN_DIR/hostname.json"

if ! PIN_OUT=$("$LXC_EXEC" --experimental --allow-testing-features \
    "$PIN_DIR/hostname.json" 2>&1); then
    echo "$PIN_OUT"
    echo "FAIL: hostname proxy pin (lxc-exec returned non-zero)"
    exit 1
fi
for sentinel in PIN_PRESENT_OK PIN_PROXY_OK PIN_DIRECT_BLOCKED_OK; do
    if ! grep -q "$sentinel" <<<"$PIN_OUT"; then
        echo "$PIN_OUT"
        echo "FAIL: hostname proxy pin (sentinel '$sentinel' not found in output)"
        exit 1
    fi
done
cleanup_pin
trap - EXIT
echo "PASS: hostname proxy pin"

# The pin outranks every filesystem-policy mount, so a policy that denies
# /etc/hosts has to be refused rather than silently handed the file back.
echo "Running Bubblewrap hostname pin vs denied /etc/hosts test..."
DENY_DIR="$(mktemp -d)"
trap 'rm -rf "$DENY_DIR"' EXIT
cat >"$DENY_DIR/denied.json" <<JSON
{
  "version": "0.8.0-alpha",
  "containerId": "CLI-Bubblewrap-Pin-Denied-Hosts",
  "containment": "bubblewrap",
  "process": { "commandLine": "echo PIN_DENIED_HOSTS_RAN" },
  "filesystem": { "deniedPaths": ["/etc/hosts"] },
  "network": {
    "defaultPolicy": "allow",
    "proxy": { "url": "http://proxy.example.com:3128" }
  }
}
JSON
DENY_OUT=$("$LXC_EXEC" --experimental --allow-testing-features \
    "$DENY_DIR/denied.json" 2>&1) && DENY_RC=0 || DENY_RC=$?
if [ "$DENY_RC" = 0 ]; then
    echo "$DENY_OUT"
    echo "FAIL: hostname pin vs denied /etc/hosts (accepted a policy it cannot honour)"
    exit 1
fi
if grep -q PIN_DENIED_HOSTS_RAN <<<"$DENY_OUT"; then
    echo "$DENY_OUT"
    echo "FAIL: hostname pin vs denied /etc/hosts (workload ran despite the rejection)"
    exit 1
fi
if ! grep -qF "deniedPaths" <<<"$DENY_OUT"; then
    echo "$DENY_OUT"
    echo "FAIL: hostname pin vs denied /etc/hosts (rejection did not name the conflict)"
    exit 1
fi
rm -rf "$DENY_DIR"
trap - EXIT
echo "PASS: hostname pin vs denied /etc/hosts"

# The same denial spelled with `..` normalizes to /etc/hosts before the masks
# are built, so it must be refused too -- checking only the written form let it
# through and the pin handed the file back.
echo "Running Bubblewrap hostname pin vs dot-dot denied /etc/hosts test..."
DOTDOT_DIR="$(mktemp -d)"
trap 'rm -rf "$DOTDOT_DIR"' EXIT
cat >"$DOTDOT_DIR/dotdot.json" <<JSON
{
  "version": "0.8.0-alpha",
  "containerId": "CLI-Bubblewrap-Pin-DotDot-Hosts",
  "containment": "bubblewrap",
  "process": { "commandLine": "cat /etc/hosts" },
  "filesystem": { "deniedPaths": ["/etc/../etc/hosts"] },
  "network": {
    "defaultPolicy": "allow",
    "proxy": { "url": "http://$PROXY_HOST:$PROXY_PORT" }
  }
}
JSON
DOTDOT_OUT=$("$LXC_EXEC" --experimental --allow-testing-features \
    "$DOTDOT_DIR/dotdot.json" 2>&1) && DOTDOT_RC=0 || DOTDOT_RC=$?
if [ "$DOTDOT_RC" = 0 ]; then
    echo "$DOTDOT_OUT"
    echo "FAIL: dot-dot denied /etc/hosts (accepted a policy it cannot honour)"
    exit 1
fi
if grep -q "localhost" <<<"$DOTDOT_OUT"; then
    echo "$DOTDOT_OUT"
    echo "FAIL: dot-dot denied /etc/hosts (the pin exposed the masked file)"
    exit 1
fi
if ! grep -qF "deniedPaths" <<<"$DOTDOT_OUT"; then
    echo "$DOTDOT_OUT"
    echo "FAIL: dot-dot denied /etc/hosts (rejection did not name the conflict)"
    exit 1
fi
rm -rf "$DOTDOT_DIR"
trap - EXIT
echo "PASS: hostname pin vs dot-dot denied /etc/hosts"

# The same policy on the legacy schema pins nothing, so it must still run --
# 0.6/0.7 behaviour is unchanged by the rejection above.
echo "Running Bubblewrap legacy (schema 0.7) denied /etc/hosts compatibility test..."
LEGACY_DIR="$(mktemp -d)"
trap 'rm -rf "$LEGACY_DIR"' EXIT
cat >"$LEGACY_DIR/legacy.json" <<JSON
{
  "version": "0.7.0-alpha",
  "containerId": "CLI-Bubblewrap-Legacy-Denied-Hosts",
  "containment": "bubblewrap",
  "process": { "commandLine": "echo LEGACY_DENIED_HOSTS_OK" },
  "filesystem": { "deniedPaths": ["/etc/hosts"] },
  "network": {
    "defaultPolicy": "allow",
    "proxy": { "url": "http://proxy.example.com:3128" }
  }
}
JSON
LEGACY_OUT=$("$LXC_EXEC" --experimental --allow-testing-features \
    "$LEGACY_DIR/legacy.json" 2>&1) || true
if grep -qF "deniedPaths" <<<"$LEGACY_OUT"; then
    echo "$LEGACY_OUT"
    echo "FAIL: legacy denied /etc/hosts (0.7 inherited the 0.8 rejection)"
    exit 1
fi
if ! grep -q LEGACY_DENIED_HOSTS_OK <<<"$LEGACY_OUT"; then
    echo "$LEGACY_OUT"
    echo "FAIL: legacy denied /etc/hosts (workload did not run)"
    exit 1
fi
rm -rf "$LEGACY_DIR"
trap - EXIT
echo "PASS: legacy (schema 0.7) denied /etc/hosts compatibility"

echo "Bubblewrap network proxy tests complete."
