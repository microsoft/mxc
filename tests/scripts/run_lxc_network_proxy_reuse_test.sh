#!/bin/bash
# LXC proxy host pin lifetime test
#
# The pin names the one address this run's chain authorized, so a container
# that outlives the run must not keep it. No other script covers reuse: every
# proxy fixture destroys its container on exit, which disposes of the pin as a
# side effect and proves nothing about who owns it.
#
# The proxy is never contacted here. The pin is written before the script runs
# and removed after it, both independently of whether the address answers, so
# an unroutable TEST-NET-1 literal is enough and no proxy fixture is needed.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_DIR="$(dirname "$(dirname "$SCRIPT_DIR")")"
LXC_EXEC="$REPO_DIR/src/target/release/lxc-exec"

if [ ! -f "$LXC_EXEC" ]; then
    LXC_EXEC="$REPO_DIR/src/target/debug/lxc-exec"
fi

CONFIG="$REPO_DIR/tests/configs/lxc_network_proxy_reuse.json"
CONTAINER="CLI-LXC-Proxy-Reuse"
CONTAINER_HOSTS="/var/lib/lxc/$CONTAINER/rootfs/etc/hosts"
PROXY_HOSTNAME="proxy.mxc.test"
PROXY_IP="192.0.2.2"
MARKER="#mxc-proxy-pin"

SKIP_EXIT=77
skip() {
    echo "SKIP: $1"
    exit "$SKIP_EXIT"
}

fail() {
    echo "FAIL: $1"
    exit 1
}

[ "$(id -u)" -eq 0 ] || skip "requires root for LXC and /etc/hosts."
command -v lxc-create >/dev/null 2>&1 || skip "LXC (lxc-create) is not installed."
[ -f "$LXC_EXEC" ] || skip "lxc-exec binary not built; run build.sh first."

HOSTS_BACKUP=""

cleanup() {
    if [ -n "$HOSTS_BACKUP" ] && [ -f "$HOSTS_BACKUP" ]; then
        cat "$HOSTS_BACKUP" > /etc/hosts
        rm -f "$HOSTS_BACKUP"
    fi
    lxc-destroy -n "$CONTAINER" -f >/dev/null 2>&1 || true
}
trap cleanup EXIT

lxc-destroy -n "$CONTAINER" -f >/dev/null 2>&1 || true

# The host resolves the proxy name while building the policy, and pins whatever
# it resolved into the container.
HOSTS_BACKUP="$(mktemp)"
cat /etc/hosts > "$HOSTS_BACKUP"
printf '%s %s\n' "$PROXY_IP" "$PROXY_HOSTNAME" >> /etc/hosts

assert_pin_gone_from_container() {
    [ -f "$CONTAINER_HOSTS" ] || fail "container rootfs hosts file $CONTAINER_HOSTS is missing after $1."
    if grep -Fq "$MARKER" "$CONTAINER_HOSTS"; then
        fail "the proxy pin outlived $1: $(grep -F "$MARKER" "$CONTAINER_HOSTS" | head -1)"
    fi
}

run_once() {
    local label="$1" out status
    set +e
    out=$("$LXC_EXEC" --debug "$CONFIG" 2>&1)
    status=$?
    set -e
    echo "$out"

    if [ "$status" -ne 0 ]; then
        fail "$label exited $status."
    fi
    if ! grep -Fq "Pinning proxy host $PROXY_HOSTNAME to $PROXY_IP" <<<"$out"; then
        fail "$label never wrote a pin, so its removal is not being tested."
    fi
    if ! grep -Fq "PIN_PRESENT_DURING_RUN" <<<"$out"; then
        fail "$label logged a pin the container could not see."
    fi
    if ! lxc-info -n "$CONTAINER" >/dev/null 2>&1; then
        fail "destroyOnExit was false, but $label destroyed the container."
    fi
    assert_pin_gone_from_container "$label"
}

echo "Running LXC proxy host pin lifetime test..."

echo "--- first run: creates the container ---"
run_once "the first run"

# A second run over the surviving container proves the removal did not make the
# container unusable, and that reuse pins again from a clean file.
echo "--- second run: reuses the container the first run left behind ---"
run_once "the second run"

echo "PASS: the pin was present during each run and gone from the reused container afterwards."
echo "LXC proxy host pin lifetime test complete."
