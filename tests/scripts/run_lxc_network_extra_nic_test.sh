#!/bin/bash
# LXC extra-interface isolation test
#
# A schema 0.8 request naming no network fields must leave the workload with
# loopback and nothing else.  The container is started with no interface rather
# than filtered, so no chain is installed and any interface that survives is
# unfiltered network access under a policy that granted none.
#
# The first run creates the container through MXC.  A second interface is then
# added to its config, which a container MXC did not create can legitimately
# carry, and the second run reuses it under the same policy.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_DIR="$(dirname "$(dirname "$SCRIPT_DIR")")"
LXC_EXEC="$REPO_DIR/src/target/release/lxc-exec"

if [ ! -f "$LXC_EXEC" ]; then
    LXC_EXEC="$REPO_DIR/src/target/debug/lxc-exec"
fi

SKIP_EXIT=77
skip() {
    echo "SKIP: $1"
    exit "$SKIP_EXIT"
}

fail() {
    echo "FAIL: $1"
    exit 1
}

[ "$(id -u)" -eq 0 ] || skip "requires root for LXC."
command -v lxc-create >/dev/null 2>&1 || skip "LXC (lxc-create) is not installed."
command -v lxc-info >/dev/null 2>&1 || skip "LXC (lxc-info) is not installed."
[ -f "$LXC_EXEC" ] || skip "lxc-exec binary not built; run build.sh first."

CONFIG="$REPO_DIR/tests/configs/lxc_network_extra_nic_omit.json"
CONTAINER="CLI-LXC-Extra-Nic"

[ -f "$CONFIG" ] || fail "fixture $CONFIG is missing."

# Drift guards: the fixture has to keep the two properties this test needs.
if grep -Fq '"network"' "$CONFIG"; then
    fail "fixture $(basename "$CONFIG") carries a network section, so it no longer covers the omitted-section case."
fi
if ! grep -Fq '"destroyOnExit": false' "$CONFIG"; then
    fail "fixture $(basename "$CONFIG") destroys its container, so the second run cannot reuse one."
fi

# This test deliberately leaves a container behind between its two runs.
cleanup() {
    lxc-destroy -n "$CONTAINER" -f >/dev/null 2>&1 || true
}
trap cleanup EXIT
lxc-destroy -n "$CONTAINER" -f >/dev/null 2>&1 || true

RUN_OUTPUT=""

run_config() {
    local label="$1" status=0
    echo "--- $label ---"
    set +e
    RUN_OUTPUT=$("$LXC_EXEC" --debug "$CONFIG" 2>&1)
    status=$?
    set -e
    echo "$RUN_OUTPUT"
    if [ "$status" -ne 0 ]; then
        fail "$label exited $status."
    fi
}

assert_loopback_only() {
    # The workload tags each interface name, so the assertion cannot be
    # confused by the runner's own log lines.  The container runs under a pty,
    # which ends every line with a carriage return.
    local tagged found
    tagged=$(tr -d '\r' <<<"$RUN_OUTPUT" | grep -oE '^IFACE=.*' || true)
    found=$(sed 's/^IFACE=//' <<<"$tagged" | grep -vx 'lo' || true)
    if ! grep -qx 'IFACE=lo' <<<"$tagged"; then
        fail "the container reported no loopback interface at all; the workload did not run."
    fi
    if [ -n "$found" ]; then
        fail "$1 Interfaces beyond loopback: $(tr '\n' ' ' <<<"$found")"
    fi
}

echo "Running LXC extra-interface isolation test..."

run_config "run 1: MXC creates the container under a policy naming no network fields"
assert_loopback_only "a container MXC created under a policy that grants no network was given more than loopback."

CONFIG_FILE="$(lxc-info -n "$CONTAINER" -c lxc.rootfs.path >/dev/null 2>&1 && echo "/var/lib/lxc/$CONTAINER/config" || echo "")"
if [ -z "$CONFIG_FILE" ] || [ ! -f "$CONFIG_FILE" ]; then
    fail "run 1 left no container config at /var/lib/lxc/$CONTAINER/config for the second run to reuse."
fi

# A second interface, which a container MXC did not create can carry.
cat >> "$CONFIG_FILE" <<'EOF'
lxc.net.1.type = veth
lxc.net.1.link = lxcbr0
lxc.net.1.flags = up
EOF
echo "--- added a second interface to the container's config ---"
grep -E '^lxc\.net\.[0-9]+\.type' "$CONFIG_FILE" || true

run_config "run 2: reuse the container, now carrying a second interface"
assert_loopback_only "a reused container carrying a second interface kept it under a policy that grants no network. The run installs no firewall, so the workload has unfiltered access the policy never granted."

echo "PASS: every configured interface is emptied, not just the first."
echo "LXC extra-interface isolation test complete."
