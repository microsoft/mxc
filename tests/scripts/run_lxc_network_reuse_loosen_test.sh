#!/bin/bash
# LXC reuse policy-loosening test
#
# Proves that a container reused under a policy that explicitly allows egress
# can reach the allowed destination, even when the previous run over the same
# container id carried no network section at all.  Run 1 is the positive
# control on a fresh container id: if it cannot reach the destination, run 3's
# blocked result proves nothing and the whole test fails rather than proceeding.
#
# The inverse of this scenario is covered by run_lxc_network_reuse_tighten_test.sh,
# which goes allowed-then-denied.  This test goes denied-then-allowed and pins
# the orthogonal half: loosening the policy on a reused container must restore
# access.
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

[ "$(id -u)" -eq 0 ] || skip "requires root for iptables/ip6tables and LXC."
command -v iptables >/dev/null 2>&1 || skip "iptables is not installed."
command -v ip6tables >/dev/null 2>&1 || skip "ip6tables is not installed."
command -v lxc-create >/dev/null 2>&1 || skip "LXC (lxc-create) is not installed."
[ -f "$LXC_EXEC" ] || skip "lxc-exec binary not built; run build.sh first."

CTRL_CONFIG="$REPO_DIR/tests/configs/lxc_network_reuse_loosen_ctrl.json"
DENY_CONFIG="$REPO_DIR/tests/configs/lxc_network_reuse_loosen_deny.json"
ALLOW_CONFIG="$REPO_DIR/tests/configs/lxc_network_reuse_loosen_allow.json"

CTRL_CONTAINER="CLI-LXC-Reuse-Loosen-Ctrl"
REUSE_CONTAINER="CLI-LXC-Reuse-Loosen"
PROBE_ADDRESS="140.82.114.6"

fixture_field() {
    sed -n "s/.*\"$2\"[[:space:]]*:[[:space:]]*\"\([^\"]*\)\".*/\1/p" "$1" | head -1
}

# Drift guard: all three fixtures must exist and declare a 0.8 schema, and all
# must probe the same address.
for config in "$CTRL_CONFIG" "$DENY_CONFIG" "$ALLOW_CONFIG"; do
    [ -f "$config" ] || fail "fixture $config is missing."

    schema_ver="$(sed -n 's/.*"version"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p' "$config" | head -1)"
    if ! echo "$schema_ver" | grep -q '^0\.8\.'; then
        fail "fixture $(basename "$config") declares schema '$schema_ver', not 0.8; this test is specific to 0.8 reuse behavior."
    fi

    if ! grep -Fq "$PROBE_ADDRESS" "$config"; then
        fail "fixture $(basename "$config") does not probe $PROBE_ADDRESS, so the runs are not measuring the same reachability."
    fi
done

# Drift guard: run 1 must use a different container id from runs 2 and 3.
actual_ctrl="$(fixture_field "$CTRL_CONFIG" containerId)"
if [ "$actual_ctrl" != "$CTRL_CONTAINER" ]; then
    fail "fixture $(basename "$CTRL_CONFIG") names container '$actual_ctrl', but run 1 must use '$CTRL_CONTAINER' (a fresh container, not the reuse id)."
fi

# Drift guard: runs 2 and 3 must name the same container id.
actual_deny="$(fixture_field "$DENY_CONFIG" containerId)"
actual_allow="$(fixture_field "$ALLOW_CONFIG" containerId)"
if [ "$actual_deny" != "$REUSE_CONTAINER" ]; then
    fail "fixture $(basename "$DENY_CONFIG") names container '$actual_deny', but runs 2 and 3 must both use '$REUSE_CONTAINER'."
fi
if [ "$actual_allow" != "$REUSE_CONTAINER" ]; then
    fail "fixture $(basename "$ALLOW_CONFIG") names container '$actual_allow', but runs 2 and 3 must both use '$REUSE_CONTAINER'."
fi
if [ "$actual_ctrl" = "$REUSE_CONTAINER" ]; then
    fail "run 1 uses the same container id as runs 2 and 3; run 1 must be a fresh container so it does not contaminate the reuse scenario."
fi

# Drift guard: the allow fixtures (runs 1 and 3) must carry a network section
# with an egress allow rule covering the probe address.
for config in "$CTRL_CONFIG" "$ALLOW_CONFIG"; do
    if ! grep -Fq '"network"' "$config"; then
        fail "fixture $(basename "$config") carries no network section; it cannot serve as a positive-control or allow case."
    fi
    if ! grep -Fq '"cidr": "140.82.112.0/20"' "$config"; then
        fail "fixture $(basename "$config") no longer permits the range that contains $PROBE_ADDRESS."
    fi
done

# Drift guard: the no-network fixture (run 2) must have no network section at
# all -- that is the setup this test depends on.
if grep -Fq '"network"' "$DENY_CONFIG"; then
    fail "fixture $(basename "$DENY_CONFIG") contains a network section; run 2 must carry no network section at all."
fi

# Drift guard: runs 2 and 3 must keep the container alive so run 3 reuses it.
for config in "$DENY_CONFIG" "$ALLOW_CONFIG"; do
    if ! grep -Fq '"destroyOnExit": false' "$config"; then
        fail "fixture $(basename "$config") does not set destroyOnExit false, so no container survives for the next run to reuse."
    fi
done

cleanup() {
    lxc-destroy -n "$CTRL_CONTAINER" -f >/dev/null 2>&1 || true
    lxc-destroy -n "$REUSE_CONTAINER" -f >/dev/null 2>&1 || true
}
trap cleanup EXIT

# Remove any container left by an earlier failed run.
lxc-destroy -n "$CTRL_CONTAINER" -f >/dev/null 2>&1 || true
lxc-destroy -n "$REUSE_CONTAINER" -f >/dev/null 2>&1 || true

CASE_OUTPUT=""

run_config() {
    local label="$1" config="$2" status=0
    echo "--- $label ---"
    set +e
    CASE_OUTPUT=$("$LXC_EXEC" --debug "$config" 2>&1)
    status=$?
    set -e
    echo "$CASE_OUTPUT"
    if [ "$status" -ne 0 ]; then
        fail "$label exited $status."
    fi
}

assert_allowed() {
    if grep -Fq "MXC_NET_BLOCKED" <<<"$CASE_OUTPUT"; then
        fail "$1"
    fi
    if ! grep -Fq "MXC_NET_ALLOWED" <<<"$CASE_OUTPUT"; then
        fail "the case produced no verdict at all; the container command did not run."
    fi
}

assert_blocked() {
    if grep -Fq "MXC_NET_ALLOWED" <<<"$CASE_OUTPUT"; then
        fail "$1"
    fi
    if ! grep -Fq "MXC_NET_BLOCKED" <<<"$CASE_OUTPUT"; then
        fail "the case produced no verdict at all; the container command did not run."
    fi
}

echo "Running LXC reuse policy-loosening test..."

# Run 1: positive control on a fresh container id.  If this fails, the probe
# destination is unreachable from this host right now, and run 3's result would
# be meaningless.
run_config "run 1 (positive control): fresh container, explicit egress allow to $PROBE_ADDRESS" "$CTRL_CONFIG"
assert_allowed "an explicitly allowed destination was unreachable on the positive control.  Run 3 would prove nothing without a working allow path, so this test fails rather than proceeding."

# Run 2: setup run on the reuse container id, with no network section.  The
# container must survive so run 3 reuses the same live instance.
run_config "run 2 (setup): reuse id, no network section -- workload must be blocked" "$DENY_CONFIG"
assert_blocked "the workload reached $PROBE_ADDRESS on a 0.8 request with no network section.  The container was not isolated as expected, so run 3 would not be testing the loosening scenario."

if ! lxc-info -n "$REUSE_CONTAINER" >/dev/null 2>&1; then
    fail "destroyOnExit was false, but run 2 destroyed the container.  There is nothing for run 3 to reuse."
fi

INIT_PID="$(lxc-info -n "$REUSE_CONTAINER" -p -H 2>/dev/null || true)"
if [ -z "$INIT_PID" ] || [ "$INIT_PID" = "-1" ]; then
    fail "run 2 left the container stopped, so run 3 cannot exercise reuse of a live container.  This test is not covering the scenario it was written for."
fi
echo "--- container survived run 2 and is still running as PID $INIT_PID ---"

# Run 3: the case under test.  Same reuse id as run 2, now with an explicit
# egress allow.  The workload must reach the allowed destination.
run_config "run 3 (case under test): same reuse id, explicit egress allow to $PROBE_ADDRESS" "$ALLOW_CONFIG"
assert_allowed "a container reused under an explicit egress allow could not reach $PROBE_ADDRESS.  The workload was blocked despite the policy explicitly permitting the destination on the second run."

echo "PASS: a container reused under a loosened policy can reach an explicitly allowed destination."
echo "LXC reuse policy-loosening test complete."
