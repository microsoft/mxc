#!/bin/bash
# LXC schema 0.8 omitted-network-section test
#
# Proves that a 0.8 request with the `network` section omitted entirely receives
# the directional deny defaults stated in the contract: the workload cannot reach
# the network.  The contract is docs/sandbox-policy/0.8.0/policy.md: "A schema
# 0.8 policy with no network fields selects directional deny defaults."
#
# The first run is the positive control.  It sends the same workload and probe
# with an explicit egress allow rule.  If that run cannot reach the destination,
# the second run's blocked result proves nothing; the test fails rather than
# passing quietly.
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

ALLOW_CONFIG="$REPO_DIR/tests/configs/lxc_network_v08_no_network_allow.json"
OMIT_CONFIG="$REPO_DIR/tests/configs/lxc_network_v08_no_network_omit.json"

PROBE_ADDRESS="140.82.114.6"

# Drift guard: confirm the fixtures still cover the cases they were written for.
for config in "$ALLOW_CONFIG" "$OMIT_CONFIG"; do
    [ -f "$config" ] || fail "fixture $config is missing."

    schema_ver="$(sed -n 's/.*"version"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p' "$config" | head -1)"
    if ! echo "$schema_ver" | grep -q '^0\.8\.'; then
        fail "fixture $(basename "$config") declares schema '$schema_ver', not 0.8; this test is specific to the 0.8 no-network-section behavior."
    fi

    if ! grep -Fq "$PROBE_ADDRESS" "$config"; then
        fail "fixture $(basename "$config") does not probe $PROBE_ADDRESS, so the two runs are not measuring the same reachability."
    fi
done

# The allow fixture must carry a network section with an egress allow rule,
# or it cannot serve as a positive control.
if ! grep -Fq '"network"' "$ALLOW_CONFIG"; then
    fail "the allow fixture carries no network section, so it cannot establish that $PROBE_ADDRESS is reachable from this container image."
fi

# The omit fixture must have no network section — that is the case under test.
if grep -Fq '"network"' "$OMIT_CONFIG"; then
    fail "the omit fixture contains a network section; the case under test requires the section to be absent."
fi

cleanup() {
    lxc-destroy -n "CLI-LXC-V08-No-Net-Allow" -f >/dev/null 2>&1 || true
    lxc-destroy -n "CLI-LXC-V08-No-Net-Omit" -f >/dev/null 2>&1 || true
}
trap cleanup EXIT

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

echo "Running LXC schema 0.8 omitted-network-section test..."

run_config "positive control: 0.8 request with explicit egress allow to $PROBE_ADDRESS" "$ALLOW_CONFIG"
assert_allowed "an explicitly allowed destination was unreachable on the positive control.  The second run's blocked result would prove nothing, so this test fails rather than proceeding."

run_config "case under test: 0.8 request with network section omitted entirely" "$OMIT_CONFIG"
assert_blocked "the workload reached $PROBE_ADDRESS under a 0.8 request with no network section.  The contract (docs/sandbox-policy/0.8.0/policy.md) states that omitted permissions remain denied and a 0.8 policy with no network fields selects directional deny defaults."

echo "PASS: a 0.8 request with the network section omitted cannot reach the network."
echo "LXC schema 0.8 omitted-network-section test complete."
