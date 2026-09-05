#!/bin/bash
# LXC legacy default-allow compatibility test (v0.7 vs v0.8)
#
# Pins the contract at docs/sandbox-policy/0.8.0/policy.md (legacy field table)
# and docs/sandbox-policy/0.8.0/networking/schema-updates.md (field mapping):
# a 0.8 request carrying the legacy "defaultPolicy": "allow" field must grant
# outbound access, as it does under 0.7.
#
# Case A is the positive control at schema 0.7.  Its failure fails the suite:
# if the 0.7 fixture cannot reach the destination, Case B's result proves
# nothing.  Case B is the case under test: byte-for-byte the same request with
# the version string bumped to "0.8.0-alpha" and a distinct container id.  Case
# C guards against a fix that simply allows everything at 0.8: the same bare
# network section with "defaultPolicy": "block" must still deny outbound.
#
# The probe is a raw IP connection -- no DNS -- so DNS handling differences
# between schema versions cannot confound the result.
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

# Case A: 0.7 positive control -- bare legacy default-allow.
CTRL_CONFIG="$REPO_DIR/tests/configs/lxc_network_legacy_v08_outbound_ctrl.json"
# Case B: 0.8 case under test -- byte-identical to A except version and containerId.
CASE_CONFIG="$REPO_DIR/tests/configs/lxc_network_legacy_v08_outbound_case.json"
# Case C: 0.8 negative guard -- same bare network section, default-block.
BLOCK_CONFIG="$REPO_DIR/tests/configs/lxc_network_legacy_v08_block_case.json"

PROBE_ADDRESS="140.82.114.6"

# ---------------------------------------------------------------------------
# Drift guards
# ---------------------------------------------------------------------------

for config in "$CTRL_CONFIG" "$CASE_CONFIG" "$BLOCK_CONFIG"; do
    [ -f "$config" ] || fail "fixture $config is missing."
done

# Version checks.
ctrl_ver="$(sed -n 's/.*"version"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p' "$CTRL_CONFIG" | head -1)"
case_ver="$(sed -n 's/.*"version"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p' "$CASE_CONFIG" | head -1)"
block_ver="$(sed -n 's/.*"version"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p' "$BLOCK_CONFIG" | head -1)"

if ! echo "$ctrl_ver" | grep -q '^0\.7\.'; then
    fail "Case A fixture declares schema '$ctrl_ver', not 0.7; the positive control must be a 0.7 request."
fi
if ! echo "$case_ver" | grep -q '^0\.8\.'; then
    fail "Case B fixture declares schema '$case_ver', not 0.8; the case under test must be a 0.8 request."
fi
if ! echo "$block_ver" | grep -q '^0\.8\.'; then
    fail "Case C fixture declares schema '$block_ver', not 0.8; the negative guard must be a 0.8 request."
fi

# Identity: Cases A and B must be identical except for version and containerId.
# Strip both fields and diff; any remaining difference means the test is not
# isolating the version string as the sole variable.
normalize_for_diff() {
    sed -e '/[[:space:]]*"version"[[:space:]]*:/d' \
        -e '/[[:space:]]*"containerId"[[:space:]]*:/d' \
        "$1"
}
if ! diff <(normalize_for_diff "$CTRL_CONFIG") <(normalize_for_diff "$CASE_CONFIG") >/dev/null 2>&1; then
    echo "--- diff (Case A vs Case B with version and containerId stripped) ---"
    diff <(normalize_for_diff "$CTRL_CONFIG") <(normalize_for_diff "$CASE_CONFIG") || true
    fail "Cases A and B differ in fields other than version and containerId.  The test is not isolating the version string as the sole variable."
fi

# Container ids must be distinct across all three cases.
id_a="$(sed -n 's/.*"containerId"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p' "$CTRL_CONFIG" | head -1)"
id_b="$(sed -n 's/.*"containerId"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p' "$CASE_CONFIG" | head -1)"
id_c="$(sed -n 's/.*"containerId"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p' "$BLOCK_CONFIG" | head -1)"

[ "$id_a" != "$id_b" ] || fail "Cases A and B share containerId '$id_a'; they must be distinct so the runs do not reuse the same container."
[ "$id_a" != "$id_c" ] || fail "Cases A and C share containerId '$id_a'; they must be distinct."
[ "$id_b" != "$id_c" ] || fail "Cases B and C share containerId '$id_b'; they must be distinct."

# All three cases must probe the same destination.
for config in "$CTRL_CONFIG" "$CASE_CONFIG" "$BLOCK_CONFIG"; do
    if ! grep -Fq "$PROBE_ADDRESS" "$config"; then
        fail "fixture $(basename "$config") does not probe $PROBE_ADDRESS; all three cases must measure reachability of the same destination."
    fi
done

# Cases A and B must carry bare default-allow with no host lists.
for config in "$CTRL_CONFIG" "$CASE_CONFIG"; do
    if ! grep -Eq '"defaultPolicy"[[:space:]]*:[[:space:]]*"allow"' "$config"; then
        fail "fixture $(basename "$config") does not carry defaultPolicy: allow; the shape under test is a bare legacy default-allow."
    fi
    for field in allowedHosts blockedHosts enforcementMode egress ingress; do
        if grep -Fq "\"$field\"" "$config"; then
            fail "fixture $(basename "$config") carries '$field'; the shape under test is a bare legacy default-allow with no other network fields."
        fi
    done
done

# Case C must carry bare default-block with no host lists.
if ! grep -Eq '"defaultPolicy"[[:space:]]*:[[:space:]]*"block"' "$BLOCK_CONFIG"; then
    fail "Case C fixture does not carry defaultPolicy: block; the negative guard must be a bare legacy default-block."
fi
for field in allowedHosts blockedHosts enforcementMode egress ingress; do
    if grep -Fq "\"$field\"" "$BLOCK_CONFIG"; then
        fail "Case C fixture carries '$field'; the negative guard must be a bare legacy default-block with no other network fields."
    fi
done

# ---------------------------------------------------------------------------
# Cleanup trap
# ---------------------------------------------------------------------------

cleanup() {
    lxc-destroy -n "$id_a" -f >/dev/null 2>&1 || true
    lxc-destroy -n "$id_b" -f >/dev/null 2>&1 || true
    lxc-destroy -n "$id_c" -f >/dev/null 2>&1 || true
}
trap cleanup EXIT

lxc-destroy -n "$id_a" -f >/dev/null 2>&1 || true
lxc-destroy -n "$id_b" -f >/dev/null 2>&1 || true
lxc-destroy -n "$id_c" -f >/dev/null 2>&1 || true

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

echo "Running LXC legacy default-allow compatibility test..."

# ---------------------------------------------------------------------------
# Case A: positive control
# ---------------------------------------------------------------------------

run_config "Case A (positive control): schema 0.7, network={defaultPolicy:allow}, probe $PROBE_ADDRESS" "$CTRL_CONFIG"
assert_allowed "the positive control could not reach $PROBE_ADDRESS under a 0.7 request with a bare legacy default-allow.  Case B's result would prove nothing without a working 0.7 allow path, so this test fails rather than proceeding."

echo "PASS: Case A -- 0.7 legacy default-allow reached $PROBE_ADDRESS."

# ---------------------------------------------------------------------------
# Case B: case under test
# ---------------------------------------------------------------------------

run_config "Case B (case under test): schema 0.8.0-alpha, same network={defaultPolicy:allow}, probe $PROBE_ADDRESS" "$CASE_CONFIG"
assert_allowed "a 0.8 request carrying the legacy defaultPolicy:allow field was blocked from reaching $PROBE_ADDRESS.  The version string alone changed the outcome.  The contract at docs/sandbox-policy/0.8.0/policy.md states that allowOutbound (defaultPolicy:allow) is a valid legacy field at schema 0.8, and docs/sandbox-policy/0.8.0/networking/schema-updates.md maps it to the same outbound posture."

echo "PASS: Case B -- 0.8 legacy default-allow reached $PROBE_ADDRESS."

# ---------------------------------------------------------------------------
# Case C: negative guard
# ---------------------------------------------------------------------------

run_config "Case C (negative guard): schema 0.8.0-alpha, network={defaultPolicy:block}, probe $PROBE_ADDRESS" "$BLOCK_CONFIG"
assert_blocked "a 0.8 request with a bare legacy default-block reached $PROBE_ADDRESS.  The firewall is not filtering this container's traffic under the 0.8 schema, which would make Case B's pass meaningless."

echo "PASS: Case C -- 0.8 legacy default-block denied $PROBE_ADDRESS."

echo "LXC legacy default-allow compatibility test complete."