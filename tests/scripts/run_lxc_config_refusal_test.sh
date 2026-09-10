#!/bin/bash
# LXC configuration refusal test
#
# Every case here states something LXC cannot deliver. The contract is that the
# run is refused and says why, rather than starting a container whose network or
# environment is not the one the configuration describes.
#
# Each case asserts three things: a non-zero exit, a message naming the specific
# problem, and that the workload never produced its sentinel. Exit code alone is
# not enough -- a fixture broken in some unrelated way also exits non-zero, and
# would pass a test that only checked the status.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_DIR="$(dirname "$(dirname "$SCRIPT_DIR")")"
CONFIG_DIR="$REPO_DIR/tests/configs"

SENTINEL="MXC_WORKLOAD_RAN"

fail() {
    echo "FAIL: $*"
    exit 1
}

# An honest skip for a missing prerequisite: exit 77 so run_lxc_all_tests.sh
# records SKIPPED rather than PASS. A suite that could not run must not look green.
SKIP_EXIT=77
skip() {
    echo "SKIP: refusal behavior UNVERIFIED -- $1"
    echo "      (fixture drift guards still ran and passed)"
    exit "$SKIP_EXIT"
}

# ---------------------------------------------------------------------------
# Drift guards. Each fixture is only interesting while it still carries the
# thing being refused. Stripping that element would leave a config LXC accepts,
# and every assertion below would pass for the wrong reason.
#
# These run before the prerequisite checks so a host that cannot launch
# containers still reports fixture rot.
# ---------------------------------------------------------------------------
assert_fixture_carries() {
    local fixture="$1" token="$2" why="$3"
    local path="$CONFIG_DIR/$fixture"
    [ -f "$path" ] || fail "fixture not found: $path"
    grep -Fq "$token" "$path" \
        || fail "fixture $fixture no longer contains '$token' -- $why"
}

assert_fixture_carries "lxc_refuse_proxy_with_allowed_hosts.json" '"proxy"' \
    "without a proxy there is nothing for the allow list to conflict with"
assert_fixture_carries "lxc_refuse_proxy_with_allowed_hosts.json" '"allowedHosts"' \
    "without an allow list the proxy config is accepted and nothing is refused"
assert_fixture_carries "lxc_refuse_unresolvable_allowed_host.json" "no-such-host.invalid" \
    "a resolvable allow entry is programmed normally and is not refused"
assert_fixture_carries "lxc_refuse_malformed_env.json" "NOT_AN_ASSIGNMENT" \
    "an env list of well-formed KEY=VALUE entries is accepted and nothing is refused"
assert_fixture_carries "lxc_capabilities_no_posture_control.json" '"lxc"' \
    "the control must remain a valid LXC config that states no network posture"

# The control's whole point is that it names no network posture. A fixture that
# grew a network section would be refused like the others, and its PASS would
# then prove the opposite of what it claims.
if grep -Fq '"network"' "$CONFIG_DIR/lxc_capabilities_no_posture_control.json"; then
    fail "the no-posture control fixture grew a network section; it no longer controls for anything"
fi

echo "Fixture drift guards passed."

# ---------------------------------------------------------------------------
# Prerequisites for the live cases.
# ---------------------------------------------------------------------------
LXC_EXEC="$REPO_DIR/src/target/release/lxc-exec"
[ -f "$LXC_EXEC" ] || LXC_EXEC="$REPO_DIR/src/target/debug/lxc-exec"

[ "$(id -u)" -eq 0 ] || skip "requires root for iptables and LXC"
command -v iptables >/dev/null 2>&1 || skip "iptables is not installed"
command -v lxc-create >/dev/null 2>&1 || skip "LXC (lxc-create) is not installed"
[ -f "$LXC_EXEC" ] || skip "lxc-exec binary not built; run build.sh first"

# `release` is preferred over `debug`, so a stale release binary built before
# these refusals existed is picked ahead of a fresh debug one -- and it fails
# exactly as a genuine regression would. Naming the artifact and its age turns
# that into one line instead of an hour hunting a phantom regression.
echo "Using $LXC_EXEC (built $(date -r "$LXC_EXEC" '+%Y-%m-%d %H:%M:%S' 2>/dev/null || echo 'unknown'))."

# shellcheck source=lib/chain_name.sh
. "$SCRIPT_DIR/lib/chain_name.sh"

CHAINS_BEFORE_V4="$(mxc_chains iptables)"
CHAINS_BEFORE_V6="$(mxc_chains ip6tables)"

# Compared against the snapshot above, so chains left behind by an earlier
# failed run are not blamed on this one.
assert_no_new_mxc_chains() {
    local tool="$1" before="$2" after="" leaked="" chain
    if ! after="$(mxc_chains "$tool")"; then
        fail "could not enumerate $tool chains, so cleanup was not verified."
    fi
    while IFS= read -r chain; do
        [ -n "$chain" ] || continue
        grep -Fxq "$chain" <<<"$before" || leaked="$leaked $chain"
    done <<<"$after"
    [ -z "$leaked" ] || fail "$tool chain(s) left behind after lxc-exec completed:$leaked"
}

# ---------------------------------------------------------------------------
# One refused case: run it, require a non-zero exit, require the message to
# name this specific problem, and require the workload never to have spoken.
# ---------------------------------------------------------------------------
assert_refused() {
    local label="$1" fixture="$2" expected="$3"
    local out="" status=0

    echo "--- $label ---"
    out="$("$LXC_EXEC" --debug "$CONFIG_DIR/$fixture" 2>&1)" || status=$?
    echo "$out"

    [ "$status" -ne 0 ] \
        || fail "$label: lxc-exec exited 0, so the configuration was accepted. If this is
      unexpected, check that $LXC_EXEC is current -- a binary built before these
      refusals existed fails here in exactly the same way as a regression."

    grep -Fq "$expected" <<<"$out" \
        || fail "$label: refused, but the message never named the problem (wanted '$expected')"

    # Without this the test would pass on a run that refused the policy after
    # already handing the container its network.
    if grep -Fq "$SENTINEL" <<<"$out"; then
        fail "$label: the workload ran despite the refusal"
    fi

    assert_no_new_mxc_chains iptables "$CHAINS_BEFORE_V4"
    assert_no_new_mxc_chains ip6tables "$CHAINS_BEFORE_V6"

    echo "PASS: $label"
}

echo "Running LXC configuration refusal test..."

# The proxy carries every packet in proxy mode, so an allow list beside it names
# destinations that are never programmed into any chain.
assert_refused \
    "proxy combined with allowedHosts" \
    "lxc_refuse_proxy_with_allowed_hosts.json" \
    "network.proxy cannot be combined with allowedHosts"

# An allow entry that resolves to nothing programs no rule, and under a blocking
# default the destination the configuration names stays unreachable.
assert_refused \
    "allowedHosts entry that resolves to no address" \
    "lxc_refuse_unresolvable_allowed_host.json" \
    "resolved to no address, so no rule can be programmed to reach it"

# An env entry that is not KEY=VALUE cannot be exported. Dropping it would run
# the workload in an environment the configuration did not describe.
assert_refused \
    "env entry that is not KEY=VALUE" \
    "lxc_refuse_malformed_env.json" \
    "is not a valid environment entry"

# ---------------------------------------------------------------------------
# Control: refusing must stay narrow. A config that names no network posture is
# not asking for enforcement, and it must still run.
# ---------------------------------------------------------------------------
echo "--- control: a config that states no network posture still runs ---"
CONTROL_OUT="$("$LXC_EXEC" --debug "$CONFIG_DIR/lxc_capabilities_no_posture_control.json" 2>&1 || true)"
echo "$CONTROL_OUT"

# Container stdout arrives with a trailing carriage return, so an exact-line
# match with grep -Fx never fires here.
if ! grep -qE "^${SENTINEL}[[:space:]]*$" <<<"$CONTROL_OUT"; then
    fail "the control config was not run to completion; the refusals above are rejecting configs they should accept"
fi

assert_no_new_mxc_chains iptables "$CHAINS_BEFORE_V4"
assert_no_new_mxc_chains ip6tables "$CHAINS_BEFORE_V6"

echo "PASS: a config that states no network posture still runs"
echo "LXC configuration refusal test complete."
