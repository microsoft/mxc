#!/bin/bash
# LXC reuse policy-tightening test
#
# A container that outlives its run must not carry the previous run's network
# access into the next one. Two policies run over one surviving container: the
# first reaches an allowed destination, the second permits nothing and must not
# reach it.
#
# No other script covers this. The proxy reuse script next door reuses a
# container but changes only the proxy pin, never the reachability the
# container is left holding, and every other network fixture destroys its
# container on exit.
#
# The first run is the positive control. If it cannot reach the destination,
# a second run that also cannot reach it proves nothing, so that case fails
# rather than passing quietly.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_DIR="$(dirname "$(dirname "$SCRIPT_DIR")")"
LXC_EXEC="$REPO_DIR/src/target/release/lxc-exec"

if [ ! -f "$LXC_EXEC" ]; then
    LXC_EXEC="$REPO_DIR/src/target/debug/lxc-exec"
fi

# Exit 77 is what run_lxc_all_tests.sh records as SKIPPED rather than PASS.
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

ALLOW_CONFIG="$REPO_DIR/tests/configs/lxc_network_reuse_tighten_allow.json"
DENY_CONFIG="$REPO_DIR/tests/configs/lxc_network_reuse_tighten_deny.json"

# Both fixtures name one container on purpose: naming the same container is
# what makes the second run a reuse rather than a fresh create.
CONTAINER="CLI-LXC-Reuse-Tighten"
PROBE_ADDRESS="140.82.114.6"

# The fixtures and these assertions rot apart the moment someone edits one
# without the other, so read the facts this test depends on back out of them.
fixture_field() {
    sed -n "s/.*\"$2\"[[:space:]]*:[[:space:]]*\"\([^\"]*\)\".*/\1/p" "$1" | head -1
}

for config in "$ALLOW_CONFIG" "$DENY_CONFIG"; do
    [ -f "$config" ] || fail "fixture $config is missing."

    actual_container="$(fixture_field "$config" containerId)"
    if [ "$actual_container" != "$CONTAINER" ]; then
        fail "fixture $(basename "$config") names container '$actual_container', but this test drives '$CONTAINER'. The second run would create a new container instead of reusing the first one, and the test would pass without exercising reuse at all."
    fi

    if ! grep -Fq "$PROBE_ADDRESS" "$config"; then
        fail "fixture $(basename "$config") does not probe $PROBE_ADDRESS, so the two runs are not measuring the same reachability."
    fi

    if ! grep -Fq '"destroyOnExit": false' "$config"; then
        fail "fixture $(basename "$config") does not set destroyOnExit false, so no container survives for the next run to reuse."
    fi
done

# The allow fixture has to actually permit the probe, or the positive control
# below is testing nothing.
if ! grep -Fq '"cidr": "140.82.112.0/20"' "$ALLOW_CONFIG"; then
    fail "the allow fixture no longer permits the range holding $PROBE_ADDRESS, so its run cannot serve as the positive control."
fi

# The deny fixture has to permit nothing, or the second run is not a tightening.
if grep -Fq '"allow"' "$DENY_CONFIG"; then
    fail "the deny fixture carries an allow list, so the second run does not tighten the policy and the test proves nothing."
fi

# This test deliberately leaves a container running between its two runs, so it
# owns the removal on every exit path rather than the runner.
cleanup() {
    lxc-destroy -n "$CONTAINER" -f >/dev/null 2>&1 || true
}
trap cleanup EXIT

# Guards against a container left by an earlier failed run being mistaken for
# this run's first run.
lxc-destroy -n "$CONTAINER" -f >/dev/null 2>&1 || true

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

echo "Running LXC reuse policy-tightening test..."

run_config "first run: policy allows tcp/443 to $PROBE_ADDRESS, container survives" "$ALLOW_CONFIG"
assert_allowed "an explicitly allowed destination was unreachable on the first run. The container never had the access this test is about taking away, so the second run below proves nothing."

if ! lxc-info -n "$CONTAINER" >/dev/null 2>&1; then
    fail "destroyOnExit was false, but the first run destroyed the container. There is nothing for the second run to reuse."
fi

# The scenario is a container reused *while still running*: a container the
# first run left stopped is started fresh by the second, which reads the new
# policy on its way up and never had the chance to carry the old one over.
INIT_PID="$(lxc-info -n "$CONTAINER" -p -H 2>/dev/null || true)"
if [ -z "$INIT_PID" ] || [ "$INIT_PID" = "-1" ]; then
    fail "the first run left the container stopped, so the second run cannot exercise reuse of a live container. This test is not covering the scenario it was written for."
fi
echo "--- container survived the first run and is still running as PID $INIT_PID ---"

run_config "second run: same container, policy permits no network" "$DENY_CONFIG"
assert_blocked "a container reused while still running reached $PROBE_ADDRESS under a policy that permits no network. It is still on the first run's topology, so tightening the policy on a surviving container does nothing and the workload keeps access the current policy never granted."

echo "PASS: a live container reused under a tightened policy lost the access its previous run had."
echo "LXC reuse policy-tightening test complete."
