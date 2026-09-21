#!/bin/bash
# LXC schema 0.8 deny-all loopback behavior test
#
# A 0.8 request that permits nothing and names no proxy denies traffic in both
# directions and leaves the container its own loopback.  That is the behavior
# this test measures, on both halves:
#
#   denied      - a destination the policy does not permit is unreachable
#   except lo   - a listener on 127.0.0.1 inside the container is still reachable
#                 from inside the container
#
# The test says nothing about how the backend delivers this.  The LXC backend
# currently gives such a container no network interface, but a veth carrying a
# drop-all ruleset would satisfy the same two statements, and this test would
# stay green across that change.  Asserting on the interface list would couple
# it to the mechanism instead.
#
# Denial here must not depend on the host.  The defect this guards against
# started the container with a bridged NIC and filtered it, which left denial
# resting on the host delivering bridged packets to iptables; a host that does
# not was left reaching the network under a policy that permitted nothing.
#
# The first run is the positive control.  It sends the same probe with an
# egress allow rule covering the destination.  The control establishes that the
# probe can reach the network at all, so a blocked result in the second run
# means the policy blocked it rather than the environment being offline.  A
# control that cannot reach the network skips the test rather than passing it,
# because a case that proves nothing is not a pass.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_DIR="$(cd "$SCRIPT_DIR/../.." && pwd)"
CTRL_CONFIG="$REPO_DIR/tests/configs/lxc_network_v08_deny_all_loopback_ctrl.json"
OMIT_CONFIG="$REPO_DIR/tests/configs/lxc_network_v08_deny_all_loopback_omit.json"

LXC_EXEC="$REPO_DIR/src/target/release/lxc-exec"
[ -x "$LXC_EXEC" ] || LXC_EXEC="$REPO_DIR/src/target/debug/lxc-exec"

SKIP_EXIT=77

skip() {
    echo "SKIP: $1"
    exit "$SKIP_EXIT"
}

fail() {
    echo "FAIL: $1"
    exit 1
}

[ "$(id -u)" -eq 0 ] || skip "must run as root."
command -v iptables >/dev/null 2>&1 || skip "iptables is not installed."
command -v ip6tables >/dev/null 2>&1 || skip "ip6tables is not installed."
command -v lxc-create >/dev/null 2>&1 || skip "lxc-create is not installed."
[ -x "$LXC_EXEC" ] || skip "lxc-exec is not built."

LOOPBACK_OK="MXC_LOOPBACK_OK"
LOOPBACK_DEAD="MXC_LOOPBACK_DEAD"
NET_ALLOWED="MXC_NET_ALLOWED"
NET_BLOCKED="MXC_NET_BLOCKED"

# Drift guard: confirm the fixtures still describe the two policies this test
# compares, that they run the same probe on the same image, and that only the
# control permits a destination.
for config in "$CTRL_CONFIG" "$OMIT_CONFIG"; do
    [ -f "$config" ] || fail "fixture $config is missing."

    schema_ver="$(sed -n 's/.*"version"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p' "$config" | head -1)"
    if ! echo "$schema_ver" | grep -q '^0\.8\.'; then
        fail "fixture $(basename "$config") declares schema '$schema_ver', not 0.8; this test is specific to 0.8 deny-all behavior."
    fi

    for marker in "$LOOPBACK_OK" "$NET_BLOCKED"; do
        if ! grep -Fq "$marker" "$config"; then
            fail "fixture $(basename "$config") never reports $marker, so this test cannot read its result."
        fi
    done

    # A proxy is a destination the container has to reach, which means the
    # policy no longer permits nothing.  Either fixture naming one would remove
    # the case under test.
    if grep -Fq '"proxy"' "$config"; then
        fail "fixture $(basename "$config") names a proxy, so its policy permits something; neither fixture in this test may name one."
    fi
done

ctrl_probe="$(grep -F '"commandLine"' "$CTRL_CONFIG" | head -1)"
omit_probe="$(grep -F '"commandLine"' "$OMIT_CONFIG" | head -1)"
if [ "$ctrl_probe" != "$omit_probe" ]; then
    fail "the two fixtures run different commands; their results are not comparable."
fi

# The probe's behavior depends on its image and its containment backend.  A
# fixture pair that disagrees on either is measuring two different things.
for field in containment distribution release; do
    ctrl_value="$(sed -n "s/.*\"$field\"[[:space:]]*:[[:space:]]*\"\([^\"]*\)\".*/\1/p" "$CTRL_CONFIG" | head -1)"
    omit_value="$(sed -n "s/.*\"$field\"[[:space:]]*:[[:space:]]*\"\([^\"]*\)\".*/\1/p" "$OMIT_CONFIG" | head -1)"
    [ -n "$ctrl_value" ] || fail "the control fixture declares no \"$field\"; this test cannot confirm both runs use the same image on the same backend."
    if [ "$ctrl_value" != "$omit_value" ]; then
        fail "the fixtures disagree on \"$field\" ('$ctrl_value' against '$omit_value'); their results are not comparable."
    fi
done

# The control must permit a destination, or it enforces the same policy as the
# case under test and stops being a control.
if ! grep -Fq '"network"' "$CTRL_CONFIG"; then
    fail "the control fixture carries no network section, so it cannot establish that the probe reaches the network when the policy permits it."
fi

# The case under test requires the section to be absent entirely.
if grep -Fq '"network"' "$OMIT_CONFIG"; then
    fail "the omit fixture contains a network section; the case under test requires the section to be absent."
fi

cleanup() {
    lxc-destroy -n "CLI-LXC-V08-DenyAll-Ctrl" -f >/dev/null 2>&1 || true
    lxc-destroy -n "CLI-LXC-V08-DenyAll-Omit" -f >/dev/null 2>&1 || true
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

# The probe prints each verdict on its own line.  Matching an anchored whole
# line keeps a diagnostic line that merely mentions a marker from being read as
# the probe's own result.  The container's pty ends each line with carriage
# returns before the newline, so the match allows trailing whitespace.
reported() {
    grep -qE "^${1}[[:space:]]*$" <<<"$CASE_OUTPUT"
}

# A run that reported neither verdict for a half never executed that half, and
# its silence must not read as the answer this test is looking for.
assert_reported() {
    local half="$1" positive="$2" negative="$3"
    if ! reported "$positive" && ! reported "$negative"; then
        fail "the container reported no $half verdict; the probe did not run, so its silence proves nothing."
    fi
}

run_config "positive control: 0.8 request permitting one destination" "$CTRL_CONFIG"
assert_reported "loopback" "$LOOPBACK_OK" "$LOOPBACK_DEAD"
assert_reported "egress" "$NET_ALLOWED" "$NET_BLOCKED"

if ! reported "$LOOPBACK_OK"; then
    fail "the control could not reach a listener on its own loopback; the probe is broken, and the case under test would prove nothing."
fi

if ! reported "$NET_ALLOWED"; then
    skip "the control could not reach 140.82.114.6:443 under a policy that permits it, so this host has no outbound path; a blocked result in the case under test would prove nothing."
fi

echo "Control reached the network and its own loopback."

run_config "case under test: 0.8 request permitting nothing and naming no proxy" "$OMIT_CONFIG"
assert_reported "loopback" "$LOOPBACK_OK" "$LOOPBACK_DEAD"
assert_reported "egress" "$NET_ALLOWED" "$NET_BLOCKED"

if reported "$NET_ALLOWED"; then
    fail "the container reached 140.82.114.6:443 under a policy that permits nothing."
fi

if ! reported "$LOOPBACK_OK"; then
    fail "the container could not reach a listener on its own loopback; a policy that permits nothing denies the network, and leaves loopback."
fi

echo "PASS: a 0.8 request permitting nothing is denied the network and keeps its own loopback."
echo "LXC schema 0.8 deny-all loopback behavior test complete."
