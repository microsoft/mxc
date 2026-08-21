#!/bin/bash
# LXC conflicting containment backends test.
#
# Proves the single-backend-section rule for LXC: a request that names
# containment "lxc" but carries a second experimental backend section is
# rejected, rather than silently honoring one section and ignoring the other.
#
# The rule is documented in docs/versioning.md ("a backend section requires
# `containment` to be set, and the value must be either the concrete backend
# name or any abstract intent that resolves to it") and is enforced by the
# parser, not by the JSON schema -- the generated schema intentionally omits
# the cross-field clauses. So this is only observable by running the binary,
# which is why it is an E2E test and not a schema fixture.
#
# The fixture deliberately carries a *complete and individually valid*
# experimental.lxc section alongside the foreign one. A fixture with only the
# foreign section would be rejected too, but for the weaker reason that no
# matching section was found; requiring both proves the request is refused
# because two backends were named, which is the scenario under test.
#
# Unlike every other LXC E2E test, this one needs no root, no LXC runtime and
# no iptables: the request is refused during config parsing, before any
# privileged work. Only a missing binary can skip it. Note that
# run_lxc_all_tests.sh still requires root before it dispatches anything, so
# under the suite this runs on the same hosts as everything else; the property
# matters when the script is invoked directly.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_DIR="$(dirname "$(dirname "$SCRIPT_DIR")")"
CONFIG="$REPO_DIR/tests/configs/lxc_state_aware_provision_conflicting_backend_rejected.json"
VALID_CONFIG="$REPO_DIR/tests/configs/lxc_state_aware_provision.json"

LXC_EXEC="$REPO_DIR/src/target/release/lxc-exec"
if [ ! -f "$LXC_EXEC" ]; then
    LXC_EXEC="$REPO_DIR/src/target/debug/lxc-exec"
fi

# An honest skip for a missing prerequisite: exit 77 so run_lxc_all_tests.sh
# records SKIPPED rather than PASS. A suite that could not run must not look
# green.
SKIP_EXIT=77
skip() {
    echo "SKIP: $1"
    exit "$SKIP_EXIT"
}

fail() {
    echo "FAIL: $1"
    exit 1
}

[ -f "$LXC_EXEC" ] || skip "lxc-exec binary not built; run build.sh first."
[ -f "$CONFIG" ] || fail "fixture is missing: $CONFIG"
[ -f "$VALID_CONFIG" ] || fail "control fixture is missing: $VALID_CONFIG"

# The positive control provisions a real container, so this test owns its
# removal on every exit path rather than leaving it for the runner or the next
# test to trip over.
CONTROL_CONTAINER=""
cleanup() {
    if [ -n "$CONTROL_CONTAINER" ]; then
        lxc-destroy -n "$CONTROL_CONTAINER" -f >/dev/null 2>&1
    fi
    return 0
}
trap cleanup EXIT
trap 'cleanup; exit 130' INT
trap 'cleanup; exit 143' TERM

# Asserting on the message text makes it part of the observable contract. It is
# quoted here exactly as the binary emits it; a reword is a breaking change for
# anyone matching on it and must fail this test rather than pass silently.
EXPECTED_CODE='"code":"malformed_request"'
EXPECTED_MESSAGE='Multiple containment backends configured'
EXPECTED_SECTION='experimental.wslc'
EXPECTED_REMEDY='Only one backend section is allowed'

# Drift guard: the fixture and these assertions rot apart the moment someone
# edits one of them. jq and python3 are not guaranteed on an LXC test host, so
# these are plain text checks against the fixture. The backend-section checks
# are scoped to the text from "experimental" onward, because an unscoped
# grep for '"lxc"' is also satisfied by the `"containment": "lxc"` line and
# would pass even if the experimental.lxc section were deleted outright.
experimental_block() {
    sed -n '/"experimental"/,$p' "$1"
}

grep -Fq '"containment": "lxc"' "$CONFIG" \
    || fail "fixture no longer selects lxc containment; the test would prove nothing."
experimental_block "$CONFIG" | grep -Fq '"lxc"' \
    || fail "fixture no longer carries an experimental.lxc section."
experimental_block "$CONFIG" | grep -Fq '"wslc"' \
    || fail "fixture no longer carries the conflicting experimental.wslc section."

echo "Running LXC conflicting containment backends test..."

# The error envelope goes to stdout and diagnostics to stderr, so stdout is
# captured on its own -- asserting against a merged stream would let a stderr
# diagnostic satisfy an assertion about the envelope.
set +e
OUTPUT="$("$LXC_EXEC" "$CONFIG" 2>/dev/null)"
RC=$?
set -e
echo "$OUTPUT"

[ "$RC" -ne 0 ] || fail "conflicting backend sections were accepted (exit 0); the request should be refused."

echo "$OUTPUT" | grep -Fq "$EXPECTED_CODE" \
    || fail "rejection did not carry $EXPECTED_CODE."
echo "$OUTPUT" | grep -Fq "$EXPECTED_MESSAGE" \
    || fail "rejection did not explain that multiple backends were configured."
echo "$OUTPUT" | grep -Fq "$EXPECTED_SECTION" \
    || fail "rejection did not name the conflicting section ($EXPECTED_SECTION)."
echo "$OUTPUT" | grep -Fq "$EXPECTED_REMEDY" \
    || fail "rejection did not tell the caller how to fix it."

# Positive control: the same binary and the same phase must accept a request
# that names exactly one backend. Without this, an lxc-exec that rejected every
# config would pass every assertion above while verifying nothing. The control
# is allowed to fail for an environmental reason -- no LXC runtime on the host
# -- which is not what is under test; it must not fail as a malformed request.
set +e
CONTROL_OUTPUT="$("$LXC_EXEC" "$VALID_CONFIG" 2>/dev/null)"
CONTROL_RC=$?
set -e
echo "$CONTROL_OUTPUT"

# Recorded from the control's own result envelope so the trap can remove it.
CONTROL_CONTAINER="$(printf '%s' "$CONTROL_OUTPUT" | sed -n 's/.*"containerName":"\([^"]*\)".*/\1/p')"

if echo "$CONTROL_OUTPUT" | grep -Fq "$EXPECTED_MESSAGE"; then
    fail "the single-backend control config was also rejected as multi-backend; the assertions above do not discriminate."
fi
if echo "$CONTROL_OUTPUT" | grep -Fq "$EXPECTED_SECTION"; then
    fail "the single-backend control config named $EXPECTED_SECTION as a conflict; the assertions above do not discriminate."
fi
if echo "$CONTROL_OUTPUT" | grep -Fq "$EXPECTED_CODE"; then
    fail "the single-backend control config was rejected as $EXPECTED_CODE; a well-formed request must get past parsing."
fi
if [ "$CONTROL_RC" -eq 0 ]; then
    echo "Control accepted (exit 0)."
else
    echo "NOTE: control exited $CONTROL_RC without a parse rejection, which is an environmental failure and not what this test covers."
fi

echo "PASS: a request naming two containment backends is refused, naming the conflicting section."
echo "LXC conflicting containment backends test complete."
