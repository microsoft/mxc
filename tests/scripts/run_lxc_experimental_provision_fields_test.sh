#!/bin/bash
# LXC experimental.lxc.provision field contract test.
#
# Covers the two fields the provision phase reads out of its own sub-object in
# the config, experimental.lxc.provision.distribution and .release:
#
#   cause                                   effect
#   --------------------------------------  ---------------------------------
#   provision names only one of the two     refused, naming both as required
#   distribution is not a string            refused, naming the exact path
#   both present and well typed             not refused for either reason
#
# Scope note: this pins the *runtime* contract. Both fields are optional in the
# wire model, as they are in the stable top-level lxc section, so the schema
# accepts a provision section that omits them and the backend is what refuses
# it -- the same layer every other state-aware backend rejects provision config
# at. The non-string case is written to a temp file rather than committed under
# tests/configs, because a committed fixture that fails schema validation would
# have to be registered in scripts/versioning/config-validation-exemptions.json,
# and no other backend has an entry there.
#
# Like the conflicting-backends test, every assertion here lands during config
# parsing, so the script itself needs no root, no LXC runtime and no iptables.
# run_lxc_all_tests.sh still requires root before it dispatches anything, so
# that property matters when the script is invoked directly.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_DIR="$(dirname "$(dirname "$SCRIPT_DIR")")"
CONFIG_DIR="$REPO_DIR/tests/configs"

MISSING_FIELD_CONFIG="$CONFIG_DIR/lxc_state_aware_provision_missing_fields_rejected.json"
VALID_CONFIG="$CONFIG_DIR/lxc_state_aware_provision.json"

LXC_EXEC="$REPO_DIR/src/target/release/lxc-exec"
if [ ! -f "$LXC_EXEC" ]; then
    LXC_EXEC="$REPO_DIR/src/target/debug/lxc-exec"
fi

# An honest skip for a missing prerequisite: exit 77 so run_lxc_all_tests.sh
# records SKIPPED rather than PASS.
SKIP_EXIT=77
skip() {
    echo "SKIP: $1"
    exit "$SKIP_EXIT"
}

PASSED=0
FAILED=0

fail() {
    echo "FAIL: $1"
    FAILED=$((FAILED + 1))
}

pass() {
    echo "PASS: $1"
    PASSED=$((PASSED + 1))
}

[ -f "$LXC_EXEC" ] || skip "lxc-exec binary not built; run build.sh first."
for c in "$MISSING_FIELD_CONFIG" "$VALID_CONFIG"; do
    [ -f "$c" ] || { echo "FAIL: fixture is missing: $c"; exit 1; }
done

# Written here rather than committed: see the scope note above.
INVALID_TYPE_CONFIG="$(mktemp)"
cat > "$INVALID_TYPE_CONFIG" <<'JSON'
{
  "version": "0.8.0-alpha",
  "phase": "provision",
  "containment": "lxc",
  "experimental": {
    "lxc": {
      "provision": { "distribution": 123, "release": "3.23" }
    }
  }
}
JSON

# A well-formed request naming a release that does not exist passes validation
# and fails inside container creation, which is the cheapest normal-use route
# to a backend_error.
# Naming the container means the failed create can be cleaned up by name. Left
# to mint its own, the only way to find it afterwards is to diff `lxc-ls`, which
# on a shared host also catches containers other runs created.
# The name must fit the backend's 20-character containerId bound. Over it, the
# request is refused as malformed and never reaches container creation, which
# is the failure this control exists to produce.
BAD_RELEASE_CONTAINER="mxc-e2e-bad-release"
BAD_RELEASE_CONFIG="$(mktemp)"
cat > "$BAD_RELEASE_CONFIG" <<JSON
{
  "version": "0.8.0-alpha",
  "phase": "provision",
  "containment": "lxc",
  "containerId": "$BAD_RELEASE_CONTAINER",
  "experimental": {
    "lxc": {
      "provision": { "distribution": "alpine", "release": "0.0-no-such-release" }
    }
  }
}
JSON

# The positive control provisions a real container, so this test owns its
# removal on every exit path rather than leaving it for the runner or the next
# test to trip over.
CONTROL_CONTAINER=""
# Nothing in here may fail. set -e is still in force inside the trap, and
# destroying a container that was never created would abort the function before
# its return and hand that status to the whole script.
cleanup() {
    if [ -n "$CONTROL_CONTAINER" ]; then
        lxc-destroy -n "$CONTROL_CONTAINER" -f >/dev/null 2>&1 || true
    fi
    lxc-destroy -n "$BAD_RELEASE_CONTAINER" -f >/dev/null 2>&1 || true
    rm -f "$INVALID_TYPE_CONFIG" "$BAD_RELEASE_CONFIG"
    return 0
}
trap cleanup EXIT
trap 'cleanup; exit 130' INT
trap 'cleanup; exit 143' TERM

# Quoted exactly as the binary emits them, which makes them part of the
# observable contract; a reword must fail here rather than pass silently.
REQUIRED_MESSAGE='LXC distribution and release are required'
INVALID_TYPE_PATH='experimental.lxc.provision.distribution'
INVALID_TYPE_DETAIL='expected a string'

# Drift guard: these fixtures only prove what they claim if they still carry
# the shape the assertions assume. jq and python3 are not guaranteed on an LXC
# test host, so these are plain text checks.
grep -Fq '"distribution"' "$MISSING_FIELD_CONFIG" \
    || fail "missing-field fixture no longer supplies distribution; a rejection would no longer prove that the *missing* field is what was caught."
grep -Fq '"release"' "$MISSING_FIELD_CONFIG" \
    && fail "missing-field fixture now supplies release; it no longer tests a missing field."
grep -Fq '"distribution": 123' "$INVALID_TYPE_CONFIG" \
    || fail "the generated invalid-type config no longer carries a non-string distribution."
grep -Fq '"distribution": "alpine"' "$VALID_CONFIG" \
    || fail "control fixture no longer carries a well-typed distribution."

# Run $1, leaving its stdout in OUT and its exit status in RUN_RC. The error
# envelope goes to stdout and diagnostics to stderr, so stdout is captured on
# its own. OUT is assigned here rather than echoed because a caller using
# command substitution would run this in a subshell and discard RUN_RC, which
# would let a rejection message printed alongside exit 0 satisfy the
# assertions below.
OUT=""
RUN_RC=0
run_config() {
    set +e
    OUT="$("$LXC_EXEC" --experimental "$1" 2>/dev/null)"
    RUN_RC=$?
    set -e
}

echo "Running LXC experimental.lxc.provision field contract test..."

echo "=== provision naming only one of the two fields ==="
run_config "$MISSING_FIELD_CONFIG"
echo "$OUT"
if [ "$RUN_RC" -eq 0 ]; then
    fail "a provision section missing 'release' was accepted (exit 0); the request should be refused."
elif echo "$OUT" | grep -Fq "$REQUIRED_MESSAGE"; then
    pass "a provision section missing 'release' is refused, naming both fields as required"
else
    fail "a provision section missing 'release' was not refused with '$REQUIRED_MESSAGE'"
fi

echo "=== provision with a non-string distribution ==="
run_config "$INVALID_TYPE_CONFIG"
echo "$OUT"
if [ "$RUN_RC" -eq 0 ]; then
    fail "a non-string distribution was accepted (exit 0); the request should be refused."
else
    pass "a non-string distribution is refused with a non-zero exit status"
fi
if echo "$OUT" | grep -Fq "$INVALID_TYPE_PATH"; then
    pass "a non-string distribution is refused, naming the exact path $INVALID_TYPE_PATH"
else
    fail "a non-string distribution was not refused with the path $INVALID_TYPE_PATH"
fi
if echo "$OUT" | grep -Fq "$INVALID_TYPE_DETAIL"; then
    pass "the type error says what was expected instead"
else
    fail "the type error did not say '$INVALID_TYPE_DETAIL'"
fi

# Positive control. Without it, an lxc-exec that refused every config would
# satisfy every assertion above while verifying nothing. This asserts only the
# absence of the two field diagnostics: the run is expected to fail later on a
# host with no LXC runtime, and that failure is not what is under test.
# A failed create can leave the container behind, and the trap removes it by
# the name the request gave it.
echo "=== provision naming a release that does not exist ==="
run_config "$BAD_RELEASE_CONFIG"
echo "$OUT"
if [ "$RUN_RC" -eq 0 ]; then
    fail "a provision naming a nonexistent release was accepted (exit 0); the request should fail."
elif echo "$OUT" | grep -Fq 'backend_error'; then
    pass "a container create that fails is reported as backend_error"
else
    fail "a container create that fails was not reported as backend_error"
fi

echo "=== control: both fields present and well typed ==="
run_config "$VALID_CONFIG"
echo "$OUT"
# Recorded from the control's own result envelope so the trap can remove it.
CONTROL_CONTAINER="$(printf '%s' "$OUT" | sed -n 's/.*"containerName":"\([^"]*\)".*/\1/p')"
if echo "$OUT" | grep -Fq "$REQUIRED_MESSAGE"; then
    fail "the control config was also refused as missing fields; the assertions above do not discriminate."
elif echo "$OUT" | grep -Fq "$INVALID_TYPE_PATH"; then
    fail "the control config also produced a distribution type error; the assertions above do not discriminate."
else
    pass "a well-formed provision section produces neither field diagnostic"
fi
# The control may still fail for an environmental reason -- no LXC runtime on
# this host -- which is not what this test covers. It must not fail as a
# malformed request, because that is the class of failure under test.
if echo "$OUT" | grep -Fq '"code":"malformed_request"'; then
    fail "the control config was rejected as malformed_request; a well-formed provision section must get past parsing."
fi
if [ "$RUN_RC" -ne 0 ]; then
    echo "NOTE: control exited $RUN_RC without a malformed_request rejection, which is environmental and not what this test covers."
fi

echo "================================"
echo "Results: $PASSED passed, $FAILED failed"
if [ "$FAILED" -gt 0 ]; then
    exit 1
fi
echo "LXC experimental.lxc.provision field contract test complete."
