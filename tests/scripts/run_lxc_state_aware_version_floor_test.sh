#!/bin/bash
# LXC state-aware schema version floor test.
#
# The state-aware lifecycle shipped after the 0.7 schema was cut. LXC accepts a
# lifecycle request only from a config declaring 0.8.0 or later. This pins that
# boundary from the outside: a config goes in, an exit status and a response
# envelope come out.
#
#   cause                                     effect
#   ----------------------------------------  -------------------------------
#   lifecycle request declaring 0.7           refused, naming the floor
#   lifecycle request declaring 0.6           refused, naming the floor
#   lifecycle request declaring no version    refused, naming the floor
#   lifecycle request on a later phase, 0.7   refused, naming the floor
#   lifecycle request with a nonsense version refused
#   lifecycle request declaring 0.8           admitted
#   one-shot request declaring 0.7            admitted
#
# The last row is the control that matters most. Committed one-shot fixtures
# declare 0.7, and the floor must leave every one of them alone.
#
# The fourth row is the second control: the floor guards the lifecycle entry
# point, not the provision phase, and a later phase must be refused the same
# way.
#
# Below-floor requests are written to temp files rather than committed under
# tests/configs. A committed config that fails dev-schema validation has to be
# listed in scripts/versioning/config-validation-exemptions.json, and that list
# is deliberately empty.
#
# Every assertion lands during config parsing or at the lifecycle entry point.
# The script needs no root, no LXC runtime and no iptables. --dry-run keeps it
# from creating anything, and an admitted request is allowed to come back
# reporting the runtime is missing. run_lxc_all_tests.sh still
# requires root before it dispatches anything, which makes that property matter
# only when this script is invoked directly.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_DIR="$(dirname "$(dirname "$SCRIPT_DIR")")"
CONFIG_DIR="$REPO_DIR/tests/configs"

# Quoted exactly as the binary emits it, which makes it part of the observable
# contract. Moving the floor in the code without moving it here fails the run
# rather than passing against a stale expectation.
EXPECTED_FLOOR='0.8.0'
REFUSAL_CODE='"code":"malformed_request"'
# What a host with no LXC tooling answers once a request has cleared the floor.
# Quoted as the binary emits it, like the refusal code above.
RUNTIME_ABSENT_CODE='"code":"backend_unavailable"'

# An admitted lifecycle request under --dry-run, and a fixture that already
# declares the floor version.
ADMITTED_CONFIG="$CONFIG_DIR/lxc_state_aware_provision.json"
# A committed one-shot fixture that declares 0.7, which the floor must ignore.
ONE_SHOT_CONFIG="$CONFIG_DIR/lxc_network_enforcement_allow.json"

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
for c in "$ADMITTED_CONFIG" "$ONE_SHOT_CONFIG"; do
    [ -f "$c" ] || { echo "FAIL: fixture is missing: $c"; exit 1; }
done

WORK_DIR="$(mktemp -d)"
cleanup() {
    rm -rf "$WORK_DIR"
    return 0
}
trap cleanup EXIT
trap 'cleanup; exit 130' INT
trap 'cleanup; exit 143' TERM

# The admitted fixture is the drift guard for the floor itself. If someone
# raises the floor in the code and leaves the fixtures behind, the whole
# state-aware suite goes red; catching it here names the reason.
if ! grep -q "\"version\"[[:space:]]*:[[:space:]]*\"$EXPECTED_FLOOR" "$ADMITTED_CONFIG"; then
    fail "the admitted fixture no longer declares $EXPECTED_FLOOR: $ADMITTED_CONFIG"
fi

# Write a provision request declaring $1 as its version, or no version at all
# when $1 is empty. Echoes the path it wrote.
write_provision_request() {
    local version="$1"
    local path="$WORK_DIR/provision-${version:-none}.json"
    {
        printf '{\n'
        if [ -n "$version" ]; then
            printf '  "version": "%s",\n' "$version"
        fi
        printf '  "phase": "provision",\n'
        printf '  "containment": "lxc",\n'
        printf '  "experimental": {\n'
        printf '    "lxc": {\n'
        printf '      "provision": { "distribution": "alpine", "release": "3.23" }\n'
        printf '    }\n'
        printf '  }\n'
        printf '}\n'
    } > "$path"
    echo "$path"
}

# Run a config and leave its exit status in LAST_STATUS and its envelope in
# LAST_STDOUT. Diagnostics go to stderr, which is not part of the contract
# under test.
LAST_STATUS=0
LAST_STDOUT=''
run_request() {
    set +e
    LAST_STDOUT="$("$LXC_EXEC" --dry-run "$1" 2>/dev/null)"
    LAST_STATUS=$?
    set -e
}

run_lifecycle_request() {
    set +e
    LAST_STDOUT="$("$LXC_EXEC" --dry-run --experimental "$1" 2>/dev/null)"
    LAST_STATUS=$?
    set -e
}

assert_refused_naming_floor() {
    local label="$1"
    if [ "$LAST_STATUS" -eq 0 ]; then
        fail "$label: expected a refusal, got exit 0 and: $LAST_STDOUT"
        return
    fi
    case "$LAST_STDOUT" in
        *"$REFUSAL_CODE"*) ;;
        *) fail "$label: expected $REFUSAL_CODE, got: $LAST_STDOUT"; return ;;
    esac
    case "$LAST_STDOUT" in
        *"$EXPECTED_FLOOR"*) ;;
        *) fail "$label: refusal does not name the $EXPECTED_FLOOR floor: $LAST_STDOUT"; return ;;
    esac
    pass "$label"
}

assert_refused() {
    local label="$1"
    if [ "$LAST_STATUS" -eq 0 ]; then
        fail "$label: expected a refusal, got exit 0 and: $LAST_STDOUT"
        return
    fi
    case "$LAST_STDOUT" in
        *"$REFUSAL_CODE"*) pass "$label" ;;
        *) fail "$label: expected $REFUSAL_CODE, got: $LAST_STDOUT" ;;
    esac
}

# Admission means the request cleared the version floor. On a host with no LXC
# tooling a cleared request comes back backend_unavailable rather than a result,
# and reaching the backend at all is proof the floor let it through.
assert_admitted() {
    local label="$1"
    case "$LAST_STDOUT" in
        *"$EXPECTED_FLOOR or later"*)
            fail "$label: refused over its schema version: $LAST_STDOUT"
            return
            ;;
    esac
    if [ "$LAST_STATUS" -eq 0 ]; then
        pass "$label"
        return
    fi
    case "$LAST_STDOUT" in
        *"$RUNTIME_ABSENT_CODE"*) pass "$label" ;;
        *) fail "$label: expected admission, got exit $LAST_STATUS and: $LAST_STDOUT" ;;
    esac
}

run_lifecycle_request "$(write_provision_request '0.7.0-alpha')"
assert_refused_naming_floor "a 0.7 lifecycle request is refused"

run_lifecycle_request "$(write_provision_request '0.6.0-alpha')"
assert_refused_naming_floor "a 0.6 lifecycle request is refused"

run_lifecycle_request "$(write_provision_request '')"
assert_refused_naming_floor "a lifecycle request with no declared version is refused"

# A later phase carries no provision fields, and the floor must still refuse it.
LATER_PHASE="$WORK_DIR/start-0.7.json"
cat > "$LATER_PHASE" <<'JSON'
{
  "version": "0.7.0-alpha",
  "phase": "start",
  "sandboxId": "lxc:mxc-version-floor-probe"
}
JSON
run_lifecycle_request "$LATER_PHASE"
assert_refused_naming_floor "a 0.7 lifecycle request on a later phase is refused"

# A version that is not semver is refused before the floor is ever compared.
# The caller sees the same code either way, which is what this pins.
NONSENSE="$WORK_DIR/provision-nonsense.json"
cat > "$NONSENSE" <<'JSON'
{
  "version": "banana",
  "phase": "provision",
  "containment": "lxc",
  "experimental": {
    "lxc": {
      "provision": { "distribution": "alpine", "release": "3.23" }
    }
  }
}
JSON
run_lifecycle_request "$NONSENSE"
assert_refused "a lifecycle request with a nonsense version is refused"

run_lifecycle_request "$ADMITTED_CONFIG"
assert_admitted "a lifecycle request declaring the floor version is admitted"

run_request "$ONE_SHOT_CONFIG"
assert_admitted "a 0.7 one-shot request is untouched by the lifecycle floor"

echo
echo "Passed: $PASSED"
echo "Failed: $FAILED"
[ "$FAILED" -eq 0 ]
