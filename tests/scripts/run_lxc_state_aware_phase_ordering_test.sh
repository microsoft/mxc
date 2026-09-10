#!/bin/bash
# LXC state-aware phase-ordering test.
#
# The lifecycle contract names twelve error codes and closes the set
# (docs/state-aware-lifecycle/mxc-state-aware-sandbox-api.md:1041-1070). Only
# malformed_request and policy_validation are exercised anywhere in
# tests/scripts. This covers the four that describe calling a phase against a
# sandbox in the wrong state, plus the one that describes calling any phase
# against a sandbox that is gone.
set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_DIR="$(dirname "$(dirname "$SCRIPT_DIR")")"
CONFIG_DIR="$REPO_DIR/tests/configs"

LXC_EXEC="$REPO_DIR/src/target/release/lxc-exec"
if [ ! -f "$LXC_EXEC" ]; then
    LXC_EXEC="$REPO_DIR/src/target/debug/lxc-exec"
fi

# Each string is the contract this test holds the backend to. A code that gets
# renamed breaks these rather than silently matching nothing and passing.
NOT_STARTED='not_started'
ALREADY_STARTED='already_started'
ALREADY_STOPPED='already_stopped'
STALE_ID='stale_id'

SKIP_EXIT=77
skip() {
    echo "SKIP: $1"
    exit "$SKIP_EXIT"
}

[ "$(id -u)" -eq 0 ] || skip "requires root for LXC."
command -v lxc-create >/dev/null 2>&1 || skip "LXC (lxc-create) is not installed."
[ -f "$LXC_EXEC" ] || skip "lxc-exec binary not built; run build.sh first."
[ -f "$CONFIG_DIR/lxc_state_aware_provision.json" ] || skip "provision config is missing."

WORK_DIR="$(mktemp -d)"
SANDBOX_ID=""
PASSED=0
FAILED=0
CLEANED_UP=0

cleanup() {
    if [ "$CLEANED_UP" -ne 0 ]; then
        return
    fi
    CLEANED_UP=1
    if [ -n "$SANDBOX_ID" ]; then
        run_phase deprovision "$SANDBOX_ID" >/dev/null 2>&1 || true
    fi
    rm -rf "$WORK_DIR"
}
trap cleanup EXIT
trap 'cleanup; exit 130' INT
trap 'cleanup; exit 143' TERM

run_phase() {
    local phase="$1"
    local sandbox_id="${2:-}"
    local extra="${3:-}"
    local req="$WORK_DIR/$phase.json"

    {
        printf '{\n  "version": "0.8.0-alpha",\n  "phase": "%s"' "$phase"
        if [ "$phase" = "provision" ]; then
            printf ',\n  "containment": "lxc"'
        fi
        if [ -n "$sandbox_id" ]; then
            printf ',\n  "sandboxId": "%s"' "$sandbox_id"
        fi
        if [ -n "$extra" ]; then
            printf ',\n  %s' "$extra"
        fi
        printf '\n}\n'
    } > "$req"

    "$LXC_EXEC" --experimental "$req"
}

extract_sandbox_id() {
    sed -n 's/.*"sandboxId"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p' | head -n 1
}

check() {
    local name="$1"
    local ok="$2"
    if [ "$ok" = "0" ]; then
        echo "PASS: $name"
        PASSED=$((PASSED + 1))
    else
        echo "FAIL: $name"
        FAILED=$((FAILED + 1))
    fi
}

# A refusal is two observations, and asserting only the exit code would pass on
# any failure at all, including a crash before the phase was ever dispatched.
expect_error_code() {
    local name="$1"
    local expected="$2"
    local phase="$3"
    local sandbox_id="$4"
    local extra="${5:-}"
    local out rc

    out="$(run_phase "$phase" "$sandbox_id" "$extra" 2>/dev/null)"
    rc=$?

    if [ "$rc" -eq 0 ]; then
        check "$name (exited 0; expected a refusal naming $expected)" 1
        return
    fi
    if printf '%s' "$out" | grep -Eq "\"code\"[[:space:]]*:[[:space:]]*\"$expected\""; then
        check "$name" 0
    else
        check "$name (envelope did not name $expected)" 1
        echo "    got: $out"
    fi
}

echo "Running LXC state-aware phase-ordering test..."

echo "=== provision ==="
PROVISION_OUT="$("$LXC_EXEC" --experimental "$CONFIG_DIR/lxc_state_aware_provision.json")"
if [ $? -ne 0 ]; then
    echo "Cannot continue: provision failed."
    echo "$PROVISION_OUT"
    exit 1
fi
SANDBOX_ID="$(printf '%s' "$PROVISION_OUT" | extract_sandbox_id)"
if [ -z "$SANDBOX_ID" ]; then
    echo "Cannot continue: provision returned no sandboxId."
    exit 1
fi
echo "sandboxId: $SANDBOX_ID"

# --- provisioned, not yet started ------------------------------------------
echo "=== exec before start ==="
expect_error_code "exec before start is refused as $NOT_STARTED" \
    "$NOT_STARTED" exec "$SANDBOX_ID" '"process": { "commandLine": "echo unreachable" }'

# LXC reads "never started" and "started and since stopped" from one probe, so
# stop answers for the state it can see rather than the history it cannot.
echo "=== stop before start ==="
expect_error_code "stop before start is refused as $ALREADY_STOPPED" \
    "$ALREADY_STOPPED" stop "$SANDBOX_ID"

# --- started ---------------------------------------------------------------
echo "=== start ==="
run_phase start "$SANDBOX_ID" >/dev/null
check "start exits 0" $?

echo "=== start again ==="
expect_error_code "a second start is refused as $ALREADY_STARTED" \
    "$ALREADY_STARTED" start "$SANDBOX_ID"

# --- stopped ---------------------------------------------------------------
echo "=== stop ==="
run_phase stop "$SANDBOX_ID" >/dev/null
check "stop exits 0" $?

echo "=== stop again ==="
expect_error_code "a second stop is refused as $ALREADY_STOPPED" \
    "$ALREADY_STOPPED" stop "$SANDBOX_ID"

# --- deprovisioned ---------------------------------------------------------
echo "=== deprovision ==="
run_phase deprovision "$SANDBOX_ID" >/dev/null
DEPROVISION_RC=$?
check "deprovision exits 0" "$DEPROVISION_RC"

# Deprovision also runs the authoritative network teardown, so a caller that
# retries after a failure mid-teardown has to be able to reach it again.
echo "=== deprovision again ==="
run_phase deprovision "$SANDBOX_ID" >/dev/null
check "a second deprovision exits 0" $?

# The id still parses once the container is destroyed, which is what separates
# this refusal from malformed_id.
echo "=== start after deprovision ==="
expect_error_code "start against a destroyed sandbox is refused as $STALE_ID" \
    "$STALE_ID" start "$SANDBOX_ID"

echo "=== exec after deprovision ==="
expect_error_code "exec against a destroyed sandbox is refused as $STALE_ID" \
    "$STALE_ID" exec "$SANDBOX_ID" '"process": { "commandLine": "echo unreachable" }'

# Stop answered already_stopped while the container existed but had never run.
# Once it is destroyed the same call answers stale_id, because the probe that
# told those two apart no longer has a container to read.
echo "=== stop after deprovision ==="
expect_error_code "stop against a destroyed sandbox is refused as $STALE_ID" \
    "$STALE_ID" stop "$SANDBOX_ID"

if [ "$DEPROVISION_RC" -eq 0 ]; then
    SANDBOX_ID=""
fi

echo "================================"
echo "Results: $PASSED passed, $FAILED failed"
if [ "$FAILED" -gt 0 ]; then
    exit 1
fi
