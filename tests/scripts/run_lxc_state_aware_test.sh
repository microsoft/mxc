#!/bin/bash
# LXC state-aware lifecycle test.
#
# Drives the full provision -> start -> exec -> stop -> deprovision sequence
# against lxc-exec, relaying the sandboxId the way a real client does. This is
# the Linux counterpart to run_isolation_session_state_aware_tests.ps1 and
# run_windows_sandbox_state_aware_tests.ps1.
#
# Until this existed, tests/configs/lxc_state_aware_provision.json was checked
# in but never executed by anything, so no test covered the LXC lifecycle end to
# end: the unit tests stub the container, and run_lxc_all_tests.sh only exercised
# the one-shot path. A phase that failed on a real host would ship green.
set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_DIR="$(dirname "$(dirname "$SCRIPT_DIR")")"
CONFIG_DIR="$REPO_DIR/tests/configs"

LXC_EXEC="$REPO_DIR/src/target/release/lxc-exec"
if [ ! -f "$LXC_EXEC" ]; then
    LXC_EXEC="$REPO_DIR/src/target/debug/lxc-exec"
fi
if [ ! -f "$LXC_EXEC" ]; then
    echo "Error: lxc-exec not found. Run build.sh first."
    exit 1
fi

WORK_DIR="$(mktemp -d)"
SANDBOX_ID=""
PASSED=0
FAILED=0
CLEANED_UP=0

# Always attempt to tear the container down, including on an early failure or a
# signal. A leaked container outlives the test run and breaks the next one, so
# this is best-effort and deliberately ignores its own exit status.
#
# A signal fires this trap and then the shell exits, firing the EXIT trap as
# well, so the guard makes the deprovision run at most once rather than twice.
cleanup() {
    if [ "$CLEANED_UP" -ne 0 ]; then
        return
    fi
    CLEANED_UP=1
    if [ -n "$SANDBOX_ID" ]; then
        echo "--- cleanup: deprovision $SANDBOX_ID ---"
        run_phase deprovision "$SANDBOX_ID" >/dev/null 2>&1 || true
    fi
    rm -rf "$WORK_DIR"
}
trap cleanup EXIT INT TERM

# Emit a state-aware request for $1 (phase) with sandboxId $2, plus any extra
# JSON members in $3, then run it. Envelope goes to stdout, diagnostics to
# stderr, so the caller can parse stdout directly.
run_phase() {
    local phase="$1"
    local sandbox_id="${2:-}"
    local extra="${3:-}"
    local req="$WORK_DIR/$phase.json"

    {
        printf '{\n  "phase": "%s",\n  "containment": "lxc"' "$phase"
        if [ -n "$sandbox_id" ]; then
            printf ',\n  "sandboxId": "%s"' "$sandbox_id"
        fi
        if [ -n "$extra" ]; then
            printf ',\n  %s' "$extra"
        fi
        printf '\n}\n'
    } > "$req"

    "$LXC_EXEC" "$req"
}

# Pull sandboxId out of a result envelope without depending on jq or python,
# neither of which is guaranteed on an LXC test host.
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

echo "Running LXC state-aware lifecycle test..."

# --- provision -------------------------------------------------------------
# Uses the checked-in config so the distribution/release stay in one place.
echo "=== provision ==="
PROVISION_OUT="$("$LXC_EXEC" "$CONFIG_DIR/lxc_state_aware_provision.json")"
PROVISION_RC=$?
check "provision exits 0" "$PROVISION_RC"
echo "$PROVISION_OUT"

SANDBOX_ID="$(printf '%s' "$PROVISION_OUT" | extract_sandbox_id)"
if [ -n "$SANDBOX_ID" ]; then
    check "provision returns a sandboxId" 0
else
    check "provision returns a sandboxId" 1
    echo "Cannot continue without a sandboxId."
    echo "Results: $PASSED passed, $FAILED failed"
    exit 1
fi

case "$SANDBOX_ID" in
    lxc:mxc-*) check "sandboxId has the lxc:mxc- prefix ($SANDBOX_ID)" 0 ;;
    *)         check "sandboxId has the lxc:mxc- prefix ($SANDBOX_ID)" 1 ;;
esac

# --- start -----------------------------------------------------------------
echo "=== start ==="
run_phase start "$SANDBOX_ID"
check "start exits 0" $?

# --- exec ------------------------------------------------------------------
# Exec relays the script's own exit code rather than an envelope, so these two
# assert the code directly: a successful command and a deliberate failure.
echo "=== exec (success) ==="
run_phase exec "$SANDBOX_ID" '"process": { "commandLine": "echo hello-from-lxc" }'
check "exec relays exit code 0" $?

echo "=== exec (nonzero) ==="
run_phase exec "$SANDBOX_ID" '"process": { "commandLine": "exit 7" }'
EXEC_RC=$?
if [ "$EXEC_RC" = "7" ]; then
    check "exec relays a nonzero exit code (got 7)" 0
else
    check "exec relays a nonzero exit code (got $EXEC_RC, want 7)" 1
fi

# --- stop ------------------------------------------------------------------
echo "=== stop ==="
run_phase stop "$SANDBOX_ID"
check "stop exits 0" $?

# --- deprovision -----------------------------------------------------------
echo "=== deprovision ==="
run_phase deprovision "$SANDBOX_ID"
check "deprovision exits 0" $?
# Claimed by this call; stop the trap from deprovisioning a second time.
SANDBOX_ID=""

echo "================================"
echo "Results: $PASSED passed, $FAILED failed"
if [ "$FAILED" -gt 0 ]; then
    exit 1
fi
