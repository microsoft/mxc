#!/bin/bash
# Run all Seatbelt (macOS) sandbox tests.
set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PASSED=0
FAILED=0
FAILURES=""

# Check for Windows line endings in test scripts
check_line_endings() {
    if grep -rPl '\r$' "$SCRIPT_DIR"/run_seatbelt_*.sh "$SCRIPT_DIR"/lib/seatbelt_*.sh >/dev/null 2>&1; then
        echo "ERROR: Shell scripts have Windows line endings (CRLF)."
        echo "Fix with: sed -i 's/\r\$//' $SCRIPT_DIR/run_seatbelt_*.sh $SCRIPT_DIR/lib/seatbelt_*.sh"
        exit 1
    fi
}

check_line_endings

if [ "$(uname -s)" != "Darwin" ]; then
    echo "SKIPPED: the Seatbelt backend only runs on macOS."
    exit 0
fi

run_test() {
    local name="$1"
    local script="$2"
    echo "=== $name ==="
    if bash "$script"; then
        echo "PASS: $name"
        PASSED=$((PASSED + 1))
    else
        echo "FAIL: $name"
        FAILED=$((FAILED + 1))
        FAILURES="$FAILURES\n  - $name"
    fi
    echo ""
}

run_test "Seatbelt Basic" "$SCRIPT_DIR/run_seatbelt_basic_test.sh"
run_test "Seatbelt Python Execution" "$SCRIPT_DIR/run_seatbelt_python_test.sh"
run_test "Seatbelt Script File Execution" "$SCRIPT_DIR/run_seatbelt_script_file_test.sh"
run_test "Seatbelt Rust Execution" "$SCRIPT_DIR/run_seatbelt_rust_test.sh"
run_test "Seatbelt Filesystem Read-Write" "$SCRIPT_DIR/run_seatbelt_filesystem_test.sh"
run_test "Seatbelt Filesystem Read-Only" "$SCRIPT_DIR/run_seatbelt_filesystem_readonly_test.sh"
run_test "Seatbelt Filesystem Denied Path" "$SCRIPT_DIR/run_seatbelt_filesystem_denied_test.sh"
run_test "Seatbelt Filesystem Nested Precedence" "$SCRIPT_DIR/run_seatbelt_filesystem_nested_precedence_test.sh"
run_test "Seatbelt Network Deny" "$SCRIPT_DIR/run_seatbelt_network_deny_test.sh"
run_test "Seatbelt Network Allow" "$SCRIPT_DIR/run_seatbelt_network_allow_test.sh"
run_test "Seatbelt Network allowedHosts Degrade" "$SCRIPT_DIR/run_seatbelt_network_allowed_hosts_degrade_test.sh"
run_test "Seatbelt Network blockedHosts Rejected" "$SCRIPT_DIR/run_seatbelt_network_blocked_hosts_rejected_test.sh"
run_test "Seatbelt Network Local (loopback listen)" "$SCRIPT_DIR/run_seatbelt_network_local_test.sh"
run_test "Seatbelt Network Legacy Proxy" "$SCRIPT_DIR/run_seatbelt_network_proxy_test.sh"
run_test "Seatbelt Network Schema-v2" "$SCRIPT_DIR/run_seatbelt_network_v2_test.sh"
run_test "Seatbelt Network Schema-v2 Validation" "$SCRIPT_DIR/run_seatbelt_network_v2_validation_test.sh"
run_test "Seatbelt Combined Integration" "$SCRIPT_DIR/run_seatbelt_combined_test.sh"

echo "================================"
echo "Results: $PASSED passed, $FAILED failed"
if [ $FAILED -gt 0 ]; then
    echo -e "Failures:$FAILURES"
    exit 1
fi
