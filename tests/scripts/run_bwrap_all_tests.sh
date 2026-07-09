#!/bin/bash
# Run all Bubblewrap sandbox tests
set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PASSED=0
FAILED=0
FAILURES=""

# Check for Windows line endings in test scripts
check_line_endings() {
    if grep -rPl '\r$' "$SCRIPT_DIR"/run_bwrap_*.sh "$SCRIPT_DIR"/run_linux_process_default_test.sh >/dev/null 2>&1; then
        echo "ERROR: Shell scripts have Windows line endings (CRLF)."
        echo "Fix with: sed -i 's/\r\$//' $SCRIPT_DIR/run_bwrap_*.sh $SCRIPT_DIR/run_linux_process_default_test.sh"
        exit 1
    fi
}

check_line_endings

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

run_test "Basic Bubblewrap" "$SCRIPT_DIR/run_bwrap_basic_test.sh"
run_test "Bubblewrap Filesystem" "$SCRIPT_DIR/run_bwrap_filesystem_test.sh"
run_test "Bubblewrap Object Validation" "$SCRIPT_DIR/run_bwrap_filesystem_object_test.sh"
run_test "Bubblewrap Most-Specific Path" "$SCRIPT_DIR/run_bwrap_most_specific_test.sh"
run_test "Bubblewrap Denied Masking" "$SCRIPT_DIR/run_bwrap_denied_masking_test.sh"
run_test "Bubblewrap Denied Kind" "$SCRIPT_DIR/run_bwrap_denied_kind_test.sh"
run_test "Bubblewrap Network Block" "$SCRIPT_DIR/run_bwrap_network_test.sh"
run_test "Bubblewrap Network Proxy" "$SCRIPT_DIR/run_bwrap_network_proxy_test.sh"
run_test "Linux Process Default" "$SCRIPT_DIR/run_linux_process_default_test.sh"

echo "================================"
echo "Results: $PASSED passed, $FAILED failed"
if [ $FAILED -gt 0 ]; then
    echo -e "Failures:$FAILURES"
    exit 1
fi
