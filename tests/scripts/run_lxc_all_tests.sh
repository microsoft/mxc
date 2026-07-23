#!/bin/bash
# Run all LXC container tests
set -uo pipefail

# LXC tests require root for container management, bind mounts, and iptables
if [ "$(id -u)" -ne 0 ]; then
    echo "ERROR: LXC tests require root privileges."
    echo "Run with: sudo $0"
    exit 1
fi

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PASSED=0
FAILED=0
FAILURES=""

# Check for Windows line endings in test scripts
check_line_endings() {
    if grep -rPl '\r$' "$SCRIPT_DIR"/run_lxc_*.sh >/dev/null 2>&1; then
        echo "ERROR: Shell scripts have Windows line endings (CRLF)."
        echo "Fix with: sed -i 's/\r\$//' $SCRIPT_DIR/run_lxc_*.sh"
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

run_test "Basic LXC" "$SCRIPT_DIR/run_lxc_basic_test.sh"
run_test "LXC Filesystem" "$SCRIPT_DIR/run_lxc_filesystem_test.sh"
run_test "LXC Object Validation" "$SCRIPT_DIR/run_lxc_object_test.sh"
run_test "LXC Most-Specific Path" "$SCRIPT_DIR/run_lxc_most_specific_test.sh"
run_test "LXC Denied Masking" "$SCRIPT_DIR/run_lxc_denied_masking_test.sh"
run_test "LXC Network" "$SCRIPT_DIR/run_lxc_network_test.sh"
run_test "LXC Timeout" "$SCRIPT_DIR/run_lxc_timeout_test.sh"
run_test "LXC Env+Cwd" "$SCRIPT_DIR/run_lxc_env_cwd_test.sh"

echo "================================"
echo "Results: $PASSED passed, $FAILED failed"
if [ $FAILED -gt 0 ]; then
    echo -e "Failures:$FAILURES"
    exit 1
fi
