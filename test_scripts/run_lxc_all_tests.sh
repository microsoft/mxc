#!/bin/bash
# Run all LXC container tests
set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PASSED=0
FAILED=0
FAILURES=""

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
run_test "LXC Network" "$SCRIPT_DIR/run_lxc_network_test.sh"

# Examples (run directly via lxc-exec)
REPO_DIR="$(dirname "$SCRIPT_DIR")"
LXC_EXEC="$REPO_DIR/src/target/release/lxc-exec"
if [ ! -f "$LXC_EXEC" ]; then
    LXC_EXEC="$REPO_DIR/src/target/debug/lxc-exec"
fi

run_exec() {
    local name="$1"
    local config="$2"
    echo "=== $name ==="
    if "$LXC_EXEC" "$config"; then
        echo "PASS: $name"
        PASSED=$((PASSED + 1))
    else
        echo "FAIL: $name"
        FAILED=$((FAILED + 1))
        FAILURES="$FAILURES\n  - $name"
    fi
    echo ""
}

run_exec "LXC Hello World (example)" "$REPO_DIR/examples/11_lxc_hello_world.json"
run_exec "LXC Filesystem Access (example)" "$REPO_DIR/examples/12_lxc_filesystem_access.json"
run_exec "LXC Network Restricted (example)" "$REPO_DIR/examples/13_lxc_network_restricted.json"

echo "================================"
echo "Results: $PASSED passed, $FAILED failed"
if [ $FAILED -gt 0 ]; then
    echo -e "Failures:$FAILURES"
    exit 1
fi
