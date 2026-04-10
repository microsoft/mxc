#!/bin/bash
# Run LXC end-to-end tests through the CLI (CLI → SDK → lxc-exec → LXC container)
#
# Usage (from WSL):
#   sed -i 's/\r$//' test_scripts/cli_e2e_tests/run_lxc_cli_tests.sh  # fix line endings (once)
#   sudo bash test_scripts/cli_e2e_tests/run_lxc_cli_tests.sh
#
# Prerequisites:
#   - Node.js installed in WSL
#   - LXC installed (sudo apt install lxc)
#   - lxc-exec built (cd src && cargo build --release -p lxc)
#   - SDK built (cd sdk && npm ci && npm run build)
#   - CLI built (cd cli && npm ci && npm run build)
set -uo pipefail

if [ "$(id -u)" -ne 0 ]; then
    echo "ERROR: LXC SDK tests require root privileges."
    echo "Run with: sudo $0"
    exit 1
fi

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_DIR="$(dirname "$(dirname "$SCRIPT_DIR")")"
CLI_JS="$REPO_DIR/cli/dist/cli.js"

if [ ! -f "$CLI_JS" ]; then
    echo "Error: CLI not built. Run 'cd cli && npm ci && npm run build' first."
    exit 1
fi

if ! command -v node &>/dev/null; then
    echo "Error: Node.js not installed in WSL."
    exit 1
fi

PASSED=0
FAILED=0
FAILURES=""
TEST_NUM=0
TOTAL_TESTS=9

run_sdk_test() {
    local name="$1"
    local script="$2"
    local policy="$3"
    local expect_output="$4"

    TEST_NUM=$((TEST_NUM + 1))
    echo "=== [$TEST_NUM/$TOTAL_TESTS] $name ==="
    echo "  Script: $script"
    echo "  Policy: $policy"
    local output
    output=$(node "$CLI_JS" run-sdk --script "$script" --policy "$policy" --debug 2>&1) || true

    if echo "$output" | grep -q "$expect_output"; then
        echo "  Output: $(echo "$output" | grep "$expect_output")"
        echo "  PASS ✓"
        PASSED=$((PASSED + 1))
    else
        echo "  FAIL ✗"
        echo "  Expected: $expect_output"
        echo "  Full output:"
        echo "$output" | sed 's/^/    /'
        FAILED=$((FAILED + 1))
        FAILURES="$FAILURES\n  - $name"
    fi
    echo ""
}

# Test 1: Basic hello world
run_sdk_test \
    "SDK → LXC Hello World" \
    "echo 'Hello from LXC via SDK'" \
    '{"version": "0.4.0-alpha"}' \
    "Hello from LXC via SDK"

# Test 2: Exit code
run_sdk_test \
    "SDK → LXC Exit Code" \
    "echo 'about to exit' && exit 0" \
    '{"version": "0.4.0-alpha"}' \
    "about to exit"

# Test 3: Environment and uname
run_sdk_test \
    "SDK → LXC System Info" \
    "uname -a && echo 'System info test passed'" \
    '{"version": "0.4.0-alpha"}' \
    "System info test passed"

# Test 4: Network with outbound access
run_sdk_test \
    "SDK → LXC Network Outbound" \
    "wget -q -T 5 -O /dev/null http://example.com && echo 'Network accessible'" \
    '{"version": "0.4.0-alpha", "network": {"allowOutbound": true}}' \
    "Network accessible"

# Test 5: Filesystem readwrite path
mkdir -p /tmp/mxc-sdk-test/rw
echo "original" > /tmp/mxc-sdk-test/rw/test.txt
run_sdk_test \
    "SDK → LXC Filesystem ReadWrite" \
    "cat /tmp/mxc-sdk-test/rw/test.txt && echo 'overwritten' > /tmp/mxc-sdk-test/rw/test.txt && cat /tmp/mxc-sdk-test/rw/test.txt" \
    '{"version": "0.4.0-alpha", "filesystem": {"readwritePaths": ["/tmp/mxc-sdk-test/rw"]}}' \
    "overwritten"

# Test 6: Filesystem readonly path
mkdir -p /tmp/mxc-sdk-test/ro
echo "readonly content" > /tmp/mxc-sdk-test/ro/data.txt
run_sdk_test \
    "SDK → LXC Filesystem ReadOnly" \
    "cat /tmp/mxc-sdk-test/ro/data.txt && echo 'Read succeeded'" \
    '{"version": "0.4.0-alpha", "filesystem": {"readonlyPaths": ["/tmp/mxc-sdk-test/ro"]}}' \
    "Read succeeded"

# Test 7: Network with allowed hosts only
run_sdk_test \
    "SDK → LXC Allowed Hosts" \
    "wget -q -T 10 -O /dev/null https://api.github.com && echo 'Allowed host accessible'" \
    '{"version": "0.4.0-alpha", "network": {"allowOutbound": true, "allowedHosts": ["api.github.com"]}}' \
    "Allowed host accessible"

# Test 8: Combined filesystem + network
mkdir -p /tmp/mxc-sdk-test/combined
run_sdk_test \
    "SDK → LXC Combined Filesystem + Network" \
    "wget -q -T 10 -O /tmp/mxc-sdk-test/combined/download.txt https://api.github.com/zen && cat /tmp/mxc-sdk-test/combined/download.txt && echo 'Combined test passed'" \
    '{"version": "0.4.0-alpha", "filesystem": {"readwritePaths": ["/tmp/mxc-sdk-test/combined"]}, "network": {"allowOutbound": true}}' \
    "Combined test passed"

# Test 9: Multi-command script
run_sdk_test \
    "SDK → LXC Multi-Command" \
    "echo 'step 1' && ls / && echo 'step 2' && whoami && echo 'Multi-command passed'" \
    '{"version": "0.4.0-alpha"}' \
    "Multi-command passed"

# Cleanup
rm -rf /tmp/mxc-sdk-test

echo "================================"
echo "Results: $PASSED passed, $FAILED failed"
if [ $FAILED -gt 0 ]; then
    echo -e "Failures:$FAILURES"
    exit 1
fi
