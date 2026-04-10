#!/bin/bash
# Run LXC end-to-end tests through the CLI (CLI → SDK → lxc-exec → LXC container)
#
# Usage (from Linux):
#   sed -i 's/\r$//' test_scripts/cli_e2e_tests/run_lxc_cli_tests.sh  # fix line endings (once)
#   sudo bash test_scripts/cli_e2e_tests/run_lxc_cli_tests.sh
#
# Prerequisites:
#   - Node.js installed
#   - LXC installed (sudo apt install lxc)
#   - lxc-exec built (cd src && cargo build --release -p lxc)
#   - SDK built (cd sdk && npm ci && npm run build)
#   - CLI built (cd cli && npm ci && npm run build)
set -uo pipefail

if [ "$(id -u)" -ne 0 ]; then
    echo "ERROR: LXC CLI e2e tests require root privileges."
    echo "Run with: sudo $0"
    exit 1
fi

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_DIR="$(dirname "$(dirname "$SCRIPT_DIR")")"
CLI_JS="$REPO_DIR/cli/dist/cli.js"

# Preflight checks
if ! command -v node &>/dev/null; then
    echo "Error: Node.js not installed."
    exit 1
fi

if [ ! -f "$CLI_JS" ]; then
    echo "Error: CLI not built. Run 'cd cli && npm ci && npm run build' first."
    exit 1
fi

if ! command -v lxc-ls &>/dev/null; then
    echo "Error: LXC not installed. Run 'sudo apt install lxc' first."
    exit 1
fi

# Check lxc-exec is built
LXC_EXEC="$REPO_DIR/src/target/release/lxc-exec"
if [ ! -f "$LXC_EXEC" ]; then
    LXC_EXEC="$REPO_DIR/src/target/debug/lxc-exec"
fi
if [ ! -f "$LXC_EXEC" ]; then
    echo "Error: lxc-exec not found. Run 'cd src && cargo build --release -p lxc' first."
    exit 1
fi

# Create isolated temp directory with cleanup trap
TEST_TMPDIR=$(mktemp -d /tmp/mxc-cli-e2e-XXXXXX)
cleanup() {
    rm -rf "$TEST_TMPDIR"
}
trap cleanup EXIT INT TERM

PASSED=0
FAILED=0
FAILURES=""
TEST_NUM=0
TOTAL_TESTS=9

run_cli_test() {
    local name="$1"
    local script="$2"
    local policy="$3"
    local expect_output="$4"

    TEST_NUM=$((TEST_NUM + 1))
    echo "=== [$TEST_NUM/$TOTAL_TESTS] $name ==="
    echo "  Script: $script"
    echo "  Policy: $policy"

    local output
    local cli_exit_code
    output=$(node "$CLI_JS" run-sdk --script "$script" --policy "$policy" --debug 2>&1)
    cli_exit_code=$?

    if [ "$cli_exit_code" -eq 0 ] \
        && echo "$output" | grep -q "$expect_output" \
        && echo "$output" | grep -q "Process exited with code 0"; then
        echo "  Output: $(echo "$output" | grep "$expect_output")"
        echo "  PASS ✓"
        PASSED=$((PASSED + 1))
    else
        echo "  FAIL ✗"
        echo "  Expected: $expect_output"
        echo "  CLI exit code: $cli_exit_code"
        echo "  Full output:"
        echo "$output" | sed 's/^/    /'
        FAILED=$((FAILED + 1))
        FAILURES="$FAILURES\n  - $name"
    fi
    echo ""
}

# Test 1: Basic hello world
run_cli_test \
    "CLI → LXC Hello World" \
    "echo 'Hello from LXC via CLI'" \
    '{"version": "0.4.0-alpha"}' \
    "Hello from LXC via CLI"

# Test 2: Exit code
run_cli_test \
    "CLI → LXC Exit Code" \
    "echo 'about to exit' && exit 0" \
    '{"version": "0.4.0-alpha"}' \
    "about to exit"

# Test 3: System info
run_cli_test \
    "CLI → LXC System Info" \
    "uname -a && echo 'System info test passed'" \
    '{"version": "0.4.0-alpha"}' \
    "System info test passed"

# Test 4: Network outbound access
run_cli_test \
    "CLI → LXC Network Outbound" \
    "wget -q -T 5 -O /dev/null http://example.com && echo 'Network accessible'" \
    '{"version": "0.4.0-alpha", "network": {"allowOutbound": true}}' \
    "Network accessible"

# Test 5: Filesystem readwrite path
mkdir -p "$TEST_TMPDIR/rw"
echo "original" > "$TEST_TMPDIR/rw/test.txt"
run_cli_test \
    "CLI → LXC Filesystem ReadWrite" \
    "cat $TEST_TMPDIR/rw/test.txt && echo 'overwritten' > $TEST_TMPDIR/rw/test.txt && cat $TEST_TMPDIR/rw/test.txt" \
    "{\"version\": \"0.4.0-alpha\", \"filesystem\": {\"readwritePaths\": [\"$TEST_TMPDIR/rw\"]}}" \
    "overwritten"

# Test 6: Filesystem readonly path
mkdir -p "$TEST_TMPDIR/ro"
echo "readonly content" > "$TEST_TMPDIR/ro/data.txt"
run_cli_test \
    "CLI → LXC Filesystem ReadOnly" \
    "cat $TEST_TMPDIR/ro/data.txt && echo 'Read succeeded'" \
    "{\"version\": \"0.4.0-alpha\", \"filesystem\": {\"readonlyPaths\": [\"$TEST_TMPDIR/ro\"]}}" \
    "Read succeeded"

# Test 7: Network outbound HTTPS endpoint
run_cli_test \
    "CLI → LXC Network Outbound HTTPS" \
    "wget -q -T 10 -O /dev/null https://api.github.com && echo 'HTTPS endpoint accessible'" \
    '{"version": "0.4.0-alpha", "network": {"allowOutbound": true}}' \
    "HTTPS endpoint accessible"

# Test 8: Combined filesystem + network
mkdir -p "$TEST_TMPDIR/combined"
run_cli_test \
    "CLI → LXC Combined Filesystem + Network" \
    "wget -q -T 10 -O $TEST_TMPDIR/combined/download.txt https://api.github.com/zen && cat $TEST_TMPDIR/combined/download.txt && echo 'Combined test passed'" \
    "{\"version\": \"0.4.0-alpha\", \"filesystem\": {\"readwritePaths\": [\"$TEST_TMPDIR/combined\"]}, \"network\": {\"allowOutbound\": true}}" \
    "Combined test passed"

# Test 9: Multi-command script
run_cli_test \
    "CLI → LXC Multi-Command" \
    "echo 'step 1' && ls / && echo 'step 2' && whoami && echo 'Multi-command passed'" \
    '{"version": "0.4.0-alpha"}' \
    "Multi-command passed"

echo "================================"
echo "Results: $PASSED passed, $FAILED failed"
if [ $FAILED -gt 0 ]; then
    echo -e "Failures:$FAILURES"
    exit 1
fi
