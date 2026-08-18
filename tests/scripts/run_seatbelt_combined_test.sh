#!/bin/bash
# Seatbelt combined integration test: a single sandboxed process that
# exercises Python execution, Rust execution (compiled with the host
# toolchain's resolved rustc), filesystem read-write / denied-path
# enforcement, and schema-v2 network policy (deny-by-default egress/ingress
# with all traffic routed through a loopback proxy) together in one config.
#
# This is deliberately heavier than the focused per-scenario scripts; it is
# meant to catch cross-cutting regressions (e.g. a filesystem grant that
# breaks network setup, or vice versa) rather than to replace them.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_DIR="$(dirname "$(dirname "$SCRIPT_DIR")")"
# shellcheck source=lib/seatbelt_env.sh
source "$SCRIPT_DIR/lib/seatbelt_env.sh"
# shellcheck source=lib/seatbelt_test_proxy.sh
source "$SCRIPT_DIR/lib/seatbelt_test_proxy.sh"

WORK_DIR="/tmp/mxc_seatbelt_combined_test"
RW_DIR="$WORK_DIR/rw"
DENIED_DIR="$RW_DIR/denied_subdir"
rm -rf "$WORK_DIR"
mkdir -p "$DENIED_DIR"
echo "DENIED_SECRET" > "$DENIED_DIR/secret.txt"

CONFIG_FILE=""
cleanup() {
    stop_test_proxy
    rm -rf "$WORK_DIR"
    [ -n "$CONFIG_FILE" ] && rm -f "$CONFIG_FILE"
}
trap cleanup EXIT

RUST_SEGMENT="echo 'RUST_SKIPPED (rustc not found on host PATH)'"
RUST_READONLY_PATH=""
if command -v rustc &> /dev/null; then
    SYSROOT="$(rustc --print sysroot)"
    RUSTC_BIN="$SYSROOT/bin/rustc"
    if [ -x "$RUSTC_BIN" ]; then
        RS_SOURCE="$WORK_DIR/combined_test.rs"
        RS_BINARY="$WORK_DIR/combined_test_bin"
        # Write the .rs source from the host (not via the sandboxed
        # commandLine) to avoid needing to embed a literal '"' inside the
        # JSON commandLine string.
        printf 'fn main() { println!("RUST_EXEC_OK"); }\n' > "$RS_SOURCE"
        RUST_SEGMENT="'$RUSTC_BIN' $RS_SOURCE -o $RS_BINARY 2>&1 && $RS_BINARY"
        RUST_READONLY_PATH="$SYSROOT"
    fi
fi

start_test_proxy
TEST_PROXY_ADDRESS="127.0.0.1:$TEST_PROXY_PORT"

READONLY_PATHS_JSON="[]"
if [ -n "$RUST_READONLY_PATH" ]; then
    READONLY_PATHS_JSON="[\"$RUST_READONLY_PATH\"]"
fi

CONFIG_FILE="$(mktemp "${TMPDIR:-/tmp}/mxc_seatbelt_combined_config.XXXXXX.json")"
cat > "$CONFIG_FILE" <<EOF
{
    "version": "0.8.0-alpha",
    "containment": "seatbelt",
    "process": {
        "commandLine": "echo COMBINED_TEST_START && python3 -c \\"print('PYTHON_EXEC_OK')\\" && $RUST_SEGMENT && echo 'combined test wrote this' > $RW_DIR/output.txt && cat $RW_DIR/output.txt && echo FS_RW_OK && (cat $DENIED_DIR/secret.txt > /dev/null 2>&1 && echo FS_DENIED_LEAK || echo FS_DENIED_BLOCKED_OK) && curl -s --max-time 5 -x http://$TEST_PROXY_ADDRESS https://api.github.com/zen > /dev/null 2>&1 && echo PROXY_OK || echo PROXY_FAIL && curl -s --max-time 5 --noproxy '*' https://example.com > /dev/null 2>&1 && echo NETWORK_LEAK || echo DIRECT_BLOCKED_OK && echo COMBINED_TEST_END",
        "timeout": 60000
    },
    "filesystem": {
        "readwritePaths": ["/tmp"],
        "deniedPaths": ["$DENIED_DIR"],
        "readonlyPaths": $READONLY_PATHS_JSON
    },
    "network": {
        "egress": { "default": "deny" },
        "ingress": { "default": "deny", "hostLoopback": "deny" }
    },
    "runtimeConfig": {
        "networkProxy": "http://$TEST_PROXY_ADDRESS"
    }
}
EOF

echo "Running Seatbelt combined integration test..."
OUTPUT=$("$MXC_EXEC_MAC" --debug "$CONFIG_FILE" 2>&1)
echo "$OUTPUT"

FAILED=0
assert_contains() {
    local sentinel="$1"
    if ! echo "$OUTPUT" | grep -q "$sentinel"; then
        echo "FAIL: expected sentinel '$sentinel' not found."
        FAILED=1
    fi
}
assert_not_contains() {
    local sentinel="$1"
    if echo "$OUTPUT" | grep -q "$sentinel"; then
        echo "FAIL: unexpected sentinel '$sentinel' found."
        FAILED=1
    fi
}

assert_contains "PYTHON_EXEC_OK"
if [ -n "$RUST_READONLY_PATH" ]; then
    assert_contains "RUST_EXEC_OK"
fi
assert_contains "FS_RW_OK"
assert_contains "FS_DENIED_BLOCKED_OK"
assert_not_contains "FS_DENIED_LEAK"
assert_contains "PROXY_OK"
assert_contains "DIRECT_BLOCKED_OK"
assert_not_contains "NETWORK_LEAK"

if [ ! -f "$RW_DIR/output.txt" ]; then
    echo "FAIL: expected output file was not found on the host after the run."
    FAILED=1
fi
if [ -f "$DENIED_DIR/should_not_exist.txt" ]; then
    echo "FAIL: a write to the denied path unexpectedly landed on the host filesystem."
    FAILED=1
fi

if [ "$FAILED" -ne 0 ]; then
    exit 1
fi
echo "Seatbelt combined integration test complete."
