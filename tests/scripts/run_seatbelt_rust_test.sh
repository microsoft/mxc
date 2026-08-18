#!/bin/bash
# Seatbelt Rust execution test: compiles and runs a small Rust program inside
# the sandbox. The toolchain path is resolved from the host's `rustc` (its
# location is machine-specific, so the config is generated on the fly rather
# than a static tests/configs/*.json file).
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_DIR="$(dirname "$(dirname "$SCRIPT_DIR")")"
# shellcheck source=lib/seatbelt_env.sh
source "$SCRIPT_DIR/lib/seatbelt_env.sh"

if ! command -v rustc &> /dev/null; then
    echo "SKIPPED: rustc not found on PATH; cannot run the Seatbelt Rust test."
    exit 0
fi

SYSROOT="$(rustc --print sysroot)"
RUSTC_BIN="$SYSROOT/bin/rustc"
if [ ! -x "$RUSTC_BIN" ]; then
    echo "SKIPPED: resolved rustc binary '$RUSTC_BIN' is not executable."
    exit 0
fi

RS_SOURCE="/tmp/mxc_seatbelt_rust_test.rs"
RS_BINARY="/tmp/mxc_seatbelt_rust_test_bin"
CONFIG_FILE="$(mktemp "${TMPDIR:-/tmp}/mxc_seatbelt_rust_test_config.XXXXXX.json")"
cleanup() {
    rm -f "$CONFIG_FILE" "$RS_SOURCE" "$RS_BINARY"
}
trap cleanup EXIT

cat > "$CONFIG_FILE" <<EOF
{
    "version": "0.7.0-alpha",
    "containment": "seatbelt",
    "process": {
        "commandLine": "printf 'fn main() { println!(\\"RUST_EXEC_OK\\"); }\\n' > $RS_SOURCE && '$RUSTC_BIN' $RS_SOURCE -o $RS_BINARY 2>&1 && $RS_BINARY",
        "timeout": 60000
    },
    "filesystem": {
        "readwritePaths": ["/tmp"],
        "readonlyPaths": ["$SYSROOT"]
    },
    "network": {
        "defaultPolicy": "block"
    }
}
EOF

echo "Running Seatbelt Rust test (toolchain: $SYSROOT)..."
OUTPUT=$("$MXC_EXEC_MAC" --debug "$CONFIG_FILE" 2>&1)
echo "$OUTPUT"

if ! echo "$OUTPUT" | grep -q "RUST_EXEC_OK"; then
    echo "FAIL: compiled Rust binary did not run successfully."
    exit 1
fi
echo "Seatbelt Rust test complete."
