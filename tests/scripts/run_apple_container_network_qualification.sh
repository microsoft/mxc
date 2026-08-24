#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
SKIP_EXIT=77
INIT_IMAGE="local/mxc-loopback-init:0.2"

skip() {
    echo "SKIP: $1"
    exit "$SKIP_EXIT"
}

[ "$(uname -s)" = "Darwin" ] || skip "Apple Container requires macOS."
[ "$(uname -m)" = "arm64" ] || skip "Apple Container requires Apple silicon."

macos_major="$(sw_vers -productVersion | cut -d. -f1)"
[ "$macos_major" -ge 26 ] || skip "Apple Container requires macOS 26 or later."

command -v node >/dev/null 2>&1 || skip "Node.js is required by the qualification harness."

if [ -n "${APPLE_CONTAINER_BIN:-}" ]; then
    APPLE_CONTAINER_BIN="$(cd "$(dirname "$APPLE_CONTAINER_BIN")" && pwd)/$(basename "$APPLE_CONTAINER_BIN")"
else
    APPLE_CONTAINER_BIN="/usr/local/bin/container"
fi

[ -x "$APPLE_CONTAINER_BIN" ] ||
    skip "Apple Container is not installed at $APPLE_CONTAINER_BIN."

if ! "$APPLE_CONTAINER_BIN" system status --format json >/dev/null 2>&1; then
    skip "Apple Container service is not running; run 'container system start'."
fi

"$REPO_ROOT/src/backends/apple_container/init/build.sh"
export APPLE_CONTAINER_QUALIFICATION_INIT_IMAGE="$INIT_IMAGE"

echo "Apple Container network qualification"
echo "Binary: $APPLE_CONTAINER_BIN"
echo "MXC init: $APPLE_CONTAINER_QUALIFICATION_INIT_IMAGE"
"$APPLE_CONTAINER_BIN" --version
sw_vers
uname -a
sysctl -n hw.optional.arm64 2>/dev/null || true
echo

exec node "$SCRIPT_DIR/apple_container_network_qualification.mjs" "$APPLE_CONTAINER_BIN"
