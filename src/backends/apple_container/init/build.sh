#!/usr/bin/env bash
set -euo pipefail

readonly CONTAINER_BIN="/usr/local/bin/container"
readonly IMAGE="local/mxc-loopback-init:0.2"
readonly EXPECTED_DIGEST="sha256:a82bc45e6fee26927b9881150ca2d8d1b29969a306ba579e8b8887345d31dc2f"
readonly SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

[ -x "$CONTAINER_BIN" ] || {
    echo "Apple Container CLI not found at $CONTAINER_BIN" >&2
    exit 1
}

"$CONTAINER_BIN" build --tag "$IMAGE" "$SCRIPT_DIR"
actual_digest="$(
    "$CONTAINER_BIN" image inspect "$IMAGE" |
        sed -n 's/.*"digest" : "\(sha256:[0-9a-f]*\)".*/\1/p' |
        head -n 1
)"

if [ "$actual_digest" != "$EXPECTED_DIGEST" ]; then
    echo "Unexpected init image digest: $actual_digest (expected $EXPECTED_DIGEST)" >&2
    exit 1
fi

echo "$IMAGE verified at $EXPECTED_DIGEST"
