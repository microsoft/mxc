#!/bin/bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_DIR="$(dirname "$(dirname "$SCRIPT_DIR")")"
LXC_EXEC="$REPO_DIR/src/target/release/lxc-exec"
[ -f "$LXC_EXEC" ] || LXC_EXEC="$REPO_DIR/src/target/debug/lxc-exec"

CONTAINER="CLI-LXC-Host-Network"
export LXC_PATH="$PWD/.mxc-lxc-host-network-$$"
mkdir "$LXC_PATH"
trap 'rm -rf "$LXC_PATH"' EXIT

# The empty rootfs and failing hook prevent a workload from starting if rejection regresses.
mkdir -p "$LXC_PATH/$CONTAINER/rootfs"
cat > "$LXC_PATH/$CONTAINER/config" <<EOF
lxc.rootfs.path = dir:$LXC_PATH/$CONTAINER/rootfs
lxc.uts.name = $CONTAINER
lxc.hook.start-host = /bin/false
lxc.net.0.type = none
EOF
cat > "$LXC_PATH/request.json" <<EOF
{
  "version": "1.0.0",
  "containerId": "$CONTAINER",
  "containment": "lxc",
  "process": { "commandLine": "true" },
  "lifecycle": { "destroyOnExit": false },
  "lxc": { "distribution": "alpine", "release": "3.23" }
}
EOF

echo "Running LXC host-network rejection test..."
set +e
OUTPUT=$("$LXC_EXEC" --debug "$LXC_PATH/request.json" 2>&1)
STATUS=$?
set -e
echo "$OUTPUT"
if [ "$STATUS" -eq 0 ] || ! grep -Fq 'LXC host networking (lxc.net.0.type=none) is not supported' <<<"$OUTPUT"; then
    echo "FAIL: expected the pre-start host-network rejection, got exit $STATUS."
    exit 1
fi
echo "PASS: host networking was rejected before startup."
