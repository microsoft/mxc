#!/bin/bash
# LXC rootless test: a config with no network section runs without root
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_DIR="$(dirname "$(dirname "$SCRIPT_DIR")")"
LXC_EXEC="$REPO_DIR/src/target/release/lxc-exec"

if [ ! -f "$LXC_EXEC" ]; then
    LXC_EXEC="$REPO_DIR/src/target/debug/lxc-exec"
fi

if [ ! -f "$LXC_EXEC" ]; then
    echo "Error: lxc-exec not found. Run build.sh first."
    exit 1
fi

if [ "$(id -u)" -ne 0 ]; then
    echo "Error: run this under sudo, so it can create the unprivileged user that runs lxc-exec."
    exit 1
fi

RUN_USER=mxc-rootless-e2e
useradd -m "$RUN_USER"
trap 'userdel -r "$RUN_USER" 2>/dev/null' EXIT

RUN_HOME="/home/$RUN_USER"
SUBUID_START=$(grep "^$RUN_USER:" /etc/subuid | cut -d: -f2)
SUBGID_START=$(grep "^$RUN_USER:" /etc/subgid | cut -d: -f2)

# The container's mapped root must be able to walk into the user's home to reach its rootfs.
chmod 755 "$RUN_HOME"
mkdir -p "$RUN_HOME/.config/lxc"
cat > "$RUN_HOME/.config/lxc/default.conf" <<EOF
lxc.include = /etc/lxc/default.conf
lxc.idmap = u 0 $SUBUID_START 65536
lxc.idmap = g 0 $SUBGID_START 65536
EOF
chown -R "$RUN_USER:" "$RUN_HOME/.config"

echo "Running LXC rootless no-network test as $RUN_USER..."
OUTPUT=$(sudo -u "$RUN_USER" -H "$LXC_EXEC" "$REPO_DIR/tests/configs/lxc_rootless_no_network.json" 2>&1) || {
    echo "FAIL: lxc-exec without root could not run a config that has no network section."
    echo "$OUTPUT"
    exit 1
}

if ! grep -q "MXC_ROOTLESS_OK" <<< "$OUTPUT"; then
    echo "FAIL: the container ran without root but the command printed nothing."
    echo "$OUTPUT"
    exit 1
fi

echo "LXC rootless no-network test complete."