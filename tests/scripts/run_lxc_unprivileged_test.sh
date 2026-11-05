#!/bin/bash
# A reused container with an identity UID map must not run a workload.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_DIR="$(dirname "$(dirname "$SCRIPT_DIR")")"
LXC_EXEC="$REPO_DIR/src/target/release/lxc-exec"
if [ ! -f "$LXC_EXEC" ]; then
    LXC_EXEC="$REPO_DIR/src/target/debug/lxc-exec"
fi

fail() {
    echo "FAIL: $1"
    exit 1
}

[ "$(id -u)" -eq 0 ] || fail "requires root for LXC."
[ -f "$LXC_EXEC" ] || fail "lxc-exec not built; run build.sh first."

CONTAINER="CLI-LXC-Unprivileged-$$"
WORK_DIR="$REPO_DIR/tests/output/lxc-unprivileged-$$"
mkdir -p "$WORK_DIR"

cleanup() {
    local status=$?
    lxc-destroy -n "$CONTAINER" -f || status=1
    rm -rf "$WORK_DIR"
    exit "$status"
}
trap cleanup EXIT

case "$(uname -m)" in
    x86_64) ARCH=amd64 ;;
    aarch64) ARCH=arm64 ;;
    *) fail "unsupported LXC image architecture: $(uname -m)" ;;
esac

# Override only this container's defaults, without using the host bridge.
printf 'lxc.net.0.type = empty\n' > "$WORK_DIR/default.conf"
lxc-create -n "$CONTAINER" -f "$WORK_DIR/default.conf" -t download -- \
    --dist alpine --release 3.23 --arch "$ARCH"

# Keep the host user namespace despite the configured shifted IDs.
cat >> "/var/lib/lxc/$CONTAINER/config" <<'EOF'
lxc.namespace.keep = user
lxc.idmap = u 0 100000 65536
lxc.idmap = g 0 100000 65536
EOF

lxc-start -n "$CONTAINER" -d
lxc-wait -n "$CONTAINER" -s RUNNING -t 30
UID_MAP="$(lxc-attach -n "$CONTAINER" -- cat /proc/self/uid_map)"
read -r inside outside count extra <<< "$UID_MAP"
[ "$inside $outside $count" = "0 0 4294967295" ] && [ -z "$extra" ] \
    || fail "fixture did not retain the identity UID map: $UID_MAP"
METADATA="$(lxc-ls --fancy --fancy-format NAME,UNPRIVILEGED --filter "^$CONTAINER$")"
awk -v name="$CONTAINER" '$1 == name && $2 == "true" { found = 1 } END { exit !found }' \
    <<< "$METADATA" || fail "fixture metadata did not report unprivileged: $METADATA"
lxc-stop -n "$CONTAINER" -k

cat > "$WORK_DIR/request.json" <<EOF
{
  "version": "1.0.0",
  "containerId": "$CONTAINER",
  "containment": "lxc",
  "process": {
    "commandLine": "touch /mxc-admission-workload-ran"
  },
  "lifecycle": { "destroyOnExit": false },
  "lxc": { "distribution": "alpine", "release": "3.23" }
}
EOF

status=0
OUTPUT="$("$LXC_EXEC" "$WORK_DIR/request.json" 2>&1)" || status=$?
echo "$OUTPUT"
[ "$status" -ne 0 ] || fail "MXC admitted a container with an identity UID map."
grep -Eiq 'privileg|uid.?map|user.?namespace' <<< "$OUTPUT" \
    || fail "MXC failed without identifying the privilege or UID-map check."
[ ! -e "/var/lib/lxc/$CONTAINER/rootfs/mxc-admission-workload-ran" ] \
    || fail "the rejected container ran its workload."
STATE="$(lxc-info -n "$CONTAINER" -s -H)"
[ "$STATE" = STOPPED ] \
    || fail "MXC left the rejected reused container $STATE with destroyOnExit false."

echo "PASS: MXC refused the live identity UID map before workload execution and stopped the reused container."
