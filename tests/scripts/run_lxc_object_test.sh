#!/bin/bash
# LXC object-based filesystem-policy validation test (roadmap D6).
#
# When two different policy paths resolve to the SAME host object (a directory
# and a symlink to it) but carry conflicting intents, the runner tightens every
# alias to the most-restrictive intent (deny > ro > rw) BEFORE building the LXC
# mount entries — so the object is masked even though it is listed under
# readwritePaths. (LXC masks a denied directory with a read-only tmpfs; see
# filesystem_mounts.rs.)
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

# Real directory with a secret, plus a symlink alias pointing at the same
# directory object. Hermetic: dynamic temp paths substituted into the config.
DATA=$(mktemp -d)
LINK=$(mktemp -u)
ln -s "$DATA" "$LINK"
echo "OBJECT_SECRET" > "$DATA/secret.txt"

cleanup() { rm -rf "$DATA" "$LINK"; }
trap cleanup EXIT

echo "Running LXC object-validation test (RW + denied alias, expect masked)..."
echo "Data dir: $DATA"
echo "Symlink alias: $LINK"

CONFIG=$(sed -e "s|/mnt/objdata|$DATA|g" -e "s|/mnt/objlink|$LINK|g" \
    "$REPO_DIR/tests/configs/lxc_filesystem_object.json")

OUTPUT=$(echo "$CONFIG" | "$LXC_EXEC" --config /dev/stdin 2>&1 || true)
echo "$OUTPUT"

if echo "$OUTPUT" | grep -q "OBJECT_MASKED_OK" && ! echo "$OUTPUT" | grep -q "OBJECT_LEAK"; then
    echo "PASS: denied alias tightened the read-write path; object masked (bypass closed)."
else
    echo "FAIL: object reachable via read-write alias of a denied path (bypass NOT closed)."
    exit 1
fi

echo "LXC object-based validation test complete."
