#!/bin/bash
# LXC most-specific-path-wins filesystem test (mirrors the denied-parent scenario
# of run_bwrap_most_specific_test.sh).
#
# The Linux backends realise the filesystem policy as an ordered list of mounts
# with "last mount at a path wins" semantics. The resolver orders paths so that
# a deeper (more specific) path always overrides a shallower ancestor with a
# different intent, regardless of which policy list it came from.
#
#   denied parent + read-write child: the deep child punches through the masked
#   parent and stays readable/writable, while a non-re-bound sibling of the
#   denied parent stays masked.
#
# The denied parent is a directory (masked with tmpfs), so this test does not
# depend on the denied-file masking work.
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

BASE="/mnt/msptest"

cleanup() { sudo rm -rf "$BASE"; }
trap cleanup EXIT

FAIL=0

# --- denied parent, read-write child -----------------------------------------
# /data is denied (masked), but /data/secret_child is read-write. The deep child
# must survive the masked parent; a sibling under the denied parent must not.
sudo rm -rf "$BASE"
sudo mkdir -p "$BASE/data/secret_child"
echo "CHILD_KEPT" | sudo tee "$BASE/data/secret_child/keep.txt" > /dev/null
echo "PARENT_SECRET" | sudo tee "$BASE/data/sibling.txt" > /dev/null
sudo chown -R "$(id -u):$(id -g)" "$BASE/data/secret_child"

echo "Running LXC most-specific test (denied parent, rw child)..."
OUT=$("$LXC_EXEC" --experimental \
    "$REPO_DIR/tests/configs/lxc_most_specific_denied_parent.json" 2>&1 || true)
echo "$OUT"

if echo "$OUT" | grep -q "CHILD_OK" && echo "$OUT" | grep -q "CHILD_WRITE_OK" \
    && echo "$OUT" | grep -q "PARENT_MASKED_OK" \
    && ! echo "$OUT" | grep -qE "CHILD_MISSING|CHILD_WRITE_FAIL|PARENT_LEAK"; then
    echo "PASS: rw child survived denied parent; parent sibling masked."
else
    echo "FAIL: most-specific rw child did not win over denied parent."
    FAIL=1
fi

if [ "$FAIL" -ne 0 ]; then
    exit 1
fi

echo "LXC most-specific-path-wins test complete."
