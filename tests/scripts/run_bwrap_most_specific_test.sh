#!/bin/bash
# Bubblewrap most-specific-path-wins filesystem tests (roadmap D4).
#
# The Linux backends realise the filesystem policy as an ordered list of mounts
# with "last mount at a path wins" semantics. The resolver orders paths so that
# a deeper (more specific) path always overrides a shallower ancestor with a
# different intent, regardless of which policy list it came from. These E2E
# tests exercise both directions:
#
#   1. denied parent + read-write child: the deep child punches through the
#      masked parent and stays readable/writable, while a non-re-bound sibling
#      of the denied parent stays masked.
#   2. read-write parent + denied child: the deep denied secret stays masked
#      while the rest of the writable parent remains accessible.
#
# Both denied paths are directories (masked with tmpfs), so these tests do not
# depend on the denied-file masking work tracked separately.
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

BASE1="/mnt/msptest"
BASE2="/mnt/msptest2"

cleanup() { sudo rm -rf "$BASE1" "$BASE2"; }
trap cleanup EXIT

FAIL=0

# --- Scenario 1: denied parent, read-write child -----------------------------
# /data is denied (masked), but /data/secret_child is read-write. The deep child
# must survive the masked parent; a sibling under the denied parent must not.
sudo rm -rf "$BASE1"
sudo mkdir -p "$BASE1/data/secret_child"
echo "CHILD_KEPT" | sudo tee "$BASE1/data/secret_child/keep.txt" > /dev/null
echo "PARENT_SECRET" | sudo tee "$BASE1/data/sibling.txt" > /dev/null
sudo chown -R "$(id -u):$(id -g)" "$BASE1/data/secret_child"

echo "Running Bubblewrap most-specific test 1 (denied parent, rw child)..."
OUT1=$("$LXC_EXEC" --experimental \
    "$REPO_DIR/tests/configs/bubblewrap_most_specific_denied_parent.json" 2>&1 || true)
echo "$OUT1"

if echo "$OUT1" | grep -q "CHILD_OK" && echo "$OUT1" | grep -q "CHILD_WRITE_OK" \
    && echo "$OUT1" | grep -q "PARENT_MASKED_OK" \
    && ! echo "$OUT1" | grep -qE "CHILD_MISSING|CHILD_WRITE_FAIL|PARENT_LEAK"; then
    echo "PASS: rw child survived denied parent; parent sibling masked."
else
    echo "FAIL: most-specific rw child did not win over denied parent."
    FAIL=1
fi

# --- Scenario 2: read-write parent, denied child -----------------------------
# /proj is read-write, but /proj/secrets is denied (masked). The parent stays
# accessible while the deep secret must be masked.
sudo rm -rf "$BASE2"
sudo mkdir -p "$BASE2/proj/secrets"
echo "PROJ_NOTES" | sudo tee "$BASE2/proj/notes.txt" > /dev/null
echo "DEEP_SECRET" | sudo tee "$BASE2/proj/secrets/key.txt" > /dev/null
sudo chown -R "$(id -u):$(id -g)" "$BASE2/proj"

echo "Running Bubblewrap most-specific test 2 (rw parent, denied child)..."
OUT2=$("$LXC_EXEC" --experimental \
    "$REPO_DIR/tests/configs/bubblewrap_most_specific_rw_parent.json" 2>&1 || true)
echo "$OUT2"

if echo "$OUT2" | grep -q "PARENT_OK" && echo "$OUT2" | grep -q "PARENT_WRITE_OK" \
    && echo "$OUT2" | grep -q "DEEP_MASKED_OK" \
    && ! echo "$OUT2" | grep -qE "PARENT_MISSING|PARENT_WRITE_FAIL|DEEP_LEAK"; then
    echo "PASS: denied child masked under read-write parent."
else
    echo "FAIL: most-specific denied child did not win over rw parent."
    FAIL=1
fi

if [ "$FAIL" -ne 0 ]; then
    exit 1
fi

echo "Bubblewrap most-specific-path-wins tests complete."
