#!/bin/bash
# Bubblewrap denied-path masking test (roadmap item #1).
#
# Verifies that a denied FILE and a denied DIRECTORY are each masked with the
# correct primitive:
#   - A denied directory is masked with a tmpfs (empty, no leak).
#   - A denied *file* is masked with a read-only bind of /dev/null. Masking a
#     file with tmpfs would turn it into a DIRECTORY (bwrap creates the mount
#     point as a dir), which both changes its type and can break tools that
#     expect a regular file. Binding /dev/null keeps it a non-directory whose
#     content is empty.
#
# Both fixtures hold secret content that is readable on the host, so any leak
# inside the sandbox is attributable to the policy, not a broken fixture. A
# non-denied sibling (visible.txt) inside the same read-write parent acts as a
# positive control: it MUST be readable in the sandbox, proving the parent
# mount is really present so that masking of the denied entries is attributable
# to the deny policy rather than to the tree simply being absent.
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

BASE="/mnt/masktest"
VISIBLE="$BASE/visible.txt"
FILE="$BASE/secret_file.txt"
DIR="$BASE/secret_dir"

cleanup() { sudo rm -rf "$BASE"; }
trap cleanup EXIT

# Set up: a readable sibling (positive control), a denied secret file, and a
# denied directory holding a secret file.
sudo rm -rf "$BASE"
sudo mkdir -p "$DIR"
echo "VISIBLE_SECRET" | sudo tee "$VISIBLE" > /dev/null
echo "FILE_SECRET" | sudo tee "$FILE" > /dev/null
echo "DIR_SECRET" | sudo tee "$DIR/inner.txt" > /dev/null

# Sanity: all fixtures are readable on the host.
if ! sudo cat "$VISIBLE" | grep -q "VISIBLE_SECRET"; then
    echo "FAIL: fixture setup — visible.txt not readable on host."
    exit 1
fi
if ! sudo cat "$FILE" | grep -q "FILE_SECRET"; then
    echo "FAIL: fixture setup — secret_file.txt not readable on host."
    exit 1
fi
if ! sudo cat "$DIR/inner.txt" | grep -q "DIR_SECRET"; then
    echo "FAIL: fixture setup — secret_dir/inner.txt not readable on host."
    exit 1
fi

echo "Running Bubblewrap denied-path masking test (denied file + denied dir)..."
OUTPUT=$("$LXC_EXEC" --experimental \
    "$REPO_DIR/tests/configs/bubblewrap_denied_masking.json" 2>&1 || true)
echo "$OUTPUT"

FAIL=0

# Positive control: the non-denied sibling must be readable, proving the parent
# mount is present (so masking below is attributable to the deny, not absence).
if echo "$OUTPUT" | grep -q "VISIBLE_OK" && ! echo "$OUTPUT" | grep -q "VISIBLE_MISSING"; then
    echo "PASS: non-denied sibling readable (parent mount present)."
else
    echo "FAIL: non-denied sibling not readable — parent mount missing, test inconclusive."
    FAIL=1
fi

if echo "$OUTPUT" | grep -q "FILE_MASKED_OK" && ! echo "$OUTPUT" | grep -q "FILE_LEAK"; then
    echo "PASS: denied file content masked."
else
    echo "FAIL: denied file content leaked."
    FAIL=1
fi

if echo "$OUTPUT" | grep -q "FILE_NOT_DIR_OK" && ! echo "$OUTPUT" | grep -q "FILE_IS_DIR_BUG"; then
    echo "PASS: denied file kept as non-directory (masked with /dev/null, not tmpfs)."
else
    echo "FAIL: denied file became a directory (tmpfs-over-file bug)."
    FAIL=1
fi

if echo "$OUTPUT" | grep -q "DIR_MASKED_OK" && ! echo "$OUTPUT" | grep -q "DIR_LEAK"; then
    echo "PASS: denied directory masked empty."
else
    echo "FAIL: denied directory content leaked."
    FAIL=1
fi

if [ "$FAIL" -ne 0 ]; then
    exit 1
fi

echo "Bubblewrap denied-path masking test complete."
