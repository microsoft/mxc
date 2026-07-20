#!/bin/bash
# LXC denied-path masking test (mirrors run_bwrap_denied_masking_test.sh).
#
# Verifies the LXC backend masks denied entries that live UNDER a read-write
# parent mount:
#   - A denied directory is masked with an empty read-only tmpfs (no leak).
#   - A denied *file* is masked with a read-only bind of /dev/null (its content
#     reads empty). The host-reality classifier (`denied_path_is_file`, uses
#     `symlink_metadata`, never follows symlinks) drives file-vs-dir choice.
#   - A denied *symlink* (to a dir or a file) is classified from the link itself
#     (never followed) and masked, so neither the target dir nor file leaks.
#
# Each fixture holds secret content readable on the host, so any leak inside the
# container is attributable to the policy, not a broken fixture. A non-denied
# sibling acts as a positive control proving the parent mount is really present.
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

# Second fixture tree for the denied-symlink cases below.
SYMBASE="/mnt/symmask"

cleanup() { sudo rm -rf "$BASE" "$SYMBASE"; }
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
    echo "FAIL: fixture setup - visible.txt not readable on host."
    exit 1
fi
if ! sudo cat "$FILE" | grep -q "FILE_SECRET"; then
    echo "FAIL: fixture setup - secret_file.txt not readable on host."
    exit 1
fi
if ! sudo cat "$DIR/inner.txt" | grep -q "DIR_SECRET"; then
    echo "FAIL: fixture setup - secret_dir/inner.txt not readable on host."
    exit 1
fi

echo "Running LXC denied-path masking test (denied file + denied dir)..."
OUTPUT=$("$LXC_EXEC" --experimental \
    "$REPO_DIR/tests/configs/lxc_denied_masking.json" 2>&1 || true)
echo "$OUTPUT"

FAIL=0

# Positive control: the non-denied sibling must be readable, proving the parent
# mount is present (so masking below is attributable to the deny, not absence).
if echo "$OUTPUT" | grep -q "VISIBLE_OK" && ! echo "$OUTPUT" | grep -q "VISIBLE_MISSING"; then
    echo "PASS: non-denied sibling readable (parent mount present)."
else
    echo "FAIL: non-denied sibling not readable - parent mount missing, test inconclusive."
    FAIL=1
fi

if echo "$OUTPUT" | grep -q "FILE_MASKED_OK" && ! echo "$OUTPUT" | grep -q "FILE_LEAK"; then
    echo "PASS: denied file content masked."
else
    echo "FAIL: denied file content leaked."
    FAIL=1
fi

if echo "$OUTPUT" | grep -q "DIR_MASKED_OK" && ! echo "$OUTPUT" | grep -q "DIR_LEAK"; then
    echo "PASS: denied directory masked empty."
else
    echo "FAIL: denied directory content leaked."
    FAIL=1
fi

# --- Denied-symlink masking ---------------------------------------------------
# A denied symlink is classified from the link itself (symlink_metadata, never
# followed) and masked, so neither the target dir nor file leaks. Each config
# also reads a non-denied sibling (control.txt) as a positive control proving
# the parent mount is present, so masking is attributable to the deny.
sudo rm -rf "$SYMBASE"
sudo mkdir -p "$SYMBASE/real_dir"
echo "CONTROL_SECRET" | sudo tee "$SYMBASE/control.txt" > /dev/null
echo "DIR_TARGET_SECRET" | sudo tee "$SYMBASE/real_dir/inner.txt" > /dev/null
echo "FILE_TARGET_SECRET" | sudo tee "$SYMBASE/real_file.txt" > /dev/null
sudo ln -s "$SYMBASE/real_dir" "$SYMBASE/link_to_dir"
sudo ln -s "$SYMBASE/real_file.txt" "$SYMBASE/link_to_file"

echo "Running LXC denied-symlink -> dir masking test..."
DIR_OUT=$("$LXC_EXEC" --experimental \
    "$REPO_DIR/tests/configs/lxc_denied_symlink_dir.json" 2>&1 || true)
echo "$DIR_OUT"
if echo "$DIR_OUT" | grep -q "CONTROL_OK" \
    && echo "$DIR_OUT" | grep -q "SYMDIR_MASKED_OK" \
    && ! echo "$DIR_OUT" | grep -q "SYMDIR_LEAK"; then
    echo "PASS: denied symlink -> dir masked its target (parent mount present)."
else
    echo "FAIL: denied symlink -> dir target not masked."
    FAIL=1
fi

echo "Running LXC denied-symlink -> file masking test..."
FILE_OUT=$("$LXC_EXEC" --experimental \
    "$REPO_DIR/tests/configs/lxc_denied_symlink_file.json" 2>&1 || true)
echo "$FILE_OUT"
if echo "$FILE_OUT" | grep -q "CONTROL_OK" \
    && echo "$FILE_OUT" | grep -q "SYMFILE_MASKED_OK" \
    && ! echo "$FILE_OUT" | grep -q "SYMFILE_LEAK"; then
    echo "PASS: denied symlink -> file masked its target (kept non-directory)."
else
    echo "FAIL: denied symlink -> file target not masked correctly."
    FAIL=1
fi

if [ "$FAIL" -ne 0 ]; then
    exit 1
fi

echo "LXC denied-path masking test complete."
