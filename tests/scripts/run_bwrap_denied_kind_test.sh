#!/bin/bash
# Bubblewrap denied-path KIND discriminator test (roadmap item #3, Part B).
#
# Part A masks denied files with /dev/null and denied directories with tmpfs,
# classifying each path with a runtime `symlink_metadata` probe. The probe is
# host-dependent: a path that does NOT exist on the host cannot be stat'd and
# falls back to tmpfs (directory) masking — so a caller cannot deterministically
# mask a not-yet-present secret file as a non-directory.
#
# Part B lets a `deniedPaths` entry declare `"type": "file"` or
# `"type": "directory"` so the masking primitive is chosen DETERMINISTICALLY,
# independent of host state. This test exercises two MISSING paths (which the
# runtime probe alone cannot classify) with opposite declared kinds:
#
#   1. ghost_file.txt — missing on host, declared "type": "file".
#      Must be masked with /dev/null (a non-directory). Under Part A's probe a
#      missing path falls back to tmpfs and would appear as an empty DIRECTORY.
#   2. ghost_dir      — missing on host, declared "type": "directory".
#      Must be masked with tmpfs (an empty directory).
#
# The contrast (one becomes a non-directory, the other a directory) proves the
# `type` field — not the host — drives the masking primitive.
#
# A non-denied sibling (visible.txt) in the same read-write parent is a positive
# control proving the parent mount is present, so masking is attributable to the
# deny policy rather than to the tree being absent.
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

BASE="/mnt/kindtest"
VISIBLE="$BASE/visible.txt"

cleanup() { sudo rm -rf "$BASE"; }
trap cleanup EXIT

# Set up: only the read-write parent and a readable sibling (positive control).
# ghost_file.txt and ghost_dir are deliberately NOT created — the whole point is
# that their masking is driven by the declared kind, not a host probe.
sudo rm -rf "$BASE"
sudo mkdir -p "$BASE"
echo "VISIBLE_SECRET" | sudo tee "$VISIBLE" > /dev/null

# Sanity: the sibling is readable on the host.
if ! sudo cat "$VISIBLE" | grep -q "VISIBLE_SECRET"; then
    echo "FAIL: fixture setup — visible.txt not readable on host."
    exit 1
fi

echo "Running Bubblewrap denied-path kind test (missing file vs missing dir)..."
OUTPUT=$("$LXC_EXEC" --experimental \
    "$REPO_DIR/tests/configs/bubblewrap_denied_kind.json" 2>&1 || true)
echo "$OUTPUT"

FAIL=0

# Positive control: the non-denied sibling must be readable.
if echo "$OUTPUT" | grep -q "VISIBLE_OK" && ! echo "$OUTPUT" | grep -q "VISIBLE_MISSING"; then
    echo "PASS: non-denied sibling readable (parent mount present)."
else
    echo "FAIL: non-denied sibling not readable — parent mount missing, test inconclusive."
    FAIL=1
fi

# Missing path declared "file" → /dev/null → a character device (provably the
# bind, not just a non-directory), and it reads empty.
if echo "$OUTPUT" | grep -q "FILE_IS_DEVNULL_OK" && ! echo "$OUTPUT" | grep -q "FILE_NOT_DEVNULL_BUG"; then
    echo "PASS: missing path declared file masked as /dev/null (character device)."
else
    echo "FAIL: missing path declared file was not a /dev/null character device (bind did not take effect)."
    FAIL=1
fi

if echo "$OUTPUT" | grep -q "FILE_EMPTY_OK" && ! echo "$OUTPUT" | grep -q "FILE_NONEMPTY_BUG"; then
    echo "PASS: /dev/null-masked file reads empty."
else
    echo "FAIL: /dev/null-masked file was not empty."
    FAIL=1
fi

# Missing path declared "directory" → tmpfs → an (empty) directory.
if echo "$OUTPUT" | grep -q "DIR_IS_DIR_OK" && ! echo "$OUTPUT" | grep -q "DIR_NOT_DIR_BUG"; then
    echo "PASS: missing path declared directory masked as a directory (tmpfs)."
else
    echo "FAIL: missing path declared directory was not masked as a directory."
    FAIL=1
fi

# The runner must reclaim the empty host stubs bwrap created as mount points for
# the missing denied paths — the host must be left as we found it.
if [ ! -e "$BASE/ghost_file.txt" ]; then
    echo "PASS: missing denied file left no host stub behind."
else
    echo "FAIL: host stub $BASE/ghost_file.txt was left behind by the runner."
    FAIL=1
fi

if [ ! -e "$BASE/ghost_dir" ]; then
    echo "PASS: missing denied directory left no host stub behind."
else
    echo "FAIL: host stub $BASE/ghost_dir was left behind by the runner."
    FAIL=1
fi

if [ "$FAIL" -ne 0 ]; then
    exit 1
fi

echo "Bubblewrap denied-path kind test complete."
