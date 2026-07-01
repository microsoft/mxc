#!/bin/bash
# Bubblewrap object-based filesystem-policy validation test (roadmap D6).
#
# Verifies that when two different policy paths resolve to the SAME host
# object (here: a directory and a symlink to it) but carry conflicting
# intents, the runner tightens every alias to the most-restrictive intent
# (deny > ro > rw) BEFORE building mounts — closing the bypass where a
# "denied" object is still reachable through its read-write alias.
#
# The object lives in readwritePaths, so a plain RW bind would expose it
# (see run_bwrap_filesystem_test.sh for the baseline that RW paths are
# readable). Here a deniedPaths symlink alias of the same directory must
# tighten the RW path to denied, so the secret is MASKED inside the sandbox.
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

BASE="/mnt/objtest"
DATA="$BASE/data"
LINK="$BASE/data_link"

cleanup() { sudo rm -rf "$BASE"; }
trap cleanup EXIT

# Set up: a real directory with a secret file, plus a symlink alias pointing
# at the same directory object.
sudo rm -rf "$BASE"
sudo mkdir -p "$DATA"
echo "OBJECT_SECRET" | sudo tee "$DATA/secret.txt" > /dev/null
sudo ln -s "$DATA" "$LINK"

# Sanity: the secret is readable on the host (so masking inside the sandbox is
# attributable to the policy, not a broken fixture).
if ! sudo cat "$DATA/secret.txt" | grep -q "OBJECT_SECRET"; then
    echo "FAIL: fixture setup — secret.txt not readable on host."
    exit 1
fi

# RW path + denied symlink alias of the same object; the object must be masked.
echo "Running Bubblewrap object-validation test (RW + denied alias, expect masked)..."
OUTPUT=$("$LXC_EXEC" --experimental \
    "$REPO_DIR/tests/configs/bubblewrap_filesystem_object.json" 2>&1 || true)
echo "$OUTPUT"
if echo "$OUTPUT" | grep -q "OBJECT_MASKED_OK" && ! echo "$OUTPUT" | grep -q "OBJECT_LEAK"; then
    echo "PASS: denied alias tightened the read-write path; object masked (bypass closed)."
else
    echo "FAIL: object reachable via read-write alias of a denied path (bypass NOT closed)."
    exit 1
fi

echo "Bubblewrap object-based validation test complete."
