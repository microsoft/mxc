#!/bin/bash
# Bubblewrap read-only denial test.
#
# Existing filesystem coverage asserts a `readonlyPaths` entry is present and
# readable. That is the mount succeeding, not the property the policy promises:
# nothing asserted that a WRITE to it actually fails.
#
# The fixture is owned by the invoking user, so a write would succeed on the
# host. Any denial inside the sandbox is therefore attributable to the
# read-only mount rather than to file permissions. Reading the fixture acts as
# a positive control, proving the mount is really present.
#
# The host is re-checked afterwards: a sandbox write must not reach the
# original file, and must not create a new one.
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

# The fixture lives under /tmp and is created by the invoking user, so the test
# needs no elevation. Note the sandbox mounts a fresh tmpfs at /tmp, so the
# read-only bind is what makes the fixture visible inside at all.
RO_DIR="/tmp/mxc_rodenial"

cleanup() { rm -rf "$RO_DIR"; }
trap cleanup EXIT

rm -rf "$RO_DIR"
mkdir -p "$RO_DIR"
echo "RO_CONTENT" > "$RO_DIR/test.txt"

# Sanity: the host CAN write here, so an in-sandbox denial is the policy's doing.
if ! echo "RO_CONTENT" > "$RO_DIR/test.txt"; then
    echo "FAIL: fixture setup — host cannot write test.txt."
    exit 1
fi

echo "Running Bubblewrap read-only denial test..."
OUTPUT=$("$LXC_EXEC" --experimental "$REPO_DIR/tests/configs/bubblewrap_readonly_denial.json" 2>&1)
echo "$OUTPUT"

fail() { echo "FAIL: $1"; exit 1; }

echo "$OUTPUT" | grep -q "READ_OK" || fail "read-only path was not readable (mount missing?)."
echo "$OUTPUT" | grep -q "WRITE_DENIED_OK" || fail "a write to a readonlyPaths entry was not denied."
echo "$OUTPUT" | grep -q "CREATE_DENIED_OK" || fail "file creation under a readonlyPaths entry was not denied."
if echo "$OUTPUT" | grep -q "WRITE_LEAK"; then
    fail "sandbox reported a successful write to a read-only path."
fi
if echo "$OUTPUT" | grep -q "CREATE_LEAK"; then
    fail "sandbox reported a successful create under a read-only path."
fi

# The host side is the one that matters: the mount must not have been a
# writable copy that silently accepted the write.
grep -q "RO_CONTENT" "$RO_DIR/test.txt" || fail "host file was modified through the read-only mount."
[ ! -e "$RO_DIR/new.txt" ] || fail "host file was created through the read-only mount."

echo "PASS: readonlyPaths denies writes and creates, on both sides of the mount."
