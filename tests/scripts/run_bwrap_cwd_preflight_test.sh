#!/bin/bash
# Bubblewrap cwd preflight and namespace-agreement tests.
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

BASE="$(mktemp -d /tmp/mxc_bwrap_cwd.XXXXXX)"
cleanup() { rm -rf "$BASE"; }
trap cleanup EXIT

fail() { echo "FAIL: $1"; exit 1; }

mkdir -p "$BASE/readwrite" "$BASE/denied/secret" "$BASE/masked/child" \
    "$BASE/links" "$BASE/hidden" "$BASE/visible-target" "$BASE/real/secret" \
    "$BASE/configs"
echo "VISIBLE_CHILD" > "$BASE/masked/child/visible.txt"
echo "DENIED_ALIAS_SECRET" > "$BASE/real/secret/marker.txt"
ln -s "$BASE/hidden" "$BASE/links/cwd"
ln -s "$BASE/visible-target" "$BASE/links/visible-cwd"
ln -s "$BASE/real" "$BASE/alias"

render_config() {
    local name="$1"
    sed "s#/tmp/mxc_bwrap_cwd#$BASE#g" \
        "$REPO_DIR/tests/configs/$name" > "$BASE/configs/$name"
}

for config in \
    bubblewrap_cwd_denied.json \
    bubblewrap_cwd_denied_parent.json \
    bubblewrap_cwd_denied_symlink_alias.json \
    bubblewrap_cwd_denied_symlink_parent.json \
    bubblewrap_cwd_mount_boundary.json \
    bubblewrap_cwd_readwrite.json \
    bubblewrap_cwd_symlink_hidden.json \
    bubblewrap_cwd_symlink_visible.json \
    bubblewrap_cwd_synthetic_parent.json; do
    render_config "$config"
done

echo "Running Bubblewrap mount-boundary cwd test..."
OUTPUT=$("$LXC_EXEC" --experimental \
    "$BASE/configs/bubblewrap_cwd_mount_boundary.json" 2>&1)
echo "$OUTPUT"
echo "$OUTPUT" | grep -q "CWD_MOUNT_BOUNDARY_OK" \
    || fail "a baseline bind destination was resolved as its host symlink."

echo "Running Bubblewrap root cwd test..."
OUTPUT=$("$LXC_EXEC" --experimental \
    "$REPO_DIR/tests/configs/bubblewrap_cwd_root.json" 2>&1)
echo "$OUTPUT"
echo "$OUTPUT" | grep -q "CWD_ROOT_OK" \
    || fail "the sandbox root was not honored as the child's cwd."

echo "Running Bubblewrap read-write cwd test..."
OUTPUT=$("$LXC_EXEC" --experimental \
    "$BASE/configs/bubblewrap_cwd_readwrite.json" 2>&1)
echo "$OUTPUT"
echo "$OUTPUT" | grep -q "CWD_READWRITE_OK" \
    || fail "cwd under readwritePaths did not match the child's real pwd."

echo "Running Bubblewrap synthetic-parent cwd test..."
OUTPUT=$("$LXC_EXEC" --experimental \
    "$BASE/configs/bubblewrap_cwd_synthetic_parent.json" 2>&1)
echo "$OUTPUT"
echo "$OUTPUT" | grep -q "CWD_SYNTHETIC_OK" \
    || fail "a permitted descendant did not recreate the denied parent's cwd."
echo "$OUTPUT" | grep -q "VISIBLE_CHILD" \
    || fail "the permitted descendant was not visible beneath the synthetic cwd."

echo "Running Bubblewrap denied-mount synthetic-parent cwd test..."
OUTPUT=$("$LXC_EXEC" --experimental \
    "$BASE/configs/bubblewrap_cwd_denied_parent.json" 2>&1)
echo "$OUTPUT"
echo "$OUTPUT" | grep -q "CWD_DENIED_PARENT_OK" \
    || fail "a denied mount did not create the synthetic parent needed for cwd."

echo "Running Bubblewrap denied cwd preflight test..."
OUTPUT=$("$LXC_EXEC" --experimental \
    "$BASE/configs/bubblewrap_cwd_denied.json" 2>&1 || true)
echo "$OUTPUT"
echo "$OUTPUT" | grep -q "process.cwd '$BASE/denied/secret'" \
    || fail "cwd inside a denied subtree did not return the actionable preflight error."
echo "$OUTPUT" | grep -q "filesystem.deniedPaths entry '$BASE/denied/secret'" \
    || fail "denied cwd error did not name the covering deniedPaths entry."
echo "$OUTPUT" | grep -q "Remove that entry or narrow it" \
    || fail "denied cwd error did not explain how to remove the conflict."
if echo "$OUTPUT" | grep -q "CWD_DENIED_COMMAND_RAN"; then
    fail "the workload ran despite its cwd being denied."
fi

echo "Running Bubblewrap denied symlink-alias cwd test..."
OUTPUT=$("$LXC_EXEC" --experimental \
    "$BASE/configs/bubblewrap_cwd_denied_symlink_alias.json" 2>&1 || true)
echo "$OUTPUT"
echo "$OUTPUT" | grep -q "filesystem.deniedPaths entry '$BASE/alias/secret'" \
    || fail "resolved denied cwd did not name the caller's symlink spelling."
if echo "$OUTPUT" | grep -q "CWD_DENIED_ALIAS_COMMAND_RAN"; then
    fail "the workload ran despite its cwd being denied through a symlink alias."
fi

echo "Running Bubblewrap denied symlink-child synthetic-parent cwd test..."
OUTPUT=$("$LXC_EXEC" --experimental \
    "$BASE/configs/bubblewrap_cwd_denied_symlink_parent.json" 2>&1)
echo "$OUTPUT"
echo "$OUTPUT" | grep -q "CWD_DENIED_ALIAS_PARENT_OK" \
    || fail "resolved denied child did not create its synthetic cwd parent."
echo "$OUTPUT" | grep -q "DENIED_ALIAS_CHILD_MASKED_OK" \
    || fail "resolved denied child was not masked beneath its cwd parent."
if echo "$OUTPUT" | grep -q "DENIED_ALIAS_CHILD_LEAK"; then
    fail "resolved denied child leaked beneath its cwd parent."
fi

echo "Running Bubblewrap hidden symlink-target cwd test..."
OUTPUT=$("$LXC_EXEC" --experimental \
    "$BASE/configs/bubblewrap_cwd_symlink_hidden.json" 2>&1 || true)
echo "$OUTPUT"
echo "$OUTPUT" | grep -q "could not be conclusively preflighted because it traverses a host symlink" \
    || fail "ambiguous symlink cwd did not emit its advisory diagnostic."
if echo "$OUTPUT" | grep -q "CWD_SYMLINK_COMMAND_RAN"; then
    fail "the workload ran despite its cwd resolving outside the mounted namespace."
fi

echo "Running Bubblewrap visible symlink-target cwd test..."
OUTPUT=$("$LXC_EXEC" --experimental \
    "$BASE/configs/bubblewrap_cwd_symlink_visible.json" 2>&1)
echo "$OUTPUT"
echo "$OUTPUT" | grep -q "CWD_SYMLINK_VISIBLE_OK" \
    || fail "a visible symlink target did not become the child's real cwd."

echo "PASS: Bubblewrap cwd preflight agrees with the assembled namespace."
