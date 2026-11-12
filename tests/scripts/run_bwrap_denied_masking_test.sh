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

# Second fixture tree for the denied-symlink rejection cases below.
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
sudo chown -R "$(id -u):$(id -g)" "$BASE"

# Sanity: all fixtures are accessible to the invoking user. The filesystem
# delegation check intentionally rejects a read-write path the caller cannot
# write, so root-owned fixtures would prevent the sandbox from starting.
if ! cat "$VISIBLE" | grep -q "VISIBLE_SECRET"; then
    echo "FAIL: fixture setup — visible.txt not readable on host."
    exit 1
fi
if ! cat "$FILE" | grep -q "FILE_SECRET"; then
    echo "FAIL: fixture setup — secret_file.txt not readable on host."
    exit 1
fi
if ! cat "$DIR/inner.txt" | grep -q "DIR_SECRET"; then
    echo "FAIL: fixture setup — secret_dir/inner.txt not readable on host."
    exit 1
fi

echo "Running Bubblewrap denied-path masking test (denied file + denied dir)..."
if ! OUTPUT=$("$LXC_EXEC" --experimental \
    "$REPO_DIR/tests/configs/bubblewrap_denied_masking.json" 2>&1); then
    echo "$OUTPUT"
    echo "FAIL: denied-path masking sandbox did not start."
    exit 1
fi
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

for path in secret_dir secret_dir/nested missing; do
    if echo "$OUTPUT" | grep -qFx "DENIED_WRITE_OK:$path" \
        && ! echo "$OUTPUT" | grep -qFx "DENIED_WRITE_FAIL:$path"; then
        echo "PASS: denied path $path cannot be modified."
    else
        echo "FAIL: denied path $path is writable or its permissions can be changed."
        FAIL=1
    fi
done

# Missing deny mountpoints must be private even when their parent is read-only.
TOOLS="$BASE/tools"
mkdir "$TOOLS"
mkfifo "$TOOLS/ready" "$TOOLS/continue"
exec 3<> "$TOOLS/ready" 4<> "$TOOLS/continue"
(
    if read -r -t 30 READY <&3 && [ "$READY" = "READY" ] \
        && [ ! -e "$BASE/.env.local" ] && [ ! -e "$BASE/absent" ]; then
        printf 'LATE_SECRET\n' > "$BASE/.env.local"
        mkdir -p "$BASE/absent/nested"
        printf 'LATE_SECRET\n' > "$BASE/absent/nested/secret"
        printf 'continue\n' >&4
    else
        printf 'abort\n' >&4
        exit 1
    fi
) &
PUBLISHER=$!
config='{
  "version": "1.0.0",
  "containment": "bubblewrap",
  "process": {
    "cwd": "/mnt/masktest/tools",
    "commandLine": "set -eu; test \"$(cat ../visible.txt)\" = VISIBLE_SECRET; test ! -s ../secret_file.txt; printf control > control; test \"$(cat control)\" = control; if touch ../parent-write 2>/dev/null; then exit 31; fi; printf \"READY\\n\" > ready; read -r action < continue; test \"$action\" = continue; if cat ../.env.local 2>/dev/null | grep -q LATE_SECRET; then exit 32; fi; test -d ../.env.local; test -d ../absent/nested; test -z \"$(ls -A ../absent/nested)\"; if touch ../.env.local/write 2>/dev/null || touch ../absent/nested/write 2>/dev/null; then exit 33; fi; echo READONLY_MISSING_DENIALS_OK"
  },
  "filesystem": {
    "readonlyPaths": ["/mnt/masktest"],
    "readwritePaths": ["/mnt/masktest/tools"],
    "deniedPaths": ["/mnt/masktest/secret_file.txt", "/mnt/masktest/.env.local", "/mnt/masktest/absent/nested"]
  }
}'
echo "Running Bubblewrap missing denials beneath a read-only parent..."
READONLY_STATUS=0
READONLY_OUT=$(timeout 60 "$LXC_EXEC" --experimental \
    --config-base64 "$(printf '%s' "$config" | base64 -w0)" 3>&- 4>&- 2>&1) || READONLY_STATUS=$?
PUBLISHER_STATUS=0
wait "$PUBLISHER" || PUBLISHER_STATUS=$?
exec 3>&- 4>&-
if [ "$READONLY_STATUS" -ne 0 ] \
    && echo "$READONLY_OUT" | grep -qF "requires bwrap 0.11.0 or newer" \
    && [ ! -e "$BASE/.env.local" ] && [ ! -e "$BASE/absent" ]; then
    echo "PASS: older Bubblewrap rejects missing denials beneath read-only parents without modifying the host."
elif [ "$READONLY_STATUS" -eq 0 ] && [ "$PUBLISHER_STATUS" -eq 0 ] \
    && echo "$READONLY_OUT" | grep -qFx "READONLY_MISSING_DENIALS_OK" \
    && [ "$(cat "$BASE/.env.local")" = "LATE_SECRET" ] \
    && [ "$(cat "$BASE/absent/nested/secret")" = "LATE_SECRET" ]; then
    echo "PASS: missing denials stay masked after host creation; writable child and read-only parent preserved."
else
    echo "$READONLY_OUT"
    echo "FAIL: missing denial enforcement or read-only-parent controls failed (sandbox $READONLY_STATUS, publisher $PUBLISHER_STATUS)."
    FAIL=1
fi

# --- Denied-symlink masking ----------------------------------------------------
# Denying a symlink masks the object it points to: the runner rewrites a denied
# symlink to its canonical target so the mask lands on the real file/dir (bwrap
# cannot mount a mask over a symlink whose parent is bound, so masking the link
# path directly would abort the sandbox). Cover both a symlink -> dir (target
# masked with tmpfs) and a symlink -> file (target masked with /dev/null). Each
# config also reads a non-denied sibling (control.txt) as a positive control
# proving the parent bind is present, so masking is attributable to the deny.
sudo rm -rf "$SYMBASE"
sudo mkdir -p "$SYMBASE/real_dir"
echo "CONTROL_SECRET" | sudo tee "$SYMBASE/control.txt" > /dev/null
echo "DIR_TARGET_SECRET" | sudo tee "$SYMBASE/real_dir/inner.txt" > /dev/null
echo "FILE_TARGET_SECRET" | sudo tee "$SYMBASE/real_file.txt" > /dev/null
sudo ln -s "$SYMBASE/real_dir" "$SYMBASE/link_to_dir"
sudo ln -s "$SYMBASE/real_file.txt" "$SYMBASE/link_to_file"
sudo chown -R "$(id -u):$(id -g)" "$SYMBASE"

echo "Running Bubblewrap denied-symlink -> dir masking test..."
if ! DIR_OUT=$("$LXC_EXEC" --experimental \
    "$REPO_DIR/tests/configs/bubblewrap_denied_symlink_dir.json" 2>&1); then
    echo "$DIR_OUT"
    echo "FAIL: denied-symlink -> dir sandbox did not start."
    exit 1
fi
echo "$DIR_OUT"
if echo "$DIR_OUT" | grep -q "CONTROL_OK" \
    && echo "$DIR_OUT" | grep -q "SYMDIR_MASKED_OK" \
    && ! echo "$DIR_OUT" | grep -q "SYMDIR_LEAK"; then
    echo "PASS: denied symlink -> dir masked its target (parent bind present)."
else
    echo "FAIL: denied symlink -> dir target not masked."
    FAIL=1
fi

echo "Running Bubblewrap denied-symlink -> file masking test..."
if ! FILE_OUT=$("$LXC_EXEC" --experimental \
    "$REPO_DIR/tests/configs/bubblewrap_denied_symlink_file.json" 2>&1); then
    echo "$FILE_OUT"
    echo "FAIL: denied-symlink -> file sandbox did not start."
    exit 1
fi
echo "$FILE_OUT"
if echo "$FILE_OUT" | grep -q "CONTROL_OK" \
    && echo "$FILE_OUT" | grep -q "SYMFILE_MASKED_OK" \
    && echo "$FILE_OUT" | grep -q "SYMFILE_NOT_DIR_OK" \
    && ! echo "$FILE_OUT" | grep -q "SYMFILE_LEAK"; then
    echo "PASS: denied symlink -> file masked its target with /dev/null (kept non-directory)."
else
    echo "FAIL: denied symlink -> file target not masked correctly."
    FAIL=1
fi

# --- Broken denied symlinks ------------------------------------------------------
# Unresolvable deniedPaths must stop startup; otherwise `..` after a broken link
# could move the mask onto an unrelated path. The successful launches above are
# the controls for this fixture tree.
sudo ln -s "$SYMBASE/missing_target" "$SYMBASE/dangling"
sudo ln -s "$SYMBASE/loop" "$SYMBASE/loop"
sudo chown -h "$(id -u):$(id -g)" "$SYMBASE/dangling" "$SYMBASE/loop"

for denied in \
    "$SYMBASE/dangling" \
    "$SYMBASE/dangling/../real_file.txt" \
    "$SYMBASE/loop" \
    "$SYMBASE/loop/../real_file.txt"; do
    config=$(printf '{"version":"1.0.0","containment":"bubblewrap","process":{"commandLine":"echo BROKEN_LINK_RAN"},"filesystem":{"readwritePaths":["%s"],"deniedPaths":["%s"]}}' \
        "$SYMBASE" "$denied")
    echo "Running Bubblewrap broken denied symlink test: $denied"
    if BROKEN_OUT=$("$LXC_EXEC" --experimental \
        --config-base64 "$(printf '%s' "$config" | base64 -w0)" 2>&1); then
        BROKEN_EXIT=0
    else
        BROKEN_EXIT=$?
    fi
    if [ "$BROKEN_EXIT" -ne 0 ] \
        && ! echo "$BROKEN_OUT" | grep -q "BROKEN_LINK_RAN" \
        && echo "$BROKEN_OUT" | grep -q "could not be resolved" \
        && echo "$BROKEN_OUT" | grep -qF "$denied"; then
        echo "PASS: broken denied symlink rejected before launch: $denied"
    else
        echo "$BROKEN_OUT"
        echo "FAIL: broken denied symlink was not rejected (exit $BROKEN_EXIT): $denied"
        FAIL=1
    fi
done

if [ "$FAIL" -ne 0 ]; then
    exit 1
fi

echo "Bubblewrap denied-path masking test complete."
