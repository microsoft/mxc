#!/bin/bash
# Check that the CLI reports a cwd mount hint without changing launch results.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_DIR="$(dirname "$(dirname "$SCRIPT_DIR")")"
LXC_EXEC="${LXC_EXEC:-$REPO_DIR/src/target/release/lxc-exec}"
if [ ! -f "$LXC_EXEC" ]; then
    LXC_EXEC="$REPO_DIR/src/target/debug/lxc-exec"
fi
if [ ! -f "$LXC_EXEC" ]; then
    echo "Error: lxc-exec not found. Run build.sh first."
    exit 1
fi

WORK_DIR=$(mktemp -d "$(cd "$HOME" && pwd -P)/.mxc_bwrap_cwd_XXXXXX")
CWD="$WORK_DIR/work"
UNRELATED="$WORK_DIR/other"
trap 'rm -f "$WORK_DIR/uncovered.json" "$WORK_DIR/unrelated.json" "$WORK_DIR/covered.json" "$WORK_DIR/uncovered.stderr" "$WORK_DIR/unrelated.stderr" "$WORK_DIR/covered.stderr"; rmdir "$CWD" "$UNRELATED" "$WORK_DIR"' EXIT
mkdir "$CWD" "$UNRELATED"

cat >"$WORK_DIR/uncovered.json" <<EOF
{"version":"0.9.0-alpha","containment":"bubblewrap",
 "process":{"commandLine":"pwd","cwd":"$CWD"}}
EOF
cat >"$WORK_DIR/covered.json" <<EOF
{"version":"0.9.0-alpha","containment":"bubblewrap",
 "process":{"commandLine":"pwd","cwd":"$CWD"},
 "filesystem":{"readonlyPaths":["$CWD"]}}
EOF
cat >"$WORK_DIR/unrelated.json" <<EOF
{"version":"0.9.0-alpha","containment":"bubblewrap",
 "process":{"commandLine":"pwd","cwd":"$CWD"},
 "filesystem":{"readonlyPaths":["$UNRELATED"]}}
EOF

for case in uncovered unrelated; do
    rc=0
    output=$("$LXC_EXEC" --experimental "$WORK_DIR/$case.json" 2>"$WORK_DIR/$case.stderr") || rc=$?
    # One warning envelope must carry the whole advisory, path included.
    if [ "$rc" -eq 0 ] \
        || ! python3 - "$WORK_DIR/$case.stderr" "$CWD" <<'PY' \
        || ! grep -Eq '(^|[[:space:]])bwrap:' "$WORK_DIR/$case.stderr"; then
import json, sys
path, cwd = sys.argv[1], sys.argv[2]
for line in open(path, encoding="utf-8"):
    try:
        message = json.loads(line)["warning"]["message"]
    except (ValueError, KeyError, TypeError):
        continue
    if all(s in message for s in ("Bubblewrap: process.cwd", cwd, "filesystem.readonlyPaths")):
        sys.exit(0)
sys.exit(1)
PY
        echo "$case cwd did not report the hint and Bubblewrap's original error: $output"
        cat "$WORK_DIR/$case.stderr"
        exit 1
    fi
done
output=$("$LXC_EXEC" --experimental "$WORK_DIR/covered.json" 2>"$WORK_DIR/covered.stderr")
if ! grep -qFx "$CWD" <<<"$output" \
    || grep -Fq 'Bubblewrap: process.cwd' "$WORK_DIR/covered.stderr"; then
    echo "Covered cwd did not run without an advisory: $output"
    cat "$WORK_DIR/covered.stderr"
    exit 1
fi
