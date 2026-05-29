#!/bin/bash
# LXC script-timeout enforcement test.
#
# Regression coverage for issue #84: the LXC backend used to ignore
# `process.timeout` from the config JSON, so a runaway script would run
# forever inside the container. After the fix, attach_run threads the
# timeout into `mxc_pty::PtyOptions` and the inner shell is killed and
# reaped once the deadline passes.
#
# The config asks for a 120s sleep with a 5s timeout. A correct backend
# kills it around the 5s mark with a non-zero exit code and a
# "timed out" message on stderr.
set -uo pipefail

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

echo "Running LXC timeout test (5s timeout vs 120s sleep)..."

STDERR_FILE=$(mktemp)
trap 'rm -f "$STDERR_FILE"' EXIT

START=$(date +%s)
set +e
"$LXC_EXEC" "$REPO_DIR/tests/configs/lxc_timeout.json" 2>"$STDERR_FILE"
EXIT_CODE=$?
set -e
ELAPSED=$(($(date +%s) - START))

echo "Elapsed: ${ELAPSED}s, exit=$EXIT_CODE"
echo "--- stderr ---"
cat "$STDERR_FILE"
echo "--- end stderr ---"

# Exit code -1 from the runner becomes 255 on Unix. Anything non-zero
# proves the run aborted; the message and elapsed checks below pin down
# *why* it aborted so a future regression can't pass for the wrong reason.
if [ "$EXIT_CODE" -eq 0 ]; then
    echo "FAIL: Expected non-zero exit code for timed-out script, got 0."
    exit 1
fi

if ! grep -q "timed out" "$STDERR_FILE"; then
    echo "FAIL: stderr did not contain a 'timed out' message."
    exit 1
fi

# Generous upper bound: 5s timeout + alpine boot/cleanup overhead. If the
# script ran the full 120s, the timeout was clearly ignored.
if [ "$ELAPSED" -gt 60 ]; then
    echo "FAIL: Script ran for ${ELAPSED}s; timeout was not enforced."
    exit 1
fi

echo "PASS: LXC script timeout enforced (~${ELAPSED}s, signaled via stderr)."
