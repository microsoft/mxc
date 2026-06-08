#!/bin/bash
# LXC env + cwd plumbing test.
#
# Asserts that `process.cwd` and `process.env` from the config actually
# reach the inner shell inside the container. The config's `commandLine`
# self-validates and exits with distinct non-zero codes if either field
# was silently dropped:
#   11 = cwd not honored (still at container default)
#   12 = MXC_TEST_FOO env not honored (or value with spaces lost)
#   13 = MXC_TEST_EQ env not honored (or embedded `=` lost)
#
# `lxc-exec` propagates the inner exit code (see `core/lxc/src/main.rs`
# line 294), so `set -e` here catches any regression. Guards against the
# silent-drop bug pattern fixed in `fix/lxc-cwd-env` — without that fix
# this test exits 11 (cwd) on the first assertion.
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

echo "Running LXC env+cwd test..."
# Pre-set MXC_TEST_FOO so the in-container assertion also proves caller-wins-over-host.
export MXC_TEST_FOO="HOST_LEAK_SHOULD_NOT_APPEAR"
"$LXC_EXEC" "$REPO_DIR/tests/configs/lxc_env_cwd_test.json"
echo "LXC env+cwd test complete."
