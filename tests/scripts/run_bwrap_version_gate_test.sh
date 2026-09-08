#!/bin/bash
# Bubblewrap version-gating test.
#
# `bwrap_version.rs` carries unit tests for parsing and comparison, but nothing
# asserted the end-to-end behavior when `bwrap` is missing or too old. The
# property that matters to a user is that the run stops with a readable,
# actionable error instead of an opaque spawn failure ("No such file or
# directory") or an "unknown option" from an old binary.
#
# Both cases are staged with a PATH shim rather than by touching the host's
# real installation. The same config is also run unshimmed as a positive
# control, so a failure below is attributable to the gate and not to a config
# that could never have run.
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

CONFIG="$REPO_DIR/tests/configs/bubblewrap_version_gate.json"
SHIM_DIR="$(mktemp -d)"
SENTINEL="VERSION_GATE_WORKLOAD_RAN"

cleanup() { rm -rf "$SHIM_DIR"; }
trap cleanup EXIT

fail() { echo "FAIL: $1"; exit 1; }

# Asserts the run was refused, refused for the stated reason, and refused
# before the workload started.
assert_gated() {
    local label="$1"
    local marker="$2"
    local out rc=0
    shift 2
    echo "Running Bubblewrap version-gate test: $label..."
    out=$(env "$@" "$LXC_EXEC" --experimental "$CONFIG" 2>&1) || rc=$?
    if [ "$rc" = 0 ]; then
        echo "$out"
        fail "$label (the run was accepted)"
    fi
    if grep -qF "$SENTINEL" <<<"$out"; then
        echo "$out"
        fail "$label (the workload ran despite the version gate)"
    fi
    if ! grep -qF "$marker" <<<"$out"; then
        echo "$out"
        fail "$label (refused, but not for the expected reason: '$marker')"
    fi
    echo "PASS: $label"
}

# Positive control: an empty shim dir is the only difference between this run
# and the "absent" case below.
echo "Running Bubblewrap version-gate test: control (real bwrap)..."
if ! "$LXC_EXEC" --experimental "$CONFIG" 2>&1 | grep -qF "$SENTINEL"; then
    fail "control — the config did not run with a real bwrap on PATH."
fi
echo "PASS: control (real bwrap)"

# PATH points at a directory with no `bwrap` in it. lxc-exec is invoked by
# absolute path, so only the sandbox binary lookup is affected.
assert_gated "an absent bwrap is reported, not spawned into" \
    "is not installed or not on PATH" \
    "PATH=$SHIM_DIR"

# A shim that reports a version below the floor set by `--clearenv`.
printf '#!/bin/sh\necho "bubblewrap 0.3.0"\n' > "$SHIM_DIR/bwrap"
chmod +x "$SHIM_DIR/bwrap"
assert_gated "a too-old bwrap is refused before any flag is passed to it" \
    "is too old" \
    "PATH=$SHIM_DIR:$PATH"

echo "All Bubblewrap version-gate tests passed."
