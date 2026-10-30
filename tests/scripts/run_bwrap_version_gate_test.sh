#!/bin/bash
# Bubblewrap version gate and executable lookup.
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

# Must match the directories MXC searches after PATH.
FALLBACK_DIRECTORIES=(/usr/local/sbin /usr/local/bin /usr/sbin /usr/bin /sbin /bin)

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
    out=$("$@" 2>&1) || rc=$?
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

# Positive control: the config runs with the host's own bwrap, so a refusal
# below comes from the case it stages rather than from the config.
echo "Running Bubblewrap version-gate test: control (real bwrap)..."
if ! "$LXC_EXEC" --experimental "$CONFIG" 2>&1 | grep -qF "$SENTINEL"; then
    fail "control — the config did not run with a real bwrap on PATH."
fi
echo "PASS: control (real bwrap)"

REAL_BWRAP="$(command -v bwrap)"
case " ${FALLBACK_DIRECTORIES[*]} " in
    *" $(dirname "$REAL_BWRAP") "*)
        echo "Running Bubblewrap version-gate test: a bwrap missing from PATH..."
        if ! env PATH="$SHIM_DIR" "$LXC_EXEC" --experimental "$CONFIG" 2>&1 |
            grep -qF "$SENTINEL"; then
            fail "a bwrap missing from PATH was not found in $(dirname "$REAL_BWRAP")"
        fi
        echo "PASS: a bwrap missing from PATH is found in a standard directory"
        ;;
    *)
        echo "NOTE: $REAL_BWRAP is outside the standard directories; not testing the fallback."
        ;;
esac

# Absent everywhere: the real bwrap hides every standard directory from the
# executor under test, which then has nothing left to find. Symlinked ones,
# such as /bin on a merged /usr, are hidden through their targets.
hidden_directories=()
for directory in "${FALLBACK_DIRECTORIES[@]}"; do
    if [ -d "$directory" ] && [ ! -L "$directory" ]; then
        hidden_directories+=(--tmpfs "$directory")
    fi
done
assert_gated "an absent bwrap is reported, not spawned into" \
    "is not installed" \
    "$REAL_BWRAP" --dev-bind / / "${hidden_directories[@]}" --setenv PATH "$SHIM_DIR" -- \
    "$LXC_EXEC" --experimental "$CONFIG"

# A shim that reports a version below the floor set by `--clearenv`.
printf '#!/bin/sh\necho "bubblewrap 0.3.0"\n' > "$SHIM_DIR/bwrap"
chmod +x "$SHIM_DIR/bwrap"
assert_gated "a too-old bwrap is refused before any flag is passed to it" \
    "$SHIM_DIR/bwrap is too old" \
    env PATH="$SHIM_DIR:$PATH" "$LXC_EXEC" --experimental "$CONFIG"

# A shim whose interpreter does not exist, so it cannot start.
printf '#!/mxc-test-missing-interpreter\n' > "$SHIM_DIR/bwrap"
chmod +x "$SHIM_DIR/bwrap"
assert_gated "a broken bwrap earlier on PATH is not bypassed" \
    "could not be executed" \
    env PATH="$SHIM_DIR:$PATH" "$LXC_EXEC" --experimental "$CONFIG"

echo "All Bubblewrap version-gate tests passed."
