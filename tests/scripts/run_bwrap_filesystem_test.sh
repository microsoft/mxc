#!/bin/bash
# Bubblewrap filesystem policy test
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

# Set up test directories
RW_DIR="/mnt/readwrite"
RO_DIR="/mnt/readonly"
DENIED_DIR="/mnt/denied"

sudo mkdir -p "$RW_DIR" "$RO_DIR" "$DENIED_DIR"
sudo chown "$USER:$USER" "$RW_DIR"
echo "test content" | sudo tee "$RO_DIR/test.txt" > /dev/null
echo "should not see this" | sudo tee "$DENIED_DIR/secret.txt" > /dev/null

echo "Running Bubblewrap filesystem test..."
"$LXC_EXEC" --experimental "$REPO_DIR/tests/configs/bubblewrap_filesystem.json"
echo "Bubblewrap filesystem test complete."

# Verify the write succeeded
if [ -f "$RW_DIR/output.txt" ]; then
    echo "PASS: Write to readwrite path succeeded."
else
    echo "FAIL: Write to readwrite path did not produce expected file."
    exit 1
fi

# Check nested restrictions and reject parent segments through the executor.
POLICY_DIR=$(mktemp -d /tmp/mxc-bwrap-policy-paths.XXXXXX)
trap 'rm -rf -- "$POLICY_DIR"' EXIT
mkdir -p "$POLICY_DIR/work/secret" "$POLICY_DIR/work/a" "$POLICY_DIR/work/b"
CANARY="$POLICY_DIR/work/secret/canary.txt"
echo HOST_ORIGINAL > "$CANARY"

run_policy() {
    local filesystem="$1"
    cat <<EOF | "$LXC_EXEC" --experimental --config /dev/stdin
{
  "version": "1.0.0",
  "containment": "bubblewrap",
  "process": {
    "commandLine": "echo WORKLOAD_STARTED; cat $CANARY; echo MODIFIED > $CANARY",
    "timeout": 30000
  },
  "filesystem": {$filesystem}
}
EOF
}

for path in "$POLICY_DIR/work" "$POLICY_DIR/work/././"; do
    OUTPUT=$(run_policy "\"readwritePaths\":[\"$path\"],\"deniedPaths\":[\"$POLICY_DIR/work/secret\"]" 2>&1 || true)
    if ! grep -q WORKLOAD_STARTED <<< "$OUTPUT" ||
        grep -q HOST_ORIGINAL <<< "$OUTPUT" ||
        [[ $(cat "$CANARY") != HOST_ORIGINAL ]]; then
        echo "FAIL: parent grant $path must preserve its child's deny."
        echo "$OUTPUT"
        exit 1
    fi
    echo "PASS: parent grant $path preserves its child's deny."
done

for path in "$POLICY_DIR/work/secret" "$POLICY_DIR/work/./secret"; do
    OUTPUT=$(run_policy "\"readwritePaths\":[\"$path\"],\"deniedPaths\":[\"$POLICY_DIR/work\"]" 2>&1)
    if ! grep -q WORKLOAD_STARTED <<< "$OUTPUT" ||
        ! grep -q HOST_ORIGINAL <<< "$OUTPUT" ||
        [[ $(cat "$CANARY") != MODIFIED ]]; then
        echo "FAIL: child grant $path must remain usable inside a denied parent."
        echo "$OUTPUT"
        exit 1
    fi
    echo HOST_ORIGINAL > "$CANARY"
    echo "PASS: child grant $path remains readable and writable."
done

for field in readwritePaths readonlyPaths deniedPaths; do
    for path in "$POLICY_DIR/work/secret/.." "$POLICY_DIR/work/a/../b/../" "$POLICY_DIR/work/./secret/../a"; do
        case "$field" in
            readwritePaths) filesystem="\"readwritePaths\":[\"$path\"],\"deniedPaths\":[\"$POLICY_DIR/work/secret\"]" ;;
            readonlyPaths) filesystem="\"readwritePaths\":[\"$POLICY_DIR/work\"],\"readonlyPaths\":[\"$path\"],\"deniedPaths\":[\"$POLICY_DIR/work/secret\"]" ;;
            deniedPaths) filesystem="\"readwritePaths\":[\"$POLICY_DIR/work\"],\"deniedPaths\":[\"$path\"]" ;;
        esac
        if OUTPUT=$(run_policy "$filesystem" 2>&1); then
            echo "FAIL: $field accepted a parent segment: $path"
            exit 1
        fi
        if ! grep -Fq "contains a '..' segment" <<< "$OUTPUT" ||
            ! grep -Fq "filesystem.$field" <<< "$OUTPUT" ||
            grep -q WORKLOAD_STARTED <<< "$OUTPUT" ||
            [[ $(cat "$CANARY") != HOST_ORIGINAL ]]; then
            echo "FAIL: invalid $field must reject before the workload runs."
            echo "$OUTPUT"
            exit 1
        fi
    done
done
echo "PASS: parent segments rejected; canonical nested policies preserved."

# Clean up
sudo rm -rf "$RW_DIR" "$RO_DIR" "$DENIED_DIR"
