#!/bin/bash
# Default Linux process sandbox tests.
#
# These configs intentionally do NOT pass --experimental and do NOT set
# containment: "bubblewrap". They exercise the default Linux process-sandbox
# resolution path:
#   - containment omitted        -> default process sandbox
#   - containment: "process"     -> default process sandbox
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

echo "Running default Linux process test (containment omitted)..."
"$LXC_EXEC" "$REPO_DIR/tests/configs/linux_process_default.json"
echo "Default Linux process test complete."
echo ""

echo "Running abstract process containment test (containment: \"process\")..."
"$LXC_EXEC" "$REPO_DIR/tests/configs/linux_process_abstract.json"
echo "Abstract process containment test complete."
