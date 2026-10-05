#!/bin/bash
# A credentialed v0.9 proxy request must fail without exposing its userinfo.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_DIR="$(dirname "$(dirname "$SCRIPT_DIR")")"
CONFIG="$REPO_DIR/tests/configs/lxc_network_proxy_credentials_rejected.json"
LXC_EXEC="$REPO_DIR/src/target/release/lxc-exec"
[ -f "$LXC_EXEC" ] || LXC_EXEC="$REPO_DIR/src/target/debug/lxc-exec"
[ -f "$LXC_EXEC" ] || { echo "SKIP: lxc-exec is not built."; exit 77; }
command -v python3 >/dev/null 2>&1 || { echo "SKIP: python3 is not installed."; exit 77; }

# Keep the expected userinfo out of process arguments and diagnostics.
python3 - "$CONFIG" <<'PY' || { echo "FAIL: credentialed proxy fixture drifted."; exit 1; }
import json
import sys

with open(sys.argv[1]) as fixture:
    data = json.load(fixture)
assert data["version"] == "0.9.0-alpha"
assert data["containment"] == "lxc"
assert data["network"]["egress"]["default"] == "deny"
assert data["runtimeConfig"]["networkProxy"] == "http://alice:hunter2@127.0.0.1:3128"
assert data["process"]["commandLine"] == "echo THIS_MUST_NEVER_RUN"
PY

set +e
output=$("$LXC_EXEC" "$CONFIG" 2>&1)
status=$?
set -e

if grep -Eq 'alice|hunter2' <<<"$output"; then
    echo "FAIL: proxy rejection disclosed URL credentials."
    exit 1
fi
[ "$status" -ne 0 ] || { echo "FAIL: LXC accepted a credentialed proxy request."; exit 1; }
if ! grep -Fq "runtimeConfig.networkProxy" <<<"$output"; then
    echo "FAIL: proxy request was not rejected for its proxy field: $output"
    exit 1
fi
if grep -Eq 'THIS_MUST_NEVER_RUN|Container created successfully' <<<"$output"; then
    echo "FAIL: proxy request created or ran an LXC container."
    exit 1
fi
echo "PASS: credentialed v0.9 proxy rejected without exposing userinfo or running the workload."
