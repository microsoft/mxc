#!/bin/bash
# Retired network contracts must be rejected before any LXC workload starts.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_DIR="$(dirname "$(dirname "$SCRIPT_DIR")")"
LXC_EXEC="$REPO_DIR/src/target/release/lxc-exec"
[ -f "$LXC_EXEC" ] || LXC_EXEC="$REPO_DIR/src/target/debug/lxc-exec"
[ -f "$LXC_EXEC" ] || { echo "SKIP: lxc-exec is not built."; exit 77; }
command -v python3 >/dev/null 2>&1 || { echo "SKIP: python3 is not installed."; exit 77; }

check_retired() {
    local config="$1" version="$2" output status
    python3 - "$config" "$version" <<'PY' || { echo "FAIL: retired fixture drifted: $config"; exit 1; }
import json, sys
data = json.load(open(sys.argv[1]))
assert data["version"] == sys.argv[2]
assert data["containment"] == "lxc"
assert data["network"]["defaultPolicy"] in ("block", "allow")
assert data["network"]["enforcementMode"] == "firewall"
PY
    set +e
    output=$("$LXC_EXEC" "$config" 2>&1)
    status=$?
    set -e
    [ "$status" -ne 0 ] || { echo "FAIL: $version was accepted."; exit 1; }
    if ! grep -Fiq "$version" <<<"$output" || ! grep -Eiq 'version|contract' <<<"$output"; then
        echo "FAIL: $version failed without identifying the retired contract: $output"
        exit 1
    fi
    if grep -Eq 'MXC_WORKLOAD_RAN|MXC_NET_(ALLOWED|BLOCKED)|Container created successfully' <<<"$output"; then
        echo "FAIL: $version created or executed a sandbox."
        exit 1
    fi
    echo "PASS: $version was rejected before LXC execution."
}

check_retired "$REPO_DIR/tests/configs/lxc_network_retired_v07.json" "0.7.0-alpha"
check_retired "$REPO_DIR/tests/configs/lxc_network_retired_v08.json" "0.8.0-alpha"
