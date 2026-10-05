#!/bin/bash
# LXC has no proxy transport in the supported directional contracts.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_DIR="$(dirname "$(dirname "$SCRIPT_DIR")")"
LXC_EXEC="$REPO_DIR/src/target/release/lxc-exec"
[ -f "$LXC_EXEC" ] || LXC_EXEC="$REPO_DIR/src/target/debug/lxc-exec"
[ -f "$LXC_EXEC" ] || { echo "SKIP: lxc-exec is not built."; exit 77; }
command -v python3 >/dev/null 2>&1 || { echo "SKIP: python3 is not installed."; exit 77; }

check_proxy() {
    local config="$1" expected_url="$2" expected_reason="$3" output status
    python3 - "$config" "$expected_url" <<'PY' || { echo "FAIL: proxy rejection fixture drifted."; exit 1; }
import json, sys
data = json.load(open(sys.argv[1]))
assert data["version"] == "0.9.0-alpha"
assert data["containment"] == "lxc"
assert data["runtimeConfig"]["networkProxy"] == sys.argv[2]
assert data["network"]["egress"]["default"] == "deny"
PY
    set +e
    output=$("$LXC_EXEC" "$config" 2>&1)
    status=$?
    set -e
    [ "$status" -ne 0 ] || { echo "FAIL: LXC accepted a proxy request."; exit 1; }
    # Never log the captured error before checking for leaked userinfo.
    if grep -Eq 'alice|hunter2' <<<"$output"; then
        echo "FAIL: the proxy rejection disclosed URL credentials."
        exit 1
    fi
    if ! grep -Fq "$expected_reason" <<<"$output"; then
        echo "FAIL: proxy request was not rejected for its proxy field: $output"
        exit 1
    fi
    if grep -Eq 'THIS_MUST_NEVER_RUN|Container created successfully' <<<"$output"; then
        echo "FAIL: proxy request created or ran an LXC container."
        exit 1
    fi
    echo "PASS: $(basename "$config") rejected before LXC execution."
}

check_proxy "$REPO_DIR/tests/configs/lxc_network_proxy.json" \
    "http://127.0.0.1:3128" "runtimeConfig.networkProxy"
check_proxy "$REPO_DIR/tests/configs/lxc_network_proxy_hostname.json" \
    "http://proxy.mxc.test:3128" "runtimeConfig.networkProxy must use localhost"
