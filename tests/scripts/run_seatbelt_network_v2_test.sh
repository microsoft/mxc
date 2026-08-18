#!/bin/bash
# Seatbelt schema-0.8 (network v2) tests, positive path:
#  1. `egress.default: deny` + `ingress.default/hostLoopback: deny` with no
#     proxy configured blocks all outbound.
#  2. A dynamically-generated config (the proxy's port is only known once it
#     is running) exercises `egress.default: deny` combined with
#     `runtimeConfig.networkProxy` pointed at a loopback proxy: traffic
#     through the proxy succeeds while direct traffic is still blocked.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_DIR="$(dirname "$(dirname "$SCRIPT_DIR")")"
# shellcheck source=lib/seatbelt_env.sh
source "$SCRIPT_DIR/lib/seatbelt_env.sh"
# shellcheck source=lib/seatbelt_test_proxy.sh
source "$SCRIPT_DIR/lib/seatbelt_test_proxy.sh"

FAILED=0

echo "Running Seatbelt schema-v2 test: egress/ingress deny, no proxy..."
OUTPUT=$("$MXC_EXEC_MAC" --debug "$REPO_DIR/tests/configs/seatbelt_network_v2_deny.json" 2>&1)
echo "$OUTPUT"
if ! echo "$OUTPUT" | grep -q "NETWORK_BLOCKED_OK"; then
    echo "FAIL: direct outbound was not blocked under egress.default=deny."
    FAILED=1
fi
echo ""

echo "Running Seatbelt schema-v2 test: egress deny + runtimeConfig.networkProxy loopback..."
start_test_proxy
TEST_PROXY_ADDRESS="127.0.0.1:$TEST_PROXY_PORT"
CONFIG_FILE="$(mktemp "${TMPDIR:-/tmp}/mxc_seatbelt_v2_proxy_config.XXXXXX.json")"
cleanup() {
    stop_test_proxy
    rm -f "$CONFIG_FILE"
}
trap cleanup EXIT

cat > "$CONFIG_FILE" <<EOF
{
    "version": "0.8.0-alpha",
    "containment": "seatbelt",
    "process": {
        "commandLine": "curl -s --max-time 5 -x http://$TEST_PROXY_ADDRESS https://api.github.com/zen && echo PROXY_OK || echo PROXY_FAIL; curl -s --max-time 5 --noproxy '*' https://example.com > /dev/null 2>&1 && echo NETWORK_LEAK || echo DIRECT_BLOCKED_OK",
        "timeout": 15000
    },
    "filesystem": {
        "readwritePaths": ["/tmp"]
    },
    "network": {
        "egress": { "default": "deny" },
        "ingress": { "default": "deny", "hostLoopback": "deny" }
    },
    "runtimeConfig": {
        "networkProxy": "http://$TEST_PROXY_ADDRESS"
    }
}
EOF

OUTPUT=$("$MXC_EXEC_MAC" --debug "$CONFIG_FILE" 2>&1)
echo "$OUTPUT"
if ! echo "$OUTPUT" | grep -q "PROXY_OK"; then
    echo "FAIL: request through the loopback proxy did not succeed."
    FAILED=1
fi
if ! echo "$OUTPUT" | grep -q "DIRECT_BLOCKED_OK"; then
    echo "FAIL: direct (non-proxied) outbound was not blocked."
    FAILED=1
fi

if [ "$FAILED" -ne 0 ]; then
    exit 1
fi
echo "Seatbelt schema-v2 positive tests complete."
