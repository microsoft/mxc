#!/bin/bash
# Seatbelt schema-0.8 (network v2) validation-rejection tests: three configs
# that should each be rejected at config-parse time, before the sandboxed
# process ever runs.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_DIR="$(dirname "$(dirname "$SCRIPT_DIR")")"
# shellcheck source=lib/seatbelt_env.sh
source "$SCRIPT_DIR/lib/seatbelt_env.sh"

FAILED=0

# run_rejected_case <label> <config-file> <expected-message-substring>
run_rejected_case() {
    local label="$1"
    local config="$2"
    local expected_substring="$3"

    echo "Running Seatbelt schema-v2 validation test: $label..."
    set +e
    local output
    output=$("$MXC_EXEC_MAC" --debug "$REPO_DIR/tests/configs/$config" 2>&1)
    local exit_code=$?
    set -e
    echo "$output"
    echo "Exit code: $exit_code"

    if [ "$exit_code" -eq 0 ]; then
        echo "FAIL ($label): expected a non-zero exit code (config should be rejected)."
        FAILED=1
    fi
    if echo "$output" | grep -q "SHOULD_NOT_RUN"; then
        echo "FAIL ($label): the sandboxed process ran; this config should have been rejected before execution."
        FAILED=1
    fi
    if ! echo "$output" | grep -qi "$expected_substring"; then
        echo "FAIL ($label): expected rejection message substring '$expected_substring' was not found."
        FAILED=1
    fi
    echo ""
}

run_rejected_case "egress.allow/deny rules not supported" \
    "seatbelt_network_v2_egress_rules_rejected.json" \
    "network.egress.allow/deny rules are not supported"

run_rejected_case "ingress.hostLoopback must equal ingress.default" \
    "seatbelt_network_v2_ingress_mismatch_rejected.json" \
    "cannot enforce an independent network.ingress.hostLoopback posture"

run_rejected_case "legacy + v2 network fields are mutually exclusive" \
    "seatbelt_network_v2_mutual_exclusion_rejected.json" \
    "cannot mix defaultPolicy, enforcementMode, allowLocalNetwork"

if [ "$FAILED" -ne 0 ]; then
    exit 1
fi
echo "Seatbelt schema-v2 validation tests complete."
