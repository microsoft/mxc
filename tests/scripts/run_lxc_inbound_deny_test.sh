#!/bin/bash

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_DIR="$(dirname "$(dirname "$SCRIPT_DIR")")"
LXC_EXEC="$REPO_DIR/src/target/release/lxc-exec"

if [ ! -f "$LXC_EXEC" ]; then
    LXC_EXEC="$REPO_DIR/src/target/debug/lxc-exec"
fi

SKIP_EXIT=77
skip()
{
    echo "SKIP: $1"
    exit "$SKIP_EXIT"
}

[ "$(id -u)" -eq 0 ] || skip "requires root for LXC."
command -v lxc-create >/dev/null 2>&1 || skip "LXC (lxc-create) is not installed."
command -v lxc-info >/dev/null 2>&1 || skip "LXC (lxc-info) is not installed."
[ -f "$LXC_EXEC" ] || skip "lxc-exec binary not built; run build.sh first."

DENY_CONFIG="$REPO_DIR/tests/configs/lxc_inbound_default_deny.json"
DIRECTIONAL_CONFIG="$REPO_DIR/tests/configs/lxc_inbound_permissive_ingress.json"
DENY_INGRESS_CONFIG="$REPO_DIR/tests/configs/lxc_inbound_deny_ingress.json"

fail()
{
    echo "FAIL: $1"
    exit 1
}

CONTAINERS=("CLI-LXC-Inbound-Deny" "CLI-LXC-Inbound-V08-Deny" "CLI-LXC-V08-Permissive-Ingress")

cleanup()
{
    local status=$? container
    trap - EXIT
    for container in "${CONTAINERS[@]}"; do
        if lxc-info -n "$container" >/dev/null 2>&1; then
            if ! timeout --kill-after=10s 30 "$LXC_EXEC" --delete --containername "$container"; then
                echo "FAIL: could not delete inbound-policy container $container." >&2
                status=1
            fi
        fi
    done
    exit "$status"
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

for container in "${CONTAINERS[@]}"; do
    if lxc-info -n "$container" >/dev/null 2>&1; then
        timeout --kill-after=10s 30 "$LXC_EXEC" --delete --containername "$container" \
            || fail "could not delete the previous inbound-policy container $container."
    fi
done

echo "Running LXC inbound default-deny acceptance test..."

if ! OUTPUT="$(timeout --kill-after=10s 300 "$LXC_EXEC" "$DENY_CONFIG" 2>&1)"; then
    echo "$OUTPUT"
    fail "lxc-exec did not finish the default-deny workload successfully within 300s."
fi
echo "$OUTPUT"
grep -Fq "inbound-default-deny-ok" <<<"$OUTPUT" \
    || fail "the supported default-deny policy did not run its workload."

echo "Running LXC directional deny-ingress acceptance test..."

if ! OUTPUT="$(timeout --kill-after=10s 300 "$LXC_EXEC" "$DENY_INGRESS_CONFIG" 2>&1)"; then
    echo "$OUTPUT"
    fail "lxc-exec did not finish the directional deny-ingress workload successfully within 300s."
fi
echo "$OUTPUT"
grep -Fq "MXC_WORKLOAD_RAN" <<<"$OUTPUT" \
    || fail "the supported directional deny-ingress policy did not run its workload."

echo "Running LXC directional permissive-ingress rejection test..."

STATUS=0
OUTPUT="$(timeout --kill-after=10s 300 "$LXC_EXEC" "$DIRECTIONAL_CONFIG" 2>&1)" || STATUS=$?
echo "$OUTPUT"

case "$STATUS" in
    0) fail "the unsupported permissive-ingress policy was accepted." ;;
    124|137) fail "lxc-exec timed out instead of rejecting permissive ingress." ;;
esac
if grep -Fq "this-should-never-run" <<<"$OUTPUT"; then
    fail "the workload ran despite the unsupported permissive-ingress policy."
fi

echo "PASS: deny-ingress policies run workloads; unsupported permissive ingress rejects before execution."
