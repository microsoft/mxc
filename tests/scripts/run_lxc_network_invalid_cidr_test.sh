#!/bin/bash
# LXC invalid CIDR network filtering test
#
# Invalid CIDR entries should be reported as unresolved hosts and then skipped;
# they must not make firewall setup fail for the rest of the policy.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_DIR="$(dirname "$(dirname "$SCRIPT_DIR")")"
LXC_EXEC="$REPO_DIR/src/target/release/lxc-exec"

if [ ! -f "$LXC_EXEC" ]; then
    LXC_EXEC="$REPO_DIR/src/target/debug/lxc-exec"
fi

# An honest skip for a missing prerequisite: exit 77 so run_lxc_all_tests.sh
# records SKIPPED rather than PASS. A suite that could not run must not look green.
SKIP_EXIT=77
skip() {
    echo "SKIP: $1"
    exit "$SKIP_EXIT"
}

[ "$(id -u)" -eq 0 ] || skip "requires root for iptables/ip6tables and LXC."
command -v iptables >/dev/null 2>&1 || skip "iptables is not installed."
command -v ip6tables >/dev/null 2>&1 || skip "ip6tables is not installed."
command -v lxc-create >/dev/null 2>&1 || skip "LXC (lxc-create) is not installed."
[ -f "$LXC_EXEC" ] || skip "lxc-exec binary not built; run build.sh first."

CONFIG="$REPO_DIR/tests/configs/lxc_network_invalid_cidr.json"
CHAIN_NAME="MXC-CLI-LXC-Network-Inva"
INVALID_HOSTS=(
    "140.82.112.0/33"
    "2606:50c0::/129"
    "140.82.112.0/not-a-prefix"
)

fail() {
    echo "FAIL: $1"
    exit 1
}

assert_firewall_chain_cleaned_up() {
    if iptables -S "$CHAIN_NAME" >/dev/null 2>&1; then
        fail "iptables chain '$CHAIN_NAME' was left behind after lxc-exec completed."
    fi
    if ip6tables -S "$CHAIN_NAME" >/dev/null 2>&1; then
        fail "ip6tables chain '$CHAIN_NAME' was left behind after lxc-exec completed."
    fi
}

echo "Running LXC invalid CIDR network filtering test..."

# The process may fail because the default policy blocks egress; this test is
# only asserting firewall validation and setup behavior.
OUTPUT=$("$LXC_EXEC" --debug "$CONFIG" 2>&1 || true)
echo "$OUTPUT"

for host in "${INVALID_HOSTS[@]}"; do
    if ! echo "$OUTPUT" | grep -Fq "Warning: could not resolve host '$host'"; then
        fail "invalid host '$host' did not produce an unresolved-host warning."
    fi
done

# Invalid CIDRs are warned about and omitted from rule generation; applying the
# remaining firewall policy should still succeed.
if echo "$OUTPUT" | grep -qE "^(ip6?tables) .* failed:|Firewall setup failed:"; then
    fail "invalid CIDR entry caused firewall setup to fail."
fi

if ! echo "$OUTPUT" | grep -q "Default network policy: DROP"; then
    fail "default-deny policy was not applied."
fi

# The FORWARD hook is what scopes the chain to this container's egress; a run
# that skipped it enforces nothing, so PASS must require it. Fail on the
# skipped-hook warning and require the positive install confirmation.
if echo "$OUTPUT" | grep -Fq "Skipping FORWARD hook"; then
    fail "FORWARD hook was skipped; the container's veth interface was not discovered."
fi
if ! echo "$OUTPUT" | grep -Fq "FORWARD hook installed"; then
    fail "FORWARD hook installation was not confirmed."
fi

assert_firewall_chain_cleaned_up

echo "PASS: invalid CIDR entries were warned about without failing firewall setup."
echo "LXC invalid CIDR network filtering test complete."
