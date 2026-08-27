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
INVALID_HOSTS=(
    "140.82.112.0/33"
    "2606:50c0::/129"
    "140.82.112.0/not-a-prefix"
)

fail() {
    echo "FAIL: $1"
    exit 1
}

# shellcheck source=lib/chain_name.sh
. "$SCRIPT_DIR/lib/chain_name.sh"

# Compared against a snapshot taken before the run, so chains left behind by an
# earlier failed run are not blamed on this one.
assert_no_new_mxc_chains() {
    local tool="$1" before="$2" after="" leaked="" chain
    # Captured before iterating rather than piped in from a process
    # substitution, whose exit status is not the loop's. A failed enumeration
    # would otherwise read as zero chains and pass this assertion while
    # verifying nothing.
    if ! after="$(mxc_chains "$tool")"; then
        fail "could not enumerate $tool chains, so cleanup was not verified."
    fi
    while IFS= read -r chain; do
        [ -n "$chain" ] || continue
        grep -Fxq "$chain" <<<"$before" || leaked="$leaked $chain"
    done <<<"$after"
    if [ -n "$leaked" ]; then
        fail "$tool chain(s) left behind after lxc-exec completed:$leaked"
    fi
}

assert_firewall_chain_cleaned_up() {
    assert_no_new_mxc_chains iptables "$MXC_CHAINS_BEFORE_V4"
    assert_no_new_mxc_chains ip6tables "$MXC_CHAINS_BEFORE_V6"
}

echo "Running LXC invalid CIDR network filtering test..."

MXC_CHAINS_BEFORE_V4="$(mxc_chains iptables)"
MXC_CHAINS_BEFORE_V6="$(mxc_chains ip6tables)"

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

# The OUTPUT hook is what puts the chain on the container's egress path; a run
# that skipped it enforces nothing, so PASS must require it. Fail on the
# skipped-hook warning and require the positive install confirmation.
if echo "$OUTPUT" | grep -Fq "Skipping the OUTPUT hook"; then
    fail "OUTPUT hook was skipped; the container network namespace was not found."
fi
if ! echo "$OUTPUT" | grep -Fq "OUTPUT hook installed"; then
    fail "OUTPUT hook installation was not confirmed."
fi

assert_firewall_chain_cleaned_up

echo "PASS: invalid CIDR entries were warned about without failing firewall setup."
echo "LXC invalid CIDR network filtering test complete."
