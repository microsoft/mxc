#!/bin/bash
# LXC invalid CIDR network filtering test
#
# An entry like 10.0.0.0/33 matches nothing on any host at any moment, so no
# rule can carry it. The run is refused and names the entry, rather than
# programming the rest of the policy and leaving the caller believing a
# destination they wrote down is being filtered.
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

# The run must be refused. A zero exit means a policy naming an entry that can
# never match was applied and reported as success.
OUTPUT=""
STATUS=0
OUTPUT=$("$LXC_EXEC" --debug "$CONFIG" 2>&1) || STATUS=$?
echo "$OUTPUT"

[ "$STATUS" -ne 0 ] \
    || fail "lxc-exec exited 0, so a policy carrying an unmatchable entry was accepted. If
      this is unexpected, check that $LXC_EXEC is current -- a binary built before
      this rule existed fails here in exactly the same way as a regression."

# Refused for this reason, not by coincidence: a fixture broken some other way
# also exits non-zero and would pass the check above on its own.
echo "$OUTPUT" | grep -Fq "is not a valid destination" \
    || fail "refused, but the message never said the destination was invalid."

# The operator has to be told which entry to fix. Only the first is named --
# the run stops at it -- so one match across the set is the contract, not three.
named=0
for host in "${INVALID_HOSTS[@]}"; do
    if echo "$OUTPUT" | grep -Fq "$host"; then
        named=$((named + 1))
    fi
done
if [ "$named" -eq 0 ]; then
    fail "the refusal named none of the invalid entries, so it says nothing about what to fix."
fi

# The refusal has to land before the workload, or the container already ran
# under a policy that was never programmed.
if echo "$OUTPUT" | grep -Fq "MXC_WORKLOAD_RAN"; then
    fail "the workload ran despite the refused policy."
fi

assert_firewall_chain_cleaned_up

echo "PASS: an unmatchable CIDR entry was refused, named, and rolled back."
echo "LXC invalid CIDR network filtering test complete."
