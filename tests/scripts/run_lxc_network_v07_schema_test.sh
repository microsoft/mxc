#!/bin/bash
# LXC schema 0.7 enforcement test
#
# LXC serves both schemas, and a run carries exactly one. These two cases pin
# what the 0.7 schema is owed, using configs that declare the version rather
# than leaving it absent.
#
# The DNS case is the sharpest contrast with 0.8: a 0.7 chain carries an
# unconditional port 53 accept, and the same intent expressed in 0.8 does not.
# Run this alongside run_lxc_network_ga_egress_test.sh, whose dns-denied case
# is the other half of the pair.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_DIR="$(dirname "$(dirname "$SCRIPT_DIR")")"
LXC_EXEC="$REPO_DIR/src/target/release/lxc-exec"

if [ ! -f "$LXC_EXEC" ]; then
    LXC_EXEC="$REPO_DIR/src/target/debug/lxc-exec"
fi

# Exit 77 is what run_lxc_all_tests.sh records as SKIPPED rather than PASS.
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

DNS_CONFIG="$REPO_DIR/tests/configs/lxc_network_v07_dns_exemption.json"
CAPABILITIES_CONFIG="$REPO_DIR/tests/configs/lxc_network_v07_capabilities.json"

[ -f "$DNS_CONFIG" ] || skip "missing config $DNS_CONFIG."
[ -f "$CAPABILITIES_CONFIG" ] || skip "missing config $CAPABILITIES_CONFIG."

fail() {
    echo "FAIL: $1"
    exit 1
}

IP_FORWARD_WAS=""
restore_ip_forward() {
    if [ -n "$IP_FORWARD_WAS" ]; then
        sysctl -w net.ipv4.ip_forward="$IP_FORWARD_WAS" >/dev/null 2>&1 || true
    fi
}
trap restore_ip_forward EXIT

# Without this the container's DNS query stops at the host and never leaves the
# box, and the dns case below reads that as a missing port 53 accept.
IP_FORWARD_WAS="$(cat /proc/sys/net/ipv4/ip_forward 2>/dev/null || true)"
sysctl -w net.ipv4.ip_forward=1 >/dev/null 2>&1 \
    || skip "could not enable IPv4 forwarding."

# shellcheck source=lib/chain_name.sh
. "$SCRIPT_DIR/lib/chain_name.sh"

# The snapshot keeps chains left behind by an earlier failed run from being
# blamed on this one.
assert_no_new_mxc_chains() {
    local tool="$1" before="$2" after="" leaked="" chain
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

CHAINS_BEFORE_V4="$(mxc_chains iptables)"
CHAINS_BEFORE_V6="$(mxc_chains ip6tables)"

# ---------------------------------------------------------------------------
# Case 1: firewall mode keeps the 0.7 DNS exemption
# ---------------------------------------------------------------------------

echo "Running LXC schema 0.7 enforcement test..."
echo "--- dns case: 0.7 defaultPolicy block, enforcementMode firewall ---"

DNS_OUTPUT=$("$LXC_EXEC" --debug "$DNS_CONFIG" 2>&1 || true)
echo "$DNS_OUTPUT"

if echo "$DNS_OUTPUT" | grep -Fq "requests no firewall; skipping iptables"; then
    fail "enforcementMode 'firewall' installed no chain, so nothing below is being enforced."
fi

if echo "$DNS_OUTPUT" | grep -Fq "MXC_NET_BLOCKED"; then
    fail "a DNS query was blocked under the 0.7 schema. The unconditional port 53 accept that every 0.7 chain carries is missing, which breaks name resolution for every existing config."
fi

if ! echo "$DNS_OUTPUT" | grep -Fq "MXC_NET_ALLOWED"; then
    fail "the case produced no verdict at all; the container command did not run."
fi

derive_chain_name "$DNS_OUTPUT"
assert_no_new_mxc_chains iptables "$CHAINS_BEFORE_V4"
assert_no_new_mxc_chains ip6tables "$CHAINS_BEFORE_V6"

echo "PASS: the 0.7 chain kept its DNS exemption."

# ---------------------------------------------------------------------------
# Case 2: capabilities mode installs nothing
# ---------------------------------------------------------------------------

echo "--- capabilities case: 0.7 defaultPolicy block, enforcementMode absent ---"

CAP_OUTPUT=$("$LXC_EXEC" --debug "$CAPABILITIES_CONFIG" 2>&1 || true)
echo "$CAP_OUTPUT"

# `capabilities` is the 0.7 default, so this is what every config that never
# wrote `enforcementMode` gets. Installing a chain here would put a firewall on
# configs that predate the field.
if ! echo "$CAP_OUTPUT" | grep -Fq "requests no firewall; skipping iptables"; then
    fail "the default enforcement mode did not skip the firewall. A 0.7 config that never asked for one is being given a chain."
fi

if ! echo "$CAP_OUTPUT" | grep -Fq "MXC_WORKLOAD_RAN"; then
    fail "the workload did not run; skipping the firewall must remain a successful no-op."
fi

assert_no_new_mxc_chains iptables "$CHAINS_BEFORE_V4"
assert_no_new_mxc_chains ip6tables "$CHAINS_BEFORE_V6"

echo "PASS: the default 0.7 enforcement mode installed nothing."
echo "LXC schema 0.7 enforcement test complete."
