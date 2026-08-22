#!/bin/bash
# LXC schema 0.8 egress enforcement test
#
# Asserts reachability rather than a log line: a chain can install cleanly,
# name the right chain, and still filter nothing.
#
# A directional posture carries no port 53 exemption, unlike the legacy chain,
# which is what the two DNS cases pin.
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

DENY_CONFIG="$REPO_DIR/tests/configs/lxc_network_ga_egress_deny.json"
ALLOW_CONFIG="$REPO_DIR/tests/configs/lxc_network_ga_egress_allow.json"
WRONG_PORT_CONFIG="$REPO_DIR/tests/configs/lxc_network_ga_egress_wrong_port.json"
DNS_DENIED_CONFIG="$REPO_DIR/tests/configs/lxc_network_ga_egress_dns_denied.json"
DNS_ALLOWED_CONFIG="$REPO_DIR/tests/configs/lxc_network_ga_egress_dns_allowed.json"
DENY_RULE_CONFIG="$REPO_DIR/tests/configs/lxc_network_ga_egress_deny_rule.json"
EXCEPT_EXCLUDED_CONFIG="$REPO_DIR/tests/configs/lxc_network_ga_egress_except_excluded.json"
EXCEPT_SIBLING_CONFIG="$REPO_DIR/tests/configs/lxc_network_ga_egress_except_sibling.json"

fail() {
    echo "FAIL: $1"
    exit 1
}

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

assert_firewall_chain_cleaned_up() {
    local chain="$1"
    if iptables -S "$chain" >/dev/null 2>&1; then
        fail "iptables chain '$chain' was left behind after lxc-exec completed."
    fi
    if ip6tables -S "$chain" >/dev/null 2>&1; then
        fail "ip6tables chain '$chain' was left behind after lxc-exec completed."
    fi
    assert_no_new_mxc_chains iptables "$MXC_CHAINS_BEFORE_V4"
    assert_no_new_mxc_chains ip6tables "$MXC_CHAINS_BEFORE_V6"
}

assert_no_forward_reference() {
    if iptables -S FORWARD 2>/dev/null | grep -Fq -- "$1"; then
        fail "a FORWARD rule still references chain '$1' after teardown."
    fi
}

# A backend reading `enforcementMode` alone skips the chain and still reports
# success, which is a silent unenforced run rather than a failure.
assert_enforcement_not_skipped() {
    if echo "$1" | grep -Fq "requests no firewall; skipping iptables"; then
        fail "the 0.8 config was treated as not using the firewall, so no rules were installed. The directional posture is not reaching the firewall gate."
    fi
}

run_case() {
    local label="$1" config="$2" output="" 
    echo "--- $label ---"
    MXC_CHAINS_BEFORE_V4="$(mxc_chains iptables)"
    MXC_CHAINS_BEFORE_V6="$(mxc_chains ip6tables)"
    output=$("$LXC_EXEC" --debug "$config" 2>&1 || true)
    echo "$output"
    CASE_OUTPUT="$output"
    assert_enforcement_not_skipped "$output"
    derive_chain_name "$output"
    assert_no_forward_reference "$CHAIN_NAME"
    assert_firewall_chain_cleaned_up "$CHAIN_NAME"
}

assert_blocked() {
    if echo "$CASE_OUTPUT" | grep -Fq "MXC_NET_ALLOWED"; then
        fail "$1"
    fi
    if ! echo "$CASE_OUTPUT" | grep -Fq "MXC_NET_BLOCKED"; then
        fail "the case produced no verdict at all; the container command did not run."
    fi
}

assert_allowed() {
    if echo "$CASE_OUTPUT" | grep -Fq "MXC_NET_BLOCKED"; then
        fail "$1"
    fi
    if ! echo "$CASE_OUTPUT" | grep -Fq "MXC_NET_ALLOWED"; then
        fail "the case produced no verdict at all; the container command did not run."
    fi
}

echo "Running LXC schema 0.8 egress enforcement test..."

# An egress-only config is the shape a backend claiming only the two egress
# bits would reject outright, which makes any verdict here a test of the
# support declaration.
run_case "deny case: egress.default deny, no rules" "$DENY_CONFIG"
assert_blocked "egress succeeded under egress.default deny with no allow rules. The chain is not filtering this container's traffic."

run_case "allow case: same default, destination allowed on tcp/443" "$ALLOW_CONFIG"
assert_allowed "an explicitly allowed destination was unreachable. The policy is over-blocking, so the deny case above proves nothing."

run_case "wrong-port case: same destination allowed on tcp/444" "$WRONG_PORT_CONFIG"
assert_blocked "traffic to tcp/443 succeeded while the policy allowed only tcp/444. The port selector is being dropped, so the allow case above proves only that the destination matched."

run_case "dns-denied case: egress.default deny, DNS probe to an external resolver" "$DNS_DENIED_CONFIG"
assert_blocked "a DNS query to 8.8.8.8 succeeded under egress.default deny with no allow rules. The legacy unconditional port 53 accept is still being emitted into a directional chain, which leaves this container a DNS-tunnel path out of a deny-all policy."

run_case "dns-allowed case: same probe, resolver allowed on udp/53" "$DNS_ALLOWED_CONFIG"
assert_allowed "a DNS query to an explicitly allowed resolver was unreachable. DNS is over-blocked, so the dns-denied case above proves only that this container has no DNS at all."

run_case "deny-rule case: egress.default allow, one destination denied on udp/53" "$DENY_RULE_CONFIG"
assert_blocked "a denied destination stayed reachable under egress.default allow. Entries from egress.deny are not reaching the chain, so a config written as allow-with-exceptions enforces nothing."

run_case "except case: allow 8.8.0.0/16 except 8.8.8.8/32, probe the excluded address" "$EXCEPT_EXCLUDED_CONFIG"
assert_blocked "an address named in except was reachable through the rule that excludes it. The exclusion is being dropped, so the surrounding allow is wider than written."

run_case "except case: same policy, probe an address the exclusion does not cover" "$EXCEPT_SIBLING_CONFIG"
assert_allowed "an address inside the allowed range but outside except was unreachable. The exclusion is over-blocking, so the case above proves only that the whole rule failed to install."

echo "PASS: schema 0.8 egress rules filtered by destination, by port, by resolver, by deny rule, and by exclusion."
echo "LXC schema 0.8 egress enforcement test complete."
