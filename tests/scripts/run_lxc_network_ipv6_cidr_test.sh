#!/bin/bash
# LXC IPv6 + CIDR network filtering test
#
# Exercises tests/configs/lxc_network_ipv6_cidr.json, whose allow/block lists
# carry IPv4 CIDRs, IPv6 CIDRs, and IPv6 literals. The assertions are on the
# firewall setup rather than on whether the container reaches the network:
# reachability depends on the host's uplink, but rule programming does not.
#
# A misrouted address family is a hard failure, not a silent one --
# `run_firewall_command` returns Err when iptables/ip6tables rejects a rule, so
# handing an IPv6 CIDR to iptables (or a v4 CIDR to ip6tables) aborts setup and
# is caught here.
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

CONFIG="$REPO_DIR/tests/configs/lxc_network_ipv6_cidr.json"
EXPECTED_HOSTS=(
    "140.82.112.0/20"
    "2606:50c0::/32"
    "2606:50c0:8000::153"
    "10.0.0.0/8"
    "2001:db8::/32"
    "fe80::1"
)

fail() {
    echo "FAIL: $1"
    exit 1
}

assert_programmed_rule() {
    local table="$1" dest="$2" target="$3"
    # The --debug log emits one line per destination rule actually generated,
    # derived from the built rule args. Asserting it here fails if
    # destination-rule emission is deleted while chain/default/hook logging is
    # kept -- the exact vacuity flagged in review. This inspects the rule
    # contents while the chain is being programmed rather than only checking
    # post-run cleanup.
    if ! grep -Fq "Programmed $table rule: -A $CHAIN_NAME -d $dest -j $target" <<<"$OUTPUT"; then
        fail "expected $table rule for '$dest' -> $target was not programmed."
    fi
}

# List the MXC-owned chains a tool currently holds. The chain name is derived
# from a digest of the container name, so a hard-coded literal rots the moment
# that derivation changes, and a cleanup assertion naming a chain that can no
# longer exist passes while testing nothing. Matching the MXC- prefix stays
# correct across naming changes.
mxc_chains() {
    "$1" -S 2>/dev/null | sed -n 's/^-N \(MXC-.*\)$/\1/p' | sort
}

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

# The chain name is a digest of the container name, so it is read back from this
# run's own debug output rather than hard-coded. Its shape and length ceiling are
# asserted independently, so a malformed name still fails here.
derive_chain_name() {
    CHAIN_NAME="$(sed -n 's/^.*Programmed [a-z0-9]* rule: -A \([^ ]*\) .*$/\1/p' <<<"$OUTPUT" | head -n 1)"
    if [ -z "$CHAIN_NAME" ]; then
        fail "no programmed rule was logged, so the chain name could not be determined."
    fi
    if ! grep -Eq '^MXC-([A-Za-z0-9_-]{1,7}-)?[a-z2-7]{16}$' <<<"$CHAIN_NAME"; then
        fail "chain name '$CHAIN_NAME' does not match the documented MXC-<slug>-<hash> shape."
    fi
    if [ "${#CHAIN_NAME}" -gt 28 ]; then
        fail "chain name '$CHAIN_NAME' exceeds the 28-character iptables ceiling."
    fi
}

load_config_hosts() {
    if command -v python3 >/dev/null 2>&1; then
        python3 -c 'import json, sys; data=json.load(open(sys.argv[1], encoding="utf-8")); net=data["network"]; print("\n".join(net.get("allowedHosts", []) + net.get("blockedHosts", [])))' "$CONFIG"
    else
        awk '
            /"allowedHosts"[[:space:]]*:/ { in_hosts=1; next }
            /"blockedHosts"[[:space:]]*:/ { in_hosts=1; next }
            in_hosts && /]/ { in_hosts=0; next }
            in_hosts { print }
        ' "$CONFIG" | sed -n 's/^[[:space:]]*"\([^"]*\)".*/\1/p'
    fi
}

mapfile -t CONFIG_HOSTS < <(load_config_hosts)
if [ "${#CONFIG_HOSTS[@]}" -ne "${#EXPECTED_HOSTS[@]}" ]; then
    fail "config host count ${#CONFIG_HOSTS[@]} does not match expected count ${#EXPECTED_HOSTS[@]}."
fi
for expected in "${EXPECTED_HOSTS[@]}"; do
    found=0
    for actual in "${CONFIG_HOSTS[@]}"; do
        if [ "$actual" = "$expected" ]; then
            found=1
            break
        fi
    done
    if [ "$found" -ne 1 ]; then
        fail "expected host '$expected' is missing from $CONFIG."
    fi
done

echo "Running LXC IPv6/CIDR network filtering test..."

# The container command may fail on a host with no outbound route; the firewall
# assertions below are what this test is about.
MXC_CHAINS_BEFORE_V4="$(mxc_chains iptables)"
MXC_CHAINS_BEFORE_V6="$(mxc_chains ip6tables)"
OUTPUT=$("$LXC_EXEC" --debug "$CONFIG" 2>&1 || true)
echo "$OUTPUT"

derive_chain_name

# Every allow/block entry must survive resolution. An unparsed CIDR or IPv6
# literal is reported here instead of silently dropping a rule.
for host in "${EXPECTED_HOSTS[@]}"; do
    if echo "$OUTPUT" | grep -Fq "Warning: could not resolve host '$host'"; then
        fail "host '$host' was not resolved."
    fi
done

# Inspect the actual destination rules that were generated -- not merely the
# absence of an unresolved-host warning. Each allow entry must yield an ACCEPT
# rule and each block entry a DROP rule, in the correct family's table, so that
# deleting destination-rule emission fails this test.
assert_programmed_rule iptables "140.82.112.0/20" ACCEPT
assert_programmed_rule ip6tables "2606:50c0::/32" ACCEPT
assert_programmed_rule ip6tables "2606:50c0:8000::153" ACCEPT
assert_programmed_rule iptables "10.0.0.0/8" DROP
assert_programmed_rule ip6tables "2001:db8::/32" DROP
assert_programmed_rule ip6tables "fe80::1" DROP

# A rejected rule aborts setup.
if echo "$OUTPUT" | grep -qE "^(ip6?tables) .* failed:|Firewall setup failed:"; then
    fail "iptables/ip6tables rejected a rule."
fi

if ! echo "$OUTPUT" | grep -q "Default network policy: DROP"; then
    fail "default-deny policy was not applied."
fi

# The v6 half is the point of the test: if ip6tables is unusable the v6 rules
# are skipped with a warning, which would make this a v4-only run.
if echo "$OUTPUT" | grep -q "IPv6 firewall rule(s) not applied"; then
    fail "IPv6 rules were skipped; ip6tables is unusable on this host."
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

echo "PASS: IPv6 and CIDR entries were resolved and programmed."
echo "LXC IPv6/CIDR network filtering test complete."
