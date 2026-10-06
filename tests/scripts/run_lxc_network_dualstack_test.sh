#!/bin/bash
# LXC mixed IPv4/IPv6 directional firewall rule programming test.
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
command -v python3 >/dev/null 2>&1 || skip "python3 is not installed."
[ -f "$LXC_EXEC" ] || skip "lxc-exec binary not built; run build.sh first."

CONFIG="$REPO_DIR/tests/configs/lxc_network_dualstack_cidr.json"
EXPECTED_ALLOWED_HOST_COUNT=5
EXPECTED_BLOCKED_HOST_COUNT=2
EXPECTED_ALLOWED_HOSTS=(
    "127.0.0.1/32"
    "1.1.1.1/32"
    "2606:4700:4700::1111/128"
    "8.8.8.8/32"
    "2001:4860:4860::8888/128"
)
EXPECTED_BLOCKED_HOSTS=(
    "10.0.0.0/8"
    "2001:db8::/32"
)

fail() {
    echo "FAIL: $1"
    exit 1
}

# shellcheck source=lib/chain_name.sh
. "$SCRIPT_DIR/lib/chain_name.sh"

assert_programmed_rule() {
    local table="$1" dest="$2" target="$3"
    # The --debug log emits one line per destination rule actually generated,
    # derived from the built rule args. Asserting it here fails if
    # destination-rule emission is deleted while chain/default/hook logging is
    # kept. This inspects the rule contents while the chain is being programmed
    # rather than only checking that an unresolved-host warning is absent.
    if ! grep -Fq "Programmed $table rule: -A $CHAIN_NAME -d $dest -j $target" <<<"$OUTPUT"; then
        fail "expected $table rule for '$dest' -> $target was not programmed."
    fi
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

load_config_counts() {
    python3 -c 'import json, sys; e=json.load(open(sys.argv[1]))["network"]["egress"]; assert e["default"] == "deny"; print(len(e["allow"]), len(e["deny"]))' "$CONFIG"
}

load_config_hosts() {
    python3 -c 'import json, sys; e=json.load(open(sys.argv[1]))["network"]["egress"]; [print(label + "\t" + dest["cidr"]) for label in ("allow", "deny") for rule in e[label] for dest in rule["to"]]' "$CONFIG"
}

counts="$(load_config_counts)" || fail "could not read the directional rule counts."
read -r allowed_count blocked_count <<<"$counts"
if [ "$allowed_count" -ne "$EXPECTED_ALLOWED_HOST_COUNT" ]; then
    fail "config allow rule count $allowed_count does not match expected count $EXPECTED_ALLOWED_HOST_COUNT."
fi
if [ "$blocked_count" -ne "$EXPECTED_BLOCKED_HOST_COUNT" ]; then
    fail "config deny rule count $blocked_count does not match expected count $EXPECTED_BLOCKED_HOST_COUNT."
fi

hosts="$(load_config_hosts)" || fail "could not read directional destinations."
mapfile -t CONFIG_HOSTS <<<"$hosts"
EXPECTED_HOSTS=("${EXPECTED_ALLOWED_HOSTS[@]}" "${EXPECTED_BLOCKED_HOSTS[@]}")
if [ "${#CONFIG_HOSTS[@]}" -ne "${#EXPECTED_HOSTS[@]}" ]; then
    fail "destination count drifted."
fi
for i in "${!EXPECTED_HOSTS[@]}"; do
    expected="${EXPECTED_HOSTS[$i]}"
    if [ "$i" -lt "$EXPECTED_ALLOWED_HOST_COUNT" ]; then label=allow; else label=deny; fi
    found=0
    for actual in "${CONFIG_HOSTS[@]}"; do
        if [ "$actual" = "$label"$'\t'"$expected" ]; then
            found=1
            break
        fi
    done
    if [ "$found" -ne 1 ]; then
        fail "expected host '$expected' is missing from $CONFIG."
    fi
done

echo "Running LXC mixed-family directional network filtering test..."

# The container command may fail if the host has no outbound route; this test is
# only asserting firewall setup and destination-family handling.
MXC_CHAINS_BEFORE_V4="$(mxc_chains iptables)"
MXC_CHAINS_BEFORE_V6="$(mxc_chains ip6tables)"
OUTPUT=$("$LXC_EXEC" --debug "$CONFIG" 2>&1 || true)
echo "$OUTPUT"

derive_chain_name "$OUTPUT"

for host in "${EXPECTED_HOSTS[@]}"; do
    if grep -Fq "Warning: could not resolve host '$host'" <<<"$OUTPUT"; then
        fail "host '$host' was not resolved."
    fi
done

# Prove a positive IPv6 rule exists rather than only checking that no
# unresolved-host warning appeared. The IPv6 literal and the IPv6 CIDR are
# offline-safe and deterministic, so their v6 rules are always asserted.
assert_programmed_rule iptables "1.1.1.1/32" ACCEPT
assert_programmed_rule ip6tables "2606:4700:4700::1111/128" ACCEPT
assert_programmed_rule ip6tables "2001:4860:4860::8888/128" ACCEPT
assert_programmed_rule ip6tables "2001:db8::/32" DROP

if ! grep -Fq "Creating iptables/ip6tables chain:" <<<"$OUTPUT"; then
    fail "iptables/ip6tables chain creation was not logged."
fi

if ! grep -Fq "Default network policy: DROP" <<<"$OUTPUT"; then
    fail "default-deny policy was not applied."
fi

# This warning means the IPv6 half was skipped.
if grep -Fq "IPv6 firewall rule(s) not applied" <<<"$OUTPUT"; then
    fail "IPv6 rules were skipped; the dual-stack bypass is still open on this run."
fi

# The OUTPUT hook is what puts the chain on the container's egress path; a run
# that skipped it enforces nothing, so PASS must require it. Fail on the
# skipped-hook warning and require the positive install confirmation.
if grep -Fq "Skipping the OUTPUT hook" <<<"$OUTPUT"; then
    fail "OUTPUT hook was skipped; the container network namespace was not found."
fi
if ! grep -Fq "OUTPUT hook installed" <<<"$OUTPUT"; then
    fail "OUTPUT hook installation was not confirmed."
fi

assert_firewall_chain_cleaned_up

echo "PASS: mixed-family directional destinations were programmed."
echo "LXC mixed-family network filtering test complete."
