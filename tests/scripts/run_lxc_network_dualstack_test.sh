#!/bin/bash
# LXC dual-stack hostname network filtering test
#
# Proves AB#62830559 / roadmap item 19: hostname allow-list entries are
# resolved to both A and AAAA records so IPv6 traffic to a dual-stack
# destination cannot bypass the firewall. The same run also keeps IPv4/IPv6
# literals and IPv4/IPv6 CIDRs in the policy to catch mixed-family regressions.
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

CONFIG="$REPO_DIR/tests/configs/lxc_network_dualstack_hostname.json"
CHAIN_NAME="MXC-CLI-LXC-Network-Dual"
EXPECTED_ALLOWED_HOST_COUNT=5
EXPECTED_BLOCKED_HOST_COUNT=2
EXPECTED_ALLOWED_HOSTS=(
    "localhost"
    "dns.google"
    "one.one.one.one"
    "8.8.8.8"
    "2001:4860:4860::8888"
)
EXPECTED_BLOCKED_HOSTS=(
    "10.0.0.0/8"
    "2001:db8::/32"
)
EXTERNAL_DUALSTACK_HOSTNAMES=(
    "dns.google"
    "one.one.one.one"
)
OFFLINE_SAFE_HOSTS=(
    "localhost"
    "8.8.8.8"
    "2001:4860:4860::8888"
    "10.0.0.0/8"
    "2001:db8::/32"
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
    # kept. This inspects the rule contents while the chain is being programmed
    # rather than only checking that an unresolved-host warning is absent.
    if ! grep -Fq "Programmed $table rule: -A $CHAIN_NAME -d $dest -j $target" <<<"$OUTPUT"; then
        fail "expected $table rule for '$dest' -> $target was not programmed."
    fi
}

assert_firewall_chain_cleaned_up() {
    if iptables -S "$CHAIN_NAME" >/dev/null 2>&1; then
        fail "iptables chain '$CHAIN_NAME' was left behind after lxc-exec completed."
    fi
    if ip6tables -S "$CHAIN_NAME" >/dev/null 2>&1; then
        fail "ip6tables chain '$CHAIN_NAME' was left behind after lxc-exec completed."
    fi
}

load_config_counts() {
    if command -v python3 >/dev/null 2>&1; then
        python3 -c 'import json, sys; data=json.load(open(sys.argv[1], encoding="utf-8")); net=data["network"]; print(len(net.get("allowedHosts", [])), len(net.get("blockedHosts", [])))' "$CONFIG"
    else
        awk '
            /"allowedHosts"[[:space:]]*:/ { section="allowed"; next }
            /"blockedHosts"[[:space:]]*:/ { section="blocked"; next }
            section && /]/ { section=""; next }
            section && /^[[:space:]]*"/ { counts[section]++ }
            END { printf "%d %d\n", counts["allowed"] + 0, counts["blocked"] + 0 }
        ' "$CONFIG"
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

host_has_records() {
    local family="$1"
    local host="$2"

    if command -v timeout >/dev/null 2>&1; then
        timeout 10s getent "$family" "$host" >/dev/null 2>&1
    else
        getent "$family" "$host" >/dev/null 2>&1
    fi
}

external_dualstack_hosts_resolve() {
    local host

    for host in "${EXTERNAL_DUALSTACK_HOSTNAMES[@]}"; do
        if ! host_has_records ahostsv4 "$host" || ! host_has_records ahostsv6 "$host"; then
            return 1
        fi
    done

    return 0
}

read -r allowed_count blocked_count < <(load_config_counts)
if [ "$allowed_count" -ne "$EXPECTED_ALLOWED_HOST_COUNT" ]; then
    fail "config allowedHosts count $allowed_count does not match expected count $EXPECTED_ALLOWED_HOST_COUNT."
fi
if [ "$blocked_count" -ne "$EXPECTED_BLOCKED_HOST_COUNT" ]; then
    fail "config blockedHosts count $blocked_count does not match expected count $EXPECTED_BLOCKED_HOST_COUNT."
fi

mapfile -t CONFIG_HOSTS < <(load_config_hosts)
EXPECTED_HOSTS=("${EXPECTED_ALLOWED_HOSTS[@]}" "${EXPECTED_BLOCKED_HOSTS[@]}")
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

ASSERT_RESOLVED_HOSTS=("${OFFLINE_SAFE_HOSTS[@]}")
if external_dualstack_hosts_resolve; then
    ASSERT_RESOLVED_HOSTS=("${EXPECTED_HOSTS[@]}")
    EXTERNAL_DUALSTACK=1
else
    EXTERNAL_DUALSTACK=0
    echo "SKIP: external dual-stack DNS unavailable; skipping external hostname resolution assertions."
fi

echo "Running LXC dual-stack hostname network filtering test..."

# The container command may fail if the host has no outbound route; this test is
# only asserting firewall setup and hostname family handling.
OUTPUT=$("$LXC_EXEC" --debug "$CONFIG" 2>&1 || true)
echo "$OUTPUT"

for host in "${ASSERT_RESOLVED_HOSTS[@]}"; do
    if grep -Fq "Warning: could not resolve host '$host'" <<<"$OUTPUT"; then
        fail "host '$host' was not resolved."
    fi
done

# Prove a positive IPv6 rule exists rather than only checking that no
# unresolved-host warning appeared. The IPv6 literal and the IPv6 CIDR are
# offline-safe and deterministic, so their v6 rules are always asserted.
assert_programmed_rule ip6tables "2001:4860:4860::8888" ACCEPT
assert_programmed_rule ip6tables "2001:db8::/32" DROP

# The dual-stack point of AB#62830559: a hostname's AAAA record must become an
# IPv6 rule. When external DNS is available, resolve an AAAA for a dual-stack
# hostname ourselves and require the firewall to have programmed an IPv6 ACCEPT
# rule for that exact address -- proving the hostname's AAAA became a v6 rule,
# not merely that a warning was absent. When external DNS is unavailable this is
# skipped loudly (never silently passed).
if [ "$EXTERNAL_DUALSTACK" -eq 1 ]; then
    aaaa=$(getent ahostsv6 dns.google 2>/dev/null | awk 'NF {print $1; exit}')
    if [ -n "${aaaa:-}" ]; then
        assert_programmed_rule ip6tables "$aaaa" ACCEPT
    else
        echo "SKIP: could not obtain an AAAA for dns.google; hostname-derived IPv6 rule not asserted."
    fi
else
    echo "SKIP: external dual-stack DNS unavailable; hostname-derived IPv6 rule not asserted."
fi

if ! grep -Fq "Creating iptables/ip6tables chain:" <<<"$OUTPUT"; then
    fail "iptables/ip6tables chain creation was not logged."
fi

if ! grep -Fq "Default network policy: DROP" <<<"$OUTPUT"; then
    fail "default-deny policy was not applied."
fi

# This warning means the IPv6 half was skipped, which is the dual-stack bypass
# AB#62830559 exists to prevent.
if grep -Fq "IPv6 firewall rule(s) not applied" <<<"$OUTPUT"; then
    fail "IPv6 rules were skipped; the dual-stack bypass is still open on this run."
fi

# The FORWARD hook is what scopes the chain to this container's egress; a run
# that skipped it enforces nothing, so PASS must require it. Fail on the
# skipped-hook warning and require the positive install confirmation.
if grep -Fq "Skipping FORWARD hook" <<<"$OUTPUT"; then
    fail "FORWARD hook was skipped; the container's veth interface was not discovered."
fi
if ! grep -Fq "FORWARD hook installed" <<<"$OUTPUT"; then
    fail "FORWARD hook installation was not confirmed."
fi

assert_firewall_chain_cleaned_up

echo "PASS: dual-stack hostnames and mixed-family destinations were resolved and programmed."
echo "LXC dual-stack hostname network filtering test complete."
