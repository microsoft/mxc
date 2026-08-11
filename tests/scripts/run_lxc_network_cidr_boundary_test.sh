#!/bin/bash
# LXC CIDR boundary network filtering test
#
# Proves roadmap item 19 / AB#62830559 accepts boundary-valid CIDR
# destinations while using the default-allow firewall path. The boundary values
# pinned here are IPv4/IPv6 /0, IPv4 /32, IPv6 /128, non-zero host-bit CIDRs,
# and a bare literal plus matching single-address CIDR spelling in one policy.
#
# NOTE: this fixture asserts that boundary prefixes are accepted and programmed,
# not effective reachability. Allow-list rules are emitted before block-list rules
# and iptables is first-match-wins (interim behaviour, AB#62830341), so the
# `0.0.0.0/0` and `::/0` allow entries shadow every blockedHosts entry here.
# Do not add reachability assertions to this file expecting the block list to win.
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

CONFIG="$REPO_DIR/tests/configs/lxc_network_cidr_boundary.json"
EXPECTED_ALLOWED_HOSTS=(
    "0.0.0.0/0"
    "::/0"
    "140.82.112.5"
    "140.82.112.5/20"
    "140.82.112.5/32"
    "2606:50c0:8000::153/32"
)
EXPECTED_BLOCKED_HOSTS=(
    "198.51.100.42"
    "198.51.100.42/32"
    "2001:db8::5"
    "2001:db8::5/128"
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
    # rather than only checking post-run cleanup.
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
        python3 -c 'import json, sys; data=json.load(open(sys.argv[1], encoding="utf-8")); net=data["network"]; [print(f"allowed\t{h}") for h in net.get("allowedHosts", [])]; [print(f"blocked\t{h}") for h in net.get("blockedHosts", [])]' "$CONFIG"
    else
        awk '
            /"allowedHosts"[[:space:]]*:/ { list="allowed"; next }
            /"blockedHosts"[[:space:]]*:/ { list="blocked"; next }
            list && /]/ { list=""; next }
            list { print list "\t" $0 }
        ' "$CONFIG" | sed -n 's/^\([^[:space:]]*\)[[:space:]]*"\([^"]*\)".*/\1\t\2/p'
    fi
}

contains_host() {
    local needle="$1"
    shift
    local host
    for host in "$@"; do
        if [ "$host" = "$needle" ]; then
            return 0
        fi
    done
    return 1
}

mapfile -t CONFIG_HOST_LINES < <(load_config_hosts)
CONFIG_ALLOWED_HOSTS=()
CONFIG_BLOCKED_HOSTS=()
for line in "${CONFIG_HOST_LINES[@]}"; do
    list="${line%%$'\t'*}"
    host="${line#*$'\t'}"
    case "$list" in
        allowed) CONFIG_ALLOWED_HOSTS+=("$host") ;;
        blocked) CONFIG_BLOCKED_HOSTS+=("$host") ;;
        *) fail "unexpected host list '$list' in $CONFIG." ;;
    esac
done

if [ "${#CONFIG_ALLOWED_HOSTS[@]}" -ne "${#EXPECTED_ALLOWED_HOSTS[@]}" ]; then
    fail "allowed host count ${#CONFIG_ALLOWED_HOSTS[@]} does not match expected count ${#EXPECTED_ALLOWED_HOSTS[@]}."
fi
if [ "${#CONFIG_BLOCKED_HOSTS[@]}" -ne "${#EXPECTED_BLOCKED_HOSTS[@]}" ]; then
    fail "blocked host count ${#CONFIG_BLOCKED_HOSTS[@]} does not match expected count ${#EXPECTED_BLOCKED_HOSTS[@]}."
fi
for expected in "${EXPECTED_ALLOWED_HOSTS[@]}"; do
    if ! contains_host "$expected" "${CONFIG_ALLOWED_HOSTS[@]}"; then
        fail "expected allowed host '$expected' is missing from $CONFIG."
    fi
done
for expected in "${EXPECTED_BLOCKED_HOSTS[@]}"; do
    if ! contains_host "$expected" "${CONFIG_BLOCKED_HOSTS[@]}"; then
        fail "expected blocked host '$expected' is missing from $CONFIG."
    fi
done

ALL_CONFIG_HOSTS=("${CONFIG_ALLOWED_HOSTS[@]}" "${CONFIG_BLOCKED_HOSTS[@]}")

echo "Running LXC CIDR boundary network filtering test..."

MXC_CHAINS_BEFORE_V4="$(mxc_chains iptables)"
MXC_CHAINS_BEFORE_V6="$(mxc_chains ip6tables)"

set +e
OUTPUT=$("$LXC_EXEC" --debug "$CONFIG" 2>&1)
STATUS=$?
set -e
echo "$OUTPUT"

derive_chain_name

# The container command is a local success command (see the fixture), so a
# non-zero status reflects a firewall-setup failure on boundary-valid prefixes
# rather than an unrelated network outage.
if [ "$STATUS" -ne 0 ]; then
    fail "lxc-exec exited with status $STATUS for boundary-valid prefixes."
fi

# SPEC_BRIEF §3 accepts prefix lengths at the inclusive family bounds, including /0.
for host in "${ALL_CONFIG_HOSTS[@]}"; do
    if echo "$OUTPUT" | grep -Fq "Warning: could not resolve host '$host'"; then
        fail "host '$host' was not resolved."
    fi
done

# Inspect the actual destination rules generated -- not merely the absence of an
# unresolved-host warning. Each allow entry must yield an ACCEPT rule and each
# block entry a DROP rule, in the correct family's table, so that deleting
# destination-rule emission fails this test even though chain/default/hook
# logging is unchanged.
assert_programmed_rule iptables "0.0.0.0/0" ACCEPT
assert_programmed_rule ip6tables "::/0" ACCEPT
assert_programmed_rule iptables "140.82.112.5" ACCEPT
assert_programmed_rule iptables "140.82.112.5/20" ACCEPT
assert_programmed_rule iptables "140.82.112.5/32" ACCEPT
assert_programmed_rule ip6tables "2606:50c0:8000::153/32" ACCEPT
assert_programmed_rule iptables "198.51.100.42" DROP
assert_programmed_rule iptables "198.51.100.42/32" DROP
assert_programmed_rule ip6tables "2001:db8::5" DROP
assert_programmed_rule ip6tables "2001:db8::5/128" DROP

if ! echo "$OUTPUT" | grep -q "Default network policy: ACCEPT"; then
    fail "default-allow policy was not applied."
fi
if echo "$OUTPUT" | grep -q "Default network policy: DROP"; then
    fail "default-deny policy was applied unexpectedly."
fi

# The v6 half is required by roadmap item 19 / AB#62830559; skipping it would be a dual-stack bypass.
if echo "$OUTPUT" | grep -q "IPv6 firewall rule(s) not applied"; then
    fail "IPv6 rules were skipped; ip6tables is unusable on this host."
fi

if ! echo "$OUTPUT" | grep -q "Creating iptables/ip6tables chain:"; then
    fail "firewall chain creation was not logged."
fi

if echo "$OUTPUT" | grep -qE "^(ip6?tables) .* failed:|Firewall setup failed:"; then
    fail "iptables/ip6tables rejected a boundary-valid rule."
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

echo "PASS: CIDR boundary entries were resolved and programmed with default allow."
echo "LXC CIDR boundary network filtering test complete."
