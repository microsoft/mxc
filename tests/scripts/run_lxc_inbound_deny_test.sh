#!/bin/bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_DIR="$(dirname "$(dirname "$SCRIPT_DIR")")"
LXC_EXEC="${LXC_EXEC:-$REPO_DIR/src/target/release/lxc-exec}"
if [ "$LXC_EXEC" = "$REPO_DIR/src/target/release/lxc-exec" ] && [ ! -f "$LXC_EXEC" ]; then
    LXC_EXEC="$REPO_DIR/src/target/debug/lxc-exec"
fi

fail() {
    echo "FAIL: $1"
    exit 1
}

BEFORE_V4="$(iptables-save | sed '/^#/d')"
BEFORE_V6="$(ip6tables-save | sed '/^#/d')"
BEFORE_NFT="$(nft -s list ruleset)"
for case in lxc_inbound_default_deny lxc_inbound_deny_ingress; do
    OUTPUT=$("$LXC_EXEC" "$REPO_DIR/tests/configs/$case.json" 2>&1) \
        || fail "the supported default-deny workload failed: $OUTPUT"
    echo "$OUTPUT"
    case "$case" in
        lxc_inbound_default_deny) MARKER="inbound-default-deny-ok" ;;
        lxc_inbound_deny_ingress) MARKER="MXC_WORKLOAD_RAN" ;;
    esac
    grep -Fq "$MARKER" <<<"$OUTPUT" || fail "the supported default-deny workload never ran."
done

if OUTPUT=$("$LXC_EXEC" "$REPO_DIR/tests/configs/lxc_inbound_permissive_ingress.json" 2>&1); then
    fail "an unsupported permissive-ingress request was accepted: $OUTPUT"
fi
echo "$OUTPUT"
grep -Fq network.ingress.default <<<"$OUTPUT" || fail "the refusal did not identify the requested ingress field."
grep -Fq "not yet implemented" <<<"$OUTPUT" || fail "the unsupported ingress request was not explicitly refused."
if grep -Fq this-should-never-run <<<"$OUTPUT"; then
    fail "the workload ran despite the unsupported ingress request."
fi
[ "$(iptables-save | sed '/^#/d')" = "$BEFORE_V4" ] || fail "ingress validation leaked IPv4 host rules."
[ "$(ip6tables-save | sed '/^#/d')" = "$BEFORE_V6" ] || fail "ingress validation leaked IPv6 host rules."
[ "$(nft -s list ruleset)" = "$BEFORE_NFT" ] || fail "ingress validation leaked nftables host rules."
echo "PASS: supported ingress requests ran, and unsupported ingress was refused without host rule leaks."
