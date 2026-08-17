#!/bin/bash
# Chain-name helpers shared by the LXC network scripts.
#
# The chain name is a digest of the container name, so a script that hard-codes
# one names a chain that cannot exist: `iptables -S <that name>` always fails, a
# cleanup check reads that failure as "the chain is gone", and the assertion
# passes without inspecting anything. Deriving the name from the run's own
# output is what keeps those assertions real.
#
# The derivation lives here rather than in each script because nothing in bash
# ties copies to each other: a change to the hash width would leave a stale
# pattern behind in every script that was not edited by hand.
#
# The sourcing script must define `fail`.

MXC_CHAIN_NAME_ERE='^MXC-([A-Za-z0-9_-]{1,7}-)?[a-z2-7]{16}$'

# iptables rejects a chain name longer than this.
MXC_CHAIN_NAME_MAX=28

# List the MXC-owned chains a tool currently holds. Matching the prefix rather
# than a name stays correct across naming changes.
mxc_chains() {
    "$1" -S 2>/dev/null | sed -n 's/^-N \(MXC-.*\)$/\1/p' | sort
}

# Set CHAIN_NAME from a run's debug output.
#
# Which of the two lines carrying the name a run emits depends on the policy it
# applied, so both are read. Every assertion that names a chain depends on this
# having succeeded, so an unparsed or misshapen name fails here instead of
# quietly reducing those assertions to no-ops.
derive_chain_name() {
    local output="$1"

    CHAIN_NAME="$(sed -n 's/^.*Creating iptables\/ip6tables chain: \([^ ]*\).*$/\1/p' <<<"$output" | head -n 1)"
    if [ -z "$CHAIN_NAME" ]; then
        CHAIN_NAME="$(sed -n 's/^.*Programmed [a-z0-9]* rule: -A \([^ ]*\) .*$/\1/p' <<<"$output" | head -n 1)"
    fi

    if [ -z "$CHAIN_NAME" ]; then
        fail "no chain name was logged, so the chain name could not be determined."
    fi
    if ! grep -Eq "$MXC_CHAIN_NAME_ERE" <<<"$CHAIN_NAME"; then
        fail "chain name '$CHAIN_NAME' does not match the documented MXC-<slug>-<hash> shape."
    fi
    if [ "${#CHAIN_NAME}" -gt "$MXC_CHAIN_NAME_MAX" ]; then
        fail "chain name '$CHAIN_NAME' exceeds the $MXC_CHAIN_NAME_MAX-character iptables ceiling."
    fi
}
