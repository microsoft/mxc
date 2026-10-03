#!/bin/bash
# LXC invalid CIDR request-parsing test
#
# Invalid CIDRs are rejected during request parsing without installing a chain.
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

[ -f "$LXC_EXEC" ] || skip "lxc-exec binary not built; run build.sh first."

CONFIG="$REPO_DIR/tests/configs/lxc_network_invalid_cidr.json"
command -v python3 >/dev/null 2>&1 || skip "python3 is not installed."
[ "$(id -u)" -eq 0 ] || skip "requires root to verify no firewall chains were installed."
command -v iptables >/dev/null 2>&1 || skip "iptables is not installed."
command -v ip6tables >/dev/null 2>&1 || skip "ip6tables is not installed."

fail() {
    echo "FAIL: $1"
    exit 1
}

# shellcheck source=lib/chain_name.sh
. "$SCRIPT_DIR/lib/chain_name.sh"

python3 - "$CONFIG" <<'PY' || fail "invalid CIDR fixtures drifted."
import json, sys
rules = json.load(open(sys.argv[1]))["network"]["egress"]["allow"]
assert [rule["to"][0]["cidr"] for rule in rules] == [
    "140.82.112.0/33", "2606:50c0::/129", "140.82.112.0/not-a-prefix"
]
PY

echo "Running LXC invalid CIDR rejection test..."
for index in 0 1 2; do
    # The parser fails on the first invalid rule, so remove earlier rules in
    # memory to exercise each invalid prefix independently.
    encoded="$(python3 - "$CONFIG" "$index" <<'PY'
import base64, json, sys
data = json.load(open(sys.argv[1]))
data["network"]["egress"]["allow"] = data["network"]["egress"]["allow"][int(sys.argv[2]):]
print(base64.b64encode(json.dumps(data).encode()).decode())
PY
)" || fail "could not build invalid CIDR case $index."
    before_v4="$(mxc_chains iptables)" || fail "could not snapshot IPv4 MXC chains."
    before_v6="$(mxc_chains ip6tables)" || fail "could not snapshot IPv6 MXC chains."
    set +e
    output="$("$LXC_EXEC" --config-base64 "$encoded" 2>&1)"
    status=$?
    set -e
    [ "$status" -ne 0 ] || fail "invalid CIDR case $index was accepted."
    grep -Fq "network.egress.allow[0].to[0].cidr must be a valid network CIDR" <<<"$output" \
        || fail "invalid CIDR case $index failed for the wrong reason: $output"
    after_v4="$(mxc_chains iptables)" || fail "could not enumerate IPv4 MXC chains after rejection."
    after_v6="$(mxc_chains ip6tables)" || fail "could not enumerate IPv6 MXC chains after rejection."
    [ "$after_v4" = "$before_v4" ] || fail "invalid CIDR case $index left a new IPv4 MXC chain."
    [ "$after_v6" = "$before_v6" ] || fail "invalid CIDR case $index left a new IPv6 MXC chain."
done
echo "PASS: all three invalid CIDRs were rejected without leaving firewall chains."
