#!/bin/bash
# Bubblewrap firewall + host-rules regression guard.
#
# This is the "does Bubblewrap still work without a veth?" half of the item-1
# fix on PR #632. LXC scopes its iptables hooks to a container veth; Bubblewrap
# runs in the host network namespace and has none. An earlier revision made
# `NetworkIptablesManager::apply_firewall_rules` reject a missing veth
# unconditionally, which made every Bubblewrap request carrying firewall host
# rules fail before `bwrap` ever started (Copilot review #4822821372). The fix
# moved the veth requirement into the LXC runner and let the shared manager
# build the policy chain and skip the veth-scoped hooks when no veth is set.
#
# bubblewrap_network_firewall.json is the only config that exercises that path:
# `needs_iptables_rules` (bwrap_runner.rs:482-493) is true only for
# enforcementMode firewall/both *and* a non-empty allowed/blocked host list, and
# the proxy must be inactive (bwrap_runner.rs:193). With those set and no veth,
# a regression re-surfaces as `Bubblewrap: network policy error: ...` before the
# process runs.
#
# Cause  : the fixture above (firewall enforcement + allowed/blocked hosts, no
#          proxy) driven through the Bubblewrap backend.
# Effect : the container's process actually runs — it prints BWRAP_FW_STARTED —
#          and no firewall-application error is emitted. If the veth rejection
#          came back, the run would error out before the echo and the guard
#          fails.
#
# Requires Linux, root, bwrap, and iptables, so it cannot run on the Windows dev
# box and no CI job invokes the Bubblewrap suite. Treat it as unproven until run
# on a Linux host.
set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_DIR="$(dirname "$(dirname "$SCRIPT_DIR")")"
CONFIG="$REPO_DIR/tests/configs/bubblewrap_network_firewall.json"

fail() {
    echo "FAIL: $*"
    exit 1
}

# ---------------------------------------------------------------------------
# Always-run drift guard (offline-safe): the fixture must still describe the
# exact posture that reaches apply_firewall_rules with no veth — firewall
# enforcement, at least one host rule, and no proxy. If someone softens it, this
# guard stops silently testing nothing.
# ---------------------------------------------------------------------------
[ -f "$CONFIG" ] || fail "fixture not found: $CONFIG"

if command -v python3 >/dev/null 2>&1; then
    python3 - "$CONFIG" <<'PY' || exit 1
import json, sys
net = json.load(open(sys.argv[1])).get("network", {})
if net.get("enforcementMode") != "firewall":
    print("FAIL: fixture enforcementMode is not 'firewall'; it would skip iptables")
    sys.exit(1)
if not (net.get("allowedHosts") or net.get("blockedHosts")):
    print("FAIL: fixture has no allowed/blocked hosts; needs_iptables_rules would be false")
    sys.exit(1)
if net.get("proxy"):
    print("FAIL: fixture configures a proxy; Bubblewrap would skip iptables entirely")
    sys.exit(1)
print("Fixture drift guard passed (firewall + host rules + no proxy).")
PY
else
    grep -q '"enforcementMode"[[:space:]]*:[[:space:]]*"firewall"' "$CONFIG" \
        || fail "fixture enforcementMode is not 'firewall'"
    grep -Eq '"(allowedHosts|blockedHosts)"' "$CONFIG" \
        || fail "fixture has no allowed/blocked hosts"
    grep -q '"proxy"' "$CONFIG" \
        && fail "fixture configures a proxy; Bubblewrap would skip iptables"
    echo "Fixture drift guard passed (firewall + host rules + no proxy)."
fi

# ---------------------------------------------------------------------------
# Conditional live run: skip loudly when a prerequisite is missing so a skip
# never reads as a pass. Exit 77 is the Automake convention for "skipped";
# run_bwrap_all_tests.sh counts it separately and never as a pass. Exiting 0
# here would make a host without root, bwrap, or iptables report this test as
# passing while none of the live behaviour ran.
# ---------------------------------------------------------------------------
SKIP_EXIT=77

skip_live() {
    echo "SKIP: Bubblewrap no-veth firewall behaviour UNVERIFIED — $*"
    echo "      (fixture drift guard still ran and passed)"
    exit "$SKIP_EXIT"
}

LXC_EXEC="$REPO_DIR/src/target/release/lxc-exec"
[ -f "$LXC_EXEC" ] || LXC_EXEC="$REPO_DIR/src/target/debug/lxc-exec"
[ -f "$LXC_EXEC" ] || skip_live "lxc-exec not built (run build.sh first)"

[ "$(id -u)" -eq 0 ] || skip_live "not root; iptables rules need root"
command -v bwrap >/dev/null 2>&1 || skip_live "bwrap not installed"
command -v iptables >/dev/null 2>&1 || skip_live "iptables not installed"

echo "Running Bubblewrap firewall regression guard..."
OUT=$("$LXC_EXEC" --experimental "$CONFIG" 2>&1 || true)
echo "$OUT"

# The regression signature: apply_firewall_rules rejects the missing veth and
# the backend surfaces it as this error before the process runs.
if grep -qi "network policy error" <<<"$OUT"; then
    fail "Bubblewrap firewall setup errored (veth rejection regression?): saw 'network policy error'"
fi
if grep -qi "Refusing to start with an unenforceable network policy" <<<"$OUT"; then
    fail "Bubblewrap refused to start over a missing veth — the item-1 regression is back"
fi

# The process must actually have run. BWRAP_FW_STARTED is printed by the
# container command before it touches the network, so it proves the firewall
# step returned Ok and bwrap launched, independent of external connectivity.
grep -q "BWRAP_FW_STARTED" <<<"$OUT" \
    || fail "container process did not run (no BWRAP_FW_STARTED); firewall step aborted the launch"

echo "PASS: Bubblewrap applied firewall host rules without a veth and ran the process."
echo "Bubblewrap firewall regression guard complete."
