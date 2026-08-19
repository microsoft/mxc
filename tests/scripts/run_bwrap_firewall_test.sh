#!/bin/bash
# Bubblewrap firewall-enforcement tests (schema 0.8+).
#
# These tests do NOT require root: enforcement runs inside the sandbox's own
# network namespace, where the supervisor holds CAP_NET_ADMIN through an
# unprivileged user namespace.
#
# The point of this file is that the rules are *enforced*, not merely emitted.
# Pre-0.8 firewall mode builds a host chain the sandbox never traverses, so a
# test that only checked "the run succeeded" passed against a sandbox with no
# filtering at all. Every case here therefore asserts a destination that must
# be reachable and one that must not.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_DIR="$(dirname "$(dirname "$SCRIPT_DIR")")"
# An explicitly set LXC_EXEC is taken literally: falling back from it would
# silently exercise a different binary than the caller named.
if [ -n "${LXC_EXEC:-}" ]; then
    if [ ! -f "$LXC_EXEC" ]; then
        echo "Error: LXC_EXEC is set to '$LXC_EXEC', which does not exist."
        exit 1
    fi
else
    LXC_EXEC="$REPO_DIR/src/target/release/lxc-exec"
    if [ ! -f "$LXC_EXEC" ]; then
        LXC_EXEC="$REPO_DIR/src/target/debug/lxc-exec"
    fi
    if [ ! -f "$LXC_EXEC" ]; then
        echo "Error: lxc-exec not found. Run build.sh first."
        exit 1
    fi
fi

if ! command -v slirp4netns >/dev/null 2>&1; then
    echo "SKIP: slirp4netns not installed; firewall enforcement needs the private namespace."
    exit 0
fi

# A host-side listener stands in for "a destination the policy allows". It is
# reached at slirp's gateway (10.0.2.2), which maps back to the host's
# loopback -- the same translation proxy mode relies on. Using a local listener
# rather than an internet address keeps the allowed direction deterministic on
# a runner with no outbound access, where an internet probe would fail for
# reasons that have nothing to do with the policy.
TEST_PROXY="$(dirname "$LXC_EXEC")/unix-test-proxy"
if [ ! -x "$TEST_PROXY" ]; then
    TEST_PROXY="$REPO_DIR/src/target/release/unix-test-proxy"
fi
if [ ! -x "$TEST_PROXY" ]; then
    TEST_PROXY="$REPO_DIR/src/target/debug/unix-test-proxy"
fi
if [ ! -x "$TEST_PROXY" ]; then
    echo "FAIL: unix-test-proxy not built."
    exit 1
fi

WORK_DIR="$(mktemp -d)"
LISTENER_PID=""
cleanup() {
    if [ -n "$LISTENER_PID" ]; then
        kill "$LISTENER_PID" 2>/dev/null || true
        wait "$LISTENER_PID" 2>/dev/null || true
    fi
    exec 9>&- 2>/dev/null || true
    rm -rf "$WORK_DIR"
}
trap cleanup EXIT

# The listener exits when its stdin reaches EOF; the fifo is opened read-write
# so the open does not block and the script holding it keeps the listener up.
mkfifo "$WORK_DIR/parent.pipe"
exec 9<>"$WORK_DIR/parent.pipe"
"$TEST_PROXY" --ready-file "$WORK_DIR/ready.port" --bind-address 127.0.0.1 \
    <"$WORK_DIR/parent.pipe" >"$WORK_DIR/listener.log" 2>&1 &
LISTENER_PID=$!
for _ in $(seq 1 100); do
    [ -s "$WORK_DIR/ready.port" ] && break
    if ! kill -0 "$LISTENER_PID" 2>/dev/null; then
        cat "$WORK_DIR/listener.log"
        echo "FAIL: the host listener exited before publishing its port."
        exit 1
    fi
    sleep 0.1
done
ALLOWED_PORT="$(cat "$WORK_DIR/ready.port" 2>/dev/null || true)"
if [ -z "$ALLOWED_PORT" ]; then
    cat "$WORK_DIR/listener.log"
    echo "FAIL: the host listener did not publish a port."
    exit 1
fi
echo "  host listener is on 127.0.0.1:$ALLOWED_PORT (10.0.2.2:$ALLOWED_PORT from the sandbox)"

HOST_NETNS="$(readlink /proc/self/ns/net)"

# A drop is only evidence of enforcement if the same destination would have
# been reachable without the rule. On a runner with no outbound access every
# "blocked" assertion below would pass while filtering nothing, so establish
# reachability first and skip rather than report a false green.
PROBE_CONFIG="$WORK_DIR/reachability_probe.json"
cat >"$PROBE_CONFIG" <<'PROBE'
{
  "version": "0.8.0-alpha",
  "containerId": "CLI-Bubblewrap-Firewall-Reachability-Probe",
  "containment": "bubblewrap",
  "process": {
    "commandLine": "bash -c 'timeout 8 bash -c \"exec 3<>/dev/tcp/1.1.1.1/443\" >/dev/null 2>&1 && echo DENY_TARGET_REACHABLE'"
  },
  "network": {
    "defaultPolicy": "allow",
    "enforcementMode": "firewall",
    "allowedHosts": ["1.1.1.0/24"]
  }
}
PROBE
PROBE_OUT=$("$LXC_EXEC" --experimental --allow-testing-features "$PROBE_CONFIG" 2>&1) || true
if ! grep -q DENY_TARGET_REACHABLE <<<"$PROBE_OUT"; then
    echo "SKIP: 1.1.1.1:443 is not reachable from an unfiltered sandbox on this host."
    echo "      The deny assertions would pass without proving anything."
    exit 0
fi
echo "  1.1.1.1:443 is reachable when allowed, so a drop is real evidence"

run_enforced() {
    local label="$1"
    local config="$2"
    shift 2
    echo "Running Bubblewrap firewall test: $label..."
    sed -e "s/{{ALLOWED_PORT}}/$ALLOWED_PORT/g" \
        "$REPO_DIR/tests/configs/$config" >"$WORK_DIR/$config"
    local out
    if ! out=$("$LXC_EXEC" --experimental --allow-testing-features "$WORK_DIR/$config" 2>&1); then
        echo "$out"
        echo "FAIL: $label (lxc-exec returned non-zero)"
        exit 1
    fi
    local sentinel
    for sentinel in "$@"; do
        if ! grep -q "$sentinel" <<<"$out"; then
            echo "$out"
            echo "FAIL: $label (sentinel '$sentinel' not found in output)"
            exit 1
        fi
    done
    echo "$out" >"$WORK_DIR/$label.out"
    echo "PASS: $label"
}

# Enforcement only happens inside the sandbox's own namespace, so a run that
# shared the host's would pass every reachability assertion while filtering
# nothing. Checked first for that reason.
run_enforced "cidr allowlist" "bubblewrap_network_firewall_cidr.json" \
    ALLOWED_DEST_OK DENIED_DEST_BLOCKED_OK LOOPBACK_EXEMPT_OK \
    CAP_NET_ADMIN_DROPPED_OK TAMPER_REFUSED_OK TAMPER_INEFFECTIVE_OK
SANDBOX_NETNS="$(sed -n 's/^SANDBOX_NETNS=//p' "$WORK_DIR/cidr allowlist.out" | tail -n 1)"
if [ -z "$SANDBOX_NETNS" ] || [ "$SANDBOX_NETNS" = "$HOST_NETNS" ]; then
    echo "FAIL: cidr allowlist (sandbox did not get a private network namespace)"
    exit 1
fi
echo "PASS: firewall mode runs in a private network namespace"

# D4: an explicit deny outranks a broader allow. The allowlist here contains
# the denied address, so a chain that appended the allow first would let it
# through.
run_enforced "denylist deny-wins" "bubblewrap_network_firewall_denylist.json" \
    OPEN_TERMINAL_OK DENY_WINS_OK

# D3: rule addresses are literals and CIDRs. A name is refused rather than
# resolved on the caller's behalf, because the sandbox resolves DNS itself and
# could be handed an address the chain never authorized.
echo "Running Bubblewrap firewall test: hostname rule address rejected..."
NAME_OUT=$("$LXC_EXEC" --experimental --allow-testing-features \
    "$REPO_DIR/tests/configs/bubblewrap_network_firewall_hostname_rejected.json" 2>&1) \
    && NAME_RC=0 || NAME_RC=$?
if [ "$NAME_RC" = 0 ]; then
    echo "$NAME_OUT"
    echo "FAIL: hostname rule address (accepted a policy it cannot enforce)"
    exit 1
fi
if grep -q FIREWALL_HOSTNAME_RAN <<<"$NAME_OUT"; then
    echo "$NAME_OUT"
    echo "FAIL: hostname rule address (workload ran despite the rejection)"
    exit 1
fi
if ! grep -qF "not an IP address or CIDR" <<<"$NAME_OUT"; then
    echo "$NAME_OUT"
    echo "FAIL: hostname rule address (rejection did not explain the contract)"
    exit 1
fi
echo "PASS: hostname rule address rejected"

# Schema <= 0.7 must be untouched. Those callers pass hostnames by construction
# and run today against a host chain that filters nothing; the 0.8 work must
# neither reject them nor change what they get. This asserts the compatibility
# promise, not that the legacy path is secure -- it is not, which is why the
# enforcing behavior is 0.8-only.
echo "Running Bubblewrap firewall test: schema 0.7 is unchanged..."
LEGACY_OUT=$("$LXC_EXEC" --experimental --allow-testing-features \
    "$REPO_DIR/tests/configs/bubblewrap_network_firewall.json" 2>&1) || true
if grep -qF "not an IP address or CIDR" <<<"$LEGACY_OUT"; then
    echo "$LEGACY_OUT"
    echo "FAIL: schema 0.7 (inherited the 0.8 rule-address rejection)"
    exit 1
fi
echo "PASS: schema 0.7 is unchanged"

cleanup
trap - EXIT
echo "Bubblewrap firewall enforcement tests complete."
