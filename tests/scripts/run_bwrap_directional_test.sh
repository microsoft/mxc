#!/bin/bash
# Bubblewrap directional network policy tests (schema 0.8 `network.egress` /
# `network.ingress`).
#
# Why this file exists separately from run_bwrap_firewall_test.sh: that suite
# drives the *legacy* fields (defaultPolicy/enforcementMode/allowedHosts). The
# directional schema is a different parse path that fills different policy
# fields, and the backend picks its network mode from them. A regression in one
# path is invisible to the other.
#
# The bug this suite is designed to catch: the mode resolver originally
# classified from the legacy fields alone. Those are left at their defaults on
# the directional path, so a rule-bearing policy read as "block, no host rules",
# resolved to the isolated (`--unshare-net`) mode, and the requested rules were
# programmed nowhere. The sandbox was offline rather than filtered, so nothing
# leaked -- but nothing was enforced either, and every unit test still passed
# because they call the plan builder directly and never cross the mode-selection
# seam. Only a live run reaches it, which is what the allow assertions below do:
# under that bug ALLOWED_DEST_OK is unreachable and this suite fails.
#
# Split by prerequisite, strongest-guarantee-first:
#   1. Rejections. These resolve during validation, ahead of the bwrap probe,
#      so they run on any host -- no bwrap, no slirp4netns, no privilege.
#   2. Enforcement. Needs slirp4netns and a destination that is genuinely
#      reachable when allowed; skips (77) rather than false-greens without them.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_DIR="$(dirname "$(dirname "$SCRIPT_DIR")")"

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

HOST_NETNS="$(readlink /proc/self/ns/net)"

# ---------------------------------------------------------------------------
# 1. Rejections
# ---------------------------------------------------------------------------
#
# Each asserts the run failed AND that the workload never started. Checking
# only the exit code would pass against a sandbox that ran the command and
# failed afterwards for an unrelated reason, which is precisely the failure a
# policy rejection must not be confused with.
run_rejected() {
    local label="$1"
    local config="$2"
    local marker="$3"
    local sentinel="$4"
    echo "Running Bubblewrap directional test: $label..."
    local out rc=0
    out=$("$LXC_EXEC" --experimental "$REPO_DIR/tests/configs/$config" 2>&1) || rc=$?
    if [ "$rc" = 0 ]; then
        echo "$out"
        echo "FAIL: $label (the config was accepted)"
        exit 1
    fi
    if grep -qF "$sentinel" <<<"$out"; then
        echo "$out"
        echo "FAIL: $label (the workload ran before the config was refused)"
        exit 1
    fi
    if ! grep -qF "$marker" <<<"$out"; then
        echo "$out"
        echo "FAIL: $label (refused, but not for the expected reason: '$marker')"
        exit 1
    fi
    echo "PASS: $label"
}

# Slirp offers no route into the namespace and the schema carries no port list
# to forward one, so an inbound-accepting posture cannot be honored.
run_rejected "ingress.default=allow is refused" \
    "bubblewrap_network_directional_ingress_allow_rejected.json" \
    "network.ingress.default='allow' is not supported" \
    "DIRECTIONAL_INGRESS_ALLOW_SHOULD_NOT_RUN"

# The sandbox's loopback belongs to its own namespace, not the host's.
run_rejected "ingress.hostLoopback=allow is refused" \
    "bubblewrap_network_directional_hostloopback_allow_rejected.json" \
    "network.ingress.hostLoopback='allow' is not supported" \
    "DIRECTIONAL_HOST_LOOPBACK_ALLOW_SHOULD_NOT_RUN"

# A directional section on a pre-0.8 schema. The parser refuses this before the
# backend ever sees it (`select_network_format`), so the message asserted here
# is the parser's, not the backend's. The backend carries its own twin of this
# rejection for programmatic callers that build an `ExecutionRequest` directly
# and never pass through the parser; that path has no config file and so is
# covered by unit tests rather than here.
run_rejected "a directional section before 0.8 is refused" \
    "bubblewrap_network_directional_pre08_rejected.json" \
    "require schema version 0.8 or later" \
    "DIRECTIONAL_PRE_0_8_SHOULD_NOT_RUN"

# ---------------------------------------------------------------------------
# 2. Enforcement
# ---------------------------------------------------------------------------
if ! command -v slirp4netns >/dev/null 2>&1; then
    echo "SKIP: slirp4netns not installed; directional enforcement needs the private namespace."
    exit 77
fi

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
CONTROL_PID=""
cleanup() {
    if [ -n "$LISTENER_PID" ]; then
        kill "$LISTENER_PID" 2>/dev/null || true
        wait "$LISTENER_PID" 2>/dev/null || true
    fi
    if [ -n "$CONTROL_PID" ]; then
        kill "$CONTROL_PID" 2>/dev/null || true
        wait "$CONTROL_PID" 2>/dev/null || true
    fi
    exec 9>&- 2>/dev/null || true
    exec 8>&- 2>/dev/null || true
    rm -rf "$WORK_DIR"
}
trap cleanup EXIT

# A host-side listener, reached at slirp's gateway (10.0.2.2). This is *only*
# the proxy endpoint for the parity section below.
#
# It used to double as an "allowed destination", and those tests passed for the
# wrong reason: the gateway is the host's own loopback seen from the sandbox,
# and `ingress.hostLoopback` -- which defaults to deny -- governs that path in
# both directions. The allow assertions now use external anchors instead.
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
LISTENER_PORT="$(cat "$WORK_DIR/ready.port" 2>/dev/null || true)"
if [ -z "$LISTENER_PORT" ]; then
    cat "$WORK_DIR/listener.log"
    echo "FAIL: the host listener did not publish a port."
    exit 1
fi
echo "  host listener is on 127.0.0.1:$LISTENER_PORT (10.0.2.2:$LISTENER_PORT from the sandbox)"

# A second listener on a port the proxy policy does not allow. The parity
# workloads assert that direct egress is refused, which only proves
# enforcement against a destination that is otherwise live -- an internet
# address would be refused just as readily on a runner with no route out.
mkfifo "$WORK_DIR/control.pipe"
exec 8<>"$WORK_DIR/control.pipe"
# 8>&- keeps the listener from inheriting the write end: holding one itself
# would mean its stdin never reports EOF, orphaning it if this script is killed.
"$TEST_PROXY" --ready-file "$WORK_DIR/control.port" --bind-address 127.0.0.1 \
    <"$WORK_DIR/control.pipe" >"$WORK_DIR/control.log" 2>&1 8>&- &
CONTROL_PID=$!
for _ in $(seq 1 100); do
    [ -s "$WORK_DIR/control.port" ] && break
    if ! kill -0 "$CONTROL_PID" 2>/dev/null; then
        cat "$WORK_DIR/control.log"
        echo "FAIL: the control listener exited before publishing its port."
        exit 1
    fi
    sleep 0.1
done
CONTROL_PORT="$(cat "$WORK_DIR/control.port" 2>/dev/null || true)"
if [ -z "$CONTROL_PORT" ]; then
    cat "$WORK_DIR/control.log"
    echo "FAIL: the control listener did not publish a port."
    exit 1
fi
echo "  control listener is on 127.0.0.1:$CONTROL_PORT (10.0.2.2:$CONTROL_PORT from the sandbox)"

# The two external anchors the egress assertions are built on. An allow proves
# the rule fired only if the destination is otherwise reachable, and a deny
# proves enforcement only under the same condition -- hence two addresses, one
# to allow and one to deny, each probed unfiltered first.
ALLOW_ANCHOR="1.1.1.1"
DENY_ANCHOR="9.9.9.9"

# Probed through the legacy path, so the probe cannot be broken by the
# directional code it exists to measure. Skips rather than fails when an anchor
# is unreachable: the assertions would still pass, having proven nothing.
probe_anchor() {
    local address="$1"
    local port="$2"
    local subnet="$3"
    local config="$WORK_DIR/reachability_probe_${address}_${port}.json"

    cat >"$config" <<PROBE
{
  "version": "0.8.0-alpha",
  "containerId": "CLI-Bubblewrap-Directional-Reachability-Probe",
  "containment": "bubblewrap",
  "process": {
    "commandLine": "bash -c 'echo PROBE_WORKLOAD_STARTED; timeout 8 bash -c \"exec 3<>/dev/tcp/$address/$port\" >/dev/null 2>&1 && echo ANCHOR_REACHABLE; exit 0'"
  },
  "network": {
    "defaultPolicy": "allow",
    "enforcementMode": "firewall",
    "allowedHosts": ["$subnet"]
  }
}
PROBE

    local rc=0
    local out
    out="$("$LXC_EXEC" --experimental --allow-testing-features "$config" 2>&1)" || rc=$?
    if [ "$rc" -ne 0 ]; then
        echo "$out"
        echo "FAIL: reachability probe exited $rc; the enforcement path itself is broken."
        exit 1
    fi
    if ! grep -q PROBE_WORKLOAD_STARTED <<<"$out"; then
        echo "$out"
        echo "FAIL: reachability probe workload never ran (no start marker)."
        exit 1
    fi
    if ! grep -q ANCHOR_REACHABLE <<<"$out"; then
        echo "SKIP: $address:$port is not reachable from an unfiltered sandbox on this host."
        echo "      The assertions built on it would pass without proving anything."
        exit 77
    fi
    echo "  $address:$port is reachable when allowed, so a verdict on it is real evidence"
}

probe_anchor "$ALLOW_ANCHOR" 443 "1.1.1.0/24"
probe_anchor "$ALLOW_ANCHOR" 80 "1.1.1.0/24"
probe_anchor "$DENY_ANCHOR" 443 "9.9.9.0/24"

run_enforced() {
    local label="$1"
    local config="$2"
    shift 2
    echo "Running Bubblewrap directional test: $label..."
    sed -e "s/{{LISTENER_PORT}}/$LISTENER_PORT/g" \
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

# The headline case. ALLOWED_DEST_OK is what fails if directional rules are
# parsed but never programmed -- the sandbox would be offline, not filtered.
run_enforced "directional cidr allow" "bubblewrap_network_directional_cidr.json" \
    ALLOWED_DEST_OK DENIED_DEST_BLOCKED_OK HOST_LOOPBACK_BLOCKED_OK \
    LOOPBACK_EXEMPT_OK CAP_NET_ADMIN_DROPPED_OK

DIRECTIONAL_NETNS="$(sed -n 's/^SANDBOX_NETNS=//p' "$WORK_DIR/directional cidr allow.out" | tail -n 1)"
if [ "$DIRECTIONAL_NETNS" = "$HOST_NETNS" ]; then
    echo "FAIL: directional cidr allow ran in the host network namespace ($HOST_NETNS)"
    echo "      Rules programmed there are not traversed by the sandbox."
    exit 1
fi
echo "  the sandbox ran in its own network namespace ($DIRECTIONAL_NETNS)"

# `except` has no iptables primitive: the backend subtracts the excluded blocks
# from the peer and emits the remainder as separate rules. Unit tests check the
# arithmetic against ground truth; this checks the result actually filters, and
# that the surrounding space stayed open -- a subtraction that dropped too much
# would fail on INCLUDED_DEST_OK rather than silently over-blocking.
run_enforced "directional except carve-out" "bubblewrap_network_directional_except.json" \
    INCLUDED_DEST_OK EXCLUDED_DEST_BLOCKED_OK HOST_LOOPBACK_BLOCKED_OK

# A ruleless deny needs no chain: it degenerates to --unshare-net, where the
# absence of connectivity is the enforcement. Pinned because it is the one
# directional posture that is *supposed* to resolve to the isolated mode, and
# so the one case where the bug above would have looked correct.
run_enforced "directional ruleless deny" "bubblewrap_network_directional_block.json" \
    EGRESS_BLOCKED_OK

# No other directional config carries an IPv6 peer or an ICMP rule, so the real
# ip6tables-restore never sees a v6 address or the icmp -> icmpv6 token the v6
# table requires. Connectivity is not the point: a token or transaction the tool
# rejects fails namespace setup, so lxc-exec exits before the workload runs.
run_enforced "directional ipv6 and icmp rendering" \
    "bubblewrap_network_directional_ipv6_icmp.json" \
    V6_ICMP_RULES_INSTALLED_OK CAP_NET_ADMIN_DROPPED_OK

# Port narrowing: one address, two ports, only one allowed. Both ports are
# probed reachable above, so the denied one being closed is the rule working.
PORT_CONFIG="$WORK_DIR/directional_ports.json"
cat >"$PORT_CONFIG" <<PORTS
{
  "version": "0.8.0-alpha",
  "containerId": "CLI-Bubblewrap-Directional-Ports",
  "containment": "bubblewrap",
  "process": {
    "commandLine": "bash -c 'set -u; if ! timeout 8 bash -c \"exec 3<>/dev/tcp/$ALLOW_ANCHOR/443\" >/dev/null 2>&1; then echo ALLOWED_PORT_UNREACHABLE; exit 1; fi; echo ALLOWED_PORT_OK; timeout 8 bash -c \"exec 3<>/dev/tcp/$ALLOW_ANCHOR/80\" >/dev/null 2>&1; if [ \$? = 0 ]; then echo DENIED_PORT_LEAKED; exit 1; fi; echo DENIED_PORT_BLOCKED_OK'"
  },
  "network": {
    "egress": {
      "default": "deny",
      "allow": [
        {
          "to": [{ "cidr": "$ALLOW_ANCHOR/32" }],
          "ports": [{ "protocol": "tcp", "port": 443 }]
        }
      ]
    },
    "ingress": { "default": "deny", "hostLoopback": "deny" }
  }
}
PORTS
echo "Running Bubblewrap directional test: directional port narrowing..."
PORT_OUT=""
if ! PORT_OUT=$("$LXC_EXEC" --experimental --allow-testing-features "$PORT_CONFIG" 2>&1); then
    echo "$PORT_OUT"
    echo "FAIL: directional port narrowing (lxc-exec returned non-zero)"
    exit 1
fi
for sentinel in ALLOWED_PORT_OK DENIED_PORT_BLOCKED_OK; do
    if ! grep -q "$sentinel" <<<"$PORT_OUT"; then
        echo "$PORT_OUT"
        echo "FAIL: directional port narrowing (sentinel '$sentinel' not found)"
        exit 1
    fi
done
echo "PASS: directional port narrowing"

# ---------------------------------------------------------------------------
# 3. legacy <-> directional proxy spelling parity
# ---------------------------------------------------------------------------
# Declaring RUNTIME_PROXY only says shared validation lets the directional
# spelling through. What matters is that it lands on the same enforcement the
# legacy spelling already gets: the parser normalizes
# `runtimeConfig.networkProxy` into the same `policy.network_proxy`, so both
# should resolve to the identical proxy-only posture. Both are therefore run
# against the same workload and compared to each other rather than to a golden
# string, which keeps the check precise without pinning it to chain formatting.
#
# Both sides are 0.8 on purpose. The variable under test is the *spelling*, not
# the schema version: on 0.7 an external proxy resolves to the legacy shared-
# host-network mode, which does no egress filtering at all, so a 0.7 baseline
# would "fail" the direct-egress assertion by design and compare two different
# modes rather than two spellings of one.
#
# The test proxy already running on 127.0.0.1:$LISTENER_PORT doubles as the
# proxy here; the parser requires a loopback endpoint, and the backend
# translates it to slirp's gateway on the way in.
# Diagnostics go to stderr and the marks to a file, never to stdout through a
# command substitution: a `$(...)` capture would swallow the failure message
# and its `exit` would only leave the subshell, turning a real failure into a
# silent stop.
run_parity() {
    local label="$1"
    local config="$2"
    sed -e "s/{{PROXY_HOST}}/127.0.0.1/g" -e "s/{{PROXY_PORT}}/$LISTENER_PORT/g" \
        -e "s/{{CONTROL_PORT}}/$CONTROL_PORT/g" \
        "$REPO_DIR/tests/configs/$config" >"$WORK_DIR/$config"
    local out
    local rc=0
    out=$("$LXC_EXEC" --experimental --allow-testing-features "$WORK_DIR/$config" 2>&1) || rc=$?
    printf '%s\n' "$out" >"$WORK_DIR/$label.parity.out"
    if [ "$rc" -ne 0 ]; then
        printf '%s\n' "$out" >&2
        echo "FAIL: legacy/directional proxy parity ($label returned $rc)" >&2
        return 1
    fi
    grep -o 'PARITY_[A-Z_]*' <<<"$out" | sort -u >"$WORK_DIR/$label.marks"
}

echo "Running Bubblewrap directional test: legacy/directional proxy parity..."
run_parity "legacy-spelling" "bubblewrap_network_proxy_parity_legacy.json" || exit 1
run_parity "directional-spelling" "bubblewrap_network_directional_proxy.json" || exit 1
LEGACY_MARKS="$(cat "$WORK_DIR/legacy-spelling.marks")"
DIRECTIONAL_MARKS="$(cat "$WORK_DIR/directional-spelling.marks")"

# Anchored, not just compared: two spellings that are broken in the same way
# would agree with each other and prove nothing.
EXPECTED_MARKS="$(printf '%s\n' \
    PARITY_DIRECT_BLOCKED_OK \
    PARITY_PROXIED_FETCH_OK \
    PARITY_PROXY_ENV_OK \
    PARITY_PROXY_REACHABLE_OK | sort -u)"

if [ "$LEGACY_MARKS" != "$EXPECTED_MARKS" ]; then
    cat "$WORK_DIR/legacy-spelling.parity.out"
    echo "FAIL: the legacy proxy spelling did not reach the expected verdict."
    echo "  expected: $(tr '\n' ' ' <<<"$EXPECTED_MARKS")"
    echo "  actual:   $(tr '\n' ' ' <<<"$LEGACY_MARKS")"
    exit 1
fi
if [ "$DIRECTIONAL_MARKS" != "$LEGACY_MARKS" ]; then
    cat "$WORK_DIR/directional-spelling.parity.out"
    echo "FAIL: the directional spelling did not enforce what the legacy spelling enforces."
    echo "  legacy:      $(tr '\n' ' ' <<<"$LEGACY_MARKS")"
    echo "  directional: $(tr '\n' ' ' <<<"$DIRECTIONAL_MARKS")"
    exit 1
fi
echo "PASS: legacy/directional proxy parity"

echo "All Bubblewrap directional network tests passed."
