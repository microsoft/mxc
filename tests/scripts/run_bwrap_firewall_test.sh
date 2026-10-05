#!/bin/bash
# Bubblewrap directional firewall enforcement and fail-closed rule validation.
# Rejections run without a network namespace; live enforcement needs slirp4netns
# and two reachable anchors, or exits 77 rather than claiming a false pass.
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

echo "Running Bubblewrap firewall test: hostname rule address rejected..."
NAME_RC=0
NAME_OUT=$("$LXC_EXEC" --experimental --allow-testing-features \
    "$REPO_DIR/tests/configs/bubblewrap_network_firewall_hostname_rejected.json" 2>&1) \
    || NAME_RC=$?
if [ "$NAME_RC" -eq 0 ] ||
    ! grep -qF "must be a valid network CIDR" <<<"$NAME_OUT" ||
    grep -qF "FIREWALL_HOSTNAME_RAN" <<<"$NAME_OUT"; then
    echo "$NAME_OUT"
    echo "FAIL: hostname rule address was not rejected before execution."
    exit 1
fi
echo "PASS: hostname rule address rejected"

if ! command -v slirp4netns >/dev/null 2>&1; then
    echo "SKIP: slirp4netns not installed; firewall enforcement needs the private namespace."
    exit 77
fi

HOST_NETNS="$(readlink /proc/self/ns/net)"
WORK_DIR="$(mktemp -d)"
trap 'rm -rf "$WORK_DIR"' EXIT

# A deny is evidence of filtering only if that destination can be reached
# without the rule. The ruleless directional allow posture establishes both
# anchors in a private namespace without relying on the policy under test.
cat >"$WORK_DIR/reachability_probe.json" <<'PROBE'
{
  "version": "1.0.0",
  "containerId": "CLI-Bubblewrap-Firewall-Reachability-Probe",
  "containment": "bubblewrap",
  "process": {
    "commandLine": "bash -c 'echo PROBE_WORKLOAD_STARTED; echo SANDBOX_NETNS=$(readlink /proc/self/ns/net); timeout 8 bash -c \"exec 3<>/dev/tcp/1.1.1.1/443\" >/dev/null 2>&1 && echo DENY_TARGET_REACHABLE; timeout 8 bash -c \"exec 3<>/dev/tcp/9.9.9.9/443\" >/dev/null 2>&1 && echo ALLOW_TARGET_REACHABLE; exit 0'"
  },
  "network": {
    "egress": { "default": "allow" },
    "ingress": { "default": "deny", "hostLoopback": "deny" }
  }
}
PROBE
PROBE_RC=0
PROBE_OUT=$("$LXC_EXEC" --experimental --allow-testing-features \
    "$WORK_DIR/reachability_probe.json" 2>&1) || PROBE_RC=$?
if [ "$PROBE_RC" -ne 0 ] || ! grep -qF "PROBE_WORKLOAD_STARTED" <<<"$PROBE_OUT"; then
    echo "$PROBE_OUT"
    echo "FAIL: the reachability probe did not execute (exit $PROBE_RC)."
    exit 1
fi
PROBE_NETNS="$(sed -n 's/^SANDBOX_NETNS=//p' <<<"$PROBE_OUT" | tail -n 1)"
if [ -z "$PROBE_NETNS" ] || [ "$PROBE_NETNS" = "$HOST_NETNS" ]; then
    echo "$PROBE_OUT"
    echo "FAIL: the reachability probe did not use a private network namespace."
    exit 1
fi
for anchor in "DENY_TARGET_REACHABLE:1.1.1.1" "ALLOW_TARGET_REACHABLE:9.9.9.9"; do
    marker="${anchor%%:*}"
    address="${anchor#*:}"
    if ! grep -qF "$marker" <<<"$PROBE_OUT"; then
        if timeout 8 bash -c "exec 3<>/dev/tcp/$address/443" >/dev/null 2>&1; then
            echo "$PROBE_OUT"
            echo "FAIL: $address:443 is reachable from the host, but not from an open sandbox."
            exit 1
        fi
        echo "SKIP: $address:443 is unreachable from the host; enforcement cannot be proven."
        exit 77
    fi
done

echo "Running Bubblewrap firewall test: CIDR allow, deny-wins, and tamper resistance..."
FIREWALL_RC=0
FIREWALL_OUT=$("$LXC_EXEC" --experimental --allow-testing-features \
    "$REPO_DIR/tests/configs/bubblewrap_network_firewall.json" 2>&1) || FIREWALL_RC=$?
if [ "$FIREWALL_RC" -ne 0 ]; then
    echo "$FIREWALL_OUT"
    echo "FAIL: firewall sandbox exited $FIREWALL_RC."
    exit 1
fi
for marker in ALLOWED_DEST_OK DENY_WINS_OK CAP_NET_ADMIN_DROPPED_OK \
    TAMPER_REFUSED_OK TAMPER_INEFFECTIVE_OK; do
    if ! grep -qF "$marker" <<<"$FIREWALL_OUT"; then
        echo "$FIREWALL_OUT"
        echo "FAIL: firewall workload did not report $marker."
        exit 1
    fi
done
SANDBOX_NETNS="$(sed -n 's/^SANDBOX_NETNS=//p' <<<"$FIREWALL_OUT" | tail -n 1)"
if [ -z "$SANDBOX_NETNS" ] || [ "$SANDBOX_NETNS" = "$HOST_NETNS" ]; then
    echo "$FIREWALL_OUT"
    echo "FAIL: firewall sandbox did not get a private network namespace."
    exit 1
fi
echo "PASS: directional firewall enforces CIDR allow, deny precedence, and tamper resistance"
