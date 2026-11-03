#!/bin/bash

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_DIR="$(dirname "$(dirname "$SCRIPT_DIR")")"
LXC_EXEC="$REPO_DIR/src/target/release/lxc-exec"
if [ ! -f "$LXC_EXEC" ]; then
    LXC_EXEC="$REPO_DIR/src/target/debug/lxc-exec"
fi

fail()
{
    echo "FAIL: $1"
    exit 1
}

. "$SCRIPT_DIR/lib/lxc_peer_listener.sh"

[ "$(id -u)" -eq 0 ] || { echo "SKIP: requires root."; exit 77; }
for tool in python3 ip timeout lxc-create lxc-start lxc-stop lxc-attach lxc-destroy lxc-info iptables ip6tables; do
    command -v "$tool" >/dev/null 2>&1 || { echo "SKIP: $tool is not installed."; exit 77; }
done
[ -f "$LXC_EXEC" ] || { echo "SKIP: lxc-exec binary not built; run build.sh first."; exit 77; }

PEER_IP="$(ip -4 -o addr show dev lxcbr0 | awk '{split($4, address, "/"); print address[1]; exit}')"
[ -n "$PEER_IP" ] || fail "lxcbr0 has no IPv4 address for the local listeners."
CONTAINER="CLI-LXC-Net-Startup-$$"
LXC_STORAGE="/var/lib/lxc/mxc startup-$$"
WORK_DIR="$REPO_DIR/tests/.lxc-network-startup-$$"
ALLOWED_PID=""
DENIED_PID=""

cleanup()
{
    lxc-destroy -P "$LXC_STORAGE" -n "$CONTAINER" -f >/dev/null 2>&1 || true
    if [ -n "$ALLOWED_PID" ]; then
        kill "$ALLOWED_PID" >/dev/null 2>&1 || true
        wait "$ALLOWED_PID" 2>/dev/null || true
    fi
    if [ -n "$DENIED_PID" ]; then
        kill "$DENIED_PID" >/dev/null 2>&1 || true
        wait "$DENIED_PID" 2>/dev/null || true
    fi
    rm -rf -- "$WORK_DIR"
    rmdir -- "$LXC_STORAGE"
}
mkdir -- "$LXC_STORAGE" || fail "could not create the isolated LXC storage directory."
trap cleanup EXIT

mkdir "$WORK_DIR"
printf 'MXC_BOOT_OK\n' >"$WORK_DIR/probe"
python3 -m http.server 18864 --bind "$PEER_IP" --directory "$WORK_DIR" >"$WORK_DIR/allowed.log" 2>&1 &
ALLOWED_PID=$!
python3 -m http.server 18865 --bind "$PEER_IP" --directory "$WORK_DIR" >"$WORK_DIR/denied.log" 2>&1 &
DENIED_PID=$!
await_peer_tcp "$PEER_IP" 18864 || fail_unreachable_peer "allowed listener" "$PEER_IP:18864" "not ready" "$WORK_DIR/allowed.log"
await_peer_tcp "$PEER_IP" 18865 || fail_unreachable_peer "denied listener" "$PEER_IP:18865" "not ready" "$WORK_DIR/denied.log"

CONFIG="$(python3 - "$CONTAINER" "$PEER_IP" <<'PY'
import base64
import json
import shlex
import sys

container, peer = sys.argv[1:]
service = f"""#!/sbin/openrc-run
depend()
{{
    need networking
}}
start()
{{
    /bin/busybox wget -qO- -T 3 http://{peer}:18865/probe >/mxc-boot-denied 2>&1 || true
    /bin/busybox wget -qO- -T 3 http://{peer}:18864/probe >/mxc-boot-allowed 2>&1 || true
    echo done >/mxc-boot-done
}}
"""
setup = f"""set -eu
test -x /sbin/openrc-run
test "$(/bin/busybox wget -qO- -T 5 http://{peer}:18864/probe)" = MXC_BOOT_OK
address="$(/bin/busybox ip -4 addr show dev eth0 | awk '$1 == "inet" {{print $2; exit}}')"
test -n "$address"
cat >/etc/network/interfaces <<NETWORK
auto lo
iface lo inet loopback
auto eth0
iface eth0 inet static
    address $address
NETWORK
cat >/etc/init.d/mxc-network-startup <<'SERVICE'
{service}SERVICE
chmod 755 /etc/init.d/mxc-network-startup
rc-update add mxc-network-startup default
echo MXC_BOOT_STAGED
"""
request = {
    "version": "1.0.0",
    "containerId": container,
    "containment": "lxc",
    "process": {"commandLine": "sh -c " + shlex.quote(setup)},
    "lifecycle": {"destroyOnExit": False, "preservePolicy": True},
    "lxc": {"distribution": "alpine", "release": "3.23"},
    "network": {
        "egress": {
            "default": "deny",
            "allow": [{
                "to": [{"cidr": peer + "/32"}],
                "ports": [{"protocol": "tcp", "port": 18864}],
            }],
        },
    },
}
print(base64.b64encode(json.dumps(request).encode()).decode())
PY
)"

if ! LXC_PATH="$LXC_STORAGE" timeout 180 "$LXC_EXEC" --config-base64 "$CONFIG" >"$WORK_DIR/setup.log" 2>&1; then
    cat "$WORK_DIR/setup.log"
    fail "MXC could not create the container and stage its boot service."
fi
grep -Fq MXC_BOOT_STAGED "$WORK_DIR/setup.log" || { cat "$WORK_DIR/setup.log"; fail "the Alpine boot service was not staged."; }

timeout 60 lxc-stop -P "$LXC_STORAGE" -n "$CONTAINER" || fail "could not stop the MXC-created container."
: >"$WORK_DIR/allowed.log"
: >"$WORK_DIR/denied.log"
timeout 60 lxc-start -P "$LXC_STORAGE" -n "$CONTAINER" -d || fail "ordinary lxc-start could not restart the container."

for ((attempt = 0; attempt < 60; attempt++)); do
    if timeout 3 lxc-attach -P "$LXC_STORAGE" -n "$CONTAINER" -- test -f /mxc-boot-done >/dev/null 2>&1; then
        break
    fi
    sleep 1
done
timeout 5 lxc-attach -P "$LXC_STORAGE" -n "$CONTAINER" -- test -f /mxc-boot-done || fail "the OpenRC boot service did not complete."

ALLOWED="$(timeout 5 lxc-attach -P "$LXC_STORAGE" -n "$CONTAINER" -- cat /mxc-boot-allowed)"
if [ "$ALLOWED" != MXC_BOOT_OK ]; then
    printf '%s\n' "$ALLOWED"
    fail "the boot service could not reach the permitted endpoint."
fi
grep -Fq 'GET /probe ' "$WORK_DIR/allowed.log" || fail "the permitted listener recorded no boot-service request."
peer_listener_running "$DENIED_PID" || { cat "$WORK_DIR/denied.log"; fail "the prohibited endpoint listener exited."; }
if grep -Fq 'GET /probe ' "$WORK_DIR/denied.log"; then
    cat "$WORK_DIR/denied.log"
    fail "the init-started service reached the prohibited endpoint after ordinary lxc-start."
fi

ROOTFS="$LXC_STORAGE/$CONTAINER/rootfs"
[ -d "$ROOTFS" ] || fail "expected the standard LXC directory rootfs at '$ROOTFS'; cannot inspect the boot marker."
[ -f "$ROOTFS/mxc-boot-done" ] || fail "the completed boot marker is not visible in the standard LXC directory rootfs '$ROOTFS'."
timeout 5 lxc-attach -P "$LXC_STORAGE" -n "$CONTAINER" -- rm /mxc-boot-done || fail "could not clear the completed boot marker."
timeout 60 lxc-stop -P "$LXC_STORAGE" -n "$CONTAINER" || fail "could not stop the container before the firewall-failure restart."
[ ! -e "$ROOTFS/mxc-boot-done" ] || fail "the boot marker was not cleared before the firewall-failure restart."

FAILING_BIN="$WORK_DIR/failing-bin"
mkdir "$FAILING_BIN"
cat >"$FAILING_BIN/iptables" <<'SH'
#!/bin/sh
printf 'called\n' >"$0.called"
exit 1
SH
chmod 755 "$FAILING_BIN/iptables"
if PATH="$FAILING_BIN:$PATH" timeout 60 lxc-start -P "$LXC_STORAGE" -n "$CONTAINER" -d; then
    fail "ordinary lxc-start succeeded despite a failing firewall command."
else
    START_STATUS=$?
fi
[ "$START_STATUS" -ne 124 ] || fail "ordinary lxc-start timed out instead of refusing the failed firewall command."
[ -f "$FAILING_BIN/iptables.called" ] || fail "the failing firewall executable was never invoked."
STATE="$(timeout 5 lxc-info -P "$LXC_STORAGE" -n "$CONTAINER" -sH)" || fail "could not inspect the container after the refused start."
[ "$STATE" = STOPPED ] || fail "the container is '$STATE' after the failed firewall command; expected STOPPED."
[ ! -e "$ROOTFS/mxc-boot-done" ] || fail "the init service completed despite the failed firewall command."

echo "PASS: ordinary restarts enforce the policy from a quoted storage path and refuse startup when the firewall fails."
