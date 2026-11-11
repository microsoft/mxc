#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_DIR="$(dirname "$(dirname "$SCRIPT_DIR")")"
if [ -z "${LXC_EXEC:-}" ]; then
    LXC_EXEC="$REPO_DIR/src/target/release/lxc-exec"
    [ -x "$LXC_EXEC" ] || LXC_EXEC="$REPO_DIR/src/target/debug/lxc-exec"
fi
if [ ! -x "$LXC_EXEC" ]; then
    echo "FAIL: lxc-exec not found; build it or set LXC_EXEC." >&2
    exit 1
fi
for tool in bwrap python3 slirp4netns unshare nsenter ip iptables ip6tables iptables-restore ip6tables-restore; do
    if ! command -v "$tool" >/dev/null 2>&1; then
        echo "SKIPPED: $tool is required for the Bubblewrap capability tests."
        exit 77
    fi
done

python3 - "$LXC_EXEC" <<'PY'
import ipaddress
import json
import os
from pathlib import Path
import shlex
import socket
import subprocess
import sys
import tempfile

workload = r'''
import ctypes
import errno
import os
from pathlib import Path
import socket
import subprocess
import sys

fixture = Path(sys.argv[1])
expected_uid, port = map(int, sys.argv[2:4])
mode, address = sys.argv[4:6]
assert os.getuid() == expected_uid, "capability removal must not change the workload UID"
status = dict(line.split(":", 1) for line in Path("/proc/self/status").read_text().splitlines())
for name in ("CapInh", "CapPrm", "CapEff", "CapBnd", "CapAmb"):
    assert int(status[name].strip(), 16) == 0, f"{mode}: {name} retained {status[name].strip()}"

SOCK_PACKET = 10
for family, kind, protocol in (
    (socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP),
    (socket.AF_PACKET, socket.SOCK_RAW, 0),
    (socket.AF_INET, SOCK_PACKET, 0),
):
    try:
        descriptor = socket.socket(family, kind, protocol)
    except OSError as error:
        assert error.errno == errno.EPERM, f"unexpected socket error: {error}"
    else:
        descriptor.close()
        raise AssertionError(f"privileged socket creation succeeded: {family}, {kind}")

assert (fixture / "sentinel").read_text() == "unchanged"
libc = ctypes.CDLL(None, use_errno=True)
libc.mount.argtypes = [ctypes.c_char_p, ctypes.c_char_p, ctypes.c_char_p,
                      ctypes.c_ulong, ctypes.c_void_p]
libc.mount.restype = ctypes.c_int
MS_REMOUNT, MS_BIND = 32, 4096
result = libc.mount(None, os.fsencode(fixture), None, MS_REMOUNT | MS_BIND, None)
assert result == -1 and ctypes.get_errno() == errno.EPERM, "read-only bind remount was not denied"
try:
    (fixture / "sentinel").write_text("changed")
except OSError as error:
    assert error.errno == errno.EROFS, f"unexpected read-only write error: {error}"
else:
    raise AssertionError("read-only fixture was writable")

if mode != "isolated":
    result = subprocess.run(["iptables", "-F", "MXC_EGRESS"], capture_output=True, text=True)
    assert result.returncode != 0, "workload flushed its egress firewall"
    with socket.create_connection((address, port), timeout=5):
        pass

print(f"CAPABILITIES_DROPPED_{mode}")
'''

failed = []
skipped = []
with tempfile.TemporaryDirectory(prefix="mxc-bwrap-capabilities-") as directory, \
        socket.socket() as proxy_listener, socket.socket() as firewall_listener:
    root = Path(directory)
    fixture = root / "readonly"
    fixture.mkdir()
    (fixture / "sentinel").write_text("unchanged")
    proxy_listener.bind(("127.0.0.1", 0))
    proxy_listener.listen(8)
    proxy_port = proxy_listener.getsockname()[1]

    for mode in ("isolated", "firewall", "proxy"):
        address, port = "10.0.2.2", proxy_port
        if mode == "firewall":
            interfaces = json.loads(subprocess.check_output(
                ["ip", "-j", "-4", "address", "show", "up", "scope", "global"], text=True,
            ))
            host_address = next((
                address["local"]
                for interface in interfaces
                if "LOOPBACK" not in interface.get("flags", [])
                for address in interface.get("addr_info", [])
                if address.get("family") == "inet"
                and ipaddress.ip_address(address["local"]) not in ipaddress.ip_network("10.0.2.0/24")
            ), None)
            if host_address is None:
                print("SKIPPED: firewall requires a non-loopback host IPv4 address "
                      "outside slirp's subnet.", flush=True)
                skipped.append(mode)
                continue

            # Firewall mode denies the slirp host-loopback gateway, even in an allowlisted CIDR.
            firewall_listener.bind((host_address, 0))
            firewall_listener.listen(8)
            address, port = firewall_listener.getsockname()
            with socket.create_connection((address, port), timeout=5):
                pass

        command = (
            f"python3 - {shlex.quote(str(fixture))} {os.getuid()} {port} {mode} {address} <<'WORKLOAD'\n"
            + workload + "\nWORKLOAD"
        )
        config = {
            "version": "1.0.0",
            "containerId": f"bwrap-capabilities-{mode}",
            "containment": "bubblewrap",
            "process": {
                "commandLine": command,
                "timeout": 15000,
                "env": ["PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"],
            },
            "filesystem": {"readonlyPaths": [str(fixture)]},
        }
        if mode == "firewall":
            config["network"] = {
                "egress": {"default": "deny", "allow": [{"to": [{"cidr": f"{address}/32"}]}]},
            }
        elif mode == "proxy":
            config["runtimeConfig"] = {"networkProxy": f"http://127.0.0.1:{port}"}
        config_path = root / f"{mode}.json"
        config_path.write_text(json.dumps(config))
        result = subprocess.run(
            [sys.argv[1], "--experimental", str(config_path)],
            capture_output=True, text=True, timeout=60,
        )
        output = result.stdout + result.stderr
        if result.returncode != 0 or f"CAPABILITIES_DROPPED_{mode}" not in output:
            print(f"FAIL: {mode}, caller UID {os.getuid()}\n{output}", flush=True)
            failed.append(mode)
        else:
            print(f"PASS: {mode}, caller UID {os.getuid()}", flush=True)
        assert (fixture / "sentinel").read_text() == "unchanged", "host fixture changed"

if failed:
    sys.exit(1)
if skipped:
    print(f"Bubblewrap capability test incomplete: skipped {', '.join(skipped)}.")
    sys.exit(77)
print("Bubblewrap capability test complete.")
PY
