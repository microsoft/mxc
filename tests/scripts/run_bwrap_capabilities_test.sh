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
import platform
import shlex
import shutil
import socket
import subprocess
import sys
import tempfile

SYSCALLS = {"x86_64": (0xC000003E, 126, 157), "aarch64": (0xC00000B7, 91, 167)}
if platform.machine() not in SYSCALLS:
    print(f"SKIPPED: the blocked capability-drop fixture does not support {platform.machine()}.")
    sys.exit(77)
audit_arch, capset_number, prctl_number = SYSCALLS[platform.machine()]

workload = r'''
import ctypes
import errno
import os
from pathlib import Path
import socket
import subprocess
import sys

fixture = Path(sys.argv[1])
expected_uid, port, blocked_port = map(int, sys.argv[2:5])
mode, address = sys.argv[5:7]
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

def connects(host, port, timeout):
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except OSError:
        return False

if mode != "isolated":
    with socket.create_connection((address, port), timeout=5):
        pass

    # Both modes drop traffic to slirp's host gateway, except the proxy port.
    assert not connects("10.0.2.2", blocked_port, 3), f"{mode}: blocked endpoint was reachable"
    result = subprocess.run(["iptables", "-F", "MXC_EGRESS"], capture_output=True, text=True)
    assert result.returncode != 0, "workload flushed its egress firewall"
    assert not connects("10.0.2.2", blocked_port, 3), \
        f"{mode}: the flush attempt opened a blocked endpoint"
    with socket.create_connection((address, port), timeout=5):
        pass

print(f"CAPABILITIES_DROPPED_{mode}")
'''

blocked_drop_wrapper = f'''#!{sys.executable}
import ctypes
import os
import struct
import sys

def statement(code, k, jump_if_true=0, jump_if_false=0):
    return struct.pack("HBBI", code, jump_if_true, jump_if_false, k)

LOAD, JUMP_IF_EQUAL, RETURN = 0x20, 0x15, 0x06
ALLOW, EPERM, PR_CAPBSET_DROP = 0x7FFF0000, 0x00050001, 24

# Load the architecture, the syscall number, then prctl's first argument;
# refuse capset and prctl(PR_CAPBSET_DROP) with EPERM and allow everything else.
program = b"".join((
    statement(LOAD, 4),
    statement(JUMP_IF_EQUAL, {audit_arch}, 0, 5),
    statement(LOAD, 0),
    statement(JUMP_IF_EQUAL, {capset_number}, 4, 0),
    statement(JUMP_IF_EQUAL, {prctl_number}, 0, 2),
    statement(LOAD, 16),
    statement(JUMP_IF_EQUAL, PR_CAPBSET_DROP, 1, 0),
    statement(RETURN, ALLOW),
    statement(RETURN, EPERM),
))
buffer = ctypes.create_string_buffer(program, len(program))

class Filter(ctypes.Structure):
    _fields_ = [("length", ctypes.c_ushort), ("statements", ctypes.c_void_p)]

seccomp_filter = Filter(len(program) // 8, ctypes.addressof(buffer))
libc = ctypes.CDLL(None, use_errno=True)
libc.prctl.argtypes = [ctypes.c_int] + [ctypes.c_ulong] * 4
PR_SET_NO_NEW_PRIVS, PR_SET_SECCOMP, SECCOMP_MODE_FILTER = 38, 22, 2
if libc.prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) or libc.prctl(
        PR_SET_SECCOMP, SECCOMP_MODE_FILTER, ctypes.addressof(seccomp_filter), 0, 0):
    raise OSError(ctypes.get_errno(), "could not install the seccomp filter")
os.execv({shutil.which("bwrap")!r}, ["bwrap"] + sys.argv[1:])
'''

failed = []
skipped = []
passed = []
with tempfile.TemporaryDirectory(prefix="mxc-bwrap-capabilities-") as directory, \
        socket.socket() as proxy_listener, socket.socket() as firewall_listener, \
        socket.socket() as blocked_listener:
    root = Path(directory)
    fixture = root / "readonly"
    fixture.mkdir()
    (fixture / "sentinel").write_text("unchanged")
    proxy_listener.bind(("127.0.0.1", 0))
    proxy_listener.listen(8)
    proxy_port = proxy_listener.getsockname()[1]
    blocked_listener.bind(("127.0.0.1", 0))
    blocked_listener.listen(8)
    blocked_port = blocked_listener.getsockname()[1]
    wrapper = root / "blocked-drop" / "bwrap"
    wrapper.parent.mkdir()
    wrapper.write_text(blocked_drop_wrapper)
    wrapper.chmod(0o755)
    blocked_drop_environment = {
        **os.environ, "PATH": f"{wrapper.parent}{os.pathsep}{os.environ['PATH']}",
    }

    # Bubblewrap stops a non-root launch itself; MXC must stop a root one.
    refusal = "still held capabilities" if os.getuid() == 0 else "capset failed"

    def launch(mode, address, port, command, environment=None):
        config = {
            "version": "1.0.0",
            "containerId": f"bwrap-capabilities-{mode}",
            "containment": "bubblewrap",
            "process": {
                "commandLine": command,
                "timeout": 30000,
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
            capture_output=True, text=True, timeout=60, env=environment,
        )
        return result.returncode, result.stdout + result.stderr

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
            f"python3 - {shlex.quote(str(fixture))} {os.getuid()} {port} {blocked_port} "
            f"{mode} {address} <<'WORKLOAD'\n"
            + workload + "\nWORKLOAD"
        )
        returncode, output = launch(mode, address, port, command)
        if returncode != 0 or f"CAPABILITIES_DROPPED_{mode}" not in output:
            print(f"FAIL: {mode}, caller UID {os.getuid()}\n{output}", flush=True)
            failed.append(mode)
        else:
            returncode, output = launch(
                mode, address, port, "printf 'WORKLOAD_%s\\n' STARTED", blocked_drop_environment,
            )
            if returncode == 0 or "WORKLOAD_STARTED" in output or refusal not in output:
                print(f"FAIL: {mode} was not refused when its capability drop was blocked, "
                      f"caller UID {os.getuid()}\n{output}", flush=True)
                failed.append(mode)
            else:
                print(f"PASS: {mode}, caller UID {os.getuid()}", flush=True)
                passed.append(mode)
        assert (fixture / "sentinel").read_text() == "unchanged", "host fixture changed"

if failed:
    sys.exit(1)
if skipped:
    print(f"Bubblewrap capability test incomplete: skipped {', '.join(skipped)}.")
    sys.exit(77)
print(f"Bubblewrap capability test complete: {', '.join(passed)}.")
PY
