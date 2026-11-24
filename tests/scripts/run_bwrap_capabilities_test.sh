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
tools=(bwrap python3 slirp4netns unshare nsenter ip iptables ip6tables iptables-restore ip6tables-restore)
if [ "$(id -u)" -eq 0 ]; then tools+=(getent setpriv); fi
for tool in "${tools[@]}"; do
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
import pwd
import re
import select
import shlex
import shutil
import socket
import subprocess
import sys
import tempfile
import time

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
import time
from urllib.parse import urlsplit

fixture = Path(sys.argv[1])
expected_uid, expected_gid, port, blocked_port = map(int, sys.argv[2:6])
mode, address = sys.argv[6:8]
uid_base, gid_base = map(int, sys.argv[8:10])
assert os.getresuid() == (expected_uid,) * 3, "unexpected workload UIDs"
assert os.getresgid() == (expected_gid,) * 3, "unexpected workload GIDs"
if uid_base:
    assert os.getgroups() == [], "root caller's supplementary groups reached the workload"
    for kind, base in (("uid", uid_base), ("gid", gid_base)):
        mapping = [int(value) for value in Path(f"/proc/self/{kind}_map").read_text().split()]
        assert mapping == [0, base, 65536], f"unexpected {kind} mapping: {mapping}"
        assert base > 0, f"namespace {kind} 0 maps to host root"
    for name in ("root-secret", "root-group-secret"):
        try:
            (fixture / name).read_bytes()
        except PermissionError:
            pass
        else:
            raise AssertionError(f"workload read root-only fixture {name}")
    writable = fixture.parent / "writable"
    (writable / mode).write_text("mapped owner")
    (fixture.parent / "group-writable" / mode).write_text("mapped group")
    try:
        os.setuid(0)
    except PermissionError:
        pass
    else:
        raise AssertionError("workload changed to namespace root")
    if mode != "isolated":
        namespaces = (os.readlink("/proc/self/ns/user"), os.readlink("/proc/self/ns/net"))
        print("NAMESPACES", *namespaces, flush=True)
        release = writable / f"{mode}.release"
        deadline = time.monotonic() + 20
        while not release.exists():
            assert time.monotonic() < deadline, "the harness did not inspect the supervisor"
            time.sleep(0.05)
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
    if mode == "proxy":
        proxy_host = urlsplit(os.environ["HTTP_PROXY"]).hostname
        assert socket.gethostbyname(proxy_host) == address, "proxy hostname pin was not applied"
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
root_caller = os.getuid() == 0
uid_base = gid_base = 0


def descendants(parent):
    children = {}
    for entry in Path("/proc").iterdir():
        if entry.name.isdecimal():
            try:
                ppid = int((entry / "stat").read_text().rsplit(")", 1)[1].split()[1])
            except (OSError, IndexError, ValueError):
                continue
            children.setdefault(ppid, []).append(int(entry.name))
    found, pending = [], [parent]
    while pending:
        for child in children.get(pending.pop(), []):
            found.append(child)
            pending.append(child)
    return found


def mounts():
    entries = set()
    for line in Path("/proc/self/mountinfo").read_text().splitlines():
        fields, filesystem = line.split(" - ", 1)
        mount_point = fields.split()[4]
        filesystem_type, source = filesystem.split()[:2]
        entries.add((mount_point, filesystem_type, source))
    return entries


def separation_problem(executor, namespaces, mode):
    caller = os.readlink("/proc/self/ns/user")
    caller_mount_namespace = os.readlink("/proc/self/ns/mnt")
    supervisors, relays, workloads = [], [], []
    for pid in descendants(executor):
        try:
            argv = Path(f"/proc/{pid}/cmdline").read_bytes().split(b"\0")
            userns = os.readlink(f"/proc/{pid}/ns/user")
            netns = os.readlink(f"/proc/{pid}/ns/net")
            mount_namespace = os.readlink(f"/proc/{pid}/ns/mnt")
            status = dict(line.split(":", 1)
                          for line in Path(f"/proc/{pid}/status").read_text().splitlines())
        except OSError:
            continue
        if b"mxc-bwrap-proxy-supervisor" in argv:
            supervisors.append((pid, userns, status["Uid"].split()))
        elif os.path.basename(argv[0]) == b"slirp4netns":
            relays.append((pid, mount_namespace, status))
        elif [userns, netns] == namespaces:
            workloads.append((pid, status["Uid"].split(), status["Gid"].split()))
    if not supervisors:
        return "no live network supervisor was found"
    for pid, userns, uids in supervisors:
        if userns != caller or uids != ["0"] * 4:
            return f"supervisor {pid} runs as {uids} in {userns}, not as root in {caller}"
    if not relays:
        return "no live slirp4netns process was found"
    CAP_NET_BIND_SERVICE = 1 << 10
    SECCOMP_FILTER_MODE = "2"
    for pid, mount_namespace, status in relays:
        retained = [name for name in ("CapPrm", "CapEff", "CapBnd")
                    if int(status[name].strip(), 16) & ~CAP_NET_BIND_SERVICE]
        confinement = (status["NoNewPrivs"].strip(), status["Seccomp"].strip())
        if retained or confinement != ("1", SECCOMP_FILTER_MODE) \
                or mount_namespace == caller_mount_namespace:
            return (f"slirp4netns {pid} kept host authority: retained {retained}, "
                    f"NoNewPrivs/Seccomp {confinement}, mount namespace {mount_namespace}")
    if namespaces[0] == caller:
        return "the workload shares the caller's user namespace"
    if not workloads:
        return "no live workload process was found"
    for pid, uids, gids in workloads:
        if uids != [str(uid_base + 1000)] * 4 or gids != [str(gid_base + 1000)] * 4:
            return f"workload process {pid} runs as host {uids}/{gids}"
    print(f"PASS: {mode} supervisor stays root in the caller's user namespace {caller}; "
          f"slirp4netns keeps only CAP_NET_BIND_SERVICE under seccomp in its own mount "
          f"namespace; workload runs in {namespaces[0]} as host "
          f"{uid_base + 1000}:{gid_base + 1000}", flush=True)
    return None


def run_with_supervisor_check(command, mode, release):
    child = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    output = b""
    try:
        namespaces = None
        deadline = time.monotonic() + 30
        while namespaces is None and time.monotonic() < deadline:
            if select.select([child.stdout], [], [], 0.1)[0]:
                chunk = os.read(child.stdout.fileno(), 65536)
                if not chunk:
                    break
                output += chunk
                match = re.search(rb"^NAMESPACES (\S+) (\S+)$", output, re.M)
                namespaces = match and [value.decode() for value in match.groups()]
            elif child.poll() is not None:
                break
        problem = separation_problem(child.pid, namespaces, mode) if namespaces else \
            "the workload did not report its namespaces"
        if problem:
            return 1, f"{problem}\n{output.decode(errors='replace')}"
        release.touch()
        rest, _ = child.communicate(timeout=60)
        return child.returncode, (output + rest).decode(errors="replace")
    finally:
        if child.poll() is None:
            child.kill()
            child.communicate()


if root_caller:
    root_names = {entry.pw_name for entry in pwd.getpwall() if entry.pw_uid == 0} | {"0"}

    def root_owner(owner):
        return int(owner) == 0 if owner.isascii() and owner.isdecimal() else owner in root_names

    for kind in ("uid", "gid"):
        path = Path(f"/etc/sub{kind}")
        ranges = [line.strip().split(":") for line in path.read_text().splitlines()
                  if line.strip() and not line.lstrip().startswith("#")]
        base = next((int(start) for owner, start, count in ranges
                     if root_owner(owner) and int(count) >= 65536), None)
        if base is None:
            raise SystemExit(f"FAIL: root requires an administrator-reserved range in {path}")
        if kind == "uid":
            uid_base = base
        else:
            gid_base = base
expected_uid = 1000 if root_caller else os.getuid()
expected_gid = 1000 if root_caller else os.getgid()
with tempfile.TemporaryDirectory(prefix="mxc-bwrap-capabilities-") as directory, \
        socket.socket() as proxy_listener, socket.socket() as firewall_listener, \
        socket.socket() as blocked_listener:
    root = Path(directory)
    fixture = root / "readonly"
    fixture.mkdir()
    (fixture / "sentinel").write_text("unchanged")
    grants = {"readonlyPaths": [str(fixture)]}
    if root_caller:
        root.chmod(0o755)
        fixture.chmod(0o755)
        (fixture / "sentinel").chmod(0o644)
        os.chown(fixture / "sentinel", uid_base + 1000, gid_base + 1000)
        for name, mode in (("root-secret", 0o600), ("root-group-secret", 0o640)):
            path = fixture / name
            path.write_text("private fixture")
            os.chown(path, 0, 0)
            path.chmod(mode)
        writable = root / "writable"
        writable.mkdir()
        os.chown(writable, uid_base + 1000, gid_base + 1000)
        writable.chmod(0o700)
        group_writable = root / "group-writable"
        group_writable.mkdir()
        os.chown(group_writable, 0, gid_base + 1000)
        group_writable.chmod(0o770)
        grants["readwritePaths"] = [str(writable), str(group_writable)]
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
    refusal = "still held capabilities" if root_caller else "capset failed"

    def launch(mode, address, port, command, environment=None, release=None, prefix=()):
        config = {
            "version": "1.0.0",
            "containerId": f"bwrap-capabilities-{mode}",
            "containment": "bubblewrap",
            "process": {
                "commandLine": command,
                "timeout": 30000,
                "env": ["PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"],
            },
            "filesystem": grants,
        }
        if mode == "firewall":
            config["network"] = {
                "egress": {"default": "deny", "allow": [{"to": [{"cidr": f"{address}/32"}]}]},
            }
        elif mode == "proxy":
            config["runtimeConfig"] = {"networkProxy": f"http://127.0.0.1:{port}"}
        config_path = root / f"{mode}.json"
        config_path.write_text(json.dumps(config))
        arguments = [*prefix, sys.argv[1], "--experimental", str(config_path)]
        if release:
            return run_with_supervisor_check(arguments, mode, release)
        result = subprocess.run(
            arguments, capture_output=True, text=True, timeout=60, env=environment,
        )
        return result.returncode, result.stdout + result.stderr

    host_mounts = mounts()
    commands = {}
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
            f"python3 - {shlex.quote(str(fixture))} {expected_uid} {expected_gid} "
            f"{port} {blocked_port} {mode} {address} {uid_base} {gid_base} <<'WORKLOAD'\n"
            + workload + "\nWORKLOAD"
        )
        commands[mode] = command
        release = writable / f"{mode}.release" if root_caller and mode != "isolated" else None
        returncode, output = launch(mode, address, port, command, release=release)
        if returncode != 0 or f"CAPABILITIES_DROPPED_{mode}" not in output:
            print(f"FAIL: {mode}, caller UID {os.getuid()}\n{output}", flush=True)
            failed.append(mode)
        else:
            if root_caller:
                for path in (writable / mode, group_writable / mode):
                    stat = path.stat()
                    assert (stat.st_uid, stat.st_gid) == (uid_base + 1000, gid_base + 1000), \
                        f"workload created {path} with an unshifted host owner"
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

    if root_caller:
        without_kill = ["setpriv", "--inh-caps=-kill", "--ambient-caps=-kill",
                        "--bounding-set=-kill", "--"]
        status = subprocess.run(without_kill + ["cat", "/proc/self/status"],
                                capture_output=True, text=True, check=True).stdout
        CAP_KILL = 1 << 5
        assert not any(int(line.split()[1], 16) & CAP_KILL
                       for line in status.splitlines() if line.startswith("Cap")), \
            "setpriv did not remove CAP_KILL"
        returncode, output = launch(
            "isolated", "10.0.2.2", proxy_port, commands["isolated"], prefix=without_kill)
        if returncode != 0 or "CAPABILITIES_DROPPED_isolated" not in output:
            print(f"FAIL: isolated, root caller without CAP_KILL\n{output}", flush=True)
            failed.append("isolated without CAP_KILL")
        else:
            print("PASS: isolated, root caller without CAP_KILL", flush=True)

        for field, path in (
            ("readonlyPaths", fixture / "root-secret"),
            ("readonlyPaths", fixture / "root-group-secret"),
            ("readwritePaths", fixture),
        ):
            config = {
                "version": "1.0.0",
                "containment": "bubblewrap",
                "process": {"commandLine": "echo WORKLOAD_STARTED"},
                "filesystem": {field: [str(path)]},
            }
            config_path = root / "rejected.json"
            config_path.write_text(json.dumps(config))
            result = subprocess.run([sys.argv[1], str(config_path)],
                                    capture_output=True, text=True, timeout=30)
            output = result.stdout + result.stderr
            if result.returncode == 0 or "mapped Bubblewrap UID" not in output \
                    or "WORKLOAD_STARTED" in result.stdout.splitlines():
                raise AssertionError(f"root-only grant was not rejected before execution:\n{output}")
            print(f"PASS: rejected mapped-identity {field} grant to {path.name}", flush=True)

    removed = sorted(host_mounts - mounts())
    if removed:
        print(f"FAIL: launches removed host mounts: {removed}", flush=True)
        failed.append("host mounts")

if failed:
    sys.exit(1)
if skipped:
    print(f"Bubblewrap capability test incomplete: skipped {', '.join(skipped)}.")
    sys.exit(77)
print(f"Bubblewrap capability test complete: {', '.join(passed)}.")
PY
