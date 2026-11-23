#!/bin/bash
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

for dependency in bwrap python3; do
    if ! command -v "$dependency" >/dev/null 2>&1; then
        echo "SKIPPED: $dependency is required for the user-namespace test."
        exit 77
    fi
done

python3 - "$LXC_EXEC" <<'PY'
import base64
import json
import shlex
import shutil
import socket
import subprocess
import sys

PROBE = r"""
import ctypes, errno, json, os, shutil, subprocess, threading

CLONE_NEWUSER = 0x10000000
SIGCHLD = 17
UNSHARE, CLONE, CLONE3 = {"x86_64": (272, 56, 435), "aarch64": (97, 220, 435)}[os.uname().machine]
libc = ctypes.CDLL(None, use_errno=True)
libc.syscall.restype = ctypes.c_long


class CloneArgs(ctypes.Structure):
    _fields_ = [(name, ctypes.c_uint64) for name in (
        "flags", "pidfd", "child_tid", "parent_tid", "exit_signal", "stack", "stack_size", "tls")]


def error_name():
    return errno.errorcode[ctypes.get_errno()]


def start_child(number, *arguments):
    child = libc.syscall(ctypes.c_long(number), *arguments)
    if child == 0:
        os._exit(0)
    if child < 0:
        return error_name()
    os.waitpid(child, 0)
    return "OK"


thread = threading.Thread(target=lambda: None)
thread.start()
thread.join()
true_path = shutil.which("true")
results = {
    "subprocess": subprocess.run([true_path]).returncode,
    "posix_spawn": os.waitstatus_to_exitcode(
        os.waitpid(os.posix_spawn(true_path, [true_path], {}), 0)[1]),
}
if shutil.which("unshare"):
    results["unshare_command"] = subprocess.run(
        ["unshare", "-Ur", "id", "-u"], capture_output=True).returncode
results["clone"] = start_child(
    CLONE, ctypes.c_ulong(CLONE_NEWUSER | SIGCHLD), *[ctypes.c_ulong(0)] * 4)
clone_args = CloneArgs(flags=CLONE_NEWUSER, exit_signal=SIGCHLD)
results["clone3"] = start_child(
    CLONE3, ctypes.byref(clone_args), ctypes.c_size_t(ctypes.sizeof(clone_args)))
results["unshare"] = "OK" if libc.unshare(CLONE_NEWUSER) == 0 else error_name()
print("USERNS_PROBE=" + json.dumps(results), flush=True)
"""

EXPECTED = {
    "subprocess": 0,
    "posix_spawn": 0,
    "clone": "EPERM",
    "clone3": "ENOSYS",
    "unshare": "EPERM",
}


def probe_results(output):
    for line in reversed(output.splitlines()):
        if line.startswith("USERNS_PROBE="):
            return json.loads(line.partition("=")[2])
    return None


def fail(message, run):
    print(run.stdout, end="")
    print(run.stderr, end="")
    print(f"FAIL: {message}")
    sys.exit(1)


host = subprocess.run(
    [sys.executable, "-c", PROBE], capture_output=True, text=True, timeout=60
)
host_results = probe_results(host.stdout)
if host_results is None or any(
    host_results[name] != "OK" for name in ("clone", "clone3", "unshare")
):
    print(host.stdout + host.stderr, end="")
    print(
        "SKIPPED: the host cannot create user namespaces, so a denial inside "
        "the sandbox would prove nothing."
    )
    sys.exit(77)

with socket.socket() as proxy:
    proxy.bind(("127.0.0.1", 0))
    proxy.listen()
    modes = {
        "isolated": {},
        "firewall": {
            "network": {
                "egress": {
                    "default": "deny",
                    "allow": [{"to": [{"cidr": "192.0.2.1/32"}]}],
                }
            }
        },
        "proxy": {
            "runtimeConfig": {
                "networkProxy": f"http://127.0.0.1:{proxy.getsockname()[1]}"
            }
        },
    }
    skipped = []
    for mode, policy in modes.items():
        if policy and shutil.which("slirp4netns") is None:
            skipped.append(mode)
            continue
        print(f"Running Bubblewrap user-namespace test: {mode} mode...")
        request = {
            "version": "1.0.0",
            "containment": "bubblewrap",
            "process": {
                "commandLine": "python3 -c " + shlex.quote(PROBE),
                "timeout": 30000,
            },
            **policy,
        }
        encoded = base64.b64encode(json.dumps(request).encode()).decode()
        run = subprocess.run(
            [sys.argv[1], "--config-base64", encoded],
            stdin=subprocess.DEVNULL,
            capture_output=True,
            text=True,
            timeout=120,
        )
        results = probe_results(run.stdout)
        if run.returncode != 0 or results is None:
            fail(f"{mode} mode probe did not complete (exit {run.returncode})", run)
        if any(results.get(name) != value for name, value in EXPECTED.items()):
            fail(f"{mode} mode: expected {EXPECTED}, got {results}", run)
        if results.get("unshare_command") == 0:
            fail(f"{mode} mode: `unshare -Ur id -u` succeeded in the sandbox", run)
        print(
            f"PASS: {mode} mode denies new user namespaces; threads and child "
            "processes still start"
        )

if skipped:
    print(f"SKIPPED: slirp4netns is required for {' and '.join(skipped)} mode.")
    sys.exit(77)
PY

echo "Bubblewrap user-namespace test complete."
