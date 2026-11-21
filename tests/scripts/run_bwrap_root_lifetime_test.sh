#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_DIR="$(dirname "$(dirname "$SCRIPT_DIR")")"
LXC_EXEC="${LXC_EXEC:-$REPO_DIR/src/target/release/lxc-exec}"
if [ "$(id -u)" -ne 0 ]; then
    echo "SKIPPED: root is required for the Bubblewrap root lifetime test."
    exit 77
fi
if [ ! -x "$LXC_EXEC" ]; then
    echo "FAIL: lxc-exec not found at $LXC_EXEC." >&2
    exit 1
fi
for tool in bwrap python3 setpriv slirp4netns unshare nsenter ip iptables ip6tables \
    iptables-restore ip6tables-restore; do
    if ! command -v "$tool" >/dev/null 2>&1; then
        echo "SKIPPED: $tool is required for the Bubblewrap root lifetime test."
        exit 77
    fi
done

python3 - "$LXC_EXEC" <<'PY'
import json
import os
from pathlib import Path
import re
import signal
import subprocess
import sys
import tempfile
import time

WITHOUT_KILL = ["setpriv", "--inh-caps=-kill", "--ambient-caps=-kill",
                "--bounding-set=-kill", "--"]

# Report the workload's host UID, then leave a process running in the background.
START = ('read -r _ base _ < /proc/self/uid_map; echo "HOST_UID $((base + $(id -u)))"; '
         'sleep 300 </dev/null >/dev/null 2>&1 & ')
ENDINGS = {
    "exit": ("exit 0", 30000),
    "timeout": ("sleep 300", 2000),
    "SIGTERM": ("sleep 300", 30000),
    "SIGKILL": ("sleep 300", 30000),
}


def processes():
    return {int(entry.name) for entry in Path("/proc").iterdir() if entry.name.isdecimal()}


def running_as(uid, excluded):
    found = []
    for pid in processes() - excluded:
        try:
            status = dict(line.split(":", 1)
                          for line in Path(f"/proc/{pid}/status").read_text().splitlines())
            command = Path(f"/proc/{pid}/cmdline").read_bytes().replace(b"\0", b" ")
        except (OSError, ValueError):
            continue
        if int(status["Uid"].split()[0]) == uid and not status["State"].strip().startswith("Z"):
            found.append((pid, command.decode(errors="replace").strip()))
    return found


def stop_leftovers(uid, excluded):
    deadline = time.monotonic() + 10
    while (left := running_as(uid, excluded)) and time.monotonic() < deadline:
        time.sleep(0.1)
    for pid, _ in left:
        try:
            os.kill(pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
    return [f"{pid} {command}" for pid, command in left]


def host_uid(executor, log_path):
    deadline = time.monotonic() + 30
    while time.monotonic() < deadline:
        exited = executor.poll() is not None
        match = re.search(r"^HOST_UID (\d+)$", log_path.read_text(errors="replace"), re.M)
        if match:
            return int(match.group(1))
        if exited:
            return None
        time.sleep(0.05)
    return None


def run(directory, mode, ending, prefix):
    command, timeout = ENDINGS[ending]
    config = {
        "version": "1.0.0",
        "containment": "bubblewrap",
        "process": {
            "commandLine": START + command,
            "timeout": timeout,
            "env": ["PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"],
        },
    }
    if mode == "firewall":
        config["network"] = {
            "egress": {"default": "deny", "allow": [{"to": [{"cidr": "192.0.2.1/32"}]}]},
        }
    config_path = directory / f"{mode}-{ending}.json"
    config_path.write_text(json.dumps(config))
    log_path = directory / f"{mode}-{ending}.log"
    before = processes()
    with log_path.open("wb") as log:
        executor = subprocess.Popen(
            [*prefix, sys.argv[1], "--experimental", str(config_path)],
            stdout=log, stderr=subprocess.STDOUT,
        )
    problem = None
    uid = host_uid(executor, log_path)
    if uid is None:
        problem = "the workload did not report its host UID"
    else:
        if ending.startswith("SIG"):
            executor.send_signal(getattr(signal, ending))
        try:
            executor.wait(timeout=60)
        except subprocess.TimeoutExpired:
            problem = "lxc-exec did not exit"
        else:
            if (ending == "exit") != (executor.returncode == 0):
                problem = f"lxc-exec exited with {executor.returncode}"
    if executor.poll() is None:
        executor.kill()
        executor.wait()
    if uid is not None:
        left = stop_leftovers(uid, before)
        if left and problem is None:
            problem = f"processes kept running as host UID {uid}:\n  " + "\n  ".join(left)
    if problem:
        return f"{problem}\n{log_path.read_text(errors='replace')}"
    return None


status = subprocess.run(WITHOUT_KILL + ["cat", "/proc/self/status"],
                        capture_output=True, text=True, check=True).stdout
CAP_KILL = 1 << 5
assert not any(int(line.split()[1], 16) & CAP_KILL
               for line in status.splitlines() if line.startswith("Cap")), \
    "setpriv did not remove CAP_KILL"

failed = []
with tempfile.TemporaryDirectory(prefix="mxc-bwrap-root-lifetime-") as directory:
    for prefix, caller in (((), "root"), (WITHOUT_KILL, "root without CAP_KILL")):
        for mode in ("isolated", "firewall"):
            for ending in ENDINGS:
                name = f"{mode}, {ending}, {caller}"
                problem = run(Path(directory), mode, ending, prefix)
                if problem:
                    print(f"FAIL: {name}: {problem}", flush=True)
                    failed.append(name)
                else:
                    print(f"PASS: {name}", flush=True)
if failed:
    sys.exit(1)
print("Bubblewrap root lifetime test complete.")
PY
