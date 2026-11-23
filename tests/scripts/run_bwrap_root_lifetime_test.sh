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

program="$(mktemp)"
trap 'rm -f "$program"' EXIT
cat > "$program" <<'PY'
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


def running_as(uid):
    found = []
    for entry in Path("/proc").iterdir():
        if not entry.name.isdecimal():
            continue
        try:
            status = dict(line.split(":", 1)
                          for line in (entry / "status").read_text().splitlines())
            command = (entry / "cmdline").read_bytes().replace(b"\0", b" ")
        except (OSError, ValueError):
            continue
        if int(status["Uid"].split()[0]) == uid and not status["State"].strip().startswith("Z"):
            found.append(f"{entry.name} {command.decode(errors='replace').strip()}")
    return found


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


def run(lxc_exec, directory, mode, ending, caller):
    command, timeout = ENDINGS[ending]
    prefix = WITHOUT_KILL if caller == "without-kill" else []
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
    config_path = directory / f"{mode}-{ending}-{caller}.json"
    config_path.write_text(json.dumps(config))
    log_path = config_path.with_suffix(".log")
    with log_path.open("wb") as log:
        executor = subprocess.Popen(
            [*prefix, lxc_exec, "--experimental", str(config_path)],
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
        deadline = time.monotonic() + 10
        while (left := running_as(uid)) and time.monotonic() < deadline:
            time.sleep(0.1)
        if left and problem is None:
            problem = f"processes kept running as host UID {uid}:\n  " + "\n  ".join(left)
    if problem:
        return f"{problem}\n{log_path.read_text(errors='replace')}"
    return None


if sys.argv[1] == "--case":
    assert os.getpid() == 1, ("the case must run as PID 1 of its own PID namespace, so it sees "
                              "only its own processes and the kernel ends them when it exits")
    lxc_exec, directory, mode, ending, caller = sys.argv[2:7]
    problem = run(lxc_exec, Path(directory), mode, ending, caller)
    if problem:
        print(problem, flush=True)
        sys.exit(1)
    sys.exit(0)

status = subprocess.run(WITHOUT_KILL + ["cat", "/proc/self/status"],
                        capture_output=True, text=True, check=True).stdout
CAP_KILL = 1 << 5
assert not any(int(line.split()[1], 16) & CAP_KILL
               for line in status.splitlines() if line.startswith("Cap")), \
    "setpriv did not remove CAP_KILL"

failed = []
with tempfile.TemporaryDirectory(prefix="mxc-bwrap-root-lifetime-") as directory:
    for caller, description in (("with-kill", "root"), ("without-kill", "root without CAP_KILL")):
        for mode in ("isolated", "firewall"):
            for ending in ENDINGS:
                name = f"{mode}, {ending}, {description}"
                result = subprocess.run(
                    ["unshare", "--pid", "--fork", "--mount-proc", "--", sys.executable,
                     __file__, "--case", sys.argv[1], directory, mode, ending, caller],
                    capture_output=True, text=True, timeout=180,
                )
                if result.returncode != 0:
                    print(f"FAIL: {name}: {result.stdout}{result.stderr}", flush=True)
                    failed.append(name)
                else:
                    print(f"PASS: {name}", flush=True)
if failed:
    sys.exit(1)
print("Bubblewrap root lifetime test complete.")
PY
python3 "$program" "$LXC_EXEC"