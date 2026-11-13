#!/bin/bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_DIR="$(dirname "$(dirname "$SCRIPT_DIR")")"
LXC_EXEC="$REPO_DIR/src/target/release/lxc-exec"
if [ ! -x "$LXC_EXEC" ]; then
    LXC_EXEC="$REPO_DIR/src/target/debug/lxc-exec"
fi
if [ ! -x "$LXC_EXEC" ]; then
    echo "Error: lxc-exec not found. Run build.sh first."
    exit 1
fi
for dependency in bwrap python3; do
    if ! command -v "$dependency" >/dev/null 2>&1; then
        echo "SKIPPED: $dependency is required for the terminal isolation test."
        exit 77
    fi
done

python3 - "$LXC_EXEC" <<'PY'
import base64
import fcntl
import json
import os
import pty
import subprocess
import sys
import termios


def run_with_controlling_terminal(command, redirected):
    primary, secondary = pty.openpty()

    def attach_terminal():
        os.setsid()
        fcntl.ioctl(secondary, termios.TIOCSCTTY, 0)
        os.close(secondary)

    try:
        with subprocess.Popen(
            command,
            stdin=subprocess.PIPE if redirected else secondary,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            pass_fds=(secondary,),
            preexec_fn=attach_terminal,
            text=True,
        ) as child:
            try:
                stdout, stderr = child.communicate(timeout=30)
            except subprocess.TimeoutExpired:
                child.kill()
                stdout, stderr = child.communicate(timeout=5)
                raise RuntimeError(f"terminal fixture timed out\n{stdout}\n{stderr}")
            if child.returncode != 0:
                raise RuntimeError(
                    f"terminal fixture exited {child.returncode}\n{stdout}\n{stderr}"
                )
            return stdout
    finally:
        os.close(secondary)
        os.close(primary)


request = {
    "version": "1.0.0",
    "containment": "bubblewrap",
    "process": {
        "commandLine": """test -c /dev/tty || exit 1
read -r pid comm state ppid pgrp session tty rest < /proc/self/stat
test "$tty" = 0 || { echo "sandbox retained controlling terminal $tty" >&2; exit 1; }
if (exec 3<>/dev/tty) 2>/dev/null; then
    echo "sandbox can open the host controlling terminal" >&2
    exit 1
fi
echo NO_CONTROLLING_TERMINAL""",
        "timeout": 10000,
    },
}
encoded = base64.b64encode(json.dumps(request).encode()).decode()
for redirected in (False, True):
    label = "redirected stdio" if redirected else "terminal stdin"
    control = run_with_controlling_terminal(
        ["/bin/sh", "-c", "exec 3<>/dev/tty && test -t 3 && echo CONTROL_HAS_TERMINAL"],
        redirected,
    )
    if "CONTROL_HAS_TERMINAL" not in control:
        raise RuntimeError(f"{label}: positive control did not acquire a controlling terminal")
    output = run_with_controlling_terminal(
        [sys.argv[1], "--config-base64", encoded], redirected
    )
    if "NO_CONTROLLING_TERMINAL" not in output:
        raise RuntimeError(f"{label}: sandbox terminal probe did not complete\n{output}")
    print(f"PASS: {label} does not share the executor's controlling terminal")
PY
