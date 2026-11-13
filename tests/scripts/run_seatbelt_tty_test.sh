#!/bin/bash
# Only disposable PTYs are used; existing host terminal sessions are untouched.
set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=lib/seatbelt_common.sh
. "$SCRIPT_DIR/lib/seatbelt_common.sh"

[ "$(id -u)" -ne 0 ] || fail "run the terminal-isolation test as an unprivileged user"
require_python3_probe

OUT=$(/usr/bin/python3 - "$MXC_EXEC_MAC" "$DEVDIR" <<'PY'
import base64
import contextlib
import json
import os
import re
import shlex
import subprocess
import sys

binary, developer_dir = sys.argv[1:]

probe = r"""
import errno, fcntl, os, sys, termios

unrelated_path, access, nested, assigned_path = sys.argv[1:]
for mode in (os.O_RDONLY, os.O_WRONLY, os.O_RDWR):
    try:
        fd = os.open(unrelated_path, mode | os.O_NOCTTY | os.O_NONBLOCK)
    except OSError as error:
        if access != "deny" or error.errno not in (errno.EPERM, errno.EACCES):
            raise
    else:
        os.close(fd)
        if access == "deny":
            raise AssertionError("unrelated host terminal opened")

if assigned_path:
    assert os.isatty(0), "assigned stdin is not a terminal"
    termios.tcgetattr(0)
    fcntl.ioctl(0, termios.TIOCGETD, bytes(4))
    fd = os.open(assigned_path, os.O_RDWR | os.O_NOCTTY | os.O_NONBLOCK)
    try:
        fcntl.ioctl(fd, termios.TIOCGETD, bytes(4))
    finally:
        os.close(fd)
else:
    assert not os.isatty(0), "unexpected inherited terminal"

try:
    master, slave = os.openpty()
except OSError as error:
    if nested != "deny" or error.errno not in (errno.EPERM, errno.EACCES):
        raise
else:
    try:
        if nested == "deny":
            raise AssertionError("nested PTY allocation was not blocked")
        termios.tcgetattr(slave)
        fcntl.ioctl(slave, termios.TIOCGETD, bytes(4))
    finally:
        os.close(slave)
        os.close(master)

print("TTY_PROBE_OK")
"""


def allocate_terminal(cleanup):
    master, slave = os.openpty()
    cleanup.callback(os.close, master)
    cleanup.callback(os.close, slave)
    return slave, os.ttyname(slave)


with contextlib.ExitStack() as cleanup:
    _, unrelated_path = allocate_terminal(cleanup)
    assigned_slave, assigned_path = allocate_terminal(cleanup)
    if not re.fullmatch(r"/dev/ttys[0-9]+", unrelated_path):
        raise AssertionError("the disposable terminal does not match the PTY rule")
    if os.stat(unrelated_path).st_uid != os.geteuid():
        raise AssertionError("the unrelated terminal must belong to the test user")
    for mode in (os.O_RDONLY, os.O_WRONLY, os.O_RDWR):
        fd = os.open(unrelated_path, mode | os.O_NOCTTY | os.O_NONBLOCK)
        os.close(fd)

    cases = [
        ("explicit filesystem grant", None, "allow", "allow"),
        ("default policy", None, "deny", "allow"),
        ("nestedPty=false", {"nestedPty": False}, "deny", "deny"),
        ("guiAccess", {"guiAccess": True, "nestedPty": False}, "deny", "allow"),
    ]
    for inherited in (False, True):
        for label, options, access, nested in cases:
            label += " / " + ("inherited terminal" if inherited else "no terminal")
            command = [
                "/usr/bin/python3", "-I", "-c", probe,
                unrelated_path, access, nested, assigned_path if inherited else "",
            ]
            request = {
                "version": "1.0.0",
                "containment": "seatbelt",
                "process": {
                    "commandLine": "exec " + " ".join(shlex.quote(arg) for arg in command),
                    "timeout": 20000,
                },
                "filesystem": {
                    "readonlyPaths": [developer_dir],
                    "readwritePaths": [unrelated_path] if access == "allow" else [],
                },
            }
            if options is not None:
                request["seatbelt"] = options
            if options and options.get("guiAccess"):
                request["ui"] = {"disable": False}
            encoded = base64.b64encode(json.dumps(request).encode()).decode()
            result = subprocess.run(
                [binary, "--config-base64", encoded],
                stdin=assigned_slave if inherited else subprocess.DEVNULL,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                close_fds=True,
                start_new_session=True,
                timeout=30,
            )
            if result.returncode != 0 or "TTY_PROBE_OK" not in result.stdout.splitlines():
                raise AssertionError(
                    f"{label} failed (exit {result.returncode})\n"
                    f"{result.stdout}\n{result.stderr}"
                )
            print(f"Verified: {label}", flush=True)
PY
) || fail "terminal-isolation probe failed" "$OUT"

printf '%s\n' "$OUT"
pass "unrelated same-user PTYs are denied while assigned and permitted nested PTYs work"
summary "Seatbelt terminal isolation"
