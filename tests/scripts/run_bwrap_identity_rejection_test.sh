#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_DIR="$(dirname "$(dirname "$SCRIPT_DIR")")"
LXC_EXEC="${LXC_EXEC:-$REPO_DIR/src/target/release/lxc-exec}"
if [ "$(id -u)" -ne 0 ]; then
    echo "SKIPPED: root is required for private subordinate-ID configuration fixtures."
    exit 77
fi
if [ ! -x "$LXC_EXEC" ]; then
    echo "FAIL: lxc-exec not found at $LXC_EXEC." >&2
    exit 1
fi
for tool in unshare mount umount python3 getent bwrap; do
    if ! command -v "$tool" >/dev/null 2>&1; then
        echo "SKIPPED: $tool is required for root identity rejection tests."
        exit 77
    fi
done

if [ "${MXC_BWRAP_IDENTITY_REJECTION_INNER:-0}" != "1" ]; then
    exec unshare --mount --propagation private -- \
        env MXC_BWRAP_IDENTITY_REJECTION_INNER=1 LXC_EXEC="$LXC_EXEC" bash "$0"
fi

python3 - "$LXC_EXEC" <<'PY'
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile

# Fixed account databases keep every case independent of the host's accounts.
PASSWD = "root:x:0:0:root:/root:/bin/sh\n"
GROUP = "root:x:0:\n"
SUBUID = "root:100000:65536\n"
SUBGID = "root:300000:65536\n"

with tempfile.TemporaryDirectory(prefix="mxc-bwrap-identity-rejections-") as directory:
    root = Path(directory)
    etc = root / "etc"
    etc.mkdir(mode=0o755)
    for name in ("hosts", "ld.so.cache"):
        source = Path("/etc") / name
        if source.is_file():
            shutil.copyfile(source, etc / name)
    (etc / "nsswitch.conf").write_text("passwd: files\ngroup: files\nhosts: files dns\n")
    config = root / "request.json"
    config.write_text(json.dumps({
        "version": "1.0.0",
        "containment": "bubblewrap",
        "process": {"commandLine": "echo WORKLOAD_STARTED"},
    }))

    def configure(subuid=SUBUID, subgid=SUBGID, passwd=PASSWD, group=GROUP):
        for kind, contents in (("subuid", subuid), ("subgid", subgid)):
            path = etc / kind
            path.unlink(missing_ok=True)
            if contents is not None:
                path.write_text(contents)
                path.chmod(0o600)
        (etc / "passwd").write_text(passwd)
        (etc / "group").write_text(group)

    def expect(name, diagnostic, environment=None):
        result = subprocess.run([sys.argv[1], str(config)], env=environment,
                                capture_output=True, text=True, timeout=30)
        output = result.stdout + result.stderr
        started = "WORKLOAD_STARTED" in result.stdout.splitlines()
        if diagnostic is None:
            if result.returncode != 0 or not started:
                raise AssertionError(f"{name} did not launch:\n{output}")
        elif result.returncode == 0 or diagnostic not in output or started:
            raise AssertionError(f"{name} did not reject before execution:\n{output}")
        print(f"PASS: {name}", flush=True)

    subprocess.run(["mount", "--bind", str(etc), "/etc"], check=True)
    try:
        configure()
        expect("valid baseline", None)
        cases = [
            ("missing UID allocation", {"subuid": None}, "allocation"),
            ("missing GID allocation", {"subgid": None}, "allocation"),
            ("empty allocation", {"subuid": ""}, "reserved allocation"),
            ("another account's allocation", {"subuid": "user:100000:65536\n"},
             "reserved allocation"),
            ("short allocation", {"subuid": "root:100000:65535\n"}, "reserved allocation"),
            ("host root mapped", {"subuid": "root:0:65536\n"}, "invalid subordinate allocation"),
            ("overflowing allocation", {"subuid": "root:4294960000:65536\n"},
             "invalid subordinate allocation"),
            ("overlapping UID allocations", {"subuid": SUBUID + "other:165535:65536\n"},
             "overlaps another subordinate allocation"),
            ("overlapping GID allocations", {"subgid": SUBGID + "other:365535:65536\n"},
             "overlaps another subordinate allocation"),
            ("allocated host UID", {"passwd": PASSWD + "mxc-fixture:x:101000:1000::/:/bin/sh\n"},
             "overlaps host account UID"),
            ("allocated host GID", {"group": GROUP + "mxc-fixture:x:301000:\n"},
             "overlaps host account GID"),
            ("primary group without group entry",
             {"passwd": PASSWD + "mxc-fixture:x:2000:301000::/:/bin/sh\n"},
             "overlaps host account GID"),
            ("malformed unrelated record", {"subuid": SUBUID + "broken\n"},
             "invalid subordinate allocation"),
            ("writable allocation file", {}, "not writable by group or others"),
            ("foreign-owned allocation file", {}, "root-owned file"),
            ("symlink allocation file", {}, "could not read root's allocation"),
        ]
        for name, changes, diagnostic in cases:
            configure(**changes)
            if name == "writable allocation file":
                (etc / "subuid").chmod(0o666)
            elif name == "foreign-owned allocation file":
                os.chown(etc / "subuid", 1000, 0)
            elif name == "symlink allocation file":
                (etc / "subuid").rename(etc / "subuid-target")
                (etc / "subuid").symlink_to("subuid-target")
            expect(name, diagnostic)

        # MXC finds getent on PATH first, so this shim replaces it for these runs only.
        real_getent = shutil.which("getent")
        shims = root / "shims"
        shims.mkdir(mode=0o700)
        shim = shims / "getent"
        environment = dict(os.environ, PATH=f"{shims}:/usr/local/sbin:/usr/local/bin:"
                                            "/usr/sbin:/usr/bin:/sbin:/bin")
        configure()
        capture_limit = 64 * 1024
        accounts = PASSWD
        index = 0
        while True:
            line = f"mxc-filler-{index:05d}:x:{20000 + index}:{20000 + index}::/:/bin/sh\n"
            remaining = capture_limit - len(accounts.encode())
            if remaining < 2 * len(line):
                accounts += line.replace("::", ":" + "p" * (remaining - len(line)) + ":", 1)
                break
            accounts += line
            index += 1
        assert len(accounts.encode()) == capture_limit
        (shims / "passwd").write_text(accounts + "mxc-conflict:x:101000:20000::/:/bin/sh\n")
        getent_cases = [
            ("complete account lookup", f'exec {real_getent} "$@"', None),
            ("failed group lookup",
             f'{real_getent} "$@"\n[ "$1" = group ] && exit 2\nexit 0',
             "getent group failed or returned an incomplete account database"),
            ("account list past the capture limit",
             f'[ "$1" = passwd ] && exec cat {shims / "passwd"}\nexec {real_getent} "$@"',
             "getent passwd failed or returned an incomplete account database"),
        ]
        for name, body, diagnostic in getent_cases:
            shim.write_text(f"#!/bin/sh\n{body}\n")
            shim.chmod(0o755)
            expect(name, diagnostic, environment)
    finally:
        subprocess.run(["umount", "--no-mtab", "--internal-only", "/etc"], check=True)
print("Bubblewrap root identity rejection test complete.")
PY
