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

with tempfile.TemporaryDirectory(prefix="mxc-bwrap-identity-rejections-") as directory:
    root = Path(directory)
    etc = root / "etc"
    etc.mkdir(mode=0o755)
    for name in ("passwd", "group", "hosts", "ld.so.cache"):
        source = Path("/etc") / name
        if source.is_file():
            shutil.copyfile(source, etc / name)
    (etc / "nsswitch.conf").write_text("passwd: files\ngroup: files\nhosts: files dns\n")
    passwd = (etc / "passwd").read_text()
    group = (etc / "group").read_text()
    config = root / "request.json"
    config.write_text(json.dumps({
        "version": "1.0.0",
        "containment": "bubblewrap",
        "process": {"commandLine": "echo WORKLOAD_STARTED"},
    }))
    subprocess.run(["mount", "--bind", str(etc), "/etc"], check=True)
    try:
        cases = [
            ("missing UID allocation", None, "root:300000:65536\n", "", "", "allocation"),
            ("missing GID allocation", "root:100000:65536\n", None, "", "", "allocation"),
            ("empty allocation", "", "", "", "", "reserved allocation"),
            ("another account's allocation", "user:100000:65536\n", "root:300000:65536\n",
             "", "", "reserved allocation"),
            ("short allocation", "root:100000:65535\n", "root:300000:65536\n",
             "", "", "reserved allocation"),
            ("host root mapped", "root:0:65536\n", "root:300000:65536\n",
             "", "", "invalid subordinate allocation"),
            ("overflowing allocation", "root:4294960000:65536\n", "root:300000:65536\n",
             "", "", "invalid subordinate allocation"),
            ("overlapping UID allocations", "root:100000:65536\nother:165535:65536\n",
             "root:300000:65536\n", "", "", "overlaps another subordinate allocation"),
            ("overlapping GID allocations", "root:100000:65536\n",
             "root:300000:65536\nother:365535:65536\n", "", "", "overlaps another subordinate allocation"),
            ("allocated host UID", "root:100000:65536\n", "root:300000:65536\n",
             "mxc-fixture:x:101000:1000::/:/bin/sh\n", "", "overlaps host account UID"),
            ("allocated host GID", "root:100000:65536\n", "root:300000:65536\n",
             "", "mxc-fixture:x:301000:\n", "overlaps host account GID"),
            ("primary group without group entry", "root:100000:65536\n", "root:300000:65536\n",
             "mxc-fixture:x:2000:301000::/:/bin/sh\n", "", "overlaps host account GID"),
            ("malformed unrelated record", "root:100000:65536\nbroken\n", "root:300000:65536\n",
             "", "", "invalid subordinate allocation"),
            ("writable allocation file", "root:100000:65536\n", "root:300000:65536\n",
             "", "", "not writable by group or others"),
            ("foreign-owned allocation file", "root:100000:65536\n", "root:300000:65536\n",
             "", "", "root-owned file"),
            ("symlink allocation file", "root:100000:65536\n", "root:300000:65536\n",
             "", "", "could not read root's allocation"),
        ]
        for name, subuid, subgid, extra_user, extra_group, diagnostic in cases:
            for kind, contents in (("subuid", subuid), ("subgid", subgid)):
                path = etc / kind
                path.unlink(missing_ok=True)
                if contents is not None:
                    path.write_text(contents)
                    path.chmod(0o600)
            (etc / "passwd").write_text(passwd + extra_user)
            (etc / "group").write_text(group + extra_group)
            if name == "writable allocation file":
                (etc / "subuid").chmod(0o666)
            elif name == "foreign-owned allocation file":
                os.chown(etc / "subuid", 1000, 0)
            elif name == "symlink allocation file":
                (etc / "subuid").rename(etc / "subuid-target")
                (etc / "subuid").symlink_to("subuid-target")
            result = subprocess.run([sys.argv[1], str(config)],
                                    capture_output=True, text=True, timeout=30)
            output = result.stdout + result.stderr
            if result.returncode == 0 or diagnostic not in output \
                    or "WORKLOAD_STARTED" in result.stdout.splitlines():
                raise AssertionError(f"{name} did not reject before execution:\n{output}")
            print(f"PASS: {name}", flush=True)
    finally:
        subprocess.run(["umount", "--no-mtab", "--internal-only", "/etc"], check=True)
print("Bubblewrap root identity rejection test complete.")
PY
