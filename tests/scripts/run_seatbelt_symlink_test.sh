#!/bin/bash
# Symlink policy must protect the target, not just the spelling in the config.
set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=lib/seatbelt_common.sh
. "$SCRIPT_DIR/lib/seatbelt_common.sh"

[ "$(id -u)" -ne 0 ] || fail "run the symlink tests as an unprivileged user"
require_python3_probe

TESTDIR="$(mktemp -d /private/tmp/mxc-seatbelt-symlink.XXXXXX)" ||
    fail "could not create the symlink fixture directory"
trap 'rm -rf "$TESTDIR" "$SEATBELT_TMP"' EXIT

OUT=$(/usr/bin/python3 - "$MXC_EXEC_MAC" "$DEVDIR" "$TESTDIR" <<'PY'
import base64
import json
from pathlib import Path
import shlex
import subprocess
import sys

binary, developer_dir, test_dir = sys.argv[1:]
root = Path(test_dir)
real_file = root / "real-file.txt"
real_dir = root / "real-dir"
real_dir.mkdir()
(real_dir / "nested").mkdir()
inner_file = real_dir / "secret.txt"
file_link = root / "file-link"
file_link.symlink_to(real_file)
file_alias = root / "file-alias"
file_alias.symlink_to("real-file.txt")
dir_link = root / "dir-link"
dir_link.symlink_to("real-dir", target_is_directory=True)
dir_chain = root / "dir-chain"
dir_chain.symlink_to("dir-link", target_is_directory=True)
traversal_link = root / "traversal-link"
traversal_link.symlink_to("real-dir/nested", target_is_directory=True)
file_paths = [real_file, file_link, file_alias, real_dir / ".." / "real-file.txt"]
dir_paths = [
    inner_file, dir_link / "secret.txt", dir_chain / "secret.txt",
    traversal_link / ".." / "secret.txt",
]
directories = [real_dir, dir_link, dir_chain, traversal_link / ".."]
secret = "SYMLINK_SECRET\n"
control = root / "secret.txt"

probe = r"""
import errno, json, sys
from pathlib import Path

root, access, paths, directories = sys.argv[1:]
paths = json.loads(paths)
directories = json.loads(directories)
control = Path(root) / "secret.txt"
assert control.read_text() == "SYMLINK_CONTROL\n", "sibling read control failed"
control.write_text("SYMLINK_CONTROL_WRITTEN\n")
failures = []

def check(operation, allowed, label):
    try:
        operation()
    except OSError as error:
        if allowed or error.errno not in (errno.EPERM, errno.EACCES):
            raise
    else:
        if not allowed:
            failures.append(label)

def read(path):
    assert path.read_text().startswith("SYMLINK_SECRET\n"), "unexpected target content"

def write(path):
    with path.open("a") as stream:
        stream.write("SYMLINK_WRITE\n")

def create(path):
    with path.open("x") as stream:
        stream.write("SYMLINK_CREATED\n")

for name in paths:
    path = Path(name)
    check(lambda: read(path), access != "deny", f"read allowed: {path}")
    check(lambda: write(path), access == "rw", f"write allowed: {path}")
for index, name in enumerate(directories):
    path = Path(name) / f"created-{index}.txt"
    check(lambda: create(path), access == "rw", f"creation allowed: {path}")
if failures:
    raise AssertionError("; ".join(failures))
print("SYMLINK_PROBE_OK")
"""

cases = [
    ("broad allow control", {}, file_paths + dir_paths, directories, "rw"),
    ("deny a file symlink", {"deniedPaths": [file_link]}, file_paths, [], "deny"),
    ("deny a chained directory symlink", {"deniedPaths": [dir_chain]}, dir_paths, directories, "deny"),
    ("deny a file through a symlinked parent",
     {"deniedPaths": [dir_link / "secret.txt"]}, dir_paths, [], "deny"),
    ("deny the real file also blocks symlink aliases",
     {"deniedPaths": [real_file]}, file_paths, [], "deny"),
    ("readonly symlink overrides readwrite target",
     {"readwritePaths": [root, real_file], "readonlyPaths": [file_link]}, file_paths, [], "ro"),
    ("deny a policy path containing parent traversal",
     {"deniedPaths": [real_dir / ".." / "real-file.txt"]}, file_paths, [], "deny"),
    ("deny follows a symlink before parent traversal",
     {"deniedPaths": [traversal_link / ".." / "secret.txt"]}, dir_paths, [], "deny"),
    ("readonly follows a symlink before parent traversal",
     {"readwritePaths": [root, inner_file],
      "readonlyPaths": [traversal_link / ".." / "secret.txt"]}, dir_paths, [], "ro"),
    ("readwrite follows a symlink before parent traversal",
     {"readwritePaths": [traversal_link / "..", control]}, dir_paths, directories, "rw"),
    ("deny folds parent traversal in a missing tail",
     {"deniedPaths": [dir_link / "missing" / ".." / "secret.txt"]}, dir_paths, [], "deny"),
    ("deny a not-yet-created file through a symlinked parent",
     {"deniedPaths": [dir_link / "created-0.txt"]}, [], [real_dir], "deny"),
]

def execute(filesystem, command, cwd="/", extra_args=()):
    policy = {"readwritePaths": [root], "readonlyPaths": [], "deniedPaths": []}
    policy.update(filesystem)
    policy["readonlyPaths"] = [developer_dir] + policy["readonlyPaths"]
    request = {
        "version": "1.0.0",
        "containment": "seatbelt",
        "process": {
            "commandLine": command,
            "cwd": str(cwd),
            "timeout": 20000,
        },
        "filesystem": {key: [str(path) for path in paths] for key, paths in policy.items()},
    }
    encoded = base64.b64encode(json.dumps(request).encode()).decode()
    return subprocess.run(
        [binary, "--config-base64", encoded, *extra_args],
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        start_new_session=True,
        timeout=30,
    )

failures = []
for label, filesystem, paths, directory_paths, access in cases:
    for path in (real_file, inner_file):
        path.write_text(secret)
    control.write_text("SYMLINK_CONTROL\n")
    for index in range(len(directories)):
        created = real_dir / f"created-{index}.txt"
        if created.exists():
            created.unlink()
    for path in paths:
        if path.read_text() != secret:
            raise AssertionError(f"host cannot read the fixture: {path}")
        with path.open("a"):
            pass
    command = [
        "/usr/bin/python3", "-I", "-c", probe, str(root), access,
        json.dumps([str(path) for path in paths]),
        json.dumps([str(path) for path in directory_paths]),
    ]
    result = execute(filesystem, "exec " + " ".join(shlex.quote(arg) for arg in command))
    errors = []
    if result.returncode != 0 or "SYMLINK_PROBE_OK" not in result.stdout.splitlines():
        errors.append(f"exit {result.returncode}\n{result.stdout}\n{result.stderr}")
    if control.read_text() != "SYMLINK_CONTROL_WRITTEN\n":
        errors.append("sandbox did not write the allowed sibling control")
    if access != "rw":
        for path in (real_file, inner_file):
            if path.read_text() != secret:
                errors.append(f"protected host file changed: {path}")
        if directory_paths and any(real_dir.glob("created-*.txt")):
            errors.append("a file was created in the denied directory")
    if errors:
        failures.append(label)
        print(f"FAIL: {label}\n" + "\n".join(errors), flush=True)
    else:
        print(f"PASS: {label}", flush=True)

dangling = root / "dangling"
dangling.symlink_to("missing-target")
loop = root / "loop"
loop.symlink_to("loop")
target_traversal = root / "target-traversal"
target_traversal.symlink_to("real-file.txt/../secret.txt")
unreadable = root / "unreadable"
unreadable.mkdir()
try:
    unreadable.chmod(0)
    try:
        (unreadable / "secret.txt").stat()
    except PermissionError:
        pass
    else:
        raise AssertionError("host permission-denied control failed")
    for label, field, path in [
        ("deny a dangling symlink", "deniedPaths", dangling),
        ("readonly through a dangling ancestor", "readonlyPaths", dangling / "child"),
        ("readwrite through a symlink loop", "readwritePaths", loop),
        ("deny a symlink loop before parent traversal", "deniedPaths", loop / ".." / "real-file.txt"),
        ("deny an inaccessible path", "deniedPaths", unreadable / "secret.txt"),
        ("missing prefix does not hide an inaccessible target", "deniedPaths",
         root / "missing" / ".." / "unreadable" / "secret.txt"),
        ("missing prefix and parent traversal do not hide a dangling link", "deniedPaths",
         root / "missing" / ".." / "dangling" / ".." / "real-file.txt"),
        ("missing prefix and parent traversal do not hide a symlink loop", "deniedPaths",
         root / "missing" / ".." / "loop" / ".." / "real-file.txt"),
        ("parent traversal cannot treat a file as a directory", "deniedPaths",
         real_file / ".." / "secret.txt"),
        ("parent traversal does not hide an inaccessible directory", "deniedPaths",
         unreadable / ".." / "real-file.txt"),
        ("a link target cannot treat a file as a directory", "readwritePaths",
         target_traversal),
    ]:
        for extra_args in [(), ("--dry-run",)]:
            result = execute({field: [path]}, "echo SYMLINK_INVALID_POLICY_RAN",
                             extra_args=extra_args)
            output = result.stdout + result.stderr
            case = label + (" (dry run)" if extra_args else "")
            if (result.returncode == 0 or "SYMLINK_INVALID_POLICY_RAN" in output
                    or "could not be resolved" not in output or str(path) not in output):
                failures.append(case)
                print(f"FAIL: {case}\nexit {result.returncode}\n{output}", flush=True)
            else:
                print(f"PASS: {case}", flush=True)
finally:
    unreadable.chmod(0o700)

result = execute({}, 'printf "%s\\n" "$PWD" "$HOME"; pwd -P', cwd=traversal_link / "..")
expected = [str(real_dir)] * 3
if result.returncode != 0 or result.stdout.splitlines() != expected:
    failures.append("working directory uses the physical path")
    print(f"FAIL: working directory uses the physical path\nexpected {expected}\n"
          f"exit {result.returncode}\n{result.stdout}\n{result.stderr}", flush=True)
else:
    print("PASS: working directory uses the physical path", flush=True)

(root / "project").mkdir()
for label, cwd in [
    ("a missing working directory fails", root / "missing"),
    ("parent traversal cannot hide a missing working directory",
     root / "missing" / ".." / "project"),
    ("a dangling working directory fails", dangling),
]:
    for extra_args in [(), ("--dry-run",)]:
        result = execute({}, "echo SYMLINK_INVALID_CWD_RAN", cwd=cwd, extra_args=extra_args)
        output = result.stdout + result.stderr
        case = label + (" (dry run)" if extra_args else "")
        if (result.returncode == 0 or "SYMLINK_INVALID_CWD_RAN" in output
                or "Seatbelt working directory" not in output):
            failures.append(case)
            print(f"FAIL: {case}\nexit {result.returncode}\n{output}", flush=True)
        else:
            print(f"PASS: {case}", flush=True)
if failures:
    raise AssertionError(f"{len(failures)} symlink policy case(s) failed")
PY
) || fail "symlink policy does not match the expected access rules" "$OUT"

printf '%s\n' "$OUT"
pass "symlink and real-target access follow the same filesystem policy"
summary "Seatbelt symlinks"
