#!/usr/bin/env python3
import argparse
import json
import os
from pathlib import Path
import stat
import subprocess
import sys

COUNT = 65536
MAX_ID = 2**32 - 1
KINDS = ("subuid", "subgid")


def number(text):
    if not text.isascii() or not text.isdecimal() or not 0 <= int(text) < MAX_ID:
        raise ValueError(f"Invalid ID or allocation count: {text!r}")
    return int(text)


def allocations(contents):
    result = []
    for line in contents.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        fields = line.split(":")
        if len(fields) != 3 or not fields[0] or fields[0] != fields[0].strip():
            raise ValueError("Malformed subordinate allocation")
        owner = fields[0]
        if owner.isascii() and owner.isdecimal():
            owner = number(owner)
        start, count = number(fields[1]), number(fields[2])
        if start == 0 or count == 0 or start + count > MAX_ID:
            raise ValueError("Invalid subordinate allocation range")
        result.append((owner, start, start + count))
    return result


def accounts(passwd, group):
    users, gids, root_names = set(), set(), set()
    for text, fields_expected in ((passwd, 7), (group, 4)):
        for line in text.splitlines():
            if not line:
                continue
            fields = line.split(":")
            if len(fields) != fields_expected or not fields[0]:
                raise ValueError("Malformed host account database")
            identity = number(fields[2])
            if fields_expected == 7:
                users.add(identity)
                gids.add(number(fields[3]))
                if identity == 0:
                    root_names.add(fields[0])
            else:
                gids.add(identity)
    if not root_names:
        raise ValueError("Host account database does not identify root")
    return root_names, users, gids


def is_root(owner, names):
    return owner == 0 if isinstance(owner, int) else owner in names


def existing_range(records, occupied, root_names):
    for index, (owner, start, end) in enumerate(records):
        if not is_root(owner, root_names) or end - start < COUNT:
            continue
        if any(start < other_end and other_start < end
               for other_index, (_, other_start, other_end) in enumerate(records)
               if other_index != index):
            raise ValueError("Root's existing allocation overlaps another allocation")
        if any(start <= identity < start + COUNT for identity in occupied):
            raise ValueError("Root's existing allocation overlaps a host account or group")
        return start
    return None


def pool_limits(contents, kind):
    prefix = "SUB_UID_" if kind == "subuid" else "SUB_GID_"
    values = {}
    for line in contents.splitlines():
        fields = line.split("#", 1)[0].split()
        if not fields or fields[0] not in (prefix + "MIN", prefix + "MAX"):
            continue
        if len(fields) != 2 or fields[0] in values:
            raise ValueError(f"Invalid or duplicate {fields[0]} in login.defs")
        values[fields[0]] = number(fields[1])
    minimum, maximum = values.get(prefix + "MIN"), values.get(prefix + "MAX")
    if minimum is None or maximum is None or minimum == 0 or maximum - minimum + 1 < COUNT:
        raise ValueError(f"login.defs must define a usable {prefix}MIN/MAX pool")
    return minimum, maximum + 1


def free_range(records, occupied, minimum, limit):
    candidate = minimum
    intervals = [(start, end) for _, start, end in records]
    intervals.extend((identity, identity + 1) for identity in occupied)
    for start, end in sorted(intervals):
        if end <= candidate:
            continue
        if candidate + COUNT <= start:
            break
        candidate = end
    if candidate + COUNT > limit:
        raise ValueError("No nonconflicting 65,536-ID allocation is available in the CI host pool")
    return candidate


def require_root_file(path):
    metadata = path.lstat()
    if not stat.S_ISREG(metadata.st_mode) or metadata.st_uid != 0 or metadata.st_mode & 0o022:
        raise ValueError(f"{path} must be a regular root-owned file, not writable by group or others")


def get_accounts():
    contents = []
    for database in ("passwd", "group"):
        result = subprocess.run(["getent", database], check=True, capture_output=True,
                                text=True, timeout=10)
        if len(result.stdout.encode()) > 65536:
            raise ValueError(f"getent {database} exceeds the runtime account-probe limit")
        contents.append(result.stdout)
    return accounts(*contents)


def configure(etc, backup, host_accounts):
    root_names, uids, gids = host_accounts

    # LXC's CI setup appends root:100000:65536 unless that exact line already exists.
    owner = "root" if "root" in root_names else "0"
    originals, replacements, selected = {}, {}, {}
    for kind, occupied in zip(KINDS, (uids, gids)):
        path = etc / kind
        if path.exists() or path.is_symlink():
            require_root_file(path)
            originals[kind] = path.read_text()
        else:
            originals[kind] = None
        records = allocations(originals[kind] or "")
        selected[kind] = existing_range(records, occupied, root_names)
        if selected[kind] is None:
            require_root_file(etc / "login.defs")
            minimum, limit = pool_limits((etc / "login.defs").read_text(), kind)
            selected[kind] = free_range(records, occupied, minimum, limit)
            previous = originals[kind] or ""
            separator = "\n" if previous and not previous.endswith("\n") else ""
            replacements[kind] = previous + separator + f"{owner}:{selected[kind]}:{COUNT}\n"

    backup.mkdir(mode=0o700)
    try:
        for kind in KINDS:
            if originals[kind] is not None:
                subprocess.run(["cp", "-a", "--", str(etc / kind), str(backup / kind)], check=True)
        manifest = backup / "originals.pending.json"
        with manifest.open("x") as stream:
            json.dump({kind: originals[kind] is not None for kind in KINDS}, stream)
            stream.flush()
            os.fsync(stream.fileno())
        manifest.rename(backup / "originals.json")
        for kind, contents in replacements.items():
            flags = os.O_WRONLY | os.O_CLOEXEC | os.O_NOFOLLOW
            flags |= os.O_CREAT | os.O_EXCL if originals[kind] is None else os.O_TRUNC
            with os.fdopen(os.open(etc / kind, flags, 0o600), "w") as stream:
                stream.write(contents)
                stream.flush()
                os.fsync(stream.fileno())
    except BaseException:
        restore(etc, backup)
        raise
    print(f"CI root ranges: UID {selected['subuid']}:{COUNT}, GID {selected['subgid']}:{COUNT}")


def restore(etc, backup):
    try:
        metadata = backup.lstat()
    except FileNotFoundError:
        print("No Bubblewrap root ID setup to restore.")
        return
    if not stat.S_ISDIR(metadata.st_mode) or metadata.st_uid != os.geteuid() or metadata.st_mode & 0o077:
        raise ValueError(f"Invalid backup directory: {backup}")
    manifest = backup / "originals.json"
    errors = []
    if manifest.exists():
        original = json.loads(manifest.read_text())
        if set(original) != set(KINDS) or any(type(value) is not bool for value in original.values()):
            raise ValueError(f"Invalid configuration backup manifest: {manifest}")
        for kind in KINDS:
            try:
                if original[kind]:
                    subprocess.run(["cp", "-aT", "--remove-destination", "--",
                                    str(backup / kind), str(etc / kind)], check=True)
                else:
                    (etc / kind).unlink(missing_ok=True)
            except (OSError, subprocess.SubprocessError) as error:
                errors.append(f"{kind}: {error}")
    if errors:
        raise RuntimeError(f"Could not restore root IDs; backups retained at {backup}: {'; '.join(errors)}")
    for kind in (*KINDS, "originals.json", "originals.pending.json"):
        (backup / kind).unlink(missing_ok=True)
    backup.rmdir()
    print("Restored the original subordinate-ID configuration.")


def main():
    parser = argparse.ArgumentParser(description="Temporary root ID reservations for disposable MXC CI hosts.")
    parser.add_argument("action", choices=("setup", "restore"))
    parser.add_argument("--backup-directory", type=Path, required=True)
    parser.add_argument("--disposable-ci-host", action="store_true")
    args = parser.parse_args()
    ci_host = os.environ.get("GITHUB_ACTIONS") == "true" or os.environ.get("TF_BUILD") == "True"
    if not args.disposable_ci_host or not ci_host:
        parser.error(
            "this helper is only for explicitly designated disposable GitHub Actions or Azure Pipelines hosts"
        )
    if os.getuid() != 0 or os.geteuid() != 0:
        parser.error("root is required")
    if not args.backup_directory.is_absolute():
        parser.error("backup-directory must be absolute")
    if args.action == "setup":
        for path in ("/proc/self/uid_map", "/proc/self/gid_map"):
            if Path(path).read_text().split() != ["0", "0", str(MAX_ID)]:
                parser.error("setup requires the unshifted host user namespace")
        configure(Path("/etc"), args.backup_directory, get_accounts())
    else:
        restore(Path("/etc"), args.backup_directory)


if __name__ == "__main__":
    main()
