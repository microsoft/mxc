# MicroVM Backend (NanVix)

The MicroVM backend runs Python code inside a NanVix microkernel VM with hardware-enforced isolation via Windows Hypervisor Platform (WHP).

## Requirements

- Windows with WHP enabled (`bcdedit /set hypervisorlaunchtype auto`)
- NanVix runtime binaries (`nanvixd.exe`, `kernel.elf`, `python3.12`, `nanvix_rootfs.img`) placed next to `wxc-exec.exe`
- `--experimental` flag (MicroVM is an experimental feature)

## Quick Start

```json
{
  "process": {
    "commandLine": "print('Hello from MicroVM!')",
    "timeout": 30000
  },
  "containment": "microvm"
}
```

```bash
wxc-exec.exe --experimental config.json
```

## SDK Usage

Use `spawnSandboxFromConfig` with `usePty: false` for reliable exit codes and
separate stdout/stderr streams:

```typescript
const child = spawnSandboxFromConfig(config, {
  experimental: true,
  usePty: false,
});

```

## Filesystem Policy

### readwrite_paths

Host directories or files listed in `readwritePaths` are copied into a private
per-run staging directory before boot. NanVix mounts are snapshot-based — host
files are **not** modified while the guest is running. No junctions or live host
mounts are used.

```json
{
  "process": {
    "commandLine": "import os\npath = 'C:\\\\Users\\\\me\\\\work'\nwith open(os.path.join(path, 'result.txt'), 'w') as f:\n    f.write('done')",
    "timeout": 30000
  },
  "containment": "microvm",
  "filesystem": {
    "readwritePaths": ["C:\\Users\\me\\work"]
  }
}
```

Inside the guest, host paths in the script are transparently rewritten to their
guest mount equivalents at staging time. The script uses the original host paths
and the staging layer translates them before the code reaches the VM.

| Host path          | Guest path                  |
| -------------------- | ----------------------------- |
| `C:\Users\me\work` | `/mnt/rw/c/Users/me/work`   |
| `C:\data\ref-data` | `/mnt/rw/c/data/ref-data`   |

**Copyback semantics:** After `nanvixd` exits normally, MXC copies the modified
snapshot back to the original host paths. Copyback runs for both exit code `0`
and non-zero guest exit codes. It is skipped for preflight failure, spawn
failure, watchdog timeout, and runner/runtime errors — no partial state is
leaked to the host.

### readonly_paths

Host directories listed in `readonlyPaths` are copied into the staging directory
with read-only file attributes. Writes return `EACCES`. Read-only paths are
never copied back to the host.

```json
{
  "filesystem": {
    "readonlyPaths": ["C:\\data\\reference"]
  }
}
```

### denied_paths

Not supported for MicroVM. If `deniedPaths` is specified, the config is rejected with an error.

## Constraints


| Constraint                              | Value                                       |
| ----------------------------------------- | --------------------------------------------- |
| Total filesystem policy content         | ≤ 16 MB                                    |
| Single file size                        | < 4 GB (FAT32 limit)                        |
| Guest RAM                               | 256 MB                                      |
| Symlinks/reparse points in source paths | Not supported (rejected at preflight)       |
| Junctions for staging                   | Not used                                    |
| `workingDirectory`                      | Not supported (guest CWD is `/`)            |
| Network policy                          | Not supported (NanVix has no network stack) |


## Not Supported


| Workload                       | Error                               |
| -------------------------------- | ------------------------------------- |
| Network I/O                    | `OSError: Function not implemented` |
| File writing outside `/mnt/rw/` | `OSError: Read-only file system`    |
