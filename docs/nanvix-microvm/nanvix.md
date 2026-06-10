# Nanvix MicroVM Backend

Nanvix MicroVM is an experimental containment backend for MxC. It is powered by the
[Nanvix OS/VM](https://aka.ms/nanvix) and runs untrusted code with hardware-enforced isolation
via the Windows Hypervisor Platform (WHP) on Windows or KVM on Linux.

## Key Features

- **Fast cold-start** — ~100 ms from process spawn to guest code execution (Windows warm-start via WHP snapshot; Linux uses cold boot via KVM every run)
- **Low Memory Footprint** — Resident memory size of ~100 MB
- **Hardware-Enforced Isolation** — Runs guest code inside a lightweight virtual machine (VM)

## Requirements

### Windows

- Windows with WHP enabled (`bcdedit /set hypervisorlaunchtype auto`)
- Nanvix runtime binaries (`nanvixd.exe`, `kernel.elf`, `python3.initrd`, `nanvix_rootfs.img`) placed next to `wxc-exec.exe`
- Build with `--with-microvm` (`build.bat --with-microvm` or `cargo build -p wxc --features microvm`)
- `--experimental` flag (Nanvix MicroVM is an experimental feature)

### Linux

- Linux with KVM available at `/dev/kvm` (and the invoking user has read/write access to it)
- Nanvix runtime binaries (`nanvixd.elf`, `kernel.elf`, `python3.initrd`, `nanvix_rootfs.img`) placed next to `lxc-exec` (the build script downloads and stages them automatically)
- Build with `--with-microvm` (`./build.sh --with-microvm` or `cargo build -p lxc --features microvm`)
- `--experimental` flag (Nanvix MicroVM is an experimental feature)

> **Note:** On Linux, WHP snapshots are not used. Each invocation cold-boots
> the VM via KVM. Snapshot-based warm-start is Windows-only.

### Offline builds

By default the `nanvix_binaries` build script downloads the NanVix release
assets at compile time. For air-gapped or hermetic builds, pre-fetch the
binaries and point the `NANVIX_BIN` environment variable at the directory
containing them:

```
# Windows (PowerShell)
$env:NANVIX_BIN = "C:\path\to\nanvix-binaries"

# Linux / macOS
export NANVIX_BIN=/path/to/nanvix-binaries
```

When `NANVIX_BIN` is set, the build performs no network downloads and uses the
provided directory directly. The directory must contain the required binaries
(the flat files plus the `bin/` subdirectory); their checksums are still
verified against `checksums.json`. The easiest way to produce such a directory
is to run a normal `--with-microvm` build once and copy the staged
`nanvix-binaries` directory out of `OUT_DIR`.

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
per-run staging directory before boot. Nanvix mounts are snapshot-based — host
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
| ------------------ | --------------------------- |
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
| --------------------------------------- | ------------------------------------------- |
| Single file size                        | < 4 GB (FAT32 limit)                        |
| Guest RAM                               | 256 MB                                      |
| Symlinks/reparse points in source paths | Not supported (rejected at preflight)       |
| Junctions for staging                   | Not used                                    |
| `workingDirectory`                      | Not supported (guest CWD is `/`)            |
| Network policy                          | Not supported (Nanvix has no network stack) |

## Not Supported

| Workload                        | Error                               |
| ------------------------------- | ----------------------------------- |
| Network I/O                     | `OSError: Function not implemented` |
| File writing outside `/mnt/rw/` | `OSError: Read-only file system`    |
