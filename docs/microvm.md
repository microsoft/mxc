# MicroVM Backend (NanVix)

The MicroVM backend runs Python code inside a NanVix microkernel VM with hardware-enforced isolation via Windows Hypervisor Platform (WHP).

## Requirements

- Windows with WHP enabled (`bcdedit /set hypervisorlaunchtype auto`)
- NanVix runtime binaries (`nanvixd.exe`, `kernel.elf`, `python.elf`, `cpython-ramfs.img`) placed next to `wxc-exec.exe`
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

## Interactive Input (PTY)

The MicroVM backend supports interactive stdin input. Scripts can use `input()` and the data flows through the ConPTY relay from the SDK:

```json
{
  "process": {
    "commandLine": "name = input('Name: ')\nprint(f'Hello, {name}!')",
    "timeout": 30000
  },
  "containment": "microvm"
}
```

**Caveat:** `sys.stdin.isatty()` returns `False` inside the guest. NanVix forwards stdin via an IKC pipe, not a kernel TTY device. This means libraries that check `isatty()` (e.g., `readline`) may behave differently.

## Filesystem Policy

### readwrite_paths

Host directories listed in `readwritePaths` are staged into the guest VM at boot and copied back to the host on clean exit:

```json
{
  "process": {
    "commandLine": "import os\npath = os.environ['MXC_PATH_WORK']\nwith open(os.path.join(path, 'result.txt'), 'w') as f:\n    f.write('done')",
    "timeout": 30000
  },
  "containment": "microvm",
  "filesystem": {
    "readwritePaths": ["C:\\Users\\me\\work"]
  }
}
```

Inside the guest, the path is accessible via the `MXC_PATH_<SLUG>` environment variable. The slug is derived from the directory basename in UPPER_SNAKE_CASE.

| Host path | Env var | Guest path |
|-----------|---------|------------|
| `C:\Users\me\work` | `MXC_PATH_WORK` | `/mnt/rw/work` |
| `C:\data\ref-data` | `MXC_PATH_REF_DATA` | `/mnt/rw/ref_data` |

**Copyback semantics:** Modified files are written back to the original host path on clean exit (exit code 0 or non-zero). On timeout or crash, copyback is skipped — no partial state is leaked.

### readonly_paths

Host directories listed in `readonlyPaths` are staged read-only. Writes return `EACCES`:

```json
{
  "filesystem": {
    "readonlyPaths": ["C:\\data\\reference"]
  }
}
```

### denied_paths

Not supported for MicroVM. If `deniedPaths` is specified, the config is rejected with an error. The guest has no host filesystem visibility, so deny-listing is meaningless.

## Constraints

| Constraint | Value |
|-----------|-------|
| Total filesystem policy content | ≤ 16 MB |
| Single file size | < 4 GB (FAT32 limit) |
| Guest RAM | 128 MB |
| Symlinks in source paths | Not supported (rejected at preflight) |
| `workingDirectory` | Not supported (guest CWD is `/`) |
| Network policy | Not supported (NanVix has no network stack) |

## Supported Workloads

Pure computation, string processing, JSON/data manipulation, math, date/time, hash computation, and data structures using Python's standard library.

## Not Supported

| Workload | Error |
|----------|-------|
| Network I/O | `OSError: Function not implemented` |
| File writing outside `/mnt/rw/` | `OSError: Read-only file system` |
| Subprocess | `OSError: Function not implemented` |
| SSL/TLS | `ModuleNotFoundError: No module named '_ssl'` |
| Interactive `input()` after stdin EOF | `EOFError` (only if SDK closes the PTY) |
