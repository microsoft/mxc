# MicroVM PTY Parity & Filesystem Policy Support

| Field          | Value                                              |
|----------------|----------------------------------------------------|
| **Status**     | Draft                                              |
| **Date**       | 2026-04-27                                         |
| **Branch**     | `user/modanish/NanVix-PTY`                         |
| **Depends on** | nanvixd `-mount` support (nanvix/nanvix PR #2057)  |
| **Depends on** | SDK `spawnSandboxFromConfig` + `usePty` (mxc PR #209) |

---

## 1. Problem Statement

The NanVix microvm backend in MXC has two limitations that prevent SDK parity with AppContainer and other containment backends:

1. **No PTY input.** The runner hijacks stdin to deliver the user's script via `exec(sys.stdin.read())`, then closes the pipe. SDK consumers using `IPty.write()` or guest code calling `input()` get nothing — the pipe is dead after script delivery.

2. **No filesystem policy.** The runner hard-rejects `readwrite_paths`, `readonly_paths`, and `denied_paths`. The guest has only a read-only ramfs with no access to host files.

Both problems trace to the same root cause: there is no mechanism to deliver the script *or* host files to the guest except stdin and the pre-built ramfs.

## 2. Solution Overview

Use nanvixd's `-mount <host-dir>` feature (PR #2057, merged to `dev`) to deliver the script as a file and stage host paths into a single mount directory. This frees stdin for genuine PTY relay and enables filesystem policy support through the same mechanism.

### Before

```
wxc-exec:
  spawn nanvixd ... -- python.elf "-S -B -c exec(stdin.read());PYTHONHOME=/sysroot"
  stdin:  piped → write script → close  (PTY dead)
  stdout: inherit  (PTY ok)
  stderr: inherit  (PTY ok)
```

### After

```
wxc-exec:
  build staging_dir/  (script + rw/ro paths)
  spawn nanvixd ... -mount staging_dir -- python.elf "/mnt/.mxc-bootstrap.py;PYTHONHOME=/sysroot"
  stdin:  inherit  (full ConPTY relay)
  stdout: inherit  (PTY ok)
  stderr: inherit  (PTY ok)
```

## 3. Architecture

### 3.1 Staging Directory

NanVix supports one `-mount` directory per VM. We build a per-request staging directory that merges the script and all filesystem policy paths into a single tree:

```
%TEMP%\mxc-microvm\<uuid>\          ← single -mount target
├── .mxc-bootstrap.py               ← loader that runs the user script
├── .mxc-script.py                  ← user's request.script_code (byte-exact)
├── .mxc-pathmap.json               ← slug→guest-path mapping
├── rw\
│   ├── <slot-1>\  ←── junction/copy of readwrite_paths[0]
│   └── <slot-2>\  ←── junction/copy of readwrite_paths[1]
└── ro\
    ├── <slot-1>\  ←── copy of readonly_paths[0] (FAT32 RO attribute set)
    └── <slot-2>\  ←── copy of readonly_paths[1]
```

**Slot naming:** `basename(host_path)`. On collision, append `-2`, `-3`, etc.

**Size cap:** total staging content must be ≤ 16 MB (nanvixd mount image limit). Larger staging → preflight rejection with a clear error message.

### 3.2 Bootstrap Script

The bootstrap lives only in the staging directory (not baked into cpython-ramfs.img):

```python
# .mxc-bootstrap.py
import json, os, runpy, sys

# Export path mapping as environment variables
with open('/mnt/.mxc-pathmap.json') as f:
    for slug, guest_path in json.load(f).items():
        os.environ[f'MXC_PATH_{slug}'] = guest_path

# Run the user's script; stdin is untouched → input()/REPLs work
sys.argv = ['/mnt/.mxc-script.py']
runpy.run_path(sys.argv[0], run_name='__main__')
```

### 3.3 Path Map

Written to `.mxc-pathmap.json` in the staging directory by the Rust runner:

```json
{
  "INPUT": "/mnt/rw/input",
  "OUTPUT": "/mnt/rw/output",
  "REF_DATA": "/mnt/ro/ref-data"
}
```

**Slug rule:** `to_upper_snake_case(basename(host_path))`.
- `C:\work\input` → `INPUT`
- `C:\data\ref-data` → `REF_DATA`
- Collision: `C:\a\input` and `C:\b\input` → `INPUT` and `INPUT_2`

Guest scripts access paths via `os.environ['MXC_PATH_INPUT']`.

### 3.4 nanvixd Spawn Line

```
nanvixd.exe
  -bin-dir <dir>
  -ramfs cpython-ramfs.img
  -mount <staging_dir>
  --
  python.elf "/mnt/.mxc-bootstrap.py;PYTHONHOME=/sysroot"
```

Guest argument note: CPython treats the first non-option argument as a script filename. `/mnt/.mxc-bootstrap.py` contains no spaces, so it survives NanVix's space-splitting in `build_string_table()`. The `;` separator places `PYTHONHOME` as an env var (parsed by NanVix's kernel at `kmain.rs:231`).

### 3.4.1 Staging: Junction vs Copy for readwrite_paths

For `readwrite_paths`, the staging directory uses **directory junctions** (Windows) or **symlinks** (future Linux) when possible. This avoids copying potentially large directories at staging time.

However, nanvixd's `-mount` reads the staged directory to build a FAT32 image, and junctions are resolved transparently by Windows filesystem APIs — so the content is captured correctly.

**Fallback to copy:** if junction creation fails (e.g., path is a single file, not a directory; or the path is on a network share), fall back to a full copy. Single files are wrapped in a slot subdirectory before copying.

For `readonly_paths`, always **copy** (we need to set the FAT32 RO attribute on the copies without modifying the originals).

### 3.5 stdin / stdout / stderr

| Stream | Before                        | After                          |
|--------|-------------------------------|--------------------------------|
| stdin  | `Stdio::piped()`, closed      | `Stdio::inherit()` (ConPTY)    |
| stdout | `Stdio::inherit()`            | `Stdio::inherit()` (unchanged) |
| stderr | `Stdio::inherit()`            | `Stdio::inherit()` (unchanged) |

With all three streams inherited, nanvixd participates in the parent's ConPTY session. The SDK's `IPty.write()` data flows through to the guest's `sys.stdin`. Guest `print()` output flows back through `IPty.onData()`.

### 3.6 Guest stdin Caveat

`sys.stdin.isatty()` returns `False` in the guest — NanVix forwards stdin via an IKC pipe, not a kernel TTY device. This is a known limitation. Documented in `docs/microvm.md`.

## 4. Filesystem Policy Semantics

### 4.1 Policy Field Behavior

| Field                      | microvm behavior                                               |
|----------------------------|----------------------------------------------------------------|
| `filesystem.readwritePaths`| Staged into `/mnt/rw/<slot>`; copyback to host on clean exit   |
| `filesystem.readonlyPaths` | Staged into `/mnt/ro/<slot>`; FAT32 RO attribute set on files  |
| `filesystem.deniedPaths`   | **Rejected** — config error; microvm has no host visibility    |
| `network.*`                | **Rejected** — NanVix has no network stack (unchanged)         |
| `network.proxy`            | **Rejected** — NanVix has no network stack (unchanged)         |
| `workingDirectory`         | **Rejected** — guest CWD is `/` (unchanged)                    |

### 4.2 Copyback Semantics (readwrite_paths)

nanvixd's `-mount` implements snapshot-based mounting:

1. **Boot:** host directory packaged into FAT32 image, loaded into guest memory.
2. **Run:** guest reads/writes freely inside `/mnt/rw/*`.
3. **Exit:** nanvixd reads modified RAMFS from guest memory, extracts files back to the original host directory.

| Exit path         | Copyback? | Staging cleanup? |
|-------------------|-----------|------------------|
| Normal exit       | Yes       | Yes              |
| Watchdog timeout  | No        | Yes              |
| nanvixd crash     | No        | Yes              |
| Preflight failure | n/a       | n/a              |
| Spawn failure     | n/a       | Yes (partial)    |

**Copyback failure handling:** if copyback fails (disk full, file locked, host path deleted), the runner logs a structured warning to stderr and returns the guest's exit code unchanged. Copyback is best-effort.

### 4.3 Read-Only Enforcement

Files under `ro/` have the FAT32 read-only attribute set during staging. The guest kernel enforces this at the FAT32 driver level — writes return `EACCES`. This is weaker than the `-share` mechanism (which returns `EROFS` at the VFS layer), but sufficient for policy enforcement since the guest is already fully sandboxed.

### 4.4 Size Constraints

| Constraint              | Value   | Source                          |
|-------------------------|---------|---------------------------------|
| Total staging dir       | ≤ 16 MB | nanvixd mount image cap         |
| Single file             | < 4 GB  | FAT32 file size limit           |
| Guest RAM               | 128 MB  | kernel_config.toml              |
| Mount image overhead    | ~20 ms/MB | Empirical (FAT32 build)       |

## 5. Error Handling

### 5.1 Error Classification

Extends the existing `NanVixError` enum:

| Variant      | New triggers                                                         |
|--------------|----------------------------------------------------------------------|
| `Preflight`  | Mount source path doesn't exist; staging > 16 MB; `denied_paths` non-empty; symlink in source; file > 4 GB; slug collision unresolvable |
| `Platform`   | Staging dir creation fails; FAT RO bit set fails; junction fails     |
| `Runtime`    | nanvixd mount image build failure; copyback failure (logged, non-fatal) |
| `Timeout`    | Unchanged — explicitly skips copyback                                |

### 5.2 Error Messages

| Condition | Message |
|---|---|
| `denied_paths` non-empty | `NanVix preflight error: denied_paths is not meaningful for the microvm backend — the guest has no host filesystem visibility. Only readwrite_paths and readonly_paths are supported.` |
| Staging too large | `NanVix preflight error: total filesystem policy content is {size} MB, exceeding the 16 MB mount image limit. Reduce the number or size of readwrite_paths/readonly_paths.` |
| Symlink in path | `NanVix preflight error: symbolic links in readwrite_paths/readonly_paths are not supported — FAT32 has no symlink representation. Path: {path}` |
| Source path missing | `NanVix preflight error: readwrite path does not exist: {path}` |

## 6. Boot Timeout Adjustment

Mount image build adds overhead proportional to staging size. The total timeout formula becomes:

```
total_timeout = BOOT_TIMEOUT_MS + staging_overhead_ms + script_timeout
```

Where:
- `BOOT_TIMEOUT_MS` = 60,000 ms (unchanged)
- `staging_overhead_ms` = `staging_size_mb × 100` ms, capped at 30,000 ms
- `script_timeout` = from JSON config `timeout` field

## 7. Concurrency

Each request gets a unique staging directory under `%TEMP%\mxc-microvm\<uuid>\`. Parallel invocations are safe — no shared state.

## 8. Lifecycle & Cleanup

The staging directory is managed by a RAII `StagingDir` struct with a `Drop` implementation that removes the directory tree. This guarantees cleanup even if the runner panics.

```rust
struct StagingDir {
    path: PathBuf,
}

impl Drop for StagingDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.path);
    }
}
```

## 9. Test Plan

### 9.1 Unit Tests (in `nanvix_runner.rs` / `microvm_staging.rs`)

| Test | Validates |
|------|-----------|
| `staging_empty_policy` | No rw/ro paths → staging has only bootstrap + script |
| `staging_single_rw_path` | One readwrite path → correct staging layout |
| `staging_multiple_rw_ro` | Mixed rw + ro paths → correct layout with subdirs |
| `staging_slug_collision` | Two paths with same basename → `-2` suffix |
| `staging_slug_generation` | Various basenames → correct UPPER_SNAKE slugs |
| `staging_size_cap_reject` | Content > 16 MB → Preflight error |
| `staging_denied_paths_reject` | Non-empty denied_paths → Preflight error |
| `staging_symlink_reject` | Symlink in source path → Preflight error |
| `staging_ro_attribute` | Files in `ro/` have FAT32 RO attribute set |
| `staging_pathmap_json` | Path map JSON shape matches expected format |
| `staging_bootstrap_stable` | Bootstrap content is byte-stable across calls |
| `staging_cleanup_on_drop` | Drop guard removes staging dir |
| `staging_single_file_rw` | Single file (not dir) as readwrite path → wrapped in slot dir |
| `total_timeout_with_staging` | Timeout formula includes staging overhead |
| `guest_args_with_mount` | Guest args use bootstrap path, not exec(stdin) |

### 9.2 Integration Tests (require WHP + nanvixd with -mount)

| Config | Validates |
|--------|-----------|
| `microvm_pty_input.json` | Script calls `input()`, SDK writes `"hello\n"`, expect echo |
| `microvm_rw_path.json` | Script reads `MXC_PATH_INPUT/data.txt`, writes output, host verifies copyback |
| `microvm_ro_path.json` | Script tries to write to `MXC_PATH_REF/x.txt`, expects EACCES |
| `microvm_collision.json` | Two paths same basename → `MXC_PATH_INPUT` and `MXC_PATH_INPUT_2` |
| `microvm_size_cap.json` | Staging > 16 MB → preflight error |
| `microvm_denied_paths.json` | Non-empty denied_paths → preflight error |
| `microvm_timeout.json` | Script exceeds timeout → copyback skipped, non-zero exit |
| `microvm_repl.json` | `code.interact()` → write commands via PTY, expect responses |
| `microvm_no_fs.json` | Empty FS policy → regression test for current behavior with mount-based script delivery |

### 9.3 E2E via `wxc_test_driver`

Wired into `test_scripts\run_test_configs.bat` with `runs_on = ["microvm"]` filter.

## 10. Files Changed

| Layer | File | Change |
|-------|------|--------|
| Rust runner | `src/wxc_common/src/nanvix_runner.rs` | Staging dir integration; mount cmdline; `Stdio::inherit()` for stdin; validate_policies lifts RW/RO rejection, adds `denied_paths` explicit reject; new unit tests |
| Rust module | `src/wxc_common/src/microvm_staging.rs` (NEW) | `StagingDir` RAII struct, slug generation, RO bit logic, path map JSON builder, size validation |
| Rust lib | `src/wxc_common/src/lib.rs` | `pub mod microvm_staging;` |
| Cargo | `src/wxc_common/Cargo.toml` | Add `uuid` + `tempfile` dependencies |
| Setup | `scripts/setup-nanvix.ps1` | Bump nanvixd artifact to release with `-mount` |
| Setup | `scripts/setup-nanvix.sh` | Same |
| Docs | `docs/microvm.md` (NEW) | User-facing: env vars, copyback semantics, size cap, `isatty()==False` caveat |
| Docs | `docs/nanvix-integration-plan.md` | Update supported/unsupported tables |
| Tests | `test_configs/microvm/*.json` (NEW) | Integration test configs from §9.2 |
| Schema | `schemas/dev/mxc-config.schema.0.5.0-dev.json` | No change |
| SDK | No change | `spawnSandboxFromConfig` + `usePty` from PR #209 is sufficient |

## 11. External Dependencies

| Dependency | Version | Required by |
|---|---|---|
| nanvixd.exe with `-mount` | nanvix/nanvix PR #2057+ | Core feature |
| SDK `usePty` option | mxc PR #209 | SDK consumers (not our code) |

## 12. Non-Goals (explicit)

- Real-time bidirectional FS via HostFs IKC proxy (future enhancement)
- Multi-mount (>1 host dir per VM) at nanvix level
- True TTY in the guest (`isatty()==True`, SIGWINCH, resize)
- `denied_paths` semantics — explicitly rejected
- `workingDirectory` support — explicitly rejected
- Network policy support — unchanged (still rejected)
- AppContainer changes
- `spawnSandbox()` API changes
