# Host preparation: `--prepare-system-drive`

The `wxc-exec --prepare-system-drive` flag adds two persistent allow ACEs to
the system-drive root (typically `C:\`) so that AppContainer-isolated
processes can read directory metadata of the drive. Many common tools —
`cmd.exe`, `powershell.exe`, `pwsh.exe`, `node.exe` — call APIs like
`GetFileAttributesW("C:\\")`, `_stat("C:\\")`, or
`[IO.DirectoryInfo]::GetAccessControl` during startup and fail with
`ERROR_ACCESS_DENIED` inside an AppContainer because the well-known
AppContainer SIDs are not granted any rights on the system-drive root
by default.

This is a one-time, host-wide setup step — it does not need to be re-run
per container or per session.

## What it grants

| Trustee | SID | Access mask | Inheritance |
| --- | --- | --- | --- |
| `ALL APPLICATION PACKAGES` | `S-1-15-2-1` | `FILE_READ_ATTRIBUTES \| FILE_READ_EA \| READ_CONTROL \| SYNCHRONIZE` (`0x00120088`) | none |
| `ALL RESTRICTED APPLICATION PACKAGES` | `S-1-15-2-2` | same | none |

What this **does not** grant:

- `FILE_LIST_DIRECTORY` — the container still cannot enumerate `C:\`.
- `FILE_READ_DATA` — irrelevant on a directory, but explicit.
- any write rights.

Because the ACEs are non-inheriting, descendant files and subdirectories
of `C:\` are not affected — the change is scoped to the directory object
itself.

## Usage

```
wxc-exec --prepare-system-drive
```

The flag self-elevates via UAC. If the current process is not already
elevated, Windows shows a UAC prompt; the elevated child does the DACL
write and exits, and the unelevated parent reports success.

```
wxc-exec --unprepare-system-drive
```

Removes ACEs the prepare step added. Uses **precise tuple matching**:
only ACEs whose `(access mask, ACE type, inheritance flags)` exactly
match what `--prepare-system-drive` would have authored are removed.
Other explicit ACEs for the same SIDs — e.g. an existing
`icacls C:\ /grant "ALL APPLICATION PACKAGES":(R)` written by a
third-party tool — are preserved. This is symmetric with the PowerShell
`Unprepare-SystemDriveForAppContainer.ps1` script's
`RemoveAccessRuleSpecific` semantics.

Re-running `--prepare-system-drive` is safe when our exact ACE is
already present — the scan-before-apply detects the existing match and
performs an idempotent no-op. The precise-revoke path is similarly
idempotent. However: if the system-drive root already has an explicit
Allow ACE for one of the well-known AppContainer SIDs with a *different*
mask or inheritance, `--prepare-system-drive` will **refuse** rather
than silently coalesce. The error message names the conflicting trustee
and suggests an `icacls` command to clean it up first. Without this
guard, `SetEntriesInAclW(GRANT_ACCESS)` would merge the masks and the
tuple-precise revoke would not be able to undo the merge.

## Verifying the result

After running `--prepare-system-drive`, the two ACEs should be visible
in the system-drive root's DACL:

```powershell
(Get-Acl C:\).Access |
    Where-Object { [uint32]$_.FileSystemRights -eq 0x00120088 -and -not $_.IsInherited }
```

You should see two entries — one each for the two AppContainer groups —
both with `FileSystemRights` listing
`ReadAttributes, ReadExtendedAttributes, ReadPermissions, Synchronize`,
`AccessControlType` of `Allow`, and `InheritanceFlags` of `None`.

## Implementation notes

- Windows does not allow a running process to elevate its own token, so
  the unelevated parent re-launches itself with `ShellExecuteExW` and the
  `runas` verb. A hidden `--internal-elevated-helper` flag is set on the
  child; if that flag is observed in a process whose token is not
  elevated (which should be unreachable in practice because
  `ShellExecuteExW(runas)` either elevates or returns `Err`), the helper
  refuses to recurse — defense in depth against unforeseen spawn loops.
- The unelevated parent resolves the target path once (from
  `%SystemDrive%`) and passes it to the elevated child via
  `--internal-target-path`. The child does **not** re-read
  `%SystemDrive%` from environment — which would otherwise let an
  unelevated user steer the elevated DACL write at an arbitrary drive
  via inherited env. The child validates the passed path is a literal
  drive root (`X:\`) before touching its DACL.
- The elevated child writes its console output to a per-invocation log
  file under the **unelevated parent's** `%TEMP%`. The parent picks the
  path (`%TEMP%\wxc-exec-prepare-system-drive-<pid>-<nonce>.log`) and
  passes it to the child via `--internal-log-path`. This works under
  both same-user UAC (where parent and child agree on `%TEMP%`
  naturally) and over-the-shoulder UAC (where the elevated child runs
  as a different user and would otherwise resolve `%TEMP%` against
  another profile, making the log invisible to the parent). The
  unelevated parent reads this file on non-zero child exit and prints
  the contents to stderr, so the user sees a real diagnostic instead
  of just `ChildFailed(<code>)`. The elevated child runs hidden
  (`SW_HIDE`) — the UAC dialog itself is system-rendered and
  unaffected.
- The parent quotes `--internal-target-path` and `--internal-log-path`
  per the documented `CommandLineToArgvW` rules — critically, doubling
  any backslashes that immediately precede the closing quote. Without
  this, a drive root like `C:\` would be passed as `"C:\"` and the
  parser would interpret `\"` as an escaped literal quote, mangling
  the argument.
- The DACL operations use the same `GetNamedSecurityInfoW` →
  `SetEntriesInAclW` → `SetNamedSecurityInfoW` sequence as
  `wxc_common::filesystem_dacl`. Apply ACEs are *not* tracked by
  `DaclManager` because the change is intentionally persistent across
  process exit. The precise-revoke path scans the existing DACL via
  `GetAce` to find ACEs matching our exact tuple, then issues a single
  `REVOKE_ACCESS` for the SID followed by replay of any non-matching
  explicit ACEs — symmetric with `restore_one`'s pattern.
- Unit tests redirect the target path to a tempdir via the debug-only
  `MXC_PREPARE_PATH_OVERRIDE` env var. The elevation flow itself is
  verified manually with the PowerShell scripts in
  [`scripts/host-prep/`](../scripts/host-prep/), which mirror the Rust
  implementation for hand-testing without rebuilding `wxc-exec`.
