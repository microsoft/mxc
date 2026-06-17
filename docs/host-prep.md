# Host preparation: `wxc-host-prep.exe`

`wxc-host-prep.exe` is a Windows-only, privileged-by-manifest binary
that owns the one-time host setup steps MXC requires before
AppContainer- and other sandboxed workloads can run reliably. It is
shipped alongside `wxc-exec.exe` inside the SDK bin payload.

The binary has `requireAdministrator` baked into its embedded
application manifest in release builds. The Windows loader prompts
for UAC at process start (or, when launched under SYSTEM — e.g. from
a scheduled task — satisfies the requirement trivially). The
sandbox launcher `wxc-exec.exe` never elevates itself; all
privilege-requiring setup work lives in `wxc-host-prep.exe` instead.

> **Migrated from `wxc-exec --prepare-system-drive`.** Earlier
> revisions of MXC let `wxc-exec` self-elevate via a hand-rolled
> `ShellExecuteExW(runas)` dance. That capability has been removed
> — `wxc-exec --prepare-system-drive` and
> `wxc-exec --unprepare-system-drive` no longer exist. Use the
> `wxc-host-prep` subcommands documented below.

## Subcommands

| Subcommand | Purpose |
| --- | --- |
| `prepare-system-drive` | Add minimum-rights ACEs for AppContainer SIDs to the system-drive root. |
| `unprepare-system-drive` | Remove ACEs added by `prepare-system-drive` using precise tuple matching. |
| `prepare-null-device` | Apply MXC's managed security descriptor to `\Device\Null`. |
| `verify-null-device` | Check `\Device\Null` SD against the target without modifying it. |
| `dump-null-device` | Print the current `\Device\Null` SD as SDDL. |

All subcommands require elevation. The binary aborts with exit code
`65` and a clear message if launched without an elevated token (e.g.
running a debug build directly without `Run as Administrator`).

### When does MXC need these?

The system-drive and null-device preparations matter for the
**AppContainer + DACL** isolation tier (Tier 3), which MXC selects on
hosts where the in-process BaseContainer API is absent *or present but
not usable* (the symbol resolves yet the feature is disabled), and (for
builds that ship without the `tier2_bfs` Cargo feature) without
AppContainer + BFS either. To make the requirement discoverable,
`wxc-exec --probe` (the
detection-only path the SDK's `getPlatformSupport()` uses) emits an
operator-visible warning recommending the relevant `wxc-host-prep`
subcommand **whenever Tier 3 is selected and the corresponding prep is
not already in effect**:

- If the system-drive root is missing the metadata ACEs, the probe
  recommends `wxc-host-prep prepare-system-drive`.
- If `\Device\Null` does not grant the AppContainer package SIDs (it
  resets to an AppContainer-hostile default at every boot), the probe
  recommends `wxc-host-prep prepare-null-device`.

The probe performs these checks read-only (no elevation, no writes); it
suppresses a recommendation once the matching prep is detected.

### `prepare-system-drive`

Adds two persistent, non-inheriting allow ACEs to the system-drive
root (typically `C:\`) for the well-known AppContainer SIDs. Many
common tools — `cmd.exe`, `powershell.exe`, `pwsh.exe`, `node.exe` —
call APIs like `GetFileAttributesW("C:\\")`, `_stat("C:\\")`, or
`[IO.DirectoryInfo]::GetAccessControl` during startup and fail with
`ERROR_ACCESS_DENIED` inside an AppContainer because the well-known
AppContainer SIDs are not granted any rights on the system-drive
root by default.

This is a one-time, host-wide setup step.

```
wxc-host-prep prepare-system-drive [--target <path>]
```

`--target` overrides the system-drive lookup; the supplied path must
be a literal drive root (`X:\`). Without it the binary uses
`%SystemDrive%`.

| Trustee | SID | Access mask | Inheritance |
| --- | --- | --- | --- |
| `ALL APPLICATION PACKAGES` | `S-1-15-2-1` | `FILE_READ_ATTRIBUTES \| FILE_READ_EA \| READ_CONTROL \| SYNCHRONIZE` (`0x00120088`) | none |
| `ALL RESTRICTED APPLICATION PACKAGES` | `S-1-15-2-2` | same | none |

What this **does not** grant:

- `FILE_LIST_DIRECTORY` — containers still cannot enumerate `C:\`.
- `FILE_READ_DATA` — irrelevant on a directory, but explicit.
- any write rights.

Because the ACEs are non-inheriting, descendant files and
subdirectories of `C:\` are unaffected.

Re-running `prepare-system-drive` is idempotent: when our exact ACE
is already present, the scan-before-apply path detects the match and
performs a no-op. If the system-drive root already has an explicit
Allow ACE for one of the well-known AppContainer SIDs with a
*different* mask or inheritance, the subcommand **refuses** rather
than silently coalesce. The error message names the conflicting
trustee and suggests an `icacls` command to clean it up first.
Without this guard, `SetEntriesInAclW(GRANT_ACCESS)` would merge the
masks and the tuple-precise revoke would not be able to undo the
merge.

### `unprepare-system-drive`

```
wxc-host-prep unprepare-system-drive [--target <path>]
```

Removes ACEs added by `prepare-system-drive`. Uses **precise tuple
matching**: only ACEs whose `(access mask, ACE type, inheritance
flags)` exactly match what `prepare-system-drive` would have
authored are removed. Other explicit ACEs for the same SIDs — e.g.
an existing `icacls C:\ /grant "ALL APPLICATION PACKAGES":(R)`
written by a third-party tool — are preserved.

After running, the two ACEs should no longer appear in the DACL:

```powershell
(Get-Acl C:\).Access |
    Where-Object { [uint32]$_.FileSystemRights -eq 0x00120088 -and -not $_.IsInherited }
```

should return nothing.

### `prepare-null-device`

```
wxc-host-prep prepare-null-device [--no-sacl] [--quiet] [--json] [--log <path>]
```

Applies MXC's managed security descriptor to `\Device\Null`. The
Windows kernel resets the SD to a default value at every boot; for
the AppContainer-based backends the default does not include the
well-known AppContainer SIDs, and processes that open `NUL` for
stdin/stdout/stderr redirection fail with `ERROR_ACCESS_DENIED`
partway through startup. Run `prepare-null-device` once per boot
from an elevated context (e.g. a scheduled task, an MDM-managed
startup script, or interactively from an elevated prompt).

The target SDDL is:

```
O:BAG:SYD:(A;;GRGWGX;;;WD)(A;;FA;;;SY)(A;;FA;;;BA)(A;;GRGX;;;RC)(A;;GRGWGX;;;AC)(A;;GRGWGX;;;S-1-15-2-2)S:(ML;;NW;;;LW)
```

That decomposes to:

| Component | Trustee | SID | Rights |
| --- | --- | --- | --- |
| Owner | `BUILTIN\Administrators` | `BA` | n/a |
| Group | `NT AUTHORITY\SYSTEM` | `SY` | n/a |
| DACL allow | `Everyone` | `WD` | `GENERIC_READ \| GENERIC_WRITE \| GENERIC_EXECUTE` |
| DACL allow | `NT AUTHORITY\SYSTEM` | `SY` | `FILE_ALL_ACCESS` |
| DACL allow | `BUILTIN\Administrators` | `BA` | `FILE_ALL_ACCESS` |
| DACL allow | `RESTRICTED` | `RC` | `GENERIC_READ \| GENERIC_EXECUTE` |
| DACL allow | `ALL APPLICATION PACKAGES` | `AC` | `GENERIC_READ \| GENERIC_WRITE \| GENERIC_EXECUTE` |
| DACL allow | `ALL RESTRICTED APPLICATION PACKAGES` | `S-1-15-2-2` | `GENERIC_READ \| GENERIC_WRITE \| GENERIC_EXECUTE` |
| SACL mandatory label | `Low Integrity` | `LW` | `NO_WRITE_UP` |

`--no-sacl` skips the SACL component (the mandatory integrity
label is still applied via the separate `LABEL_SECURITY_INFORMATION`
write path, which does not require `SeSecurityPrivilege`). Use this
when `SeSecurityPrivilege` is unavailable in the calling token. The
DACL — the part that actually unblocks AppContainer access — is
still written.

`--quiet` suppresses the human-readable status line. `--json`
emits a single-line JSON record describing the result. `--log`
overrides the default log path
(`%ProgramData%\mxc\null-device-acl.log`).

The apply path reads the current SD, compares it structurally
against the target (order-insensitive set comparison of
`(SID, ACE type, ACE flags, access mask)` tuples), and only
writes when a difference is found. When the current SD already
matches the result is reported as `"no-change"`; a successful write
is reported as `"applied"`. Both are exit code 0; consumers
distinguish them by the JSON / log record.

### `verify-null-device`

```
wxc-host-prep verify-null-device [--json]
```

Reads the current `\Device\Null` SD and compares it against the
target without modifying anything. Exit code `0` means match; exit
code `1` means drift. With `--json` a single-line JSON record
documents which component differs (`owner-differs`,
`group-differs`, `dacl-differs`, `sacl-differs`).

Intended for monitoring: scheduled-task or telemetry agents can
invoke `verify-null-device --json` periodically and alert on a
non-zero exit code.

### `dump-null-device`

```
wxc-host-prep dump-null-device [--json]
```

Prints the current `\Device\Null` SD as SDDL. With `--json` the
SDDL string is wrapped in a JSON object of the form
`{"op":"dump-null-device","sddl":"…"}`. Read-only — the SD is not
modified.

Use for triage after `verify-null-device` reports drift.
`verify-null-device --json` is the right place to look for the
drift label; `dump-null-device` deliberately only reports the
current SD.

## Logs

`prepare-null-device` writes a JSON-Lines log record to
`%ProgramData%\mxc\null-device-acl.log`, rotated at ~1 MB. Each
record contains:

```json
{"ts":"2025-01-01T12:00:00Z","op":"prepare-null-device","want_sacl":true,"result":"applied","drift":"dacl-differs"}
```

Drift label is `"n/a"` when the result is `"no-change"`. Pass
`--log <path>` to redirect.

`prepare-system-drive` and `unprepare-system-drive` do not write
file logs today — they print one line per operation to stdout
(success path) or stderr (failure path). They're intended to be
run interactively by an admin or once at install time by a wrapper
that captures stdout/stderr itself.

## Exit codes

| Code | Meaning |
| --- | --- |
| `0` | Operation completed successfully (no-change or applied). |
| `1` | Drift detected (`verify-null-device` only) or generic non-fatal error. |
| `2` | Could not open `\Device\Null` (typically a missing privilege or device-namespace ACL). |
| `3` | `SeSecurityPrivilege` could not be enabled for the calling token. |
| `4` | `SetKernelObjectSecurity` failed during write. |
| `5` | The hard-coded target SDDL failed to parse. Indicates an MXC bug — report it. |
| `6` | System-drive DACL operation failed. |
| `64` | clap parse error (unknown flag / bad argument). |
| `65` | The current token is not elevated. |

## Implementation notes

- The binary's elevation requirement is enforced by both the
  embedded application manifest (Windows-loader-level guard) and a
  runtime `GetTokenInformation(TokenElevation)` check in
  `elevation_check::require_elevated`. Defence in depth — the
  runtime check still trips if a debug build (no manifest) is
  launched without `Run as Administrator`.
- The DACL operations for `prepare-system-drive` /
  `unprepare-system-drive` use the same
  `GetNamedSecurityInfoW` → `SetEntriesInAclW` →
  `SetNamedSecurityInfoW` sequence as
  `wxc_common::filesystem_dacl`. Apply ACEs are *not* tracked by
  `DaclManager` — the change is intentionally persistent across
  process exit. The precise-revoke path scans the existing DACL
  via `GetAce` to find ACEs matching our exact tuple, then issues
  a single `REVOKE_ACCESS` for the SID followed by replay of any
  non-matching explicit ACEs — symmetric with the runtime
  `restore_one` pattern.
- `prepare-null-device` writes the entire target SD in one
  `SetKernelObjectSecurity` call rather than mutating components
  piecemeal. Writing components in sequence creates
  failure-recovery edge cases (partial application leaves the
  device in an unintended state); writing the whole SD trades a
  slightly larger blob for atomic semantics.
- The mandatory integrity label is part of the SACL on disk, but
  its in-API info bit is the separate `LABEL_SECURITY_INFORMATION`
  flag, which does not require `SeSecurityPrivilege`. Reads and
  writes always include this bit even when the caller declined to
  touch the full SACL (`--no-sacl`), so the integrity label
  round-trips faithfully.
