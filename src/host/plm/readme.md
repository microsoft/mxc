# PLM — Permissive Learning Mode

`plm.exe` is the Windows-only legacy WPR trace helper for Learning Mode. It captures both `learningModeLogging` block events and `permissiveLearningMode` allow events, then delegates ETL decoding to the same canonical `learning_mode_windows::EtlDenialAnalyzer` used by `captureDenials`.

The canonical analyzer decodes filesystem, capability, registry, and UI findings from both provider shapes. The standalone `extract-caps` command remains available only as a low-level ACE diagnostic.

PLM is invoked automatically by [`wxc-exec --audit`](../../../README.md#audit-mode-permissive-learning-mode); the standalone CLI provides interactive capture through `plm log` and existing-ETL analysis through `plm stop --trace-file`.

## How it works

1. **Capture** — the public `plm.exe` runs `asInvoker`; it does not add a service. It uses UAC once to launch a retained restricted child. That child acquires the host-wide singleton, starts WPR with the embedded profile, and remains alive through explicit stop or uncertain teardown.
2. **Run** — the operator runs the workload. The OS-side permissive sandbox logs `EventID=14` / `EventID=27` for every access that *would* have been denied.
3. **Stop** — the retained child returns ETL bytes and status over the original authenticated named pipe. The unelevated parent owns the trace, log, and config destinations, then analyzes the ETL through `EtlDenialAnalyzer`.
4. **Emit** — canonical findings are written to `denials.json` in the log directory, and a one-line JSON result reports the trace, denials, and optional adjusted-config paths.
5. **Merge (temporary compatibility)** — file and capability denials are adapted into the existing adjusted-config generator until the shared regeneration engine replaces it.

> **Capability merge caveats.** Capabilities are only merged into a `processContainer` block — backends that cannot express AppContainer capabilities (LXC, Windows Sandbox, …) are left untouched and the discovered set is reported on stderr instead. The reserved names `learningModeLogging` and `permissiveLearningMode` are never written back, because `processContainer.capabilities` rejects them.

## Layout (this PR)

| File                    | Role                                                                              |
|-------------------------|-----------------------------------------------------------------------------------|
| `src/main.rs`           | `clap` dispatch for `plm stop` / `plm log` / `plm extract-caps`                    |
| `src/elevated.rs`       | Retained `runas` guardian, singleton/WPR ownership, authenticated control pipe, ETL transfer |
| `src/elevated_protocol.rs` | Bounded success/error/ETL framing shared across the privilege boundary          |
| `src/start.rs`          | Bounded fixed `wpr -start …!AccessFailureProfile -filemode` and shared WPR command monitoring |
| `src/stop.rs`           | Existing-ETL analysis + FS/capability merge                                       |
| `src/log.rs`            | Interactive mode: Enter to start, Enter to stop, then diff vs a blank config      |
| `src/analysis.rs`       | Canonical ETL analysis, denials JSON emission, and temporary config-generator adapter |
| `src/access_event.rs`   | `LearningModeAccessEvent` plain struct                                            |
| `src/extract_caps.rs`   | DACL ACE blob decoder; resolves capability SIDs via `DeriveCapabilitySidsFromName` |
| `src/config.rs`         | JSON load/mutate; FS + capability merge into containment-backend section          |
| `src/coordination.rs`   | Cross-process singleton named-mutex and Ctrl-handler coordination                  |
| `src/secure_scratch.rs` | Pinned, access-controlled ProgramData scratch directory and recovery marker        |
| `src/wpr_path.rs`       | Resolves `wpr.exe` to its absolute `%SystemRoot%\System32` path (PATH-spoof-safe) |
| `src/profile_gen.rs`    | Inline, non-overridable WPR profile (`EMBEDDED_WPRP`)                              |

## Privilege boundary

`plm.exe` is `asInvoker`; it does **not** carry a `requireAdministrator` manifest, and no service is added. Caller-selected filesystem operations—including trace persistence, `--log-dir`, `--config-path`, `--trace-file`, ETL parsing, denials output, and adjusted-config generation—run under the caller token.

Only one hidden guarded `start` operation is launched with `ShellExecuteExW("runas")`. Its command line contains only the operation, a strictly validated unique local pipe name, and the unelevated server/owner PIDs. The retained elevated child:

- resolves `wpr.exe` from `GetSystemDirectoryW`;
- always uses the compiled-in profile (there is no public `--wprp` override or arbitrary elevated destination);
- keeps its scratch internal and temporary under an OS-resolved trusted local location with restrictive ACL/integrity handling;
- rejects remote pipes and pipe squatting (`PIPE_REJECT_REMOTE_CLIENTS` and `FILE_FLAG_FIRST_PIPE_INSTANCE`);
- authenticates the pipe server PID, while the parent authenticates the child PID returned by `ShellExecuteExW`;
- requires the invoking and elevating Windows identities to match, rejecting over-the-shoulder elevation before capture because the returned ETL is system-wide;
- acquires and retains `Global\Mxc_Plm_Audit` before touching WPR;
- creates that mutex with a protected administrator/SYSTEM-owned descriptor
  and rejects an untrusted pre-existing object;
- maintains an administrator/SYSTEM-owned high-integrity ProgramData recovery
  marker while WPR may be armed; the marker survives simultaneous process
  termination and is retained whenever cleanup is uncertain or fails;
- never auto-cancels stale or otherwise unverified WPR state: if the protected
  recovery marker remains and start conflicts, PLM fails closed so an
  administrator can inspect/clean the host without risking an unrelated trace;
- applies a 10-minute timeout to WPR start and stop operations and terminates a
  WPR control process that exceeds that bound;
- uses bounded framing for explicit success, stopped, error, and ETL responses;
- receives STOP on the original authenticated pipe, runs `wpr -stop`, marks the lifecycle stopped before ETL transfer, and releases the singleton only when the child exits;
- preserves the recovery marker and leaves WPR untouched if the owner,
  authenticated pipe, or guardian monitoring fails before an explicit stop.
  This avoids a check-then-act race in which host-wide `wpr -cancel` could
  terminate a replacement recording; an administrator must inspect the marker
  and recover WPR state manually.

There is no public or hidden standalone elevated stop/cancel entry point and no parent-to-child singleton handoff.

## CLI

### `plm stop`

Analyzes a previously captured trace without elevation.

```powershell
plm.exe stop [--config-path <path>] [--log-dir <path>] [--bin-path <path>]
             --trace-file <path>
             [--exit-code <code>] [--verbose-logging]
```

The retained guardian transfers its ETL to the unelevated caller before this command is launched. `--exit-code` is copied into the canonical `denials.json` summary.

When `--log-dir` is omitted, artifacts are written beneath `%LOCALAPPDATA%\Microsoft\MXC\PLM\logs\<timestamp>_pid<pid>`; if `%LOCALAPPDATA%` is unavailable, PLM falls back to the equivalent directory beneath `%TEMP%`. `--verbose-logging` prints per-event and per-ACE diagnostics while the trace is analyzed.

`--config-path` temporarily preserves the existing adjusted-config behavior. The adjusted config is written next to the operator's config snapshot in `--log-dir`; there is deliberately no flag to redirect it independently. The write is atomic so a downstream enforcing run never observes a truncated policy.

### `plm extract-caps`

Decode a raw hex-encoded DACL ACE buffer into a sorted list of AppContainer capability names. Useful for debugging the ACE decoder against ETW payloads dumped by other tools.

```powershell
plm.exe extract-caps --hex-bytes <hex> [--verbose-logging]
```

> **An empty result does not mean the blob contained no capabilities.** Only names on the module's built-in known-capability list are recognized, and only when the OS resolves them via `DeriveCapabilitySidsFromName` — names this Windows build rejects are skipped at table-build time, and any SID that is not in the resulting index is ignored. Capabilities are also only collected from *allow* ACEs that grant a non-zero access mask. Use `--verbose-logging` to see per-ACE decisions, including SIDs that resolved to nothing.

### `plm log`

Interactive iteration mode: press Enter to start a host-wide trace, run the operator-selected workload, then press Enter again to stop. Because this standalone flow has no sandbox job to define a process scope, the elevated guardian analyzes the source trace in protected scratch and returns only the bounded canonical findings; the host-wide ETL never crosses the privilege boundary. It then synthesizes a blank config, runs the filesystem merge, and prints the resulting config as a "diff against a blank config" preview. Automated `--audit` and `captureDenials` flows instead attach an authenticated sandbox job and analyze or retain only the process-scoped filtered trace.

It also has no public `--wprp` or destination override flags.

```powershell
plm.exe log [--verbose-logging]
```

## Building

PLM is part of the MXC workspace but excluded from `default-members` because it's Windows-only. Build it explicitly:

```powershell
cd C:\src\mxc\src
cargo build -p plm --target x86_64-pc-windows-msvc
# or for release:
cargo build -p plm --target x86_64-pc-windows-msvc --release
```

The WPR profile is embedded into `plm.exe` itself (see `src/profile_gen.rs`) and is materialized only inside the elevated child's internal temporary scratch area. `build.bat` from the repo root builds `plm.exe` and stages it next to `wxc-exec.exe` for the `--audit` integration.

## Guarded WPR `captureDenials` fallback

Besides `--audit`, `plm.exe` also serves as the elevated **guardian** for the
`processContainer.captureDenials` legacy-tier fallback (`src/elevated.rs`). When
the native PSEC/V2 Learning Mode capture path is unavailable, MXC starts a
guarded WPR session that is scoped to the sandbox's job object and its exact
process generations, then stops/analyzes it after the sandbox exits.

### Discovery and pre-launch trust gate

MXC locates `plm.exe` **module-relative to the loaded MXC native binary** — the
directory that holds `wxc-exec.exe` (the executor) and `mxc_ffi.dll` (the native
asset directory used by the FFI/C# SDK). `current_exe()` is deliberately not
used, because a framework-dependent .NET host reports `dotnet.exe` rather than
the loaded MXC module.

Co-location only *discovers* the guardian; it does not attest it. Because
`plm.exe` self-elevates, the PLM launch path enforces a **runtime trust gate**
(`src/trust.rs`) immediately before `ShellExecuteExW("runas")`, failing closed
on any of:

1. **Authenticode trust** — `WinVerifyTrust` (generic verify-v2) must succeed
   (signed, untampered, chaining to a trusted root). Revocation is checked
   across the whole chain, excluding the self-signed root
   (`WTD_REVOKE_WHOLECHAIN` + `WTD_REVOCATION_CHECK_CHAIN_EXCLUDE_ROOT`).
2. **Microsoft signer identity** — the embedded PKCS#7 signer certificate's
   Organization (`O`) must be `Microsoft Corporation`. This is keyed on the
   organization name, not a fixed thumbprint, so it survives certificate
   rollover.
3. **Directory & ancestry integrity** — every directory from the one containing
   `plm.exe` (the *leaf*) up through the volume root must be **owned** by a
   privileged principal (SYSTEM, Administrators, or TrustedInstaller — an owner
   has implicit `WRITE_DAC`), and its DACL must not grant a non-privileged
   principal dangerous rights. The masks are differentiated: the leaf rejects
   any *side-load/create/replace* right (create-file/create-subdir,
   delete-child, `DELETE`, `WRITE_DAC`, `WRITE_OWNER`, generic write/all);
   ancestors reject only rights that let someone delete/rename/re-secure the
   protected subtree (`FILE_DELETE_CHILD`, `DELETE`, `WRITE_DAC`, `WRITE_OWNER`,
   `GENERIC_ALL`) — harmless "create a sibling" rights at, say, a drive root are
   deliberately *not* over-rejected. Broad principals (Everyone, Authenticated
   Users, BUILTIN\Users) and ordinary users are non-privileged. Inherited ACEs
   are honored; inherit-only ACEs are skipped; a NULL DACL or any ACE type that
   is not a standard allow/deny **fails closed**.

To close the check-then-launch (TOCTOU) window, the gate opens `plm.exe` first
with a share mode that denies write and delete, resolves the pinned object's
stable canonical local path with `GetFinalPathNameByHandleW` (collapsing SUBST /
DOS-device / junction / symlink aliases, and rejecting UNC/remote or non-DOS
paths), and **holds that handle across `ShellExecuteExW`** while launching the
*resolved* path — never the caller's original, possibly-aliased string.
Authenticode is verified against the pinned handle itself, and the signer/
ancestor checks all run on the resolved path. So the exact object verified is
the exact object launched: it cannot be renamed, deleted, overwritten, or
alias-substituted in between.

**DLL side-loading.** `plm.exe` is a self-contained Rust/MSVC binary with no
private adjacent DLL dependencies (it links only system DLLs resolved from
`System32`). As defense-in-depth atop the leaf/ancestor integrity checks, the
elevated child additionally calls `SetDefaultDllDirectories(LOAD_LIBRARY_SEARCH_SYSTEM32)`
at startup so runtime `LoadLibrary` calls cannot resolve a bare DLL name to an
adjacent file.

Runtime verification is therefore **enforced**; an unsigned, non-Microsoft, or
user-replaceable `plm.exe` is refused before any elevation. On unsigned local/
dev builds the gate deliberately refuses to elevate. Consequently, locally
built `plm.exe` binaries cannot run guarded-WPR end-to-end scenarios; those
validations must use a signed packaged binary in a protected directory.
Producing that signed `plm.exe` alongside `wxc-exec.exe` / `mxc_ffi.dll` is
owned by **#834**.

The same constraint applies to Rust SDK consumers. `mxc-sdk` is compiled into
the consuming executable, so module-relative discovery normally points at the
consumer's local Cargo output directory. A locally built or user-writable
adjacent `plm.exe` is intentionally rejected, which means native PSEC capture
may remain available but the guarded-WPR legacy fallback is unavailable.

For an isolated developer validation loop, a locally built `plm.exe` can be
Authenticode-signed with a short-lived development code-signing certificate
whose signer Organization is `Microsoft Corporation`. Trust that certificate
only on the validation machine, deploy the signed binary in an
administrator-protected directory, and remove the certificate after testing.
This exercises the production trust gate without adding an unsigned-build
bypass; production packages still require the normal Microsoft-signed binary.

`signtool.exe` is included with the Windows SDK. If it is not available on the
development machine, install the SDK from the
[official Windows SDK downloads](https://learn.microsoft.com/windows/apps/windows-sdk/downloads)
before running the example. The following PowerShell creates a one-day,
non-exportable local certificate, signs a development build, and exports only
its public certificate:

```powershell
$cert = New-SelfSignedCertificate `
    -Type CodeSigningCert `
    -Subject 'CN=MXC Local Validation TEST ONLY,O=Microsoft Corporation' `
    -CertStoreLocation 'Cert:\CurrentUser\My' `
    -KeyExportPolicy NonExportable `
    -NotAfter (Get-Date).AddDays(1) `
    -HashAlgorithm SHA256

$signTool = Get-ChildItem `
    "${env:ProgramFiles(x86)}\Windows Kits\10\bin" `
    -Filter signtool.exe -Recurse |
    Where-Object FullName -Like '*\x64\signtool.exe' |
    Sort-Object FullName -Descending |
    Select-Object -First 1

& $signTool.FullName sign `
    /sha1 $cert.Thumbprint /s My /fd SHA256 .\plm.exe

Export-Certificate -Cert $cert -FilePath .\mxc-dev-validation.cer
$cert.Thumbprint | Set-Content .\mxc-dev-validation.thumbprint
```

On an isolated validation machine, an administrator can trust the public
certificate locally and verify the signed binary:

```powershell
$certificate = Import-Certificate `
    -FilePath .\mxc-dev-validation.cer `
    -CertStoreLocation 'Cert:\LocalMachine\Root'
Import-Certificate `
    -FilePath .\mxc-dev-validation.cer `
    -CertStoreLocation 'Cert:\LocalMachine\TrustedPublisher'

Get-AuthenticodeSignature .\plm.exe
```

Deploy `plm.exe` in an administrator-protected directory such as
`C:\Program Files\MXC-Dev\`; the directory-integrity gate still rejects a
signed binary from a user-writable location. After validation, remove the
certificate from the validation machine and remove the private-key certificate
from the development machine:

```powershell
$thumbprint = Get-Content .\mxc-dev-validation.thumbprint

# Run elevated on the validation machine.
Remove-Item "Cert:\LocalMachine\Root\$thumbprint"
Remove-Item "Cert:\LocalMachine\TrustedPublisher\$thumbprint"

# Run on the development machine.
Remove-Item "Cert:\CurrentUser\My\$thumbprint"
```

The certificate and signed binary are test artifacts: do not publish,
redistribute, or use them outside the isolated validation environment.

### Bounded discard-confirmation

If discarding a guarded session fails, MXC confirms that the elevated guardian
actually released the sandbox before continuing. Each confirmation is given a
**short 10-second bound** (not `plm`'s multi-minute WPR stop timeout) and is
retried only a small, bounded number of times, so a failed discard can never
block teardown for tens of minutes. If release still cannot be confirmed after
the bounded attempts, MXC aborts to preserve sandbox enforcement rather than
proceeding with an unconfirmed live guardian.

### Short-lived descendant attestation race

Job completion-port notifications carry a PID, and Windows documents (see
`JOBOBJECT_ASSOCIATE_COMPLETION_PORT`) that such a PID may already refer to an
**inactive or recycled** process unless an open handle is held. The guardian
authenticates every `NEW_PROCESS` PID by opening a process **handle** and
checking `IsProcessInJob` (plus a PID re-read and a non-zero creation time)
before retaining it — a PID is never trusted on its own.

A short-lived descendant can exit before the guardian manages to open it. That
observation race is **recorded, not fatal to the sandbox**: the running sandbox
is *never* terminated because of it. Instead, the guardian fails the capture
**analysis closed** after the sandbox has completed, and **no denials artifact
is emitted** for that run (the operator gets an explicit error rather than a
partial or mis-scoped denials report). Genuine tracker corruption (e.g. a
duplicate active-process start, or an exit with no tracked start that is not a
recorded race) still fails closed and terminates the job.

## Limitations

- **Windows-only.** Uses `wpr.exe` and Job-Object UI-limit semantics that have no portable equivalent.
- **Deny matching is enforced on literal, lexically-normalized paths only.** `config::normalize_path` strips verbatim/device prefixes, lowercases, collapses separators, and rejects ADS / `.` / `..`, but it is filesystem-free and does **not** resolve directory junctions, symlinks/reparse points, or 8.3 short names. 8.3 short-name aliases of a denied directory are detected lexically and refused promotion (fail-closed), but a junction/symlink alias (e.g. `C:\work\link` → `C:\Secrets`) is a lexically distinct path that will **not** match a deny entry and can therefore be promoted into the persisted `Adjusted_*.json`. Operators must deny the canonical target path; aliasing the target through a reparse point is a known gap. See the deny-matching code in `src/config.rs`.
- The compatibility adjusted-config generator consumes file and capability denials only. UI regeneration moves to the shared opt-in regeneration engine; UI denials are already present in `denials.json`.

## See also

- [`docs/process-container/guide.md`](../../../docs/process-container/guide.md) — process-container backend overview
- [README → Debugging → Audit Mode](../../../README.md#audit-mode-permissive-learning-mode) — `wxc-exec --audit` integration
