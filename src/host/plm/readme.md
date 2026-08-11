# PLM — Permissive Learning Mode

`plm.exe` is the Windows-only legacy WPR trace helper for Learning Mode. It captures both `learningModeLogging` block events and `permissiveLearningMode` allow events, then delegates ETL decoding to the same canonical `learning_mode_windows::EtlDenialAnalyzer` used by `captureDenials`.

The canonical analyzer decodes filesystem, capability, registry, and UI findings from both provider shapes. The standalone `extract-caps` command remains available only as a low-level ACE diagnostic.

PLM is invoked automatically by [`wxc-exec --audit`](../../../README.md#audit-mode-permissive-learning-mode); the standalone CLI documented here is for capturing traces, interactive iteration, and debugging the parser itself.

## How it works

1. **Capture** — the public `plm.exe` runs `asInvoker`; it does not add a service. It uses UAC only to launch a hidden restricted child for the fixed WPR start/stop/cancel controls, and that child uses the embedded profile only.
2. **Run** — the operator runs the workload. The OS-side permissive sandbox logs `EventID=14` / `EventID=27` for every access that *would* have been denied.
3. **Stop** — the restricted child returns ETL bytes and status over a unique local authenticated named pipe. The unelevated parent owns caller-selected `--trace-output`, `--log-dir`, and `--config-path` destinations, then analyzes the ETL through `EtlDenialAnalyzer`.
4. **Emit** — canonical findings are written to `denials.json` in the log directory, and a one-line JSON result reports the trace, denials, and optional adjusted-config paths.
5. **Merge (temporary compatibility)** — file and capability denials are adapted into the existing adjusted-config generator until the shared regeneration engine replaces it.

> **Capability merge caveats.** Capabilities are only merged into a `processContainer` block — backends that cannot express AppContainer capabilities (LXC, Windows Sandbox, …) are left untouched and the discovered set is reported on stderr instead. The reserved names `learningModeLogging` and `permissiveLearningMode` are never written back, because `processContainer.capabilities` rejects them.

## Layout (this PR)

| File                    | Role                                                                              |
|-------------------------|-----------------------------------------------------------------------------------|
| `src/main.rs`           | `clap` dispatch for `plm start` / `plm stop` / `plm log` / `plm extract-caps`     |
| `src/elevated.rs`       | Restricted `runas` child, PID-authenticated local pipe, fixed WPR operations, ETL transfer |
| `src/elevated_protocol.rs` | Bounded success/error/ETL framing shared across the privilege boundary          |
| `src/parent_auth.rs`    | Mutual-PID one-shot authentication for the wxc-exec singleton handoff             |
| `src/start.rs`          | Fixed `wpr -start …!AccessFailureProfile -filemode` and cleanup-only cancel       |
| `src/stop.rs`           | `wpr -stop` (or skip with `--trace-file`) + parse + FS/capability merge           |
| `src/log.rs`            | Interactive mode: Enter to start, Enter to stop, then diff vs a blank config      |
| `src/analysis.rs`       | Canonical ETL analysis, denials JSON emission, and temporary config-generator adapter |
| `src/access_event.rs`   | `LearningModeAccessEvent` plain struct                                            |
| `src/extract_caps.rs`   | DACL ACE blob decoder; resolves capability SIDs via `DeriveCapabilitySidsFromName` |
| `src/config.rs`         | JSON load/mutate; FS + capability merge into containment-backend section          |
| `src/coordination.rs`   | Cross-process singleton named-mutex and Ctrl-handler coordination                  |
| `src/wpr_path.rs`       | Resolves `wpr.exe` to its absolute `%SystemRoot%\System32` path (PATH-spoof-safe) |
| `src/profile_gen.rs`    | Inline, non-overridable WPR profile (`EMBEDDED_WPRP`)                              |

## Privilege boundary

`plm.exe` is `asInvoker`; it does **not** carry a `requireAdministrator` manifest, and no service is added. Caller-selected filesystem operations—including `--log-dir`, `--config-path`, `--trace-file`, `--trace-output`, ETL parsing, denials output, and adjusted-config generation—run under the caller token.

Only hidden fixed `start`, `stop`, and `cancel` control operations are launched with `ShellExecuteExW("runas")`. Their command line contains only an operation, a strictly validated unique local pipe name, and the unelevated server PID. The elevated child:

- resolves `wpr.exe` from `GetSystemDirectoryW`;
- always uses the compiled-in profile (there is no public `--wprp` override or arbitrary elevated destination);
- keeps its scratch internal and temporary under an OS-resolved trusted local location with restrictive ACL/integrity handling;
- rejects remote pipes and pipe squatting (`PIPE_REJECT_REMOTE_CLIENTS` and `FILE_FLAG_FIRST_PIPE_INSTANCE`);
- authenticates the pipe server PID, while the parent authenticates the child PID returned by `ShellExecuteExW`;
- uses bounded framing for explicit success, error, and ETL responses.
- for `wxc-exec --audit` and interactive `plm log`, starts an already-elevated owner-death guardian before reporting start success; the guardian cancels only after acquiring the PLM singleton, and refuses to cancel if a new owner won that race.

`wxc-exec --audit` launches the public PLM process normally. Its host-wide singleton handoff uses a separate mutually PID-authenticated one-shot pipe rather than a spoofable environment variable or hidden bypass flag.

## CLI

### `plm start`

Starts a new permissive-learning-mode trace. If another WPR session already owns the host logger, start fails without cancelling that peer recording.

This command has no public flags; the removed `--wprp` override is no longer accepted.

```powershell
plm.exe start
```

### `plm stop`

Stops the active trace (or accepts a previously captured one).

```powershell
plm.exe stop [--config-path <path>] [--log-dir <path>] [--bin-path <path>]
             [--trace-file <path> | --trace-output <path>]
             [--exit-code <code>] [--verbose-logging]
```

`--trace-output` selects the exact destination the **unelevated parent** writes after receiving ETL bytes from the elevated child; it is never passed to `wpr.exe` or opened by elevated code. It cannot be combined with `--trace-file`, which is an entirely unelevated path for re-processing an existing ETL. `--exit-code` is copied into the canonical `denials.json` summary.

`--config-path` temporarily preserves the existing adjusted-config behavior. The adjusted config is written next to the operator's config snapshot in `--log-dir`; there is deliberately no flag to redirect it independently. The write is atomic so a downstream enforcing run never observes a truncated policy.

### `plm extract-caps`

Decode a raw hex-encoded DACL ACE buffer into a sorted list of AppContainer capability names. Useful for debugging the ACE decoder against ETW payloads dumped by other tools.

```powershell
plm.exe extract-caps --hex-bytes <hex> [--verbose-logging]
```

> **An empty result does not mean the blob contained no capabilities.** Only names on the module's built-in known-capability list are recognized, and only when the OS resolves them via `DeriveCapabilitySidsFromName` — names this Windows build rejects are skipped at table-build time, and any SID that is not in the resulting index is ignored. Capabilities are also only collected from *allow* ACEs that grant a non-zero access mask. Use `--verbose-logging` to see per-ACE decisions, including SIDs that resolved to nothing.

### `plm log`

Interactive iteration mode: press Enter to start a trace, run the workload, press Enter again to stop. It then synthesizes a blank config, runs the filesystem merge, and prints the resulting config as a "diff against a blank config" preview.

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

## Limitations

- **Windows-only.** Uses `wpr.exe` and Job-Object UI-limit semantics that have no portable equivalent.
- **Deny matching is enforced on literal, lexically-normalized paths only.** `config::normalize_path` strips verbatim/device prefixes, lowercases, collapses separators, and rejects ADS / `.` / `..`, but it is filesystem-free and does **not** resolve directory junctions, symlinks/reparse points, or 8.3 short names. 8.3 short-name aliases of a denied directory are detected lexically and refused promotion (fail-closed), but a junction/symlink alias (e.g. `C:\work\link` → `C:\Secrets`) is a lexically distinct path that will **not** match a deny entry and can therefore be promoted into the persisted `Adjusted_*.json`. Operators must deny the canonical target path; aliasing the target through a reparse point is a known gap. See the deny-matching code in `src/config.rs`.
- The compatibility adjusted-config generator consumes file and capability denials only. UI regeneration moves to the shared opt-in regeneration engine; UI denials are already present in `denials.json`.

## See also

- [`docs/process-container/guide.md`](../../../docs/process-container/guide.md) — process-container backend overview
- [README → Debugging → Audit Mode](../../../README.md#audit-mode-permissive-learning-mode) — `wxc-exec --audit` integration
