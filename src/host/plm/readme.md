# PLM — Permissive Learning Mode

`plm.exe` is the Windows-only trace driver for permissive learning mode. Long-form, it captures the access-denied events emitted by Windows' permissive sandbox layer, decodes them into structured findings, and merges those findings back into an MXC container config so the next enforcing run succeeds.

This PR introduces **filesystem extraction**: `EventID=14` records are walked from the captured `.etl`, file paths are extracted and merged into `filesystem.{readwritePaths,readonlyPaths}` on a copy of the input config. The host-wide singleton mutex, embedded `plm.wprp` materializer, and `wxc-exec --audit` plumbing landed in the previous PR. Capability extraction, UI relaxation, and the `Adjusted_*.json` writer arrive in subsequent PRs.

PLM is invoked automatically by [`wxc-exec --audit`](../../../README.md#audit-mode-permissive-learning-mode); the standalone CLI documented here is for capturing traces, interactive iteration, and debugging the parser itself.

## How it works

1. **Capture** — `plm start` calls `wpr -start <plm.wprp>!AccessFailureProfile -filemode`, enabling the `Microsoft-Windows-Privacy-Auditing-PermissiveLearningMode` and `Microsoft-Windows-Kernel-General` ETW providers in a secure realtime collector.
2. **Run** — the operator runs the workload. The OS-side permissive sandbox logs `EventID=14` / `EventID=27` for every access that *would* have been denied.
3. **Stop** — `plm stop` calls `wpr -stop <trace.etl>` and walks the `.etl` with `EvtQuery` / `EvtRender`.
4. **Parse** — for each `EventID=14`, the parser pulls the file path / access mask. Capability ACE-blob decoding lands in a later PR; `EventID=27` UI relaxation lands in a later PR.
5. **Merge** — file paths are added to `filesystem.readwritePaths` / `filesystem.readonlyPaths` on a copy of the input config. The `Adjusted_*.json` writer arrives in the next PR; this PR only prints the per-event summary.

## Layout (this PR)

| File                    | Role                                                                              |
|-------------------------|-----------------------------------------------------------------------------------|
| `src/main.rs`           | `clap` dispatch for `plm start` / `plm stop` / `plm log` (`extract-caps` lands later) |
| `src/start.rs`          | `wpr -cancel` (best-effort) + `wpr -start …!AccessFailureProfile -filemode`       |
| `src/stop.rs`           | `wpr -stop` (or skip with `--trace-file`) + parse + FS merge                      |
| `src/log.rs`            | Interactive mode: Enter to start, Enter to stop, then diff vs a blank config      |
| `src/event_parser.rs`   | `EvtQuery` / `EvtRender` walk; shared `ParseAccumulator` + per-event dispatcher   |
| `src/access_failure.rs` | `EventID=14` decoder: file-path normalization, post-XPath filters                 |
| `src/access_event.rs`   | `LearningModeAccessEvent` plain struct                                            |
| `src/config.rs`         | JSON load/mutate; path merge into `filesystem.{readwritePaths,readonlyPaths}`     |
| `src/coordination.rs`   | Cross-process singleton named-mutex + bypass-env-var coordination for `plm log`   |
| `src/wpr_path.rs`       | Resolves `wpr.exe` to its absolute `%SystemRoot%\System32` path (PATH-spoof-safe) |
| `src/profile_gen.rs`    | Inline WPR profile (`EMBEDDED_WPRP`) + run-time writer that drops `plm.wprp` next to `plm.exe` when missing |

## CLI

### `plm start`

Cancels any in-progress WPR session and starts a new permissive-learning-mode trace.

```powershell
plm.exe start [--wprp <path>]
```

| Flag       | Default                | Purpose                                                       |
|------------|------------------------|---------------------------------------------------------------|
| `--wprp`   | `<exe dir>\plm.wprp`   | Override the WPR profile path. By default `plm` materializes its embedded profile next to the exe on first use; an existing `plm.wprp` is never overwritten, so operator hand-edits are preserved. |

### `plm stop`

Stops the active trace (or accepts a previously captured one).

```powershell
plm.exe stop [--config-path <path>] [--log-dir <path>] [--bin-path <path>]
             [--adjusted-config-path <path>] [--trace-file <path>]
             [--verbose-logging]
```

`--config-path` drives an in-memory filesystem merge against the input config; the `Adjusted_*.json` writer that persists it arrives in the config-generation PR. `--adjusted-config-path` is accepted today so `wxc-exec --audit` can pass it through.

### `plm log`

Interactive iteration mode: press Enter to start a trace, run the workload, press Enter again to stop. The "diff against a blank config" preview arrives in later PRs.

```powershell
plm.exe log [--wprp <path>] [--verbose-logging]
```

## Building

PLM is part of the MXC workspace but excluded from `default-members` because it's Windows-only. Build it explicitly:

```powershell
cd C:\src\mxc\src
cargo build -p plm --target x86_64-pc-windows-msvc
# or for release:
cargo build -p plm --target x86_64-pc-windows-msvc --release
```

The WPR profile is embedded into `plm.exe` itself (see `src/profile_gen.rs`); on first use of `plm start` / `plm log`, `profile_gen::ensure_wprp_next_to_exe` writes it to disk next to the binary if no `plm.wprp` is already present. `build.bat` from the repo root builds `plm.exe` and stages it next to `wxc-exec.exe` for the `--audit` integration.

## Limitations

- **Windows-only.** Uses `wpr.exe` and Job-Object UI-limit semantics that have no portable equivalent.
- **No adjusted-config writer yet.** `plm stop` merges discovered paths into an in-memory copy of the input config and prints the per-event summary, but does not yet write an `Adjusted_*.json`. Later PRs add the adjusted-config writer, capability extraction, and UI-policy extraction.

## See also

- [`docs/process-container/guide.md`](../../../docs/process-container/guide.md) — process-container backend overview
- [README → Debugging → Audit Mode](../../../README.md#audit-mode-permissive-learning-mode) — `wxc-exec --audit` integration
