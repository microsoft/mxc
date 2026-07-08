# PLM — Permissive Learning Mode

`plm.exe` captures the access-denied events emitted by Windows' permissive sandbox layer, decodes them into structured findings, and (optionally) merges those findings back into an MXC container config so the next enforcing run succeeds without changes to the workload.

PLM is invoked automatically by [`wxc-exec --audit`](../../../README.md#audit-mode-permissive-learning-mode); the standalone CLI documented here is for re-processing captured traces, interactive iteration, and debugging the parser itself.

## How it works

1. **Capture** — `plm start` calls `wpr -start <plm.wprp>!AccessFailureProfile -filemode`, enabling the `Microsoft-Windows-Privacy-Auditing-PermissiveLearningMode` and `Microsoft-Windows-Kernel-General` ETW providers in a secure realtime collector.
2. **Run** — the operator runs the workload. The OS-side permissive sandbox logs an `EventID=14` for every file/capability access that *would* have been denied, and an `EventID=27` for every UI operation that *would* have been blocked by a Win32k or Job UI Limit. Operations are allowed to proceed regardless.
3. **Stop** — `plm stop` calls `wpr -stop <trace.etl>` and walks the `.etl` with `EvtQuery` / `EvtRender`.
4. **Parse** — for each `EventID=14`, the parser pulls the file path / access mask and feeds the embedded DACL ACE blob to `DeriveCapabilitySidsFromName` to identify any AppContainer capability the process needed. For each `EventID=27`, it decodes the violation `Category` (`CONVERT_TO_GUI` or `UI_OPERATION`) and `Detail` bit (`JOB_OBJECT_UILIMIT_*`).
5. **Merge** — when a `--config-path` is supplied, the findings are merged into a copy of the config and written as `Adjusted_<name>.json` next to the captured trace.

The schema mapping for UI relaxations is documented in [`docs/process-container/UIPolicy_Schema.md`](../../../docs/process-container/UIPolicy_Schema.md).

## Layout

| File                  | Role                                                                                |
|-----------------------|-------------------------------------------------------------------------------------|
| `src/main.rs`         | `clap` dispatch for `plm start` / `plm stop` / `plm log` / `plm extract-caps`       |
| `src/start.rs`        | `wpr -cancel` (best-effort) + `wpr -start …!AccessFailureProfile -filemode`         |
| `src/stop.rs`         | `wpr -stop` (or skip with `--trace-file`) + parse + merge + write `Adjusted_*.json` |
| `src/log.rs`          | Interactive mode: Enter to start, Enter to stop, then diff vs a blank config        |
| `src/event_parser.rs`   | `EvtQuery` / `EvtRender` walk; shared `ParseAccumulator` + per-event dispatcher |
| `src/access_failure.rs` | `EventID=14` decoder: file-path normalization, post-XPath filters, ACE-blob ingestion |
| `src/ui_violation.rs`   | `EventID=27` decoder: hex-payload + named-data parsers, category classification |
| `src/extract_caps.rs` | ACE blob walk + `DeriveCapabilitySidsFromName` capability resolution                |
| `src/config.rs`       | JSON load/mutate/save; path & capability merge; `apply_ui_operation_flags`          |
| `src/access_event.rs` | `LearningModeAccessEvent` plain struct                                              |
| `src/ui_limits.rs`    | `JOB_OBJECT_UILIMIT_*` constants + UI-violation category constants                  |
| `src/coordination.rs` | Cross-process singleton named-mutex + bypass-env-var coordination for `plm log`     |
| `src/wpr_path.rs`     | Resolves `wpr.exe` to its absolute `%SystemRoot%\System32` path (PATH-spoof-safe)   |
| `src/profile_gen.rs`  | Inline WPR profile (`EMBEDDED_WPRP`) + run-time writer that drops `plm.wprp` next to `plm.exe` when missing |

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

Stops the active trace (or re-parses an existing one), prints a detection summary, and writes `Adjusted_*.json` when a config is supplied.

```powershell
plm.exe stop [--config-path <path>] [--log-dir <path>] [--bin-path <path>]
             [--adjusted-config-path <path>] [--trace-file <path>]
             [--verbose-logging]
```

| Flag                      | Default                                  | Purpose                                                                              |
|---------------------------|------------------------------------------|--------------------------------------------------------------------------------------|
| `--config-path`           | *(none)*                                 | MXC container config (JSON) to merge findings into. Without it, only the summary is printed. |
| `--log-dir`               | `<exe dir>\logs\<timestamp>`             | Destination for `trace.etl`, the copied input config, and `Adjusted_*.json`.         |
| `--bin-path`              | `<exe dir>`                              | App binary location. Events targeting this exact path are skipped as self-access.    |
| `--adjusted-config-path`  | `<log-dir>\Adjusted_<input>.json`        | Override the merged config's output path.                                            |
| `--trace-file`            | `<log-dir>\trace.etl`                    | Re-process an existing `.etl` instead of stopping a live WPR session. Skips `wpr -stop`. |
| `--verbose-logging`       | off                                      | Per-event / per-ACE diagnostics on stdout, including skip reasons.                   |

The merge pipeline:

1. **File paths** — every `EventID=14` whose path passes the validity filters is added to `filesystem.readwritePaths` or `filesystem.readonlyPaths` based on the OR-ed access mask, excluding anything already in `filesystem.deniedPaths`.
2. **Capabilities** — every resolved capability name not already present is appended to the containment block's `capabilities` array.
3. **UI subsystem** — any `CONVERT_TO_GUI` violation flips `ui.disable` to `false` so Win32k syscalls succeed.
4. **UI operations** — every `UI_OPERATION` violation contributes its `JOB_OBJECT_UILIMIT_*` bit to a mask which is then mapped per the [UI policy schema](../../../docs/process-container/UIPolicy_Schema.md) — e.g. `WRITECLIPBOARD` widens `ui.clipboard`, `HANDLES` relaxes `processContainer.ui.isolation`, `INJECTION` sets `ui.injection = true`.

An `Adjusted_*.json` is written whenever the trace yielded *any* mergeable finding — file path, capability, `CONVERT_TO_GUI`, or `UI_OPERATION`.

### `plm log`

Interactive iteration mode: press Enter to start a trace, run the workload, press Enter again to stop. Prints the diff that would be applied to a blank (`{}`) config — useful for authoring a policy from scratch.

```powershell
plm.exe log [--wprp <path>] [--verbose-logging]
```

### `plm extract-caps`

Standalone capability decoder for a hex-encoded ACE blob. Mirrors the original PowerShell `extract_caps.ps1` and is mainly useful for parser debugging.

```powershell
plm.exe extract-caps --hex-bytes "<hex>" [--verbose-logging]
```

## Workflow examples

### From scratch with `wxc-exec`

```powershell
# wxc-exec --audit starts the trace, runs the workload in permissive mode,
# stops the trace, and writes Adjusted_<config>.json next to the captured .etl.
wxc-exec.exe --audit C:\policies\my-app.json
```

The adjusted config can be diff-ed against the input and copied back over the
original once it looks right.

### Manual capture / replay

```powershell
# 1. Start a trace.
plm.exe start

# 2. Run the workload to be profiled (anywhere — different shell is fine).
my-app.exe

# 3. Stop the trace and merge findings into a config.
plm.exe stop --config-path C:\policies\my-app.json
```

### Re-process a captured trace

Useful after editing the parser, or when an operator hands you a `.etl` from
a machine without `plm.exe` installed:

```powershell
plm.exe stop --trace-file C:\temp\trace.etl `
             --config-path C:\policies\my-app.json `
             --log-dir   C:\temp\plm-out
```

`--trace-file` bypasses `wpr -stop`, so it works whether or not a WPR session is live.

## Building

PLM is part of the MXC workspace but excluded from `default-members` because it's Windows-only. Build it explicitly:

```powershell
cd C:\src\mxc\src
cargo build -p plm --target x86_64-pc-windows-msvc
# or for release:
cargo build -p plm --target x86_64-pc-windows-msvc --release
```

The WPR profile is embedded into `plm.exe` itself (see `src/profile_gen.rs`); on first use of `plm start` / `plm log`, `profile_gen::ensure_wprp_next_to_exe` writes it to disk next to the binary if no `plm.wprp` is already present. There is no separate file in the repo and nothing for `build.rs` to stage. `build.bat` from the repo root builds `plm.exe` and stages it next to `wxc-exec.exe` for the `--audit` integration.

## ETW event reference

| EventID | Provider                                                       | Meaning                                              | Decoded into                                |
|---------|----------------------------------------------------------------|------------------------------------------------------|---------------------------------------------|
| 14      | `Microsoft-Windows-Privacy-Auditing-PermissiveLearningMode`    | File / capability access that would have been denied | `valid_access_events`, `requested_capabilities` |
| 27      | `Microsoft-Windows-Privacy-Auditing-PermissiveLearningMode`    | UI operation blocked by Job UI Limits or Win32k disable | `need_ui` (CONVERT_TO_GUI) or `ui_operation_flags` (UI_OPERATION) |

The full `JOB_OBJECT_UILIMIT_*` constant set lives in
[`src/ui_limits.rs`](src/ui_limits.rs) alongside the
`CONVERT_TO_GUI` / `UI_OPERATION` category constants. UI events whose payload
cannot be decoded are surfaced in `--verbose-logging` output and otherwise
ignored — they do not contribute to either relaxation.

## Filtering

For transparency, `plm.exe stop` filters events at four layers; `--verbose-logging` prints a line for every skip:

1. **WPR profile** — only the two providers above end up in the `.etl`.
2. **EvtQuery XPath** — `*[System[EventID=14 or EventID=27]]` drops everything else.
3. **EventID=14 post-filters** — skip `\Device\MountPointManager`, empty paths, paths under the current working directory at parse time, non-drive-letter paths, the app accessing its own binary, and paths containing illegal Win32 filename characters.
4. **EventID=27 classification** — unknown categories are counted but contribute no relaxation; undecodable payloads are reported in verbose mode and otherwise ignored.

## Limitations

- **Windows-only.** Uses `wpr.exe`, `EvtQuery`, `DeriveCapabilitySidsFromName`, and Job-Object UI-limit semantics that have no portable equivalent.
- **AppContainer/BaseContainer scope.** Only operations gated by the OS permissive-learning-mode auditing layer produce events — plain Win32 access checks outside the AppContainer envelope are invisible to PLM.
- **Capability names limited to `KNOWN_CAPABILITIES`.** New named capabilities require an entry in [`src/extract_caps.rs`](src/extract_caps.rs). Capabilities the local OS doesn't recognise via `DeriveCapabilitySidsFromName` are silently dropped at table-build time.
- **No targeted UI grants.** `apply_ui_operation_flags` widens whole policy fields (e.g. `ui.injection = true`); the schema doesn't yet support per-target grants like `UserHandleGrantAccess`.
- **`--audit` plumbing only forwards file configs.** Policies passed as base64 don't carry a path, so `wxc-exec --audit` runs `plm stop` without `--config-path` — you'll get the detection summary but no `Adjusted_*.json`. Run `plm stop --trace-file …` afterwards against the file form of the policy to merge.

## See also

- [`docs/process-container/UIPolicy_Schema.md`](../../../docs/process-container/UIPolicy_Schema.md) — UI policy schema and `JOB_OBJECT_UILIMIT_*` mappings
- [`docs/process-container/guide.md`](../../../docs/process-container/guide.md) — process-container backend overview
- [README → Debugging → Audit Mode](../../../README.md#audit-mode-permissive-learning-mode) — `wxc-exec --audit` integration
