# Learning Mode — PLM Logging Scripts

PowerShell helpers that drive a Windows Performance Recorder (WPR) trace of a sandboxed run and roll the observed file accesses and capability requests back into an MXC container config. This is currently capable of detecting and resolving filesystem access failures and AppContainer capability requests; UI and network failure mitigation are planned.

There are two supported workflows:

### Workflow A — Manual: drive the scripts directly

1. Run `start_plm_logging.ps1` to begin profiling.
2. Exercise the workload you want to learn (e.g., run your app or test config under MXC).
3. Run `stop_plm_logging.ps1 -ConfigPath <path-to-mxc-config.json>` to stop profiling, parse the trace, and emit an "Adjusted_" config with the discovered read/write paths and capabilities merged in.

Use this when you want full control over what runs between the start and stop calls, or when the workload is launched by something other than `wxc-exec`.

### Workflow B — `wxc-exec --audit`: one-shot run

Run the binary you want to profile under `wxc-exec` with `--audit` and the same `--config-path` you'd normally pass:

```powershell
.\wxc-exec.exe --config-path C:\path\to\mxc-config.json --audit
```

When `--audit` is set, `wxc-exec` automatically:

1. Injects the `permissiveLearningMode` capability into the request's capability list so the AppContainer logs access failures instead of blocking on them.
2. Invokes `start_plm_logging.ps1` before launching the sandboxed process.
3. Runs the sandboxed process to completion (stdout/stderr/exit code surface normally).
4. Invokes `stop_plm_logging.ps1 -ConfigPath <the same config path>` so the trace is parsed and an `Adjusted_*.json` is emitted alongside `trace.etl` in `logs\<timestamp>\`.

Use this when the workload is itself an MXC-sandboxed process — it's the shortest path from "I have a config that's missing capabilities/paths" to "I have an `Adjusted_*.json` with the missing entries merged in." The Rust glue lives in `src/wxc/src/learning_mode.rs`.

All four PowerShell scripts plus `PLM.wprp` live next to each other and are copied into the build output (`target/<profile>/`) by the `wxc` crate's `build.rs`, so `wxc-exec --audit` can find them next to itself and you can also run the scripts manually from there without staging files.

## Output layout

Every invocation of `stop_plm_logging.ps1` creates a timestamped sub-directory under `logs/` (relative to the caller's current directory by default, overridable with `-LogDir`):

```
<cwd>\logs\<yyyy-MM-dd_HHmmss>\
├── trace.etl                       # raw WPR trace (written by `wpr -stop`)
├── <original-config-name>.json     # verbatim copy of the input -ConfigPath
└── Adjusted_<original-config-name>.json   # input config with learned paths + capabilities merged in
```

Both the **input config** (copied as-is) and the **modified config** (`Adjusted_*.json`) are written into the same `logs/<timestamp>/` directory, so each run is self-contained and you can diff the two files to inspect exactly what learning mode changed.

## `start_plm_logging.ps1`

Starts a WPR trace using the `AccessFailureProfile` profile defined in the sibling `PLM.wprp`. No parameters.

```powershell
.\start_plm_logging.ps1
```

Internally:

```powershell
$wprp = Join-Path $PSScriptRoot 'PLM.wprp'
wpr -start "$wprp!AccessFailureProfile" -filemode
```

`$PSScriptRoot` is used so the script finds `PLM.wprp` regardless of the caller's current directory.

## `stop_plm_logging.ps1`

Stops the in-progress WPR trace into `trace.etl`, parses the resulting events with `Get-WinEvent`, classifies file-access and capability events, and (optionally) merges the findings into a provided MXC container config.

```powershell
.\stop_plm_logging.ps1 [-LogDir <path>] [-BinPath <path>] [-ConfigPath <path-to-config.json>]
```

### Parameters

| Name           | Type     | Default                                          | Description |
|----------------|----------|--------------------------------------------------|-------------|
| `-LogDir`      | `string` | `<cwd>\logs\yyyy-MM-dd_HHmmss`                   | Directory where the ETL trace, the input config copy, and the adjusted config are written. Created if missing. |
| `-BinPath`     | `string` | absolute form of `<cwd>`                         | Path treated as the application binary's location. Events whose `FilePath` equals this are skipped (the app reading its own image). |
| `-ConfigPath`  | `string` | *(none)*                                         | Optional path to an MXC container config (JSON). When provided, the file is copied into `$LogDir` and an `Adjusted_*.json` sibling is produced with discovered read/write paths and capabilities merged in. |

### Outputs (written to `$LogDir`)

- `trace.etl` — raw WPR trace.
- If `-ConfigPath` is supplied:
  - `<original-name>.json` — verbatim copy of the source config.
  - `Adjusted_<original-name>.json` — same config with merged `filesystem.readwritePaths`, `filesystem.readonlyPaths`, and `<containment>.capabilities`.

### Behavior

1. Stops the WPR trace into `$LogDir\trace.etl`.
2. Reads the trace with `Get-WinEvent` filtered to event IDs `14` (file access failure) and `27` (UI event).
3. Dot-sources `event_dacl_parser.ps1` and calls `Invoke-EventDaclParser`, which:
   - Builds a list of valid file-access events (skipping `\Device\MountPointManager` and self-access).
   - For each event, hands the DACL ACE blob (`EventData.ComplexData[4].InnerText`) to `extract_caps.ps1`, which resolves each ACE's SID against the well-known capability SID table (via `DeriveCapabilitySidsFromName`) and returns a `HashSet[string]` of matched capability names.
   - Reports whether any UI event was observed.
4. If `-ConfigPath` is provided:
   - Copies the input config into `$LogDir`, parses it as JSON, and ensures `filesystem.readwritePaths` / `filesystem.readonlyPaths` exist.
   - For each access event, classifies it as read or write based on the access mask, walks parent-directory coverage to avoid redundant entries, and appends to the appropriate `readwritePaths` / `readonlyPaths` list.
   - Merges the discovered capability names into `<config.containment>.capabilities` (case-insensitive dedupe against existing entries) and prints which capabilities were newly included vs. already present.
   - Writes the merged config to `Adjusted_<name>.json` in `$LogDir`.

### Example

```powershell
.\start_plm_logging.ps1

# ... run the workload to be profiled (e.g. wxc-exec with the source config) ...

.\stop_plm_logging.ps1 -ConfigPath C:\Tessera\mxc\test_configs\basic_appcontainer.json
```

After completion, look in `logs\<timestamp>\` for both `basic_appcontainer.json` (the original) and `Adjusted_basic_appcontainer.json` (with learned paths and capabilities folded in).

## Supporting files

| File                       | Role |
|----------------------------|------|
| `PLM.wprp`                 | WPR recording profile that defines the `AccessFailureProfile` collector. Resolved via `$PSScriptRoot` so cwd doesn't matter. |
| `event_dacl_parser.ps1`    | Defines `Invoke-EventDaclParser` (event walker) plus the property-index map and the path to `extract_caps.ps1`. Dot-sourced from `stop_plm_logging.ps1`. |
| `extract_caps.ps1`         | Parses a hex-encoded blob of concatenated ACEs from a learning-mode event's DACL, resolves each SID to a capability name when possible, and returns a `HashSet[string]` of matched names. Invoked once per event from `event_dacl_parser.ps1`. |
