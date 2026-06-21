# Rust_PLM — Rust port of the PLM PowerShell scripts

A native Rust reimplementation of the four PowerShell scripts in the parent
directory. Same behavior, same WPR/Win32 calls, no PowerShell dependency.

## Layout

| File                     | PS counterpart            | Role                                                         |
|--------------------------|---------------------------|--------------------------------------------------------------|
| `src/main.rs`            | —                         | CLI dispatch (`plm start` / `plm stop` / `plm log` / `plm extract-caps`) |
| `src/start.rs`           | `start_plm_logging.ps1`   | `wpr -cancel` + `wpr -start ...!AccessFailureProfile`        |
| `src/stop.rs`            | `stop_plm_logging.ps1`    | `wpr -stop` + parse + merge into config                      |
| `src/log.rs`             | (new — interactive mode)  | Press Enter to start, Enter to stop, then print diff vs blank config |
| `src/event_parser.rs`    | `event_dacl_parser.ps1`   | `EvtQuery`/`EvtRender` walk over the .etl                    |
| `src/extract_caps.rs`    | `extract_caps.ps1`        | ACE blob walk + `DeriveCapabilitySidsFromName`               |
| `src/config.rs`          | (config-update section of `stop_plm_logging.ps1`) | JSON load / mutate / save               |
| `src/access_event.rs`    | `LearningModeAccessEvent` PS class | Plain struct                                        |

## Usage

```powershell
# Start a trace (resolves PLM.wprp next to the executable by default).
.\target\debug\plm.exe start

# Run the workload to be profiled...

# Stop the trace and merge findings into a config.
.\target\debug\plm.exe stop --config-path C:\path\to\mxc-config.json

# Optional flags:
#   --log-dir <path>             Override <exe dir>\logs\<timestamp>.
#   --bin-path <path>            App binary location (events targeting this
#                                exact path are skipped as self-access).
#   --adjusted-config-path <p>   Override Adjusted_*.json output location.
#   --verbose-logging            Per-event/per-ACE diagnostics on stdout.

# Run the capability extractor standalone:
.\target\debug\plm.exe extract-caps --hex-bytes "<hex>" --verbose-logging

# Interactive mode: start/stop on Enter, then print changes
# that would be merged into a blank ({}) config.
.\target\debug\plm.exe log [--verbose-logging] [--wprp <path>]
```

## Building

```powershell
cd C:\Tessera\learning_mode\Rust_PLM
cargo build
# or for release:
cargo build --release
```

`PLM.wprp` is expected to live next to the resulting executable. Either copy
it into `target\debug\` / `target\release\` after build, or pass its path via
`plm start --wprp <path>`.

## Notes / parity caveats

- The Rust `stop` defaults `--log-dir` and `--bin-path` to the executable's
  directory (`current_exe()` parent), matching the PS `$PSScriptRoot`
  convention.
- ETL parsing uses `EvtQuery` with `EvtQueryFilePath`, the same code path
  PowerShell's `Get-WinEvent -Path` uses. Event property indexes (file
  path = data[2], app path = data[3], access mask = data[5]) and the DACL
  blob location (`EventData/ComplexData[4]`) match the PS parser exactly.
- `Test-Path -IsValid` is approximated with a check for invalid Win32
  filename characters in the path.
- The adjusted config is emitted with `serde_json` and the
  `preserve_order` feature so existing key order in the input config is
  retained around the merged `filesystem` / `<containment>` / `ui` blocks.
