# Learning Mode — PLM Logging Scripts

PowerShell helpers around the `ApplicationCapabilityProfiler` module that capture an ETW trace of a sandboxed run and roll the observed file accesses back into an MXC container config. This is currently capable of detecting and resoving filesystem access failures. This will be expanded to capability, UI, and network failure mitigation. 
The intended workflow is:

1. Run `start_plm_logging.ps1` to begin profiling.
2. Exercise the workload you want to learn (e.g., run your app or test config).
3. Run `stop_plm_logging.ps1 -FilePath <path-to-mxc-config.json>` to stop profiling and emit an "Adjusted_" config with the discovered read/write paths merged in.

Both scripts depend on `Microsoft.Windows.Win32Isolation.ApplicationCapabilityProfiler.dll` being available at:

```
c:\users\adminuser\desktop\acp\
```

(see the `$AcpPath` variable in each script).

> NOTE: There is a `#TODO replace with xperf` marker in both scripts — long term the intent is to migrate away from the ACP module to xperf.

## `start_plm_logging.ps1`

Imports the profiler module and starts a profiling session.

```powershell
.\start_plm_logging.ps1
```

No parameters. Internally:

- Imports `$AcpPath\Microsoft.Windows.Win32Isolation.ApplicationCapabilityProfiler.dll`.
- Calls `Start-Profiling -Force` to begin a new trace (the `-Force` flag overrides any existing session).

## `stop_plm_logging.ps1`

Stops the in-progress profiling session, writes trace artifacts to a timestamped log directory, parses the resulting summary to extract observed file paths, and optionally merges those paths into a provided MXC container config.

```powershell
.\stop_plm_logging.ps1 [-LogDir <path>] [-FilePath <path-to-config.json>] [-OutputConfigPath <path>] [-InPlaceEdit <bool>] [-AcpPath <path>]
```

### Parameters

| Name                 | Type     | Default                                                         | Description |
|----------------------|----------|-----------------------------------------------------------------|-------------|
| `-LogDir`            | `string` | `<cwd>\logs\yyyy-MM-dd_HHmmss`                                  | Directory where the ETL trace and profiling outputs are written. Created if missing. |
| `-FilePath`          | `string` | *(none)*                                                        | Optional path to an MXC container config (JSON). When provided, an adjusted copy is produced and the discovered file paths are merged into `filesystem.readwritePaths`. |
| `-OutputConfigPath`  | `string` | *(none)*                                                        | *(stubbed — not yet wired up)* Reserved for specifying an explicit output location for the adjusted config. |
| `-InPlaceEdit`       | `bool`   | `$false`                                                        | *(stubbed — not yet wired up)* Reserved for editing `-FilePath` in place instead of producing an `Adjusted_*.json` copy. |
| `-AcpPath`           | `string` | *(none — script falls back to `c:\users\adminuser\desktop\acp`)*| *(stubbed — not yet wired up)* Reserved for overriding the location of `Microsoft.Windows.Win32Isolation.ApplicationCapabilityProfiler.dll`. |

### Outputs (written to `$LogDir`)

- `trace.etl`     — raw profiling trace.
- `results.csv`   — per-record results from `Get-ProfilingResults`.
- `summary.txt`   — human-readable summary (used by the script to extract file paths).
- `manifest.xml`  — manifest emitted by `Get-ProfilingResults`.
- If `-FilePath` is supplied:
  - `<original-name>.json`           — verbatim copy of the source config.
  - `Adjusted_<original-name>.json`  — config with the merged `filesystem.readwritePaths`. A copy of this adjusted file is also written back next to the original `-FilePath`.

### Behavior

1. Imports the profiler module and creates `$LogDir`.
2. Calls `Stop-Profiling -TracePath $LogDir\trace.etl`.
3. Calls `Get-ProfilingResults` to produce `results.csv`, `summary.txt`, and `manifest.xml` in `$LogDir`.
4. Parses `summary.txt`:
   - Finds the section that begins with `Type: File`.
   - For each non-blank line in that section, strips the `\??\` NT-path prefix and collects the remaining path.
5. If `-FilePath` is provided:
   - Copies the config into `$LogDir`, parses it as JSON, and ensures `filesystem.readwritePaths` exists (creating it — and a `filesystem` object — if missing).
   - Appends any newly observed file paths that aren't already present in `readwritePaths`.
   - For each entry in the merged list that exists on disk as a file (`Test-Path -PathType Leaf`), also adds its parent directory to `readwritePaths` if not already covered. (The current implementation widens `readwritePaths` rather than emitting a separate `readonlyPaths` — see the inline comment in the script.)
   - Writes the result to `Adjusted_<name>.json` in `$LogDir` and copies it back to the directory containing `-FilePath`.

### Example

```powershell
.\start_plm_logging.ps1

# ... run the workload to be profiled ...

.\stop_plm_logging.ps1 -FilePath C:\Tessera\mxc\test_configs\basic_appcontainer.json
```

After completion, `Adjusted_basic_appcontainer.json` will sit next to the original config with the learned paths folded into `filesystem.readwritePaths`.
