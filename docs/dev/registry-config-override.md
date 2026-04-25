# Registry-Based Config Override for wxc-exec

wxc-exec supports per-executable configuration overrides via the Windows registry. This allows administrators and testers to redirect wxc-exec to use a different JSON config for specific executables without modifying the calling application.

## Overview

When wxc-exec loads a config, it parses the command line to extract the executable name (e.g., `powershell.exe`, `pwsh.exe`). It then checks for a registry key at:

```
HKLM\SOFTWARE\Microsoft\MXC\Diagnostics\Exec\<exe_name>
```

If the key exists and has a valid config path, wxc-exec loads that config and applies it according to the override mode.

## Registry Layout

```
HKLM\SOFTWARE\Microsoft\MXC\Diagnostics\Exec\
    powershell.exe\
        (Default)                   REG_SZ    C:\MxcConfigs\ps51.json
        OverrideConfig              REG_DWORD 0
        OverrideFilesystemPolicy    REG_DWORD 0
        OverrideNetworkPolicy       REG_DWORD 0
        OverrideUiPolicy            REG_DWORD 0
```

### Registry Values

| Value | Type | Required | Description |
|---|---|---|---|
| (Default) | REG_SZ | Yes | Absolute path to a JSON config file (must use a supported MXC schema version) |
| OverrideConfig | REG_DWORD | No | When 1, the registry config replaces the original entirely. When 0 or absent, merge mode is used. |
| OverrideFilesystemPolicy | REG_DWORD | No | Merge mode only. When 1, use the registry config's filesystem policy. When 0 or absent, keep the original. |
| OverrideNetworkPolicy | REG_DWORD | No | Merge mode only. When 1, use the registry config's network policy. When 0 or absent, keep the original. |
| OverrideUiPolicy | REG_DWORD | No | Merge mode only. When 1, use the registry config's UI policy. When 0 or absent, keep the original. |

## Modes

### Full Override (OverrideConfig=1)

The registry config completely replaces the original. The original config is discarded.

### Merge Mode (OverrideConfig=0, the default)

The registry config is loaded as the base. Then:

1. Execution context is always carried over from the original request:
   - Command line
   - Working directory
   - Environment variables
   - Timeout
   - Container ID
   - Experimental flag

2. Each policy area defaults to keeping the original unless its override flag is set:
   - Filesystem: `readwritePaths`, `readonlyPaths`, `deniedPaths`
   - Network: `defaultNetworkPolicy`, `networkEnforcementMode`, `allowedHosts`, `blockedHosts`, proxy
   - UI: cross-platform fields from `ui` (`disable`, `clipboard`, `injection`) and Windows process-specific fields from `appContainer.ui` (`isolation`, `desktopSystemControl`, `systemSettings`, `ime`)

This means an admin who wants to tweak only the UI policy can set `OverrideUiPolicy=1` and leave everything else at 0. The original filesystem and network policies pass through untouched.

## Command Line Parsing

wxc-exec extracts the executable name from the command line using these rules:

- If the command line starts with `"`, the path between the first pair of quotes is used.
- Otherwise, the first space-delimited token is used.
- The filename (last path component) is extracted, lowercased, and `.exe` is appended if missing.

Examples:
- `"C:\Program Files\PowerShell\7\pwsh.exe" -NoProfile` -> `pwsh.exe`
- `powershell.exe -Command "echo hi"` -> `powershell.exe`
- `python -c "print('hi')"` -> `python.exe`

## Error Handling

- If the registry key does not exist, wxc-exec proceeds with the original config (no error).
- If the key exists but has no default value, wxc-exec proceeds with the original config.
- If the config file referenced by the registry cannot be loaded or parsed, wxc-exec logs an error and proceeds with the original config (non-fatal).

## Example: Adjusting UI Policy for a Workload

PowerShell and other processes that use Win32k system calls need UI enabled to
run. By default MXC denies all UI access (`disable: true`), so these processes
fail with `STATUS_DLL_INIT_FAILED` or similar errors.

Suppose an application is sending a PowerShell workload into the sandbox and it
is not working correctly. You suspect the UI policy is too restrictive but you
cannot change the calling application. You can use a registry override to test
different UI settings without touching the caller.

1. Create an override config file on the machine (e.g. `C:\MxcConfigs\ps51.json`):

   ```json
   {
     "version": "0.5.0-dev",
     "containerId": "Debug-PS51",
     "containment": "appcontainer",
     "process": {
       "commandLine": "powershell.exe -NoProfile -Command \"Write-Output 'Hello'\"",
       "timeout": 30000
     },
     "ui": {
       "disable": false
     }
   }
   ```

   This is the minimal change -- just enabling UI. If the workload still fails,
   you can try adding Windows process-specific fields under `appContainer.ui`:

   ```json
   {
     "version": "0.5.0-dev",
     "containerId": "Debug-PS51",
     "containment": "appcontainer",
     "process": {
       "commandLine": "powershell.exe -NoProfile -Command \"Write-Output 'Hello'\"",
       "timeout": 30000
     },
     "ui": {
       "disable": false,
       "clipboard": "read",
       "injection": false
     },
     "appContainer": {
       "ui": {
         "isolation": "desktop",
         "desktopSystemControl": false,
         "systemSettings": "none",
         "ime": false
       }
     }
   }
   ```

2. Point the registry at your config with `OverrideUiPolicy=1` so only the UI
   policy comes from your file while everything else stays as the caller set it:

   ```
   reg add "HKLM\SOFTWARE\Microsoft\MXC\Diagnostics\Exec\powershell.exe" /ve /d "C:\MxcConfigs\ps51.json" /f
   reg add "HKLM\SOFTWARE\Microsoft\MXC\Diagnostics\Exec\powershell.exe" /v OverrideUiPolicy /t REG_DWORD /d 1 /f
   ```

3. Run the application normally. wxc-exec will detect the registry key, load
   your config, and apply your UI policy while keeping the caller's filesystem,
   network, and execution context.

4. Check the debug output for `Registry override:` log lines to confirm the
   override was applied.

5. Iterate -- adjust the UI fields in your config file and re-run until the
   workload behaves correctly.

6. Clean up when done:

   ```
   reg delete "HKLM\SOFTWARE\Microsoft\MXC\Diagnostics\Exec" /f
   ```

The same approach works for other policies. Use `OverrideFilesystemPolicy=1` to
test different filesystem paths, or `OverrideNetworkPolicy=1` to adjust network
restrictions. Set `OverrideConfig=1` to replace the entire configuration.

## Testing

Test configs and an automated test script are in the repository:

- `test_configs/registry_override_configs/` -- JSON configs for PowerShell 5.1
- `test_scripts/registry_override/run_registry_override_tests.ps1` -- automated test script

### Prerequisites

- Windows machine with MXC-supported OS build
- wxc-exec.exe built (debug or release)
- Administrator privileges (required to write to HKLM)
- PowerShell 5.1 (built into Windows)

### Running the Tests

1. Build wxc-exec using the repo build script (only needed once, or after code changes):

   ```
   build.bat
   ```

   For debug builds, use `build.bat --debug` instead.

2. Run the test script from an elevated PowerShell prompt:

   ```
   cd test_scripts\registry_override
   .\run_registry_override_tests.ps1
   ```

   For debug builds, pass `-Debug`. To use a custom binary directory:

   ```
   .\run_registry_override_tests.ps1 -BinDir C:\path\to\wxc-exec\dir
   ```

3. The script creates registry keys, runs wxc-exec against baseline configs, verifies the override behavior, and cleans up. It prints PASS/FAIL for each test and a summary at the end.

### Manual Testing

To manually test a single override:

1. Create the registry key:

   ```
   reg add "HKLM\SOFTWARE\Microsoft\MXC\Diagnostics\Exec\powershell.exe" /ve /d "C:\path\to\override.json" /f
   reg add "HKLM\SOFTWARE\Microsoft\MXC\Diagnostics\Exec\powershell.exe" /v OverrideUiPolicy /t REG_DWORD /d 1 /f
   ```

2. Run wxc-exec with any config that launches powershell.exe:

   ```
   wxc-exec.exe --debug your_config.json
   ```

3. Check the debug output for `Registry override:` log lines.

4. Clean up:

   ```
   reg delete "HKLM\SOFTWARE\Microsoft\MXC\Diagnostics\Exec" /f
   ```
