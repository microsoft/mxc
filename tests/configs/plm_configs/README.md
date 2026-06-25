# plm_configs

JSON step configurations for `wxc-exec.exe` (or the equivalent MXC
runner) that drive `plmtester.exe` through baseline Win32 surface
probes inside a plain processcontainer.

All configs invoke `plmtester.exe` without an absolute path, so it must
be on `PATH` (or co-located with `wxc-exec.exe` / the MXC runner) at the
time the config is run.

## Files

| Config | Tests |
|--------|-------|
| `ui_system_param_set.json`    | `SetSysColors(1, [COLOR_BACKGROUND], [0x00112233])` — per-user color table write; always broadcasts `WM_SYSCOLORCHANGE`. The write is the part most likely to be blocked by PLM / AppContainer. |
| `ui_display_settings.json`    | `ChangeDisplaySettingsW(current_mode, CDS_TEST)` — non-destructive validation; expect `DISP_CHANGE_SUCCESSFUL`. |
| `ui_clipboard_roundtrip.json` | `OpenClipboard` + `SetClipboardData(CF_UNICODETEXT)` + `GetClipboardData` in one process — distinguishes AppContainer clipboard isolation from owner-HWND failures. |
| `ui_find_window.json`         | `FindWindowW("Shell_TrayWnd", NULL)` — locates the taskbar top-level window owned by `explorer.exe`. Tests cross-process window discovery / UIPI / desktop isolation. |
| `ui_injection_child_window.json` | Full child-window injection flow: (1) `CreateWindowExW(HWND_MESSAGE, …)` to obtain a message-only window owned by this process, (2) `ConsoleControl(ConsoleSetForeground)` (undocumented user32 export) to grant this process the right to call `SetForegroundWindow` even under UIPI / foreground-lock, (3) `SetForegroundWindow` on the owned HWND, (4) `SendInput`. Process exit code is `GetLastError()` from `SendInput` on failure or `ERROR_SUCCESS` on success, mirroring the JobTests `InjectionTests` reference pattern. |
| `cap_screenshot.json`          | `Windows.Graphics.Capture` + `GraphicsCapturePicker` (WinRT) — prompts the user to pick a display/window via the system picker and writes the captured frame as PNG to `screenshot.png` in the binary's directory. Exercises the WinRT graphics-capture broker path. |
| `fs_promoted.json`             | `cmd.exe` writes a file into `C:\Tessera\plm_fs_test\readonly\` (pre-created by `run_plm_test.ps1`). The config pre-seeds that directory in `readonlyPaths`; PLM should observe the write and add the parent to `readwritePaths`, widening the policy from read-only to read+write. |
| `fs_add_readonly.json`         | `cmd.exe` reads `C:\Tessera\plm_fs_test\src\input.txt` (pre-created). Config has no `filesystem` section; PLM should add the file path to `readonlyPaths`. |
| `fs_add_readwrite.json`        | `cmd.exe` writes `C:\Tessera\plm_fs_test\dst\out.txt` (dir pre-created). Config has no `filesystem` section; PLM should add the parent dir to `readwritePaths`. |

All configs use:

- `version`: `0.5.0-alpha`
- `containment`: `processcontainer` (no `leastPrivilege`, no `permissiveLearningMode` — plain Medium-IL baseline)
- `process.timeout`: 30000 ms
- `ui.disable`: `false`
