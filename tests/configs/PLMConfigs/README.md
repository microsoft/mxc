# PLMConfigs

JSON step configurations for `wxc-exec.exe` (or the equivalent MXC
runner) that drive `plmtester.exe` through baseline Win32 surface
probes inside a plain processcontainer.

All configs assume `plmtester.exe` is at
`C:\Users\AdminUser\Desktop\lily\plmtester.exe`.

## Files

| Config | Tests |
|--------|-------|
| `system_param_set_basic.json`    | `SetSysColors(1, [COLOR_BACKGROUND], [0x00112233])` — per-user color table write; always broadcasts `WM_SYSCOLORCHANGE`. The write is the part most likely to be blocked by PLM / AppContainer. |
| `display_settings_basic.json`    | `ChangeDisplaySettingsW(current_mode, CDS_TEST)` — non-destructive validation; expect `DISP_CHANGE_SUCCESSFUL`. |
| `clipboard_roundtrip_basic.json` | `OpenClipboard` + `SetClipboardData(CF_UNICODETEXT)` + `GetClipboardData` in one process — distinguishes AppContainer clipboard isolation from owner-HWND failures. |
| `find_window_basic.json`         | `FindWindowW("Shell_TrayWnd", NULL)` — locates the taskbar top-level window owned by `explorer.exe`. Tests cross-process window discovery / UIPI / desktop isolation. |
| `injection_child_window_basic.json` | Full child-window injection flow: (1) `CreateWindowExW(HWND_MESSAGE, …)` to obtain a message-only window owned by this process, (2) `ConsoleControl(ConsoleSetForeground)` (undocumented user32 export) to grant this process the right to call `SetForegroundWindow` even under UIPI / foreground-lock, (3) `SetForegroundWindow` on the owned HWND, (4) `SendInput`. Process exit code is `GetLastError()` from `SendInput` on failure or `ERROR_SUCCESS` on success, mirroring the JobTests `InjectionTests` reference pattern. |
| `screenshot_basic.json`          | `Windows.Graphics.Capture` + `GraphicsCapturePicker` (WinRT) — prompts the user to pick a display/window via the system picker and writes the captured frame as PNG to `screenshot.png` in the binary's directory. Exercises the WinRT graphics-capture broker path. |

All configs use:

- `version`: `0.5.0-alpha`
- `containment`: `processcontainer` (no `leastPrivilege`, no `permissiveLearningMode` — plain Medium-IL baseline)
- `process.timeout`: 30000 ms
- `ui.disable`: `false`
