# PLMTester

A small Rust-built Windows harness for probing how various Win32 / WinRT
surfaces behave under restricted tokens — primarily **AppContainer**,
**Low Integrity Level**, and **Permissive Learning Mode (PLM)**.

Each subcommand exercises one Windows API surface in the smallest way
that's still meaningful, and prints enough environment context
(integrity level, window station, desktop, clipboard owner) that you
can tell *which* gate fired when a call is denied.

## Build

```powershell
cargo build --release
```

Produces a single binary at `target\release\PLMTester.exe`.

## Why this exists

The Windows security model layers many different access checks on top
of each other, and they don't all relax under the same conditions:

| Surface                       | Gated by                                    | Relaxed by PLM? |
|-------------------------------|---------------------------------------------|-----------------|
| File / registry DACL          | `SeAccessCheck` vs token                    | Yes             |
| Clipboard (USER32)            | Window-station + desktop ACL, UIPI, owner-HWND rule | No (token-side, not DACL) |
| WGC `CreateForMonitor/Window` | `graphicsCaptureProgrammatic` capability    | No (DWM broker) |
| WGC `GraphicsCapturePicker`   | User consent gesture                        | n/a             |
| `ChangeDisplaySettings`       | UIPI + registry write                       | Partial         |
| `SystemParametersInfo` (set)  | HKCU write + WM_SETTINGCHANGE broadcast     | Partial         |

PLMTester gives you one tool to ping each of these and see what
actually happens in your sandbox configuration.

## Top-level usage

```
PLMTester.exe <SUBCOMMAND> [args]
```

Subcommands:

| Subcommand          | What it tests |
|---------------------|---------------|
| `clipboard set`     | `OpenClipboard` + `SetClipboardData(CF_UNICODETEXT)` write path. |
| `clipboard get`     | `OpenClipboard` + `GetClipboardData(CF_UNICODETEXT)` read path. |
| `clipboard roundtrip` | Set then get in one process — isolates clipboard isolation from owner-HWND / UIPI bugs. |
| `tasklist32`        | `CreateToolhelp32Snapshot` + `Process32NextW` process enumeration. |
| `tasklist`          | Same, via the `tasklist` crate, which additionally calls `QueryFullProcessImageNameW` / token APIs per process. |
| `screenshot`        | WinRT `GraphicsCapturePicker` — the user-consent screen-capture path (requires the `graphicsCapture` AppContainer capability, not `graphicsCaptureProgrammatic`). |
| `screenshot-simple` | GDI `BitBlt` against the primary monitor DC. |
| `system-param`      | `SystemParametersInfoW` — read/write USER preferences. |
| `display-settings`  | `ChangeDisplaySettingsW` — primary display mode change. |
| `ui-isolation`      | `FindWindowW` probes against foreign top-level windows — tests the `processContainer.ui.isolation` gate. |
| `injection`         | `SendInput` through the full `CreateMessageWindow → ConsoleControl(ConsoleSetForeground) → SetForegroundWindow → SendInput` flow — tests the `ui.injection` gate. |

Every run prints an `[info] PLMTester environment:` block first
showing the caller's integrity level, window station, desktop, and
the current clipboard owner (HWND + PID + image + IL). This is the
"who am I?" snapshot you compare against on failures.

---

## `clipboard set <VALUE> [--hwnd ...]`

Writes `VALUE` to the system clipboard as `CF_UNICODETEXT`.

Tests:
1. Whether `OpenClipboard(hwnd)` is allowed by **UIPI**, the **window-station ACL** (`WINSTA_ACCESSCLIPBOARD`), and the **desktop ACL** (`DESKTOP_READOBJECTS | DESKTOP_WRITEOBJECTS`).
2. Whether the owner-HWND rule is satisfied (see `--hwnd` below).
3. Whether `SetClipboardData` is allowed to transfer ownership of an `HGLOBAL` to the OS.

The **AppContainer `clipboard` capability does NOT gate this path** —
that capability only applies to the WinRT broker
(`Windows.ApplicationModel.DataTransfer.Clipboard`).

### `--hwnd <SOURCE>`

Controls which HWND is passed to `OpenClipboard`. Every choice tests a
different facet of USER32's owner-HWND rule:

| Value      | What it tests |
|------------|---------------|
| `none`     | `HWND(NULL)`. Tests the "ownerless" path — the strictest one; most likely to be rejected under UIPI / sandboxed callers. |
| `console`  | `GetConsoleWindow()`. The window is owned by `conhost.exe`, **not** by us — tests USER32's response to a foreign-owned HWND. |
| `owned`    | A real visible top-level window we just created. The correct "this is mine" handle; **default**. |
| `desktop`  | `GetDesktopWindow()`. Owned by the window manager — tests behavior when the HWND is valid but not ours. |

## `clipboard get [--hwnd ...]`

Reads `CF_UNICODETEXT` from the clipboard and prints it to stdout.
Logs the returned `HANDLE`, whether `is_invalid()` is true, and the
`GlobalSize` of the published HGLOBAL — useful for distinguishing
"clipboard is empty" (size 0), "format not present" (handle invalid),
and "AppContainer clipboard isolation" (handle invalid even after a
successful in-process set).

## `clipboard roundtrip <VALUE> [--hwnd ...] [--reopen true|false]`

Sets `VALUE` and then reads it back in the same process.

This is the diagnostic test for **AppContainer clipboard isolation**:
the OS may virtualize the clipboard per-token so that even a
successful `SetClipboardData` is invisible to `GetClipboardData` from
the same process. If `set` and `get` separately succeed but
`roundtrip` reads back empty/invalid, isolation is in play.

- `--reopen true` (default): drop the `OpenClipboard` scope between
  the set and the get. Mirrors what two separate process invocations
  do, including any service-side replication step.
- `--reopen false`: read from inside the same `OpenClipboard` scope,
  bypassing any replication step. Tells you whether the HGLOBAL is
  visible to *this* token at all.

---

## `tasklist32 [TASKNAME]`

Enumerates processes via `CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS)`
+ `Process32FirstW` / `Process32NextW`. Tests the toolhelp snapshot
surface, which generally works from Low IL / AppContainer.

Prints `PID / PPID / THREADS / IMAGE`. Optional `TASKNAME` is a
case-insensitive substring filter on the image name.

## `tasklist [TASKNAME]`

Same enumeration, via the public `tasklist` crate, which additionally
calls `OpenProcess` + `QueryFullProcessImageNameW` + token APIs on
every target. Tests whether per-process attribute lookups
(`PROCESS_QUERY_LIMITED_INFORMATION` / `PROCESS_QUERY_INFORMATION`)
are granted by the sandbox. Protected processes get `?` for unknown
fields rather than failing the whole enumeration.

Prints `PID / PPID / IMAGE / USER / PATH`.

---

## `screenshot [OUTPUT]`

Captures the screen via WinRT `Windows.Graphics.Capture` using
`GraphicsCapturePicker`. The user picks a display or window from the
system picker, the frame is rendered through D3D11, and a PNG is
written.

Tests the **user-consent capture path**, which is gated by a
foreground-consent gesture instead of the `graphicsCaptureProgrammatic`
capability. Works inside AppContainers that don't have that capability.

Output defaults to `screenshot.png` in the CWD.

## `screenshot-simple [OUTPUT]`

Captures the primary display via plain GDI `BitBlt` (through the
`win-screenshot` crate). No AppContainer capability is required, but
this path is typically blocked by the desktop ACL inside an
AppContainer or LPAC.

Output defaults to `screenshot.png` in the CWD.

---

## `system-param --action <SPI> [--value <N>] [--persist]`

Calls `SystemParametersInfoW`. Tests both the *read* path
(`SPI_GET*`, which almost always succeeds) and the *write* path
(`SPI_SET*`, which under PLM / AppContainer is gated by HKCU write
access and broker policy).

| `--action`                  | API call                       | Read/Write |
|-----------------------------|--------------------------------|------------|
| `get-mouse-speed`           | `SPI_GETMOUSESPEED`            | read       |
| `set-mouse-speed --value N` | `SPI_SETMOUSESPEED` (N in 1..=20) | write   |
| `get-screen-saver-timeout`  | `SPI_GETSCREENSAVETIMEOUT`     | read       |
| `set-screen-saver-timeout --value N` | `SPI_SETSCREENSAVETIMEOUT` (seconds) | write |
| `get-wallpaper`             | `SPI_GETDESKWALLPAPER`         | read       |

- `--value <N>`: required for the `set-*` actions.
- `--persist`: passes `SPIF_UPDATEINIFILE | SPIF_SENDCHANGE` so the
  change is written to HKCU and `WM_SETTINGCHANGE` is broadcast. This
  is the part that PLM / AppContainer is most likely to block; runs
  without `--persist` only mutate the in-memory user-preference cache.

Default with no arguments: `--action get-mouse-speed`.

---

## `display-settings [--width N] [--height M] [--refresh Hz] [--bpp N] [--apply]`

Calls `ChangeDisplaySettingsW`. **Non-destructive by default**:

1. Reads the current mode via `EnumDisplaySettingsW(ENUM_CURRENT_SETTINGS)`.
2. Substitutes any of `width / height / refresh / bpp` you pass.
3. Calls `ChangeDisplaySettingsW` with `CDS_TEST`, which only
   validates the mode — nothing actually changes.

Prints the `DISP_CHANGE_*` result label so you can tell whether the
sandbox returned `DISP_CHANGE_BADPARAM`, `DISP_CHANGE_FAILED`, or
`DISP_CHANGE_SUCCESSFUL`.

Pass `--apply` to drop `CDS_TEST` and actually commit the change. This
is destructive; use it deliberately.

---

## Source layout

```
src/
  main.rs              CLI parser + dispatch
  clipboard.rs         Clipboard set/get/roundtrip + Win32 diagnostic helpers
  tasklist.rs          tasklist32 (toolhelp) + tasklist (crate-based)
  screenshot.rs        WinRT GraphicsCapturePicker capture
  screenshot_simple.rs GDI BitBlt capture (win-screenshot crate)
  system_param.rs      SystemParametersInfoW probe
  display_settings.rs  ChangeDisplaySettingsW probe
```
