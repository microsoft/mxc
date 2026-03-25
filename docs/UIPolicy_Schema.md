# Tessera UI Policy Schema — `"ui"` Section

> **Status:** Draft — for review
> **Location:** WXC container configuration JSON
> **Reference:** [UIContainer.md](https://dev.azure.com/microsoft/OS/_git/os.2020?path=/onecoreuap/windows/core/ntuser/kernel/docs/UIContainer.md&version=GBofficial/ge_current_directwinpd_sf2)

---

## Overview

The `"ui"` section of the WXC container configuration controls how a contained process interacts with the Windows GUI subsystem. It maps developer intent to the underlying enforcement mechanisms:

- **Job Object UI Restrictions** (`NtUserSetJobUILimits`)
- **Process Mitigation: Win32k System Call Disable** (`PROCESS_MITIGATION_SYSTEM_CALL_DISABLE_POLICY`)

Developers declare *what the process is allowed to do* — Tessera translates that into the correct kernel flags and mitigations.

### Design Principles

1. **Default-deny** — All omitted fields default to the most restrictive value. `"ui": {}` = total lockdown.
2. **Forward compatible** — New fields added to the schema are automatically denied by existing configs, requiring no updates. Default-deny ensures new capabilities are opt-in from day one.
3. **Flat structure** — No nesting, no profiles, no precedence rules.
4. **Intent over mechanism** — The schema describes permissions, not kernel APIs.
5. **Opt-in** — Developers explicitly enable only what the process needs.

---

## Config Structure

The `"ui"` section is a sibling of `"appContainer"`, `"filesystem"`, `"network"`, and `"sandbox"` in the WXC config. All fields shown explicitly for illustration — in practice, omitted fields default to their most restrictive value:

```json
{
  "script": "myapp.exe",
  "containment": "appcontainer",
  "ui": {
    "disable": false,
    "dataChannels": "none",
    "isolation": "container",
    "desktopSystemControl": false,
    "systemSettings": "none",
    "ime": false,
    "injection": false
  }
}
```

> **Note:** The `"ui"` section is only meaningful when `"containment"` is `"appcontainer"`. When `"containment"` is `"sandbox"`, the sandbox VM provides its own isolation — the `"ui"` section is ignored and a warning is emitted.

---

## Field Reference

### `disable`

| | |
|---|---|
| **Type** | `boolean` |
| **Default** | `true` |
| **Description** | Kill switch. Completely disables access to the GUI subsystem. The process cannot create windows, use GDI, or make any `NtUser*`/`NtGdi*` system calls. Atom table is also isolated. |
| **Enforcement** | Process mitigation: `DisallowWin32kSystemCalls` (`PROC_THREAD_ATTRIBUTE_MITIGATION_POLICY`) + Job UI limit: `JOB_OBJECT_UILIMIT_GLOBALATOMS` (0x0020) |

**When `true`:**
- All other `"ui"` fields are ignored — the process has no GUI surface.

**When `false`:**
- The process retains GUI capability — other fields control what it can do.

---

### `dataChannels`

| | |
|---|---|
| **Type** | `enum` |
| **Default** | `"none"` |
| **Values** | `"read"`, `"write"`, `"all"`, `"none"` |
| **Description** | Controls access to data exchange channels between the contained process and the rest of the system. |
| **Enforcement** | `JOB_OBJECT_UILIMIT_READCLIPBOARD` (0x0002), `JOB_OBJECT_UILIMIT_WRITECLIPBOARD` (0x0004) |

| Value | Flags Set | Read (paste in) | Write (copy out) | Use Case |
|-------|-----------|---------------|----------------|----------|
| `"all"` | *(none)* | ✅ Allowed | ✅ Allowed | Process needs full clipboard access |
| `"read"` | `UILIMIT_WRITECLIPBOARD` | ✅ Allowed | ❌ Blocked | Process can paste but not copy out |
| `"write"` | `UILIMIT_READCLIPBOARD` | ❌ Blocked | ✅ Allowed | Process can copy but not paste in |
| `"none"` | `UILIMIT_READCLIPBOARD` + `UILIMIT_WRITECLIPBOARD` | ❌ Blocked | ❌ Blocked | Complete clipboard isolation |

---

### `isolation`

| | |
|---|---|
| **Type** | `enum` |
| **Default** | `"container"` |
| **Values** | `"desktop"`, `"handles"`, `"atoms"`, `"container"` |
| **Description** | Determines whether the process can see and interact with UI objects (windows, menus, atoms) belonging to other processes. |
| **Enforcement** | `JOB_OBJECT_UILIMIT_HANDLES` (0x0001), `JOB_OBJECT_UILIMIT_GLOBALATOMS` (0x0020) |

| Value | Flags Set | Handle Access | Atom Table | Use Case |
|-------|-----------|--------------|-----------|----------|
| `"desktop"` | *(none)* | All handles on the desktop | Global (session-wide) | Process needs to interact with other windows |
| `"handles"` | `UILIMIT_HANDLES` | Same-job handles only | Global (session-wide) | Handle isolation without atom isolation |
| `"atoms"` | `UILIMIT_GLOBALATOMS` | All handles on the desktop | Per-job (isolated) | Atom isolation without handle restriction |
| `"container"` | `UILIMIT_HANDLES` + `UILIMIT_GLOBALATOMS` | Same-job handles only | Per-job (isolated) | Sandboxed — process only sees its own UI objects |

**When `"handles"` or `"container"`:**
- `JOB_OBJECT_UILIMIT_HANDLES` — USER handle validation restricts access to same-job only
- Broadcast messages only delivered to same-job top-level windows

> **Targeted access:** Even under handle isolation, individual handles can be explicitly granted to the contained process via [`UserHandleGrantAccess`](https://learn.microsoft.com/en-us/windows/win32/api/winuser/nf-winuser-userhandlegrantaccess). This is the one mechanism that supports targeted cross-job handle sharing today — a caller with access to both the handle and the job can selectively punch through the isolation boundary.

**When `"atoms"` or `"container"`:**
- `JOB_OBJECT_UILIMIT_GLOBALATOMS` — Per-job atom table via `RtlCreateAtomTable`

---

### `desktopSystemControl`

| | |
|---|---|
| **Type** | `boolean` |
| **Default** | `false` |
| **Description** | Controls whether the process can manipulate the GUI system — creating/switching desktops and initiating shutdown/logoff/restart. |
| **Enforcement** | `JOB_OBJECT_UILIMIT_DESKTOP` (0x0040), `JOB_OBJECT_UILIMIT_EXITWINDOWS` (0x0080) |

**When `false`:**
- `JOB_OBJECT_UILIMIT_DESKTOP` — Blocks [`CreateDesktop`](https://learn.microsoft.com/en-us/windows/win32/api/winuser/nf-winuser-createdesktopa) and [`SwitchDesktop`](https://learn.microsoft.com/en-us/windows/win32/api/winuser/nf-winuser-switchdesktop) (returns `ERROR_ACCESS_DENIED`)
- `JOB_OBJECT_UILIMIT_EXITWINDOWS` — Blocks [`ExitWindows`](https://learn.microsoft.com/en-us/windows/win32/api/winuser/nf-winuser-exitwindows) / [`ExitWindowsEx`](https://learn.microsoft.com/en-us/windows/win32/api/winuser/nf-winuser-exitwindowsex) (silently returns `FALSE`)

**Why bundled:** Both are system-level GUI operations that typically share the same trust requirement.

---

### `systemSettings`

| | |
|---|---|
| **Type** | `enum` |
| **Default** | `"none"` |
| **Values** | `"all"`, `"parameters"`, `"display"`, `"none"` |
| **Description** | Controls whether the process can change system-wide UI settings. |
| **Enforcement** | `JOB_OBJECT_UILIMIT_SYSTEMPARAMETERS` (0x0008), `JOB_OBJECT_UILIMIT_DISPLAYSETTINGS` (0x0010) |

| Value | Flags Set | SystemParametersInfo / SetSysColors | ChangeDisplaySettings | Use Case |
|-------|-----------|-------------------------------------|----------------------|----------|
| `"all"` | *(none)* | ✅ Allowed | ✅ Allowed | Process needs to modify system settings |
| `"parameters"` | `UILIMIT_DISPLAYSETTINGS` | ✅ Allowed | ❌ Blocked | Process can change UI params but not resolution |
| `"display"` | `UILIMIT_SYSTEMPARAMETERS` | ❌ Blocked | ✅ Allowed | Process can change display but not UI params |
| `"none"` | `UILIMIT_SYSTEMPARAMETERS` + `UILIMIT_DISPLAYSETTINGS` | ❌ Blocked | ❌ Blocked | No system settings changes |

---

### `ime`

| | |
|---|---|
| **Type** | `boolean` |
| **Default** | `false` |
| **Description** | Controls whether the Input Method Editor (IME) is available to the process. Once disabled, cannot be undone. |
| **Enforcement** | `JOB_OBJECT_UILIMIT_IME` (0x0100) |

**When `false`:**
- `JOB_OBJECT_UILIMIT_IME` — IME is disabled for the process

> ⚠️ **Irreversible.** Cannot be removed once set.

> **Atypical limit:** UI limits protect the system from the contained process. This one is the opposite — it protects the contained process from the system by preventing untrusted IME modules from loading into the container.

---

### `injection`

| | |
|---|---|
| **Type** | `boolean` |
| **Default** | `false` |
| **Description** | Controls whether the process can inject synthetic input into other processes. |
| **Enforcement** | `JOB_OBJECT_UILIMIT_INJECTION` (0x0200) |

**When `false`:**
- `JOB_OBJECT_UILIMIT_INJECTION` — Blocks synthetic input injection

---

## Defaults Summary

All fields default to the most restrictive value. **`"ui": {}` = total lockdown.**

| Field | Default | Effect |
|-------|---------|--------|
| `disable` | `true` | No GUI — Win32k disabled + atom isolation |
| `dataChannels` | `"none"` | No clipboard access |
| `isolation` | `"container"` | Job-scoped handles and atoms |
| `desktopSystemControl` | `false` | Cannot create/switch desktops or shutdown |
| `systemSettings` | `"none"` | Cannot change system parameters or display |
| `ime` | `false` | IME disabled |
| `injection` | `false` | Cannot inject synthetic input |

---

## Examples

### Example 1: Sandboxed App — GUI enabled, everything else locked down

The process can create and manage its own windows but is fully isolated from other applications and the system.

```json
"ui": {
  "disable": false,
  "isolation": "container"
}
```

> `isolation: "container"` is the default — provided here for clarity, can be omitted.

Resolved (with defaults):
- `disable: false` — GUI enabled
- `dataChannels: "none"` — no clipboard
- `isolation: "container"` — job-scoped handles and atoms
- `desktopSystemControl: false` — no desktop/shutdown
- `systemSettings: "none"` — no system changes
- `ime: false` — no IME
- `injection: false` — no input injection

---

### Example 2: Background Service — no GUI at all

The process has zero UI surface. Win32k attack surface eliminated.

```json
"ui": {}
```

Or equivalently:
```json
"ui": {
  "disable": true
}
```

All defaults apply — maximum lockdown.

---

### Example 3: Selective permissions — GUI with clipboard access

Process has full GUI access and can interact with other windows on the desktop. Full clipboard access is granted, but all other capabilities remain locked down.

```json
"ui": {
  "disable": false,
  "dataChannels": "all",
  "isolation": "desktop"
}
```

---

## Internal Mapping (Tessera Implementation Reference)

This section is for Tessera developers. The JSON fields map to kernel enforcement as follows:

| Field | Value | OS Enforcement |
|-------|-------|----------------|
| `disable` | `true` | `PROCESS_MITIGATION_SYSTEM_CALL_DISABLE_POLICY.DisallowWin32kSystemCalls` + `JOB_OBJECT_UILIMIT_GLOBALATOMS` |
| `dataChannels` | `"none"` | `JOB_OBJECT_UILIMIT_READCLIPBOARD` + `JOB_OBJECT_UILIMIT_WRITECLIPBOARD` |
| `dataChannels` | `"read"` | `JOB_OBJECT_UILIMIT_WRITECLIPBOARD` |
| `dataChannels` | `"write"` | `JOB_OBJECT_UILIMIT_READCLIPBOARD` |
| `dataChannels` | `"all"` | *(no flags)* |
| `isolation` | `"container"` | `JOB_OBJECT_UILIMIT_HANDLES` + `JOB_OBJECT_UILIMIT_GLOBALATOMS` |
| `isolation` | `"handles"` | `JOB_OBJECT_UILIMIT_HANDLES` |
| `isolation` | `"atoms"` | `JOB_OBJECT_UILIMIT_GLOBALATOMS` |
| `isolation` | `"desktop"` | *(no flags)* |
| `desktopSystemControl` | `false` | `JOB_OBJECT_UILIMIT_DESKTOP` + `JOB_OBJECT_UILIMIT_EXITWINDOWS` |
| `systemSettings` | `"none"` | `JOB_OBJECT_UILIMIT_SYSTEMPARAMETERS` + `JOB_OBJECT_UILIMIT_DISPLAYSETTINGS` |
| `systemSettings` | `"parameters"` | `JOB_OBJECT_UILIMIT_DISPLAYSETTINGS` |
| `systemSettings` | `"display"` | `JOB_OBJECT_UILIMIT_SYSTEMPARAMETERS` |
| `systemSettings` | `"all"` | *(no flags)* |
| `ime` | `false` | `JOB_OBJECT_UILIMIT_IME` |
| `injection` | `false` | `JOB_OBJECT_UILIMIT_INJECTION` |

---

## Future Extensions

### Targeted Permissions

Handle isolation already supports selective cross-boundary access today via [`UserHandleGrantAccess`](https://learn.microsoft.com/en-us/windows/win32/api/winuser/nf-winuser-userhandlegrantaccess) — a caller with visibility into both the handle and the target job can explicitly grant access to a specific USER handle without relaxing the isolation boundary.

This pattern — default-deny with explicit, targeted exceptions — might be the right model for other capabilities too. Injection is the most obvious candidate: a contained process should be able to inject input into a designated partner process without being granted blanket injection rights across the desktop.

The open architectural question is **where targeted grants live**. Two approaches:

1. **Declarative (schema)** — The container config names specific targets (by job, process, or endpoint), and Tessera resolves the grants at container creation. Clean for static relationships, but requires a target naming and resolution framework that does not exist today.
2. **Imperative (runtime API)** — A broker process calls a system API at runtime to grant specific cross-boundary access, similar to how `UserHandleGrantAccess` works today. More flexible for dynamic relationships, but shifts responsibility to the caller.

These are not mutually exclusive — declarative config could resolve to runtime API calls under the hood. The decision depends on whether targeted relationships are known at container creation time or emerge dynamically. **TBD.**

### Upcoming Changes

| Feature | Schema Change |
|---------|--------------|
| [Hooks](https://learn.microsoft.com/en-us/windows/win32/api/winuser/nf-winuser-setwindowshookexa) | TBD — at minimum, prevent low-level (`WH_KEYBOARD_LL`, `WH_MOUSE_LL`), CBT (`WH_CBT`), and debug (`WH_DEBUG`) hooks that reach outside the job |
| [Foreground](https://learn.microsoft.com/en-us/windows/win32/api/winuser/nf-winuser-setforegroundwindow) | New field controlling the process ability to change foreground |
| [Raw input](https://learn.microsoft.com/en-us/windows/win32/inputdev/raw-input) | New field controlling the process ability to observe and influence raw input |

---

## References

- [UIContainer.md](https://dev.azure.com/microsoft/OS/_git/os.2020?path=/onecoreuap/windows/core/ntuser/kernel/docs/UIContainer.md&version=GBofficial/ge_current_directwinpd_sf2) — Comprehensive reference for Job Object UI Restrictions and Win32k System Call Disable
- [WXC Configuration Schema](https://github.com/microsoft/mxc/tree/main/docs) — Existing WXC config format
- [JOBOBJECT_BASIC_UI_RESTRICTIONS](https://learn.microsoft.com/en-us/windows/win32/api/winnt/ns-winnt-jobobject_basic_ui_restrictions)
