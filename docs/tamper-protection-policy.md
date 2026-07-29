# Per-Application Tamper Protection Policy (`experimental.tamperProtection`)

> **Status:** Experimental (Windows only). Requires `--experimental`. One-shot
> requests only — a state-aware lifecycle request carrying
> `experimental.tamperProtection` is rejected at parse time.

## Overview

The `experimental.tamperProtection` section defines per-application
anti-tampering and data-isolation policy. It maps developer *intent* onto two
OS enforcement mechanisms:

- **Per-application mandatory access control (MAC)** via compound SACL ACEs that
  require **both** the user SID **and** the application's identity SID before
  full access to kernel objects (processes, threads, tokens, files, registry
  keys) is granted.
- **Security compartments** — each protected application gets its own
  non-hierarchical compartment used for window isolation and global-atom
  lifetime protection (mitigating shatter, hooking, and atom-smashing attacks).

Developers declare *what the process may expose or allow*; the OS translates
that into the corresponding kernel-level security descriptors. This document
describes the **mxc config surface**; the kernel enforcement lives in the OS.

The section is only meaningful for a process with a verifiable **App Identity**
(signature-verified via MSIX, sparse package, or PE manifest).

## Design principles

| Principle | Description |
|---|---|
| **Default-deny** | Omitted fields resolve to their most restrictive value. `"tamperProtection": {}` = maximum lockdown. |
| **Closed section** | Every `tamperProtection` object rejects unknown fields. A misspelled protection flag (e.g. `blockUIAccess` vs `blockUiAccess`) is a hard config error, never a silently-dropped field that leaves a protection off. |
| **Intent over mechanism** | The schema describes developer permissions and security posture, not kernel APIs or SID structures. |
| **Opt-in exemptions** | Every relaxation from the locked-down default is a conscious, auditable choice. |

### Why the section is closed

The surrounding `experimental` block is intentionally permissive (unknown
fields are tolerated so in-flux backends stay forward-compatible). Because a
silently-dropped *security* flag is a fail-open footgun, `tamperProtection` is
**selectively** closed (`deny_unknown_fields`) — fail-closed on typos — without
imposing that constraint on the other experimental backends. The broader
question of closing the whole `experimental` block is tracked separately.

## Config structure

```json
{
  "containment": "processcontainer",
  "process": { "commandLine": "myApp.exe" },
  "experimental": {
    "tamperProtection": {
      "enabled": true,
      "debugProtection": {
        "allowDebugging": false,
        "requireEntitlement": false,
        "useSpecificEntitlement": false,
        "entitlement": {
          "requiredSigningLevel": "none",
          "requiredSids": []
        }
      },
      "uiProtection": {
        "blockUiAccess": false,
        "allowExternalHook": false,
        "allowHandleAccess": false,
        "allowWindowMessages": false,
        "allowSyntheticInput": false
      },
      "processProtection": {
        "neverInheritFromParent": false,
        "allowInheritFromAnyIdentity": false,
        "shareInstanceWithChildren": false,
        "crossInstanceAccess": {
          "readVirtualMemory": false,
          "duplicateHandle": false
        }
      },
      "requireSigning": {
        "executable": true,
        "libraries": true,
        "requiredSigningLevel": "none"
      }
    }
  }
}
```

## Field reference

### Top level

| Field | Type | Default | Description |
|---|---|---|---|
| `enabled` | boolean | `true` | Master switch. When `false`, the entire section is disabled and no protections are applied. |
| `debugProtection` | object | — | Debugger-attach controls (below). |
| `uiProtection` | object | — | Cross-compartment UI controls (below). |
| `processProtection` | object | — | Process isolation and cross-instance access (below). |
| `requireSigning` | object | — | Code-signing requirements (below). |

### `debugProtection`

| Field | Type | Default | Description |
|---|---|---|---|
| `allowDebugging` | boolean | `false` | `false` blocks debugger attach and SeDebugPrivilege-based manipulation; `true` lifts anti-debug restrictions (dev/debug builds). |
| `requireEntitlement` | boolean | `false` | When `true`, otherwise-denied debug-class callers may present a matching entitlement. When `false`, the restriction is absolute. |
| `useSpecificEntitlement` | boolean | `false` | `false` uses the built-in anti-tamper debug entitlement (ignoring `entitlement`); `true` requires the explicit `entitlement`. |
| `entitlement.requiredSigningLevel` | signing level | `"none"` | Minimum caller signing level. Only evaluated when `requireEntitlement` **and** `useSpecificEntitlement` are both `true`. |
| `entitlement.requiredSids` | string[] | `[]` | SIDs that must all be present and enabled on the caller's token. Same evaluation gate as above. |

### `uiProtection`

Allow-by-exception: `false` (default) blocks the interaction, `true` permits it
— except `blockUiAccess`, which blocks when `true`.

| Field | Type | Default | Description |
|---|---|---|---|
| `blockUiAccess` | boolean | `false` | When `true`, UIAccess (assistive technology, IMEs) is blocked across the compartment boundary. The one UI field allowed by default. |
| `allowExternalHook` | boolean | `false` | `false` blocks external hooks (e.g. `SetWindowsHookEx`). |
| `allowHandleAccess` | boolean | `false` | `false` blocks access to the process's USER handles. |
| `allowWindowMessages` | boolean | `false` | `false` blocks window messages (mitigates shatter attacks). |
| `allowSyntheticInput` | boolean | `false` | `false` blocks injected (synthetic) input (e.g. `SendInput`). |

### `processProtection`

| Field | Type | Default | Description |
|---|---|---|---|
| `neverInheritFromParent` | boolean | `false` | When `true`, the process always receives its own isolated instance. |
| `allowInheritFromAnyIdentity` | boolean | `false` | When `true`, a child may inherit the parent's instance regardless of identity; `false` restricts inheritance to a matching app identity. |
| `shareInstanceWithChildren` | boolean | `false` | Parent-side opt-in: when `true`, children share this process's anti-tamper instance. |
| `crossInstanceAccess.readVirtualMemory` | boolean | `false` | `false` blocks cross-instance `VM_READ`. |
| `crossInstanceAccess.duplicateHandle` | boolean | `false` | `false` blocks cross-instance handle duplication. |

### `requireSigning`

| Field | Type | Default | Description |
|---|---|---|---|
| `executable` | boolean | `true` | Main executable (or package) must be signed. |
| `libraries` | boolean | `true` | All loaded DLLs must be signed. |
| `requiredSigningLevel` | signing level | `"none"` | Minimum signer trust level for the process and (when `libraries`) its DLLs. |

### Signing levels

`requiredSigningLevel` is one of: `none`, `authenticode`, `store`, `microsoft`,
`windows`. A higher level demands a more trusted signer; `none` imposes no
minimum beyond the presence check implied by `executable` / `libraries`.

## Defaults summary

`"tamperProtection": {}` = maximum lockdown. All fields default to their most
restrictive value; the fields whose restrictive value *is* enabled default to
`true`:

- `enabled` → `true`
- `requireSigning.executable` → `true`
- `requireSigning.libraries` → `true`
- every other boolean → `false`
- `requiredSigningLevel` → `"none"`
- `requiredSids` → `[]`

## Not currently in the schema

The following fields from the design are intentionally **excluded** from the
current schema (under review) and will be rejected by the closed section:
`protectNewFiles`, `protectNewRegistryKey`, and `restrictModules`
(`enabled` / `allowedModules`).

## Where this lives in the code

| Layer | Location |
|---|---|
| Wire model (schema source of truth) | `src/core/wxc_common/src/wire.rs` (`TamperProtection` and nested structs; `SigningLevel`) |
| Domain model | `src/core/wxc_common/src/models.rs` (`TamperProtectionConfig` and friends; wire→domain `From` impls) |
| Parser mapping / state-aware rejection | `src/core/wxc_common/src/config_parser.rs` |
| Generated dev schema | `schemas/dev/mxc-config.schema.0.8.0-dev.json` (regenerate with `mxc_schema_gen`, do not hand-edit) |
| Example config | `tests/configs/experimental_tamper_protection.json` |
