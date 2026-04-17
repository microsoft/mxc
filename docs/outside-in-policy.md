## Tessera Per-Application Protection Policy Schema - "appProtection" Section

**Status:** Draft for review

**Location:** WXC container configuration JSON

---

### Overview

The **`"appProtection"`** section of the WXC container configuration defines per-application anti-tampering and data-isolation policy. It requires processes to run in dedicated **security `compart`ments** with mandatory access controls that isolate their memory, threads, tokens, windows, global atoms, and persistent data from every other process on the system including those running as the same user or as an administrator.

The section maps developer intent to two underlying enforcement mechanisms:

- **Per-application mandatory access control (MAC)** via the System Access Control List (SACL). Access to kernel objects (processes, threads, tokens, files, registry keys) is controlled by compound access control entries that require **both** the user SID **and** the application's Instance (if isolated instance) or AppIdentity SID to match before full access is granted. Other principals the same user running a different application, SYSTEM, or an administrator are granted only minimal rights (e.g. terminate or query limited information).
- **Security compartments**. Each protected application is assigned its own non-hierarchical compartment, identified by an **AppIdentity SID** (derived from the Application User Model ID or a secure hash) and optionally an **AppSuite SID** (derived from the Package Family Name). Compartments extend protections to the GUI subsystem by using **compartment numbers** for window isolation (analogous to UIPI across integrity levels) and for global-atom lifetime protection, preventing shatter attacks, window hooking, and atom-smashing attacks.

Developers declare *what the process is allowed to do or expose*; Tessera translates that into the correct kernel-level policy which in turns adjusts kernel object security descriptors which include mandatory access control ACEs that reflect the policy for a given object.

---

### Design Principles

| Principle | Description |
|---|---|
| **Default-deny** | All omitted fields default to the most restrictive value. `"appProtection": {}` = **maximum lockdown** no external process can inspect, modify, or interact with the protected app or its data. Executable and libraries must be signed. |
| **Forward compatible** | New fields added to the schema in a future version are automatically denied for existing configs. No existing application silently gains new attack surface. |
| **Flat structure** | No nesting, no profiles, no precedence rules. Each field is independent. |
| **Intent over mechanism** | The schema describes developer *permissions and security posture*, not kernel APIs or SID structures. |
| **Opt-in** | Developers explicitly enable only the interactions the process needs. Every exemption from the locked-down default is a conscious, auditable choice. |

---

### Versioning and Compatibility

Default-deny produces the strongest security posture but creates a compatibility question whenever the schema evolves.

**Within a version**   default-deny applies fully. Omitted fields are denied, and any new field introduced in a minor revision of the same version is denied for all existing configs.

**Across major versions**   applications pinned to an older version continue to run under the policy semantics of that version. New fields introduced in a later major version are not applied to configs that declare an older version, preserving the behaviour the developer explicitly designed for.

A config that says `"version": 1` will always behave as a v1 config, regardless of the current schema version.

---

### Config Structure

The **`"appProtection"`** section is a sibling of `"ui"`, `"appContainer"`, `"filesystem"`, `"network"`, and `"windows_sandbox"` in the WXC config. All fields are shown explicitly for illustration in practice, omitted fields default to their most restrictive value:

```json
{
  "script": "myApp.exe",
  "containment": "appcontainer",
  "integritylevel" : "default"
  "ui": { "..." : "..." },
  "appProtection": {
    "enabled":                          true,
    "allowDebugging" : {
        "enabled":                      false
    },
    "processProtection": {
        "isolatedInstance":             true,
        "crossInstanceAccess": {
          "readVirtualMemory":          false,
          "duplicateHandle":            false,
        },
    },
    "requireSigning": {
        "executable":                   true,
        "libraries":                    true
    },
    "protectNewFiles":                  false,
    "protectNewRegistryKeys":           false,
    "accessibilityEnabled":             false,
    "restrictModules" : {
      "enabled":                        true,
      "allowedModules":                 []
    }
  }
}
```

> **Note:** The **`"appProtection"`** section is meaningful only when the process has a verifiable **App Identity** (actual, signature-verified identity via MSIX, sparse package, or PE manifest). Applications with only a mutable identity (unsigned hash-based) receive baseline in-memory protections (process, thread, token, window, atom) but **cannot** configure persistent-data protections, suite sharing, debug modes, or module whitelisting.

---

### Field Reference

#### enabled

<table>
<tr><th></th><th></th></tr>
<tr><td><b>Type</b></td><td>boolean</td></tr>
<tr><td><b>Default</b></td><td>true</td></tr>
<tr><td><b>Description</b></td><td>Master switch for app protection. When true (default), all protection mechanisms are active according to their individual settings, however, tokens are fully protected when this is true ensuring they cannot be used to impersonate the application beyond app identification. When false, the entire appProtection section is disabled and no protections are applied.</td></tr>
<tr><td><b>Enforcement</b></td><td>When false, no mandatory ACEs, compartment isolation, or signing requirements are applied to the process.</td></tr>
</table>

---

#### allowDebugging

<table>
<tr><th></th><th></th></tr>
<tr><td><b>Type</b></td><td>object</td></tr>
<tr><td><b>Description</b></td><td>Controls whether external debuggers may attach to the process.</td></tr>
</table>

##### allowDebugging.enabled

<table>
<tr><th></th><th></th></tr>
<tr><td><b>Type</b></td><td>boolean</td></tr>
<tr><td><b>Default</b></td><td>false</td></tr>
<tr><td><b>Description</b></td><td>When false (default), the system blocks debugger attachment and SeDebugPrivilege-based process manipulation. When true, anti-debug restrictions are lifted to support development/debug builds.</td></tr>
<tr><td><b>Enforcement</b></td><td>Mandatory access control on process handle rights denies debug-class access when false; when true, the debug-class restriction is removed and standard OS checks apply.</td></tr>
</table>

**When false (default):**
- Debugger attachment is blocked, including remote debugging and SeDebugPrivilege abuse.
- Administrators may still terminate the process, but cannot inspect or modify memory.

**When true:**
- Debugger attachment is permitted (subject to standard OS access control).
- Recommended only for internal/non-production builds.

---

#### processProtection

<table>
<tr><th></th><th></th></tr>
<tr><td><b>Type</b></td><td>object</td></tr>
<tr><td><b>Description</b></td><td>Controls process-level isolation and cross-instance access restrictions.</td></tr>
</table>

##### processProtection.isolatedInstance

<table>
<tr><th></th><th></th></tr>
<tr><td><b>Type</b></td><td>boolean</td></tr>
<tr><td><b>Default</b></td><td>true</td></tr>
<tr><td><b>Description</b></td><td>When true (default), each instance of the process runs in its own isolated security compartment. External callers cannot obtain CREATE_THREAD/VM_READ/VM_WRITE/VM_OPERATION or other injection rights. When false, the process relies on standard discretionary ACLs only.</td></tr>
<tr><td><b>Enforcement</b></td><td>Mandatory compound ACE requires both User SID and App Instance SID for full access; others receive minimal rights (terminate, query limited info).</td></tr>
</table>

##### processProtection.crossInstanceAccess

<table>
<tr><th></th><th></th></tr>
<tr><td><b>Type</b></td><td>object</td></tr>
<tr><td><b>Description</b></td><td>Controls which cross-instance operations are permitted between separate instances of the same protected application.</td></tr>
</table>

##### processProtection.crossInstanceAccess.readVirtualMemory

<table>
<tr><th></th><th></th></tr>
<tr><td><b>Type</b></td><td>boolean</td></tr>
<tr><td><b>Default</b></td><td>false</td></tr>
<tr><td><b>Description</b></td><td>When false (default), one instance of the application cannot read the virtual memory of another instance. When true, cross-instance VM_READ for the same application is permitted.</td></tr>
<tr><td><b>Enforcement</b></td><td>Mandatory ACE on process objects blocks VM_READ across instances when false.</td></tr>
</table>

##### processProtection.crossInstanceAccess.duplicateHandle

<table>
<tr><th></th><th></th></tr>
<tr><td><b>Type</b></td><td>boolean</td></tr>
<tr><td><b>Default</b></td><td>false</td></tr>
<tr><td><b>Description</b></td><td>When false (default), one instance of the application cannot duplicate handles from another instance. When true, cross-instance handle duplication for the same applicaiton is permitted.</td></tr>
<tr><td><b>Enforcement</b></td><td>Mandatory ACE on process objects blocks DUPLICATE_HANDLE across instances when false.</td></tr>
</table>

---

#### requireSigning

<table>
<tr><th></th><th></th></tr>
<tr><td><b>Type</b></td><td>object</td></tr>
<tr><td><b>Description</b></td><td>Controls code-signing requirements for the protected process.</td></tr>
</table>

##### requireSigning.executable

<table>
<tr><th></th><th></th></tr>
<tr><td><b>Type</b></td><td>boolean</td></tr>
<tr><td><b>Default</b></td><td>true</td></tr>
<tr><td><b>Description</b></td><td>When true (default), the main executable (or package) must be signed with a valid signature. When false, unsigned executables are permitted.</td></tr>
<tr><td><b>Enforcement</b></td><td>Signature verification is performed at process creation; unsigned executables are rejected when true.</td></tr>
</table>

##### requireSigning.libraries

<table>
<tr><th></th><th></th></tr>
<tr><td><b>Type</b></td><td>boolean</td></tr>
<tr><td><b>Default</b></td><td>true</td></tr>
<tr><td><b>Description</b></td><td>When true (default), all loaded DLLs must be signed with a valid signature. When false, unsigned libraries are permitted.</td></tr>
<tr><td><b>Enforcement</b></td><td>Code-loading paths validate library signatures; unsigned DLLs are rejected when true.</td></tr>
</table>

---

#### protectNewFiles

<table>
<tr><th></th><th></th></tr>
<tr><td><b>Type</b></td><td>boolean</td></tr>
<tr><td><b>Default</b></td><td>false</td></tr>
<tr><td><b>Description</b></td><td>When true, newly created files are automatically protected with mandatory compound ACEs requiring User+AppIdentity. When false (default), new files inherit standard discretionary ACLs and are not automatically placed under app protection, however, they will still be able to request this on a per-file/per-directory basis when creating those files/directories through an extended SECURITY_ATTRIBUTES structure (SECURITY_ATTRIBUTES_EX). This only applies to applications with a stable AppIdentity (otherwise it is ignored).</td></tr>
<tr><td><b>Enforcement</b></td><td>Mandatory ACEs applied to file/directory security descriptors at creation time; relies on stable (signature-verified) AppIdentity for persistent protection.</td></tr>
</table>

---

#### protectNewRegistryKey

<table>
<tr><th></th><th></th></tr>
<tr><td><b>Type</b></td><td>boolean</td></tr>
<tr><td><b>Default</b></td><td>false</td></tr>
<tr><td><b>Description</b></td><td>When true, newly created registry keys are automatically protected with mandatory compound ACEs requiring User+AppIdentity. When false (default), new registry keys inherit standard discretionary ACLs and are not automatically placed under app protection, however, they will still be able to request this on a per-key basis when creating keys through an extended SECURITY_ATTRIBUTES structure (SECURITY_ATTRIBUTES_EX). This only applies to applications with a stable AppIdentity (otherwise it is ignored).</td></tr>
<tr><td><b>Enforcement</b></td><td>Mandatory ACEs applied to registry key security descriptors at creation time; requires stable AppIdentity for persistent protection.</td></tr>
</table>

---

#### accessibilityEnabled

<table>
<tr><th></th><th></th></tr>
<tr><td><b>Type</b></td><td>boolean</td></tr>
<tr><td><b>Default</b></td><td>false</td></tr>
<tr><td><b>Description</b></td><td>Controls whether trusted assistive technologies (e.g., UIA/UIAccess) may interact with the protected application's UI. Default false blocks accessibility interactions across the compartment boundary. True permits access via an accessibility entitlement.</td></tr>
<tr><td><b>Enforcement</b></td><td>When true, an accessibility entitlement SID enables narrowly-scoped UI access for trusted assistive tools; otherwise blocked like any external process.</td></tr>
</table>

---

#### restrictModules

<table>
<tr><th></th><th></th></tr>
<tr><td><b>Type</b></td><td>object</td></tr>
<tr><td><b>Description</b></td><td>Controls whether third-party module loading is restricted to an explicit allow-list.</td></tr>
</table>

##### restrictModules.enabled

<table>
<tr><th></th><th></th></tr>
<tr><td><b>Type</b></td><td>boolean</td></tr>
<tr><td><b>Default</b></td><td>true</td></tr>
<tr><td><b>Description</b></td><td>When true (default), only modules listed in <code>allowedModules</code> may load into the process; all unlisted modules are rejected. When false, module restriction is disabled and <code>allowedModules</code> is ignored &mdash; any module permitted by standard OS policy may load.</td></tr>
<tr><td><b>Enforcement</b></td><td>Code-loading and injection paths validate candidate modules against the allow-list when true; when false, no module filtering is applied.</td></tr>
</table>

##### restrictModules.allowedModules

<table>
<tr><th></th><th></th></tr>
<tr><td><b>Type</b></td><td>array of strings</td></tr>
<tr><td><b>Default</b></td><td>[]</td></tr>
<tr><td><b>Description</b></td><td>Allow-list of specific external modules permitted to load into or interact with the process, identified by file hash or publisher identity. Only evaluated when <code>restrictModules.enabled</code> is true. An empty list means no third-party modules or overlays are allowed.</td></tr>
<tr><td><b>Enforcement</b></td><td>Code-loading and injection paths validate candidate modules against this list; unmatched modules are rejected.</td></tr>
</table>

---
### Defaults Summary

**`"appProtection": {}` = maximum lockdown.** All fields default to the most restrictive value.

| Field | Default | Effect of Default |
|---|---|---|
| `enabled` | `true` | App protection active; all sub-policies enforced. |
| `allowDebugging.enabled` | `false` | No debugging; debugger attach and SeDebugPrivilege bypass blocked. |
| `processProtection.isolatedInstance` | `true` | Process isolated; no external memory read/write/injection. |
| `processProtection.crossInstanceAccess.readVirtualMemory` | `false` | Cross-instance VM_READ blocked. |
| `processProtection.crossInstanceAccess.duplicateHandle` | `false` | Cross-instance handle duplication blocked. |
| `requireSigning.executable` | `true` | Main executable must be signed. |
| `requireSigning.libraries` | `true` | All loaded DLLs must be signed. |
| `protectNewFiles` | `false` | New files not automatically protected with app-identity ACEs. |
| `protectNewRegistryKey` | `false` | New registry keys not automatically protected with app-identity ACEs. |
| `accessibilityEnabled` | `false` | Assistive technology access blocked. |
| `restrictModules.enabled` | `true` | Module loading restricted to allow-list. |
| `restrictModules.allowedModules` | `[]` | No third-party modules/overlays allowed. |

---

### Examples

#### Example 1: Hardened DirectX / Anti-Cheat Game   Maximum Tamper Protection, No External Interaction

A competitive game wants a sealed execution environment. No debugging, no overlay, no accessibility tool, and no external process may interact with the games process, memory, windows, or data.

```json
"appProtection": {
}
```

Resolved (with defaults):
- enabled: true
- allowDebugging.enabled: false
- processProtection.isolatedInstance: true
- processProtection.crossInstanceAccess.readVirtualMemory: false
- processProtection.crossInstanceAccess.duplicateHandle: false
- requireSigning.executable: true
- requireSigning.libraries: true
- protectNewFiles: false
- protectNewRegistryKey: false
- accessibilityEnabled: false
- restrictModules.enabled: true
- restrictModules.allowedModules: []

---

#### Example 2: Password Manager / Credential Vault   Strong Data Protection with Accessibility Enabled

A password manager needs maximum data confidentiality while remaining accessible.

```json
"appProtection": {
  "accessibilityEnabled": true
}
```

Resolved (with defaults):
- enabled: true
- allowDebugging.enabled: false
- processProtection.isolatedInstance: true
- processProtection.crossInstanceAccess.readVirtualMemory: false
- processProtection.crossInstanceAccess.duplicateHandle: false
- requireSigning.executable: true
- requireSigning.libraries: true
- protectNewFiles: false
- protectNewRegistryKey: false
- accessibilityEnabled: true
- restrictModules.enabled: true
- restrictModules.allowedModules: []

---

#### Example 3: Enterprise Line-of-Business App   Balanced Protection with Controlled Integrations

An enterprise app requires accessibility support. Debugging remains disabled in production, but dev builds may use a separate config with `"allowDebugging": { "enabled": true }`.

```json
"appProtection": {
  "accessibilityEnabled": true
}
```

Resolved (with defaults):
- enabled: true
- allowDebugging.enabled: false (production)
- processProtection.isolatedInstance: true
- processProtection.crossInstanceAccess.readVirtualMemory: false
- processProtection.crossInstanceAccess.duplicateHandle: false
- requireSigning.executable: true
- requireSigning.libraries: true
- protectNewFiles: false
- protectNewRegistryKey: false
- accessibilityEnabled: true
- restrictModules.enabled: true
- restrictModules.allowedModules: []

---

### Internal Mapping (Tessera Implementation Reference)

| Field | Value | OS Enforcement |
|---|---|---|
| `enabled` | true | All app protection mechanisms active. |
| `enabled` | false | No protections applied; process runs under standard ACLs only. |
| `allowDebugging.enabled` | false | Mandatory SACL denies debug-class access on the process and thread objects. |
| `allowDebugging.enabled` | true | Debug-class restriction removed; standard OS checks apply. |
| `processProtection.isolatedInstance` | true | Mandatory compound ACE (User SID + AppIdentity SID) allows minimal query-only/execute (terminate) access from outside the instance. |
| `processProtection.crossInstanceAccess.readVirtualMemory` | false | Mandatory ACE blocks VM_READ across instances of the same app. |
| `processProtection.crossInstanceAccess.duplicateHandle` | false | Mandatory ACE blocks DUPLICATE_HANDLE across instances of the same app. |
| `requireSigning.executable` | true | Signature verification at process creation; unsigned executables rejected. |
| `requireSigning.libraries` | true | Signature verification at DLL load; unsigned libraries rejected. |
| `protectNewFiles` | true | Mandatory compound ACE on newly created files/directories; requires stable AppIdentity. |
| `protectNewRegistryKey` | true | Mandatory compound ACE on newly created registry keys; requires stable AppIdentity. |
| `accessibilityEnabled` | true | Accessibility entitlement permits narrowly-scoped UI interaction for trusted assistive tools. |
| `restrictModules.enabled` | true | Module loading restricted to allow-list; unlisted modules rejected at load time. |
| `restrictModules.enabled` | false | No module filtering applied; `allowedModules` ignored. |
| `restrictModules.allowedModules` | []/list | Only allow-listed publishers/hashes may load (when `restrictModules.enabled` is true). |

---

### Future Extensions

- **Targeted permissions** for screen capture/streaming overlays and selective partner interactions.
- **Persistent data exclusions** (path- or key-based) for files/registry.
- **Child process identity policy** to control inheritance vs separation.
- **Kernel-mode hardening** (Phase 3+) for VSM/VTL-backed protections.

---
