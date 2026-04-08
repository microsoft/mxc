# SandboxRequest Reference

> **This is the API reference for `SandboxRequest`.** For design rationale
> and development guidance, see [policy.md](policy.md).

> **Language:** The MXC SDK is TypeScript-only (`@microsoft/mxc-sdk`).
> All types below are TypeScript interfaces.

---

## SandboxRequest Type

```typescript
type SandboxRequest = {
  version: string;
  policy: SandboxPolicy;
  environment?: SandboxEnvironment;
};
```

---

## SandboxPolicy Type

```typescript
type SandboxPolicy = {
  filesystem?: FilesystemPolicy;
  network?: NetworkPolicy;
  ui?: UIPolicy;
  resources?: ResourcesPolicy;
  timeoutMs?: number;
  lifecycle?: LifecyclePolicy;
};
```

---

## SandboxEnvironment Type

```typescript
type SandboxEnvironment = {
  isolation?: "process" | "container" | "microvm" | "disposableVm";
  linux?: {
    distribution?: string;
    release?: string;
  };
};
```

---

## SandboxRequest Fields

### `version`

| | |
|---|---|
| **Type** | `string` (semver) |
| **Required** | Yes |
| **Description** | Policy/schema version. Must match the MXC config schema version. This is NOT the SDK npm version. See [versioning.md](../../versioning.md). |
| **Example** | `"0.5.0-dev"` |

---

## SandboxPolicy Fields

### `filesystem`

Controls which host filesystem paths are accessible inside the sandbox.

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `readwritePaths` | `string[]` | `[]` | Paths granted read-write access. |
| `readonlyPaths` | `string[]` | `[]` | Paths granted read-only access. |
| `deniedPaths` | `string[]` | `[]` | Paths explicitly denied all access. |
| `tempDir` | `"shared" \| "isolated"` | `"isolated"` | `"shared"`: use host temp dir. `"isolated"`: sandbox gets its own private temp directory. |

**Example:**
```typescript
filesystem: {
  readwritePaths: ["/workspace"],
  readonlyPaths: ["/usr/local/bin", "/tools"],
  deniedPaths: ["/home/user/.ssh"],
  tempDir: "isolated",
}
```

---

### `network`

Controls network access from the sandbox.

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `policy` | `"none" \| "local" \| "outbound" \| "full"` | `"none"` | Network access posture. `"none"`: no network. `"local"`: localhost + RFC 1918 only (narrowed by `allowedHosts` if set). `"outbound"`: outbound internet, no inbound (`allowedHosts` acts as allowlist if set). `"full"`: all traffic. |
| `allowedHosts` | `string[]` |: | Host allowlist (hostnames, IPs, CIDR). Only valid with `policy: "outbound"`. If omitted, all outbound traffic is allowed. |
| `blockedHosts` | `string[]` |: | Hosts to explicitly block. Only valid with `policy: "outbound"`. |
| `proxy` | `{ builtinTestServer: true } \| { url: string }` | — | Proxy configuration. `builtinTestServer`: MXC's built-in test proxy. `url`: proxy URL including protocol, host, and port (e.g., `"http://localhost:8080"`, `"socks5://proxy.corp.com:1080"`). |
| `enforcementMode` | `"firewall" \| "both"` | `"firewall"` | How network policy is enforced. `"firewall"`: firewall rules only. `"both"`: firewall + additional backend-specific enforcement. |

> ⚠️ With `policy: "outbound"` and no `allowedHosts`, ALL outbound traffic is allowed. For untrusted code, combine
with `allowedHosts`.

**Example:**
```typescript
network: {
  policy: "outbound",
  allowedHosts: ["github.com", "npmjs.org", "pypi.org"],
}
```

---

### `ui`

Controls whether the sandboxed process can interact with the
host's graphical environment. All fields default to the most
restrictive value (default-deny).

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `allowWindows` | `boolean` | `false` | Allow the process to create windows and use the GUI subsystem. |
| `clipboard` | `"none" \| "read" \| "write" \| "readwrite"` | `"none"` | Clipboard access between sandbox and host. |
| `allowInputInjection` | `boolean` | `false` | Allow synthetic keyboard/mouse input injection. |
| `isolation` | `"desktop" \| "handles" \| "atoms" \| "full"` | `"full"` | UI handle and atom table isolation level. Windows only. |
| `desktopSystemControl` | `boolean` | `false` | Allow desktop creation/switching and session shutdown. Windows only. |
| `systemSettings` | `"all" \| "parameters" \| "display" \| "none"` | `"none"` | System UI settings access. Windows only. |
| `ime` | `boolean` | `false` | Allow IME module loading. Windows only. Irreversible once disabled. |

**Example:**
```typescript
ui: {
  allowWindows: true,
  clipboard: "read",
  allowInputInjection: false,
  // Windows-only fields (ignored on other platforms):
  isolation: "full",
  ime: false,
}
```

---

### `resources`

Resource limits for the sandbox.

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `maxMemoryMB` | `number` | `0` (no limit) | Maximum memory in MB. |
| `maxCpus` | `number` | `0` (no limit) | Maximum CPU cores. |

---

### `timeoutMs`

| | |
|---|---|
| **Type** | `number` |
| **Default** | `0` (no timeout) |
| **Description** | Execution timeout in milliseconds. The process is terminated after this duration. `0` means no timeout. |

---

### `lifecycle`

Controls sandbox lifecycle behavior.

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `destroyOnExit` | `boolean` | `true` | Destroy the sandbox after the process exits. Set to `false` for persistent/reusable sandboxes. |

---

### `leastPrivilege`

| | |
|---|---|
| **Type** | `boolean` |
| **Default** | `false` |
| **Description** | Enforce least privilege mode on the sandbox process. When `true`, the sandbox runs with the minimum permissions needed. Windows only. |

---

### `integrityLevel`

| | |
|---|---|
| **Type** | `"inherit" \| "low" \| "medium"` |
| **Default** | `"inherit"` |
| **Description** | Process integrity level for the sandbox. `"inherit"`: use caller's IL. `"low"`: Low IL (most restricted, traditional AppContainer). `"medium"`: Medium IL (less restricted, enabled by AppContainer/IL decoupling). Windows only. |

---

## SandboxEnvironment Fields

### `isolation`

| | |
|---|---|
| **Type** | `"process" \| "container" \| "microvm" \| "disposableVm"` |
| **Default** | `"process"` |
| **Description** | Desired isolation strength. The SDK selects the best available backend for the current OS. |

| Value | What you get | Win backend | Linux backend |
|-------|-------------|-------------|---------------|
| `"process"` | Restricted process on host OS. Shared kernel, shared filesystem. Fastest startup. | BaseProcessContainer | LXC |
| `"container"` | Self-contained environment with its own filesystem root and packages. | WSLC (future) | Docker (future) |
| `"microvm"` | Lightweight VM. Minimal footprint, fast boot, limited environment. | Hyperlight/NanVix (future) | microVM (future) |
| `"disposableVm"` | Full VM. Complete OS environment, hardware-level isolation. | Disposable VM (future) | (future) |

> Today only `"process"` is implemented. Other levels return
> `BACKEND_UNAVAILABLE` until their backends ship.

---

### `linux`

Linux-specific runtime options.

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `distribution` | `string` | SDK default (`"alpine"`) | Linux distribution for the container rootfs. |
| `release` | `string` | SDK default (`"3.23"`) | Distribution release version. |

---

### `vm`

VM-specific runtime options. Only used when `isolation` is
`"microvm"` or `"disposableVm"`.

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `idleTimeoutMs` | `number` | `300000` (5 min) | Idle timeout in ms before the VM is torn down. `0` = no timeout. |
| `daemonPipeName` | `string` | `"wxc-sandbox"` | Named pipe name for the VM daemon (Windows only). |

---

### `linux`

Linux-specific runtime options. Silently ignored on non-Linux platforms.

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `distribution` | `string` | SDK default | Preferred Linux distribution (e.g., `"alpine"`, `"ubuntu"`). Used with `"container"` isolation (future). |
| `release` | `string` | SDK default | Distribution release version (e.g., `"3.23"`, `"24.04"`). |

---

## Backend Coverage

The `environment.isolation` enum maps to backends. Only `"process"` is fully implemented today:

| Config Backend | `isolation` Level | Status |
|----------------|------------------|--------|
| `appcontainer` | `"process"` (Windows) | Stable (BaseProcessContainer) |
| `lxc` | `"process"` (Linux) | Stable |
| `sandbox` | `"disposableVm"` (Windows) | Experimental |
| `wslc` | `"container"` (Windows) | Planned |
| `nanvix` | `"microvm"` (Windows) | Experimental |
| `docker` | `"container"` | Not started |

---

## Defaults Summary

All fields default to the most restrictive value. **An empty policy = maximum lockdown.**

```typescript
// This creates a fully locked-down sandboxed process (the default):
const request: SandboxRequest = { version: "0.5.0-dev", policy: {} };
// No filesystem access, no network, no GUI, no timeout, ephemeral.
```

| Section | Field | Default | Effect |
|---------|-------|---------|--------|
| `policy` | `timeoutMs` | `0` | No timeout |
| `policy.filesystem` | `readwritePaths` | `[]` | No write access |
| `policy.filesystem` | `readonlyPaths` | `[]` | No read access |
| `policy.filesystem` | `deniedPaths` | `[]` | No explicit denies |
| `policy.filesystem` | `tempDir` | `"isolated"` | Private temp dir |
| `policy.network` | `policy` | `"none"` | No network |
| `policy.ui` | `allowWindows` | `false` | GUI disabled |
| `policy.ui` | `clipboard` | `"none"` | No clipboard |
| `policy.ui` | `allowInputInjection` | `false` | No input injection |
| `policy.ui` | `isolation` | `"full"` | Full handle + atom isolation (Win) |
| `policy.ui` | `desktopSystemControl` | `false` | No desktop control (Win) |
| `policy.ui` | `systemSettings` | `"none"` | No system settings (Win) |
| `policy.ui` | `ime` | `false` | IME disabled (Win) |
| `policy.resources` | `maxMemoryMB` | `0` | Unlimited |
| `policy.resources` | `maxCpus` | `0` | Unlimited |
| `policy` | `leastPrivilege` | `false` | Not enforced (Win) |
| `policy` | `integrityLevel` | `"inherit"` | Caller's IL (Win) |
| `policy.network` | `enforcementMode` | `"firewall"` | Firewall enforcement |
| `policy.lifecycle` | `destroyOnExit` | `true` | Ephemeral sandbox |
| `environment` | `isolation` | `"process"` | Process-level isolation |
| `environment.vm` | `idleTimeoutMs` | `300000` | 5 min idle timeout |
| `environment.vm` | `daemonPipeName` | `"wxc-sandbox"` | Default pipe name (Win) |

---

## Cross-Field Interactions

| Field Combination | Behavior |
|-------------------|----------|
| `network.policy: "none"` + `network.proxy` | Proxy is ignored. No network means no proxy. SDK logs a warning. |
| `network.policy: "none"` + `network.allowedHosts` | allowedHosts is ignored. |
| `ui.allowWindows: false` + `ui.clipboard` | Clipboard is irrelevant when GUI is disabled. SDK still passes the value for defense-in-depth. |
