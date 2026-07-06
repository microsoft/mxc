# MXC Sandbox Policy Spec v1

---

## Table of Contents

1. [Problem Statement](#1-problem-statement)
2. [Non-Goals](#2-non-goals)
3. [Design Principles](#3-design-principles)
4. [Architecture](#4-architecture)
5. [SandboxPolicy](#5-sandboxpolicy)
6. [ContainerConfig](#6-containerconfig)
7. [Containment Types](#7-containment-types)
8. [Versioning](#8-versioning)
9. [Development Guide](#9-development-guide)
10. [Worked Example: UI Policy](#10-worked-example-ui-policy)
11. [FAQ](#11-faq)

---

## 1. Problem Statement

- The SDK has no way to express isolation intent. Callers cannot request stronger containment
  (microVM) when they need it.
- UI containment (clipboard, windows, input injection) has no cross-platform abstraction.
  Existing drafts are Windows-specific.
- The boundary between user-facing Policy and backend-specific Config is undefined.
  Contributors do not know where new features belong.
- New backends (Nanvix, WSLC, macOS) are planned. The current approach does not scale to
  N backends x M policy surfaces.

---

## 2. Non-Goals

- **Enterprise policy injection:** IT admin restrictions (Group Policy, MDM) and merge strategy.
- **Runtime permission brokering:** Flatpak-style portal dialogs. MXC policies are upfront.
- **Multi-container orchestration:** Composing sandboxes or sandbox-to-sandbox communication.
- **Audit logging and telemetry:** Compliance logging is a separate spec.

---

## 3. Design Principles

### Principle 1: Intent, Not Mechanism

Policy describes *what* the caller wants. ContainerConfig describes *how* the platform enforces it.

A caller writes `network: { allowOutbound: true }`. They never write firewall rules, iptables
chains, or capability lists. Mechanisms belong in ContainerConfig and backend executors.

### Principle 2: Default-Deny

Omitted policy fields = most restrictive permissions. Adding a field opts *in* to a capability.

```typescript
// Fully locked down:
spawnSandbox("script.sh", { version: "0.5.0-dev" });

// Allow outbound network:
spawnSandbox("script.sh", {
  version: "0.5.0-dev",
  network: { allowOutbound: true },
});
```

New fields added in future versions default to "denied" for existing policies that do not set
them. This is a security guarantee.

### Principle 3: Cross-Platform Where Possible

Policy fields work on two or more platforms. The enforcement mechanism differs per platform, but
the intent is the same. Fields that only apply to one backend live in ContainerConfig, not Policy.

### Principle 4: Version Is a Contract

> See [versioning.md](../../versioning.md) for the full versioning design.

The Policy version and ContainerConfig schema version are locked in step. A version number
guarantees behavior.

---

## 4. Architecture

MXC has two user-facing concepts:

1. **SandboxPolicy** (input): what the caller wants restricted.
   Cross-platform security intent: filesystem,
   network, UI, timeout. No OS-specific content.
2. **ContainerConfig** (output): the full configuration for one
   specific backend. Returned by `createConfigFromPolicy()`.
   Modifiable before spawning. Contains backend-specific sections.

A **backend** is the containment technology that the executor
uses to create the sandbox (e.g., BaseProcessContainer on
Windows, LXC on Linux).

### Flow

```
SandboxPolicy --> createConfigFromPolicy(policy, containment) --> ContainerConfig --> spawnSandboxFromConfig() --> executor --> OS
```

### Two API paths

```typescript
// Simple: policy in, sandbox out. Always uses process containment.
spawnSandbox(script, policy);

// Advanced: choose containment, get config, modify, then spawn.
const config = createConfigFromPolicy(policy, "process");
config.processContainer!.ui!.isolation = "atoms";  // backend-specific tweak
spawnSandboxFromConfig(config);
```

`spawnSandbox` accepts a SandboxPolicy. For pre-built configs, use `spawnSandboxFromConfig`.

### Layer diagram

```
┌───────────────────────────────────────────────────────────────┐
│ LAYER 1: SDK + SandboxPolicy                                  │
│                                                               │
│ Users: GitHub CLI, Copilot, third-party agents                │
│                                                               │
│ SandboxPolicy: filesystem, network, ui, timeout               │
│ Simple:   spawnSandbox(script, policy)                        │
│ Advanced: createConfigFromPolicy(policy, "process")           │
│             → modify config                                   │
│             → spawnSandboxFromConfig(config)                  │
└─────────────────────────────┬─────────────────────────────────┘
                              │ ContainerConfig (JSON)
                              ▼
┌───────────────────────────────────────────────────────────────┐
│ LAYER 2: Executors (wxc-exec, lxc-exec)                       │
│                                                               │
│ Parse ContainerConfig JSON, select backend runner             │
│ Backends: BaseProcessContainer, LXC,                          │
│           microVM (Nanvix), WSLC                              │
│                                                               │
│ Rust. Schema-validated.                                       │
└─────────────────────────────┬─────────────────────────────────┘
                              │ OS API calls
                              ▼
┌───────────────────────────────────────────────────────────────┐
│ LAYER 3: OS Primitives                                        │
│                                                               │
│ Windows: BaseProcessContainer, BFS, Firewall, Job Objects     │
│ Linux: LXC cgroups, bind mounts, iptables, seccomp            │
│                                                               │
│ Kernel-level enforcement.                                     │
│ Never referenced by name in Layer 1.                          │
└───────────────────────────────────────────────────────────────┘
```

### Config granularity

ContainerConfig translates policy into something the executors can act on. It is not a
general-purpose deployment manifest.

Rules:

- **Every Config field must be reachable** from policy or SDK defaults. If a
  field has no path from user-facing input, it should not exist.
- **Keep Config minimal.** Only add fields that executors actually need.
- **SDK defaults to deny** for unfilled policy fields.

---

## 5. SandboxPolicy

SandboxPolicy is the user-facing input. It expresses security intent: what to allow, what to
deny. Cross-platform. No OS-specific content.

```typescript
type SandboxPolicy = {
  version: string;
  filesystem?: {
    readwritePaths?: string[];
    readonlyPaths?: string[];
    deniedPaths?: string[];
    tempDir?: "shared" | "isolated";
  };
  network?: {
    allowOutbound?: boolean;
    allowLocalNetwork?: boolean;
    allowedHosts?: string[];
    blockedHosts?: string[];
    proxy?: { builtinTestServer: true } | { localhost: number } | { url: string };
  };
  ui?: {
    allowWindows?: boolean;
    clipboard?: "none" | "read" | "write" | "readwrite";
    allowInputInjection?: boolean;
  };
  timeoutMs?: number;
};
```

### `filesystem`

| Field            | Description                                                                  |
|------------------|------------------------------------------------------------------------------|
| `readwritePaths` | Paths the sandbox can read and write.                                        |
| `readonlyPaths`  | Paths the sandbox can read but not write.                                    |
| `deniedPaths`    | Paths the sandbox cannot access at all.                                      |
| `tempDir`        | `"shared"`: host temp dir. `"isolated"`: private temp dir (`TEMP`/`TMPDIR`). |

Omitted = no filesystem access beyond the default sandbox root.

### `network`

All flags default to `false` (no network access).

| Field              | Description |
|--------------------|-------------|
| `allowOutbound`    | Allow outbound connections to the internet (HTTP, DNS, etc.). |
| `allowLocalNetwork`| Allow connections to local networks. |
| `allowedHosts`     | When set, ONLY these outbound hosts are reachable. Host-filtering backends (Linux, macOS) accept this without `allowOutbound`; Windows ProcessContainer requires `allowOutbound`. |
| `blockedHosts`     | Hosts to block even when outbound is allowed. Same `allowOutbound` requirement as `allowedHosts` (Windows ProcessContainer only). |
| `proxy`            | `{ builtinTestServer: true }`, `{ localhost: <port> }`, or `{ url: "..." }`. Routes all traffic through this proxy. Cannot be combined with other network flags. `builtinTestServer` is testing-only and requires the `--allow-testing-features` flag (set `allowTestingFeatures: true` in the SDK spawn options). |

Omitted = no network access.

### `ui`

Cross-platform intent fields only. Backend-specific UI mechanisms live in ContainerConfig.

| Field                 | Description                                                   |
|-----------------------|---------------------------------------------------------------|
| `allowWindows`        | Whether the sandbox may create visible windows. Default: no.  |
| `clipboard`           | `"none"` (default), `"read"`, `"write"`, or `"readwrite"`.   |
| `allowInputInjection` | Whether the sandbox may inject keyboard/mouse input. Default: no. |

### `timeoutMs`

Execution timeout in milliseconds. Omitted = SDK default (no timeout).

### Default-deny

An empty policy is fully locked down:

```typescript
spawnSandbox("script.sh", { version: "0.5.0-dev" });
// No filesystem, no network, no UI, no input injection.
```

---

## 6. ContainerConfig

`createConfigFromPolicy()` returns a ContainerConfig: the complete configuration for one
specific backend. Users receive it, may modify backend-specific fields, then pass it to
`spawnSandboxFromConfig()`.
Key rules:

- **One backend per Config.** A Windows process config has an `processcontainer` section; no `lxc`
  section. A Linux process config has an `lxc` section; no `processcontainer`.
- **User-modifiable.** Advanced users can set any Config field before spawning.
- **Schema-defined.** Schemas live in `schemas/`. The SDK TypeScript types mirror them.

All configs share common sections (filesystem, network, ui).
Each backend adds its own sections on top:

```typescript
type ContainerConfig =
  | ProcessContainerConfig
  | LxcContainerConfig
  | MicroVmConfig;
```

### Example: ProcessContainerConfig

```json
{
  "version": "0.5.0-dev",
  "containment": "process",
  "process": {
    "commandLine": "node agent.js",
    "cwd": "C:\\workspace",
    "env": ["NODE_ENV=production"],
    "timeout": 30000
  },
  "lifecycle": {
    "destroyOnExit": true,
    "preservePolicy": false
  },
  "filesystem": {
    "readwritePaths": ["C:\\workspace"],
    "readonlyPaths": ["C:\\tools"],
    "deniedPaths": []
  },
  "network": {
    "defaultPolicy": "outbound",
    "enforcementMode": "firewall",
    "allowedHosts": [],
    "blockedHosts": [],
    "proxy": null
  },
  "processcontainer": {
    "leastPrivilege": true,
    "capabilities": [],
    "ui": {
      "isolation": "full",
      "desktopSystemControl": false,
      "systemSettings": "none",
      "ime": false
    }
  },
  "ui": {
    "disable": true,
    "clipboard": "none",
    "injection": false
  }
}
```

Backend-specific UI fields (`isolation`, `desktopSystemControl`, `systemSettings`, `ime`)
live inside `processcontainer.ui`, not at the top level. Top-level `ui` contains only the
cross-platform fields mapped from Policy.

### Example: LxcContainerConfig

```json
{
  "version": "0.5.0-dev",
  "containment": "lxc",
  "process": {
    "commandLine": "bash run.sh",
    "cwd": "/workspace",
    "env": [],
    "timeout": 30000
  },
  "lifecycle": {
    "destroyOnExit": true
  },
  "filesystem": {
    "readwritePaths": ["/workspace"],
    "readonlyPaths": [],
    "deniedPaths": []
  },
  "network": {
    "defaultPolicy": "outbound",
    "allowedHosts": [],
    "blockedHosts": []
  },
  "lxc": {
    "distribution": "alpine",
    "release": "3.23"
  }
}
```

No `processcontainer` section. No `ui` section. Backend-specific fields are scoped to the backend
that uses them.

---

## 7. Containment Types

The second parameter to `createConfigFromPolicy()` selects
the containment backend:

```typescript
const config = createConfigFromPolicy(policy, "process");
```

| Value              | Windows backend           | Linux backend   | Status      |
|--------------------|---------------------------|-----------------|-------------|
| `"process"`        | BaseProcessContainer      | LXC             | Implemented |
| `"microvm"`        | Nanvix                    | microVM         | Future      |
| `"agentSession"`   | Agent session container   | N/A             | Future      |

Only `"process"` is end-to-end implemented today.

`spawnSandbox(script, policy)` always defaults to `"process"`.

---

## 8. Versioning

> See [versioning.md](../../versioning.md) for full details.

- Policy version = ContainerConfig schema version. Always bumped together.
- SDK version is independent. SDK v5.0 can use policy/schema v2.1.
- During alpha, expect breaking changes.

---

## 9. Development Guide

> See [authoring-a-new-feature.md](../../authoring-a-new-feature.md) for the full workflow and
> decision tree.
>
> See [process-container/guide.md](../../process-container/guide.md) for OS-level implementation
> details.

---

## 10. Worked Example: UI Policy

### 10.1 SDK user perspective

**Simple path:** policy only, defaults to process containment:

```typescript
const policy: SandboxPolicy = {
  version: "0.5.0-dev",
  filesystem: { readwritePaths: ["C:\\workspace"] },
  network: {},
  ui: {
    allowWindows: true,
    clipboard: "read",
    allowInputInjection: false,
  },
  timeoutMs: 60000,
};

spawnSandbox("myapp.exe --flag1 arg", policy);
```

**Advanced path:** choose containment, get config, tweak:

```typescript
const config = createConfigFromPolicy(policy, "process");
config.processContainer!.ui!.isolation = "atoms";
spawnSandboxFromConfig(config);
```

### 10.2 MXC developer perspective

An MXC developer adding UI containment support would:

**1. Add policy fields (if applicable)** (`sdk/src/types.ts`):

If the feature is cross-platform security intent, add it to
`SandboxPolicy`. If the feature introduces a new containment
backend, add a new value to the `createConfigFromPolicy()`
containment parameter. UI is not a new backend, so we only
add policy fields here:

```typescript
ui?: {
  allowWindows?: boolean;
  clipboard?: "none" | "read" | "write" | "readwrite";
  allowInputInjection?: boolean;
};
```

**2. Add Config schema fields** (`schemas/dev/`):

Top-level `ui` (maps from policy, all backends):

```json
"ui": {
  "disable": true,
  "clipboard": "none",
  "injection": false
}
```

Process container-specific UI fields (in this case Windows):

```json
"processcontainer": {
  "ui": {
    "isolation": "full",
    "desktopSystemControl": false,
    "systemSettings": "none",
    "ime": false
  }
}
```

**3. Add Config TypeScript types** (`sdk/src/types.ts`):

Top-level UI (all backends):

```typescript
// Add to BaseContainerConfig:
ui: {
  disable: boolean;
  clipboard: string;
  injection: boolean;
};
```

Process container-specific UI (inside `processcontainer`):

```typescript
// Add to ProcessContainerConfig.processcontainer:
ui: {
  isolation: "desktop" | "handles" | "atoms" | "full";
  desktopSystemControl: boolean;
  systemSettings: string;
  ime: boolean;
};
```

**4. Map policy to Config in SDK** (`sdk/src/sandbox.ts`):

In `createConfigFromPolicy()`, map policy `ui` fields to
Config `ui` fields and fill backend-specific defaults:

```typescript
// Top-level ui (from policy, all backends):
config.ui = {
  disable: !policy.ui?.allowWindows,
  clipboard: mapClipboard(policy.ui?.clipboard ?? 'none'),
  injection: policy.ui?.allowInputInjection ?? false,
};

// Process container-specific ui (Windows only):
if (platform === 'win32' && config.containment === 'process') {
  config.processcontainer.ui = {
    isolation: 'full',
    desktopSystemControl: false,
    systemSettings: 'none',
    ime: false,
  };
}
```

**5. Implement in executor** (`base_container_runner.rs`):

Build the `ui_restrictions` bitmask from the `ui` section of
the ContainerConfig schema and translate it to OS-level Job
Object UI restriction flags.

> See
> [authoring-a-new-feature.md](../../authoring-a-new-feature.md)
> for the full workflow.
> See
> [process-container/guide.md](../../process-container/guide.md) for
> the executor and OS implementation guide.

---

## 11. FAQ

### "Where does my new feature go: Policy or ContainerConfig?"

Use the decision tree in
[authoring-a-new-feature.md](../../authoring-a-new-feature.md). In short: if it is a
cross-platform security intent that works on two or more platforms, it belongs in Policy.
Backend-specific mechanisms belong in ContainerConfig.

### "What if my feature is Windows-only?"

Put it in ContainerConfig under the appropriate backend section (e.g., `processcontainer` or `ui`
inside ProcessContainerConfig). Policy stays cross-platform.

### "Can a developer bypass the SDK defaults?"

Yes, via the advanced path. `createConfigFromPolicy()` returns secure defaults; the user
modifies any Config field before calling `spawnSandboxFromConfig()`. No bypass needed: Config is the
thing they modify.

### "What happens if I omit all policy fields?"

```typescript
spawnSandbox("script.sh", { version: "0.5.0-dev" });
```

Produces a fully locked-down config: no filesystem access, no network, UI disabled, no input
injection. Default-deny.

### "Can I pass ContainerConfig JSON directly to an executor?"

Yes. `wxc-exec config.json` accepts raw ContainerConfig. Useful for testing and internal
development. `createConfigFromPolicy()` is the recommended SDK path for production if needing control over
the configuration itself.

