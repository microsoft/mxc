# MXC Linux Container Support from Windows frontend — Design Document

## Problem

MXC (Microsoft eXecution Container) runs untrusted code in sandboxed environments, but only supports Windows AppContainer. There is no way to run Linux apps today from Windows front-end.

## Proposed Solution

Add a **WSL Container runner** directly into the existing `wxc-exec.exe` Rust binary, using the **[WSL Container SDK (WSLC SDK)](https://microsoft-my.sharepoint-df.com/:w:/p/richfr/cQp13XN0n_AURL9yxz2qBILYEgUCvFhTO6rwSfNlSVE6lUjBxQ?CID=4cb4ab01-ef3a-6ce4-1676-4706077e81ca)** as the container runtime interface. When the JSON config specifies `"containment": "wslc"`, the binary routes to a new `WSLContainerRunner` instead of `AppContainerScriptRunner`. The runner calls WSLC SDK C APIs (via Rust FFI bindings) to manage sessions, containers, and process I/O — eliminating the need to build a custom containerd gRPC client or OCI spec builder. This leverages the existing `ScriptRunner` trait and keeps everything in a single binary.

## How It Works

```
Path A — CLI (direct):
  User: wxc-exec.exe --container --image python:3.12 "python3 my_app.py"
    └── Clap parses args → builds JSON config internally → dispatches to WSLContainerRunner

Path B — SDK (programmatic):
  App calls: spawnSandbox("python3 my_app.py", policy, { containment: "wslc" })
    ├── Detects WSLC SDK available via wxc-exec.exe --check-platform
    ├── Builds JSON config with containment = "wslc"
    └── Spawns wxc-exec.exe with the config

Both paths converge here:
  wxc-exec.exe (Rust — single binary, three backends)
    ├── Parses JSON config → sees containment = "wslc"
    ├── Creates WSLContainerRunner (via existing Box<dyn ScriptRunner> dispatch)
    ├── Calls WSLC SDK via Rust FFI bindings:
    │     WslcCanRun()                → preflight check
    │     WslcSessionInitSettings()   → init session settings (with storagePath)
    │     WslcSessionSettingsSetCpuCount() / SetMemory() / SetTimeout() → configure session
    │     WslcSessionCreate()         → create WSL2 micro-VM session
    │     WslcSessionImageList()      → verify image exists (fail if not found)
    │     WslcContainerInitSettings() → init from image name
    │     WslcContainerSettingsAddVolume()  → mount host paths
    │     WslcContainerSettingsSetNetworkingMode() → network policy
    │     WslcProcessInitSettings()   → configure executable, args, env, cwd
    │     WslcContainerSettingsSetInitProcess() → attach process to container
    │     WslcContainerCreate(session, settings) → create container in session
    │     WslcContainerStart()        → start container
    │     WslcContainerGetInitProcess() → get process handle
    │     WslcProcessGetIOHandles()   → get stdout/stderr Win32 HANDLEs
    │     ReadFile(stdout/stderr)     → capture output → ScriptResponse
    │     WslcContainerStop()         → teardown
    │     WslcContainerDelete()       → cleanup
    │     WslcSessionTerminate()      → release micro-VM
    └── Returns ScriptResponse with captured output + exit code
```

## Architecture: Single Binary, Three Backends

The recent SandboxRunner work introduced a `ContainmentBackend` enum and dynamic dispatch in `main.rs` — the binary already supports multiple backends. We add a third variant for Linux containers.

```
                    wxc-exec.exe (Rust)
                          │
                   config_parser.rs
                   reads "containment" field
                          │
           ┌──────────────┼──────────────┐
           ▼              ▼              ▼
  AppContainerScript   Sandbox       WSLContainer
  Runner (existing)    ScriptRunner  Runner (new)
           │           (existing)         │
     AppContainer          │         WSLC SDK (C API)
     NTFS ACLs        Windows        via Rust FFI
     WFP firewall     Sandbox VM     ├── WSL2 micro-VM
                                     ├── OCI containers
                                     └── Win32 HANDLE I/O
```

All three backends implement the `ScriptRunner` trait. `main.rs` already uses `Box<dyn ScriptRunner>` with a `match` on `request.containment`. Adding the WSLC path requires one new match arm:

```rust
// main.rs — current dispatch (from SandboxRunner work)
let mut runner: Box<dyn ScriptRunner> = match request.containment {
    ContainmentBackend::AppContainer => Box::new(AppContainerScriptRunner::new()),
    ContainmentBackend::Sandbox => Box::new(SandboxScriptRunner::new(&request.sandbox_config)),
    // NEW — add this arm:
    ContainmentBackend::Wslc => Box::new(WSLContainerRunner::new(&request.container_config)),
};
```

## What We Take from [WLXC](https://github.com/vriveras/wlxc) (Reference Only)

| WLXC Pattern | MXC Implementation |
|---|---|
| Container lifecycle model (`daemon.rs:505-953`) | Adapted into `WSLContainerRunner` — but calling WSLC SDK APIs instead of containerd gRPC |
| Backend enum + routing (`backend.rs`, `daemon.rs:220-279`) | Already exists: `ContainmentBackend` enum + `match` dispatch in `main.rs` (the SandboxRunner work) |
| Policy → mount translation (`policy.rs`) | `wxc_common/src/policy_mapping.rs` — maps to `WslcContainerSettingsAddVolume()` calls |
| `setup-containerd.ps1` setup script | Replaced by WSLC SDK's `WslcInstallWithDependencies()` + lightweight setup script |

**Note:** The WSLC SDK replaces the need for WLXC's containerd gRPC client (`containerd/client.rs`) and OCI spec builder (`daemon.rs:2450-2627`) entirely. The SDK handles containerd communication, image management, OCI spec construction, and namespace setup internally.

## Development Phases

---

### Phase 1 — SDK Types & Platform Detection

**Goal:** Make the SDK aware that more than one sandboxing backend can exist, and detect what's available on the current machine.

**Why it matters:** This phase is specifically needed for **programmatic SDK consumers** — apps (e.g., Electron, Node.js services) that call `spawnSandbox()` directly rather than going through the CLI. Today, `spawnSandbox(script, policy)` always spawns `wxc-exec.exe` with an AppContainer config. After this phase, `spawnSandbox(script, policy, { containment: 'wslc' })` generates a WSLC config and passes it to the same `wxc-exec.exe` binary, which routes internally.

**Note:** If the only entry point is the CLI (`wxc-exec.exe --container`), this phase can be deferred — the CLI can set `containment: "wslc"` in the config directly. Phase 1 becomes necessary when SDK consumers need programmatic access to Linux containers.

**What already exists:**
- `PlatformSupport` interface (`types.ts:106-113`) already has an `availableMethods: SandboxingMethod[]` field.
- `getPlatformSupport()` (`platform.ts:85-87`) already initializes it as an empty array.
- The plumbing is in place — we need to extend the type and populate the array.

**What changes:**
- `sdk/src/types.ts` — Extend `SandboxingMethod = 'appcontainer' | 'wslc' | 'sandbox'` (line 101) to mirror the Rust `ContainmentBackend` enum variants. Add `TargetOs = 'linux' | 'windows'` type. Add a `ContainerConfig` interface with `targetOs`, `image`, `cpuCount`, `memoryMb`, `gpu`, and `storagePath` fields.

**Naming note:** The TypeScript SDK uses `SandboxingMethod` while the Rust binary uses `ContainmentBackend`. These are the same concept at different layers — the SDK generates JSON with a `containment` field value that maps directly to the Rust enum variant:
| SDK (`SandboxingMethod`) | JSON `containment` value | Rust (`ContainmentBackend`) |
|---|---|---|
| `'appcontainer'` | `"appcontainer"` | `AppContainer` |
| `'sandbox'` | `"sandbox"` | `Sandbox` |
| `'wslc'` | `"wslc"` | `Wslc` (new) |
- `sdk/src/platform.ts` — In `getPlatformSupport()`, after existing Windows checks, probe for WSLC SDK availability by spawning `wxc-exec.exe --check-platform` and parsing its JSON output (which wraps `WslcCanRun()` internally). If the output reports `canRun: true`, push `'wslc'` into the existing `availableMethods[]`. If it reports missing components, populate `availableMethods` conditionally so the caller knows what's missing vs what's present. SDK consumers check `support.availableMethods.includes('wslc')` to know if Linux containers are available.
- `sdk/src/sandbox.ts` — Accept `containment` in `SandboxSpawnOptions`. When `containment: 'wslc'`, set `containment: "wslc"` in the JSON config passed to `wxc-exec.exe`. The SDK still spawns the same binary — it generates a different config.
- `sdk/package.json` — Remove the `"os": ["win32"]` restriction so the package can be installed on any platform (even if execution is gated at runtime).

**WLXC reference:** WLXC's `Backend` enum (`backend.rs:24-28`) and `ContainerType` proto enum (`wlxc.proto:34-37`). We're expressing the same concepts in TypeScript as `SandboxingMethod` and `TargetOs`.

---

### Phase 2 — Configuration Schema & Backend Routing

**Goal:** Extend the JSON config format so users can request WSLC execution, and add the new variant to the existing backend routing.

**What already exists (the SandboxRunner work):**
- `ContainmentBackend` enum in `models.rs` with `AppContainer` and `Sandbox` variants
- `main.rs` already does `Box<dyn ScriptRunner>` dispatch via `match request.containment`
- `SandboxScriptRunner` — a working second backend that delegates to a Windows Sandbox daemon
- The config parser already reads a `containment` field from JSON

**What this means:** We don't need to build the routing infrastructure — it's already there. We extend it with a third variant.

**What changes:**

Models (`wxc_common/src/models.rs`):
- Add `Wslc` variant to existing `ContainmentBackend` enum.
- Add `ContainerConfig` struct with `target_os`, `image`, `cpu_count`, `memory_mb`, `gpu`, `storage_path`.
- Add `container_config: ContainerConfig` field to `CodexRequest`.

Config parser (`wxc_common/src/config_parser.rs`):
- Add `RawContainerConfig` struct with fields: `targetOs` (`"linux"` or `"windows"`), `image` (user-specified, e.g., `"python:3.12"`, `"ubuntu:22.04"`, `"alpine:latest"`), `cpuCount` (optional, defaults to host-determined), `memoryMb` (optional), `gpu` (optional bool), `storagePath` (optional, for WSLC session storage), `portMappings` (optional array of `{ windowsPort, containerPort, protocol }` entries for host↔container port forwarding).
- Add `container` field to `RawConfig` (optional `RawContainerConfig`).
- Extend `convert_raw_config()` to populate the new `container_config` field on `CodexRequest`.
- The existing `containment` field parsing already handles the enum — adding `"wslc"` as a valid value is sufficient (serde does this automatically from the new enum variant).

Entry point (`wxc/src/main.rs`):
- Add one match arm to the existing dispatch (line 135-138):

```rust
// main.rs — add the Wslc arm to the existing match
let mut runner: Box<dyn ScriptRunner> = match request.containment {
    ContainmentBackend::AppContainer => Box::new(AppContainerScriptRunner::new()),
    ContainmentBackend::Sandbox => Box::new(SandboxScriptRunner::new(&request.sandbox_config)),
    ContainmentBackend::Wslc => Box::new(WSLContainerRunner::new(&request.container_config)),
};
```

**Example config after this phase:**
```json
{
  "containment": "wslc",
  "container": {
    "targetOs": "linux",
    "image": "python:3.12",
    "cpuCount": 2,
    "memoryMb": 4096
  },
  "script": "python3 -c \"print('hello')\"",
  "filesystem": { "readwritePaths": ["C:\\workspace"] },
  "network": { "defaultPolicy": "block" }
}
```

**Note on the `appContainer` section:** Existing configs may include an `appContainer` section (name, capabilities, leastPrivilege). When `containment` is `"wslc"`, this section is ignored — `WSLContainerRunner` reads from the `container` section
instead. No error is raised if both are present, making configs forward/backward compatible.

**WLXC reference:** WLXC's `Backend` enum (`backend.rs:24-28`) and `ContainerType` proto enum (`wlxc.proto:34-37`). We're expressing the same concepts in TypeScript as `SandboxingMethod` and `TargetOs`. The JSON `container` section maps to WSLC SDK settings calls (session CPU/memory, container image/networking, process executable/args).

---

### Phase 3 — WSLC SDK Backend (Core Work)

**Goal:** Implement `WSLContainerRunner` — a new `ScriptRunner` implementation that uses the WSL Container SDK (WSLC SDK) to manage Linux container lifecycle, I/O, and cleanup. This is added directly to `wxc_common` as new modules alongside the existing AppContainer code.

**Why WSLC SDK instead of raw containerd:** The WSLC SDK is a first-party Microsoft C API that abstracts away containerd, OCI spec building, namespace setup, and image management behind a clean Session → Container → Process model. This eliminates the need to build a custom gRPC client, OCI spec builder, or image snapshot manager. The SDK provides native Win32 HANDLEs for stdout/stderr, avoiding gRPC stream bridging.

**Why it matters:** This is the heart of the feature. Without this, nothing runs.

**What changes in the workspace:**

```
mxc/src/
├── Cargo.toml                    # Add workspace deps: windows-sys (for Win32 types)
├── wxc/
│   ├── Cargo.toml                # No new deps (imports WSLContainerRunner from wxc_common)
│   └── src/main.rs               # Backend selection (Phase 2)
├── wxc_common/
│   ├── Cargo.toml                # Add windows-sys dep (for HANDLE, HRESULT, ReadFile)
│   ├── build.rs                  # NEW — link against WslcSDK.lib (sourced from WSLC SDK NuGet package)
│   └── src/
│       ├── lib.rs                # Add: pub mod wslc_bindings; pub mod wsl_container_runner;
│       │                         #      pub mod policy_mapping;
│       ├── appcontainer.rs       # UNCHANGED
│       ├── config_parser.rs      # Extended (Phase 2)
│       ├── models.rs             # Extended (Phase 2)
│       ├── script_runner.rs      # NO CHANGES NEEDED (see below)
│       ├── sandbox_runner.rs     # UNCHANGED (The existing Sandbox backend)
│       ├── sandbox_protocol.rs   # UNCHANGED (The existing IPC protocol)
│       ├── wslc_bindings.rs      # NEW — Rust FFI bindings to WslcSDK.h
│       ├── wsl_container_runner.rs  # NEW — WSLContainerRunner impl
│       └── policy_mapping.rs     # NEW — SandboxPolicy → WSLC settings translation
└── wxc_test_driver/              # UNCHANGED
```

**ScriptRunner trait — no refactor needed:**
The existing `SandboxScriptRunner` already overrides `run()` entirely (it bypasses the default BFS/firewall orchestration). This proves the pattern works. `WSLContainerRunner` does the same — override `run()` with its own lifecycle:
`session → container → process → I/O → cleanup`. No changes to
`script_runner.rs` or `AppContainerScriptRunner` are required.

**Component A — WSLC FFI Bindings** (`wslc_bindings.rs`)
Rust FFI declarations for the WSLC SDK C API. Generated via `bindgen` from `WslcSDK.h` or hand-written `extern "C"` blocks. Key bindings:

Session APIs:
- `WslcCanRun()` — preflight: check if WSLC runtime is available and what components are missing
- `WslcSessionInitSettings()` / `WslcSessionCreate()` — create a WSL2 micro-VM session
- `WslcSessionSettingsSetCpuCount()` / `WslcSessionSettingsSetMemory()` — resource limits
- `WslcSessionSettingsSetTimeout()` — session-level timeout
- `WslcSessionImageList()` — check if image already exists (used by the runner to fail fast if image is missing)
- `WslcSessionImagePull()` — pull image from registry (not used by the runner; exposed for the setup utility `wxc-exec.exe --pull-image`)
- `WslcSessionTerminate()` / `WslcSessionRelease()` — cleanup

Container APIs:
- `WslcContainerInitSettings()` / `WslcContainerCreate(session, settings)` / `WslcContainerStart()` — lifecycle (note: `WslcContainerCreate` takes the session handle as its first parameter — a container always belongs to a session)
- `WslcContainerSettingsSetInitProcess()` — attach process settings to container settings before creation (required — the container needs to know what process to run)
- `WslcContainerSettingsSetNetworkingMode()` — NONE (isolated) or BRIDGED (NAT)
- `WslcContainerSettingsAddVolume()` — mount Windows paths into Linux container
- `WslcContainerSettingsSetPortMapping()` — host↔container port forwarding
- `WslcContainerSettingsSetFlags()` — GPU passthrough, privileged mode, auto-remove
- `WslcContainerGetInitProcess()` — retrieve the `WslcProcess` handle after container start (needed to access I/O handles and exit status)
- `WslcContainerStop()` / `WslcContainerDelete()` / `WslcContainerRelease()` — teardown

Process APIs:
- `WslcProcessInitSettings()` — initialize process settings struct
- `WslcProcessSettingsSetExecutable()` / `WslcProcessSettingsSetCmdLineArgs()` — command setup
- `WslcProcessSettingsSetCurrentDirectory()` — set working directory inside the container
- `WslcProcessSettingsSetEnvVariables()` — environment variables
- `WslcProcessGetIOHandles()` — get native Win32 HANDLEs for stdin/stdout/stderr
- `WslcProcessGetExitCode()` — retrieve exit code after process completes
- `WslcProcessGetExitEvent()` — get Win32 event HANDLE to wait on process exit
- `WslcProcessRelease()` — cleanup

Key dependency: `windows-sys` crate for Win32 types (`HANDLE`, `HRESULT`, `BOOL`, `PCWSTR`, `PCSTR`). Link against `WslcSDK.lib` at build time — `WslcSDK.lib` and `WslcSDK.h` are sourced from the WSLC SDK NuGet package. The `build.rs` script references the NuGet package output path to locate the lib and header files.

**Component B — WSLContainerRunner** (`wsl_container_runner.rs`)
Implements `ScriptRunner` trait. Orchestrates the full lifecycle using WSLC SDK:

1. `initialize()`:
   - Call `WslcCanRun()` — fail fast if WSLC runtime is not available
   - Call `WslcSessionInitSettings()` with storage path
   - Configure session: CPU count, memory, timeout from `ContainerConfig`
   - Call `WslcSessionCreate()` to start the WSL2 micro-VM
   - Check if image exists via `WslcSessionImageList()`; if not found, fail fast with a clear error message (MXC does not pull images — container management is handled externally)

2. `run_internal()`:
   - Initialize container settings from image name via `WslcContainerInitSettings()`
   - Apply policy: set networking mode, add volume mounts, configure port mappings
   - Configure init process: `WslcProcessInitSettings()` → `WslcProcessSettingsSetExecutable()` → `WslcProcessSettingsSetCmdLineArgs()` → `WslcProcessSettingsSetCurrentDirectory()` → `WslcProcessSettingsSetEnvVariables()`
   - Attach process to container: `WslcContainerSettingsSetInitProcess(containerSettings, processSettings)`
   - Call `WslcContainerCreate(session, containerSettings)` + `WslcContainerStart()`
   - Retrieve the process handle: `WslcContainerGetInitProcess(container, &process)`
   - Get stdout/stderr HANDLEs via `WslcProcessGetIOHandles(process, ...)`
   - Read stdout/stderr using Win32 `ReadFile()` in a loop (same pattern as the WSLC SDK sample code)
   - Wait for process exit via `WslcProcessGetExitEvent()` or `WslcProcessGetExitCode()`
   - Return `ScriptResponse` with captured stdout/stderr and exit code

3. Cleanup (always runs, even on error/timeout):
   - `WslcProcessRelease()`
   - `WslcContainerStop()` with configurable signal and timeout
   - `WslcContainerDelete()`
   - `WslcContainerRelease()`
   - `WslcSessionTerminate()`
   - `WslcSessionRelease()`

**I/O and process behavior:**
- `WSLContainerRunner` captures stdout/stderr from native Win32 HANDLEs returned by `WslcProcessGetIOHandles()` and returns them in `ScriptResponse`, matching the current `AppContainerScriptRunner` behavior
- The exit code is retrieved via `WslcProcessGetExitCode()` after the process exit event signals
- The `timeout` config field is enforced via `WslcSessionSettingsSetTimeout()` at the session level, plus a Rust-side watchdog that calls `WslcContainerStop(WSLC_SIGNAL_SIGKILL)` if needed

**Path translation (Windows host → Linux container):**
- Volume mounts use `WslcContainerSettingsAddVolume()` which accepts `WslcContainerVolume` structs with explicit `windowsPath` (PCWSTR) and `containerPath` (PCSTR) fields
- The runner translates `readwritePaths`/`readonlyPaths` from the policy into volume entries using the WSL2 convention: `C:\workspace` → `/mnt/c/workspace` (strip drive letter, lowercase, prefix `/mnt/`)
- The WSLC SDK handles the actual cross-OS path bridging internally via WSL2's 9P/Plan9 filesystem

**Cleanup and error handling:**
- On normal exit: release process → stop container → delete container → terminate session (reverse creation order)
- On crash/signal: register a `ctrlc` handler that runs the same cleanup sequence
- If WSLC runtime is not available: `WslcCanRun()` reports missing components — fail fast with a clear message listing what needs to be installed
- If image is not found: fail fast with a clear error message listing the expected image name
- HRESULT error codes from WSLC SDK are translated to descriptive Rust errors

---

### Phase 4 — Policy Mapping

**Goal:** Translate MXC's existing platform-agnostic `SandboxPolicy` into WSLC SDK settings calls, so the same policy language works for both AppContainer and Linux containers.

**Why it matters:** The `SandboxPolicy` type already describes what to restrict (filesystem paths, network access) without saying how. Today it's translated to NTFS ACLs + Windows Firewall. For Linux containers, the same policy needs to become WSLC volume mounts and networking mode settings. This is what makes the "one policy, any platform" vision work.

**What changes:**
This logic lives in `wxc_common/src/policy_mapping.rs` and is called by `WSLContainerRunner` during container settings configuration.

Filesystem mapping:
| SandboxPolicy field | WSLC SDK equivalent |
|---|---|
| `readwritePaths: ["C:\\workspace"]` | `WslcContainerSettingsAddVolume()` with `windowsPath: "C:\\workspace"`, `containerPath: "/mnt/c/workspace"`, `readOnly: false` |
| `readonlyPaths: ["C:\\data"]` | `WslcContainerSettingsAddVolume()` with `windowsPath: "C:\\data"`, `containerPath: "/mnt/c/data"`, `readOnly: true` |
| `deniedPaths: ["C:\\secrets"]` | Simply not added as a volume — Linux container isolation means it's inaccessible by default |

**Path mapping rule:** Windows paths are converted to Linux mount points using the WSL2 convention: strip the drive letter, lowercase it, and prefix with `/mnt/`. For example, `C:\Projects\my-app` → `/mnt/c/Projects/my-app`, `D:\data` → `/mnt/d/data`. This means scripts running inside the container must use `/mnt/c/...` style paths. A future iteration could support explicit `{ windowsPath, containerPath }` pairs for custom mount points.

Network mapping:
| SandboxPolicy field | WSLC SDK equivalent |
|---|---|
| `defaultPolicy: "block"` | `WslcContainerSettingsSetNetworkingMode(WSLC_CONTAINER_NETWORKING_MODE_NONE)` |
| `defaultPolicy: "allow"` | `WslcContainerSettingsSetNetworkingMode(WSLC_CONTAINER_NETWORKING_MODE_BRIDGED)` |
| `allowedHosts / blockedHosts` | Post-start iptables rules via `WslcContainerExec()` (run iptables commands inside container). **Prerequisite:** the container image must include iptables, and the container must run with `WSLC_CONTAINER_FLAG_PRIVILEGED` or `NET_ADMIN` capability to modify network rules. Images without iptables will not support per-host filtering — only the all-or-nothing `defaultPolicy` applies. |

Port mapping (new capability enabled by WSLC SDK):
| Config field | WSLC SDK equivalent |
|---|---|
| `portMappings: [{ windowsPort: 8080, containerPort: 80 }]` | `WslcContainerSettingsSetPortMapping()` with `WslcContainerPortMapping` structs |

**WSLC SDK advantage:** The `WslcContainerVolume` struct directly models the Windows↔Linux path mapping with `windowsPath` (PCWSTR) and `containerPath` (PCSTR) fields. The runner applies the deterministic `/mnt/<drive>/...` mapping rule and the SDK's 9P filesystem handles the cross-OS bridging internally.

---

### Phase 5 — CLI Updates & Setup

**Goal:** Give users a simple way to invoke Linux container execution from the command line, and a one-command setup for the WSLC SDK prerequisite.

**Why it matters:** Without CLI support, users would have to hand-write JSON configs with `containment` and `container` sections. Without a setup script, installing the WSLC runtime + pulling images is a manual multi-step process.

**What changes:**

CLI (`wxc/src/main.rs` — Clap definition):
- Add `--container` flag to the existing `Cli` struct — sets `containment: "wslc"` automatically
- Add `--image` optional flag to override the default container image (requires `--container`)
- If `--container` is used without `--image`, default to `alpine:latest` (the lightest general-purpose image; users can override for specific runtimes like `python:3.12`)
- This flag aligns with the Tessera base model (future flags: `--microvm`, `--session`, `--vm`, `--app`)
- Update `platform` command to show WSLC SDK status

Setup script (`scripts/setup-wslc.ps1`):
- Calls `wxc-exec.exe --check-platform` to invoke `WslcCanRun()` and report missing components as JSON
- If missing components, calls `wxc-exec.exe --install-wslc` which invokes `WslcInstallWithDependencies()` (SDK handles WSL2, VM platform, and WSL package installation)
- Pulls default Linux image via `wxc-exec.exe --pull-image alpine:latest` (wraps `WslcSessionImagePull()`)
- Verify setup by running a smoke test: `wxc-exec.exe --container "echo hello"`
- **Note:** `--check-platform`, `--install-wslc`, and `--pull-image` are **admin utility subcommands** for setup and maintenance only. They are not part of the execution code path — `WSLContainerRunner` never calls them. The runner only checks if an image exists and fails fast if it's missing.

SDK health check (`sdk/src/platform.ts`):
- `getPlatformSupport()` spawns `wxc-exec.exe --check-platform` and parses JSON output (wraps `WslcCanRun()`)
- CLI `platform` command surfaces this to the user, including which components are missing

---

## Important Constraint

WLXC is a **prototype / not production-ready**. We are using it as a **reference for patterns and approach only**. The actual container runtime interface uses the **WSL Container SDK (WSLC SDK)** — a first-party Microsoft C API. All functionality is implemented directly in MXC's existing Rust workspace (`wxc_common` crate) via Rust FFI bindings to the WSLC SDK. The WSLC backend shares the same binary (`wxc-exec.exe`) and has no runtime dependency on WLXC.

## Open Design Questions

These need team decisions before implementation:

1. **Image management** — ~~Does the WSLC backend pull images on demand?~~ 
   **Decision: Pre-pulled images only.** MXC is an execution layer, not a container management layer. Image pulling, caching, and lifecycle are handled externally (e.g., by the setup script, a separate tool, or the WSLC SDK's own image management
   APIs called outside of MXC). If an image is not found, `wxc-exec.exe` fails fast with a clear error message. This keeps MXC focused on its core job: sandboxed execution. Container management and execution are separate concerns.

2. **Custom images** — ~~Do we validate/restrict images?~~
   **Decision: Allow any image.** Whatever the WSLC SDK can pull or has locally can be used. No validation or allow-listing at the MXC layer for now. In the future, image governance (e.g., SBOM tracking, vulnerability scanning, registry allow-listing) will be handled at the policy enforcement layers above MXC — not inside the execution engine itself. MXC executes whatever image the caller specifies; it is the caller's responsibility to ensure the image is approved.

3. **Windows containers via containerd** — The architecture supports routing Windows containers through containerd too (using `runhcs.v1` + `nanoserver`). Is this in scope?
   **Decision: Linux containers first.** This design targets Linux containers only. Windows Server containers (e.g., `nanoserver`, `servercore`) are a different workload category — they use a different runtime (`runhcs.v1`), different isolation model, and serve different use cases (typically long-running services rather than script execution). We will prioritize Windows Server container support when there is a clear need for it. The `ContainmentBackend` enum and routing architecture can accommodate a future Windows container variant without redesign.

4. **Elevated privileges** — ~~The WSLC SDK may require specific Windows capabilities (VM Platform, WSL optional component). Do we invoke the install API automatically, or require users to run setup manually?~~
   **Decision: SDK install is out of band.** MXC does not install the WSLC SDK or its dependencies at runtime. Installation of the WSLC SDK NuGet package (build time) and runtime components — VM Platform, WSL optional component, WSL package — is handled separately, outside of MXC's execution path (e.g., by IT admin tooling, a setup script, or the caller's deployment process). At runtime, `WslcCanRun()` checks if everything is in place and fails fast with a clear error if not.

5. ~~**ScriptRunner refactor strategy**~~ — **Resolved.** The existing `SandboxScriptRunner` already overrides `run()` entirely, proving the pattern. `WSLContainerRunner` does the same. No refactoring of the base trait needed.

6. ~~**GPU passthrough**~~ — ~~Should we expose GPU support in the MXC config schema?~~
   **Decision: Yes.** Expose `"gpu": true` in the `container` config section. When enabled, `WSLContainerRunner` sets both `WSLC_SESSION_FLAG_ENABLE_GPU` on the session and `WSLC_CONTAINER_FLAG_ENABLE_GPU` on the container. Defaults to `false`. This enables CUDA and GPU compute workloads (ML inference, training) inside Linux containers.

7. **Session reuse** — Each `WSLContainerRunner.run()` currently creates and destroys a full WSL2 session (micro-VM). For rapid successive invocations, should we pool/reuse sessions to reduce startup overhead?

## Prerequisites for End Users

- Windows 11 or Windows Server 2022/2025
- WSL2 enabled (VM Platform optional component)
- WSL Container SDK runtime installed (`WslcInstallWithDependencies()` handles this)
- WSLC SDK NuGet package referenced in the project (provides `WslcSDK.lib` and `WslcSDK.h` at build time)
- `WslcCanRun()` returns `canRun = true` (setup script verifies this)

## Risks

| Risk | Mitigation |
|---|---|
| `ScriptRunner::run()` hardcodes BFS/firewall (Windows-specific) | `WSLContainerRunner` overrides `run()` entirely — same pattern used by `SandboxScriptRunner` |
| WSLC SDK is in public preview — API may change | Pin to a specific SDK version; isolate all WSLC calls behind `wslc_bindings.rs` so API changes are contained to one file |
| Rust FFI to C API requires careful memory management | Follow WSLC SDK ownership rules: caller frees `CoTaskMemAlloc`'d strings; use Rust RAII wrappers for WSLC handles (Session, Container, Process) |
| WSL2/WSLC setup complexity for users | `WslcCanRun()` diagnoses missing components; `WslcInstallWithDependencies()` automates installation; setup script wraps both |
| New dependency on WslcSDK.lib increases coupling | Feature-gate behind `wslc` Cargo feature so AppContainer-only builds don't require the SDK. Dependency is managed via NuGet, providing controlled versioning and a standard acquisition path |
| Windows→Linux path translation edge cases | WSLC SDK's `WslcContainerVolume` handles path bridging natively via `windowsPath`/`containerPath` fields |
| Orphaned containers on crash | `ctrlc` handler + RAII drop impl that calls `WslcContainerStop()` → `WslcContainerDelete()` → `WslcSessionTerminate()` |
| Session startup overhead (micro-VM per invocation) | Document as known cost; explore session pooling in future iteration (Open Question #7) |
| WSLC SDK requires specific Windows components | `WslcCanRun()` returns `WslcComponentFlags` listing exactly what's missing (VM Platform OC, WSL OC, WSL Package) |

## Testing Strategy

- **Unit tests (Rust):** FFI binding safety, policy-to-WSLC-settings translation, config parsing — no WSLC runtime needed. These live in `wxc_common` alongside the new modules.
- **Integration tests:** Require WSL2 + WSLC SDK runtime; run `wxc-exec.exe` end-to-end with WSLC configs, verify stdout/stderr capture and exit code propagation
- **Regression:** Existing AppContainer tests must pass unchanged — the AppContainer code path is not modified
- **WSLC SDK smoke test:** Ensure `alpine:latest` is pre-pulled → `WslcCanRun()` → create session → run `echo hello` → verify output → cleanup

## End-User Experience (After Implementation)

```powershell
# One-time setup
.\scripts\setup-wslc.ps1

# Run a Linux command with --container flag (script is positional arg)
wxc-exec.exe --container --image python:3.12 "python3 -c \"print('hello')\""

# Or via JSON config (containment + image specified inside the JSON)
wxc-exec.exe --config linux-app.json

# Or programmatically via SDK
spawnSandbox("python3 app.py", policy, { containment: "wslc" })

# Existing Windows AppContainer usage is unchanged
wxc-exec.exe --config windows-app.json
```

**Example: Running a Linux app with filesystem access**

Config file (`app-policy.json`):
```json
{
  "containment": "wslc",
  "container": {
    "targetOs": "linux",
    "image": "python:3.12"
  },
  "script": "python3 /mnt/c/Projects/my-app/app.py",
  "filesystem": {
    "readwritePaths": ["C:\\Projects\\my-app"],
    "readonlyPaths": ["C:\\Projects\\shared-data"]
  },
  "network": {
    "defaultPolicy": "allow",
    "blockedHosts": ["internal.corp.net"]
  },
  "timeout": 60000
}
```

This mounts `C:\Projects\my-app` as `/mnt/c/Projects/my-app` (read-write) inside the Linux container, gives it network access (except to `internal.corp.net`), runs `app.py` with Python 3.12, and kills the container after 60 seconds
if it hasn't exited.

## Supported Workloads

MXC's Linux container support is **language-agnostic and image-agnostic**. The container image defines the capabilities — not MXC. Any workload that meets the following criteria is supported:

> **Runs on Linux, exits on its own, and produces output via stdout/stderr.**

### Supported

| Category | Example images | Use cases |
|---|---|---|
| Script execution | `python:3.12`, `node:20`, `ruby:3.3` | Run scripts in any interpreted language |
| Compiled binaries | `golang:1.22`, `rust:latest`, `gcc:latest` | Build and/or run Linux ELF binaries |
| Shell automation | `alpine`, `ubuntu:22.04` | Bash scripts, file processing, CLI pipelines |
| Data processing | `python:3.12` with NumPy/Pandas | CSV transforms, ML inference, analytics |
| DevOps tooling | `hashicorp/terraform`, `alpine/k8s` | IaC plan output, kubectl queries |
| .NET on Linux | `mcr.microsoft.com/dotnet/sdk:8.0` | Cross-platform .NET workloads |
| Custom toolchains | Any private registry image | Team-specific or proprietary tools |

### Not Supported

| Workload type | Why |
|---|---|
| Interactive processes (REPLs, shells) | MXC does not pass stdin — execution is fire-and-forget |
| GUI applications (X11, Wayland) | No display server — MXC captures stdout/stderr only |
| Long-running daemons (web servers, databases) | MXC expects the process to exit within the configured timeout |
| Hardware access (USB, serial, Bluetooth) | The micro-VM does not expose host hardware beyond filesystem and network |

**Note:** GPU compute (CUDA, ML training/inference) is supported when `"gpu": true` is set in the container config. The WSLC SDK passes through the host GPU via `WSLC_CONTAINER_FLAG_ENABLE_GPU`. Requires a GPU-capable host machine with appropriate drivers.
