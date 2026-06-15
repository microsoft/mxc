# MXC WSL Container Support from Windows frontend — Design Document

## Changes from Original Design

This document was written before the experimental features infrastructure and
the WSLC SDK self-host release. Key changes:

- **WSLC is experimental:** `"containment": "wslc"` requires the `--experimental`
  CLI flag (same as the sandbox backend).
- **Config format updated:** The JSON section is `"wslc"` (not `"container"`),
  command is `"process": { "commandLine": ... }` (not `"script"`), and timeout
  is under `"process": { "timeout": ... }`.
- **WSLC SDK available:** The SDK (v2.8.1) has been released as a self-host
  package with `wslcsdk.h`, `wslcsdk.lib`, and `wslcsdk.dll`. API names use
  verb-first convention (e.g., `WslcInitSessionSettings` not
  `WslcInitSessionSettings`).
- **Phases 1-2 complete:** Config parsing and backend routing shipped in PR #44.
- **Sandbox is experimental:** References to `WindowsSandboxScriptRunner` and
  `request.sandbox_config` are outdated — sandbox is now behind `--experimental`.

## Problem

MXC (Microsoft eXecution Container) runs untrusted code in sandboxed environments. There is no way to run Linux apps today from Windows front-end.

## Proposed Solution

Add a **WSL Container runner** directly into the existing `wxc-exec.exe` Rust binary, using the **WSLC SDK** as the container runtime interface. When the JSON config specifies `"containment": "wslc"` and the `--experimental` flag is passed, the binary routes to a new `WSLContainerRunner` instead of `AppContainerScriptRunner`. The runner calls WSLC SDK C APIs (via Rust FFI bindings) to manage sessions, containers, and process I/O — eliminating the need to build a custom containerd gRPC client or OCI spec builder. This leverages the existing `ScriptRunner` trait and keeps everything in a single binary.

## How It Works

```
Path A — CLI (direct):
  User: wxc-exec.exe --experimental --debug config.json
    └── Clap parses args → loads JSON config → dispatches to WSLContainerRunner

Path B — SDK (programmatic):
  App calls: spawnSandbox("python3 my_app.py", policy, { experimental: true })
    ├── Builds JSON config with containment = "wslc"
    └── Spawns wxc-exec.exe --experimental with the config

Both paths converge here:
  wxc-exec.exe (Rust — single binary, multiple backends)
    ├── Parses JSON config → sees containment = "wslc"
    ├── Checks --experimental flag → creates WSLContainerRunner
    ├── Calls WSLC SDK via Rust FFI bindings:
    │     WslcCanRun()                         → preflight check
    │     WslcInitSessionSettings()            → init session settings (with storagePath)
    │     WslcSetSessionSettingsCpuCount() / Memory() / Timeout() → configure session
    │     WslcCreateSession()                  → create WSL2 micro-VM session
    │     WslcListSessionImages()              → verify image exists (fail if not found)
    │     WslcInitContainerSettings()          → init from image name
    │     WslcSetContainerSettingsVolumes()    → mount host paths
    │     WslcSetContainerSettingsNetworkingMode() → network policy
    │     WslcInitProcessSettings()            → configure executable, args, env, cwd
    │     WslcSetContainerSettingsInitProcess() → attach process to container
    │     WslcCreateContainer(session, settings) → create container in session
    │     WslcStartContainer()                 → start container
    │     WslcGetContainerInitProcess()        → get process handle
    │     WslcGetProcessIOHandle()             → get stdout/stderr Win32 HANDLEs
    │     ReadFile(stdout/stderr)              → capture output → ScriptResponse
    │     WslcContainerStop()         → teardown
    │     WslcContainerDelete()       → cleanup
    │     WslcSessionTerminate()      → release micro-VM
    └── Returns ScriptResponse with captured output + exit code
```

## Architecture: Single Binary, Multiple Backends

```
                    wxc-exec.exe (Rust)
                          │
                   config_parser.rs
                   reads "containment" field
                          │
           ┌──────────────┼──────────────┐
           ▼              ▼              ▼
  AppContainerScript   Sandbox        WSLContainer
  Runner (stable)      Runner         Runner (experimental)
           │           (experimental)      │
     AppContainer          │         WSLC SDK (C API)
     NTFS ACLs         Windows       via Rust FFI
     WFP firewall      Sandbox VM    ├── WSL2 micro-VM
                                     ├── OCI containers
                                     └── I/O via SDK callbacks
```

All backends implement the `ScriptRunner` trait. `main.rs` uses `Box<dyn ScriptRunner>` with a `match` on `request.containment`. Experimental backends (Sandbox, WSLC) require the `--experimental` flag:

```rust
// main.rs — current dispatch
let mut runner: Box<dyn ScriptRunner> = match request.containment {
    ContainmentBackend::AppContainer => Box::new(AppContainerScriptRunner::new()),
    // ... other stable backends ...
    ContainmentBackend::Wslc => {
        if !request.experimental_enabled {
            eprintln!("Error: WSLC is an experimental feature. Use --experimental flag.");
            process::exit(1);
        }
        Box::new(WslContainerRunner::new(&request.container_config))
    }
};
```

## What We Take from [WLXC](https://github.com/vriveras/wlxc) (Reference Only)

| WLXC Pattern | MXC Implementation |
|---|---|
| Container lifecycle model (`daemon.rs:505-953`) | Adapted into `WSLContainerRunner` — but calling WSLC SDK APIs instead of containerd gRPC |
| Backend enum + routing (`backend.rs`, `daemon.rs:220-279`) | Already exists: `ContainmentBackend` enum + `match` dispatch in `main.rs` (the SandboxRunner work) |
| Policy → mount translation (`policy.rs`) | `wxc_common/src/policy_mapping.rs` — maps to `WslcSetContainerSettingsVolumes()` calls |
| `setup-containerd.ps1` setup script | Replaced by WSLC SDK's `WslcInstallWithDependencies()` + lightweight setup script |

**Note:** The WSLC SDK replaces the need for WLXC's containerd gRPC client (`containerd/client.rs`) and OCI spec builder (`daemon.rs:2450-2627`) entirely. The SDK handles containerd communication, image management, OCI spec construction, and namespace setup internally.

## Development Phases

---

### Phase 1 — SDK Types & Platform Detection ✅ Complete

Shipped in earlier PRs. The SDK supports `SandboxingMethod` types and
`getPlatformSupport()` for detection.

---

### Phase 2 — Configuration Schema & Backend Routing ✅ Complete

Shipped in PR #44. The config parser reads `"containment": "wslc"` and the
`"wslc"` section with image, cpuCount, memoryMb, gpu, storagePath, and
portMappings. `ContainerConfig` struct and `container_config` field on
`ExecutionRequest` are in place.

**Example config (current format):**
```json
{
  "containment": "wslc",
  "process": {
    "commandLine": "python3 -c \"print('hello')\"",
    "timeout": 60000
  },
  "wslc": {
    "image": "python:3.12",
    "cpuCount": 2,
    "memoryMb": 4096
  },
  "filesystem": { "readwritePaths": ["C:\\workspace"] },
  "network": { "defaultPolicy": "block" }
}
```

Run with: `wxc-exec.exe config.json --experimental --debug`

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
│       ├── windows_sandbox_runner.rs     # UNCHANGED (The existing Sandbox backend)
│       ├── sandbox_protocol.rs   # UNCHANGED (The existing IPC protocol)
│       ├── wslc_bindings.rs      # NEW — Rust FFI bindings to WslcSDK.h
│       ├── wsl_container_runner.rs  # NEW — WSLContainerRunner impl
│       └── policy_mapping.rs     # NEW — SandboxPolicy → WSLC settings translation
└── wxc_test_driver/              # UNCHANGED
```

**ScriptRunner trait — no refactor needed:**
The existing `WindowsSandboxScriptRunner` already overrides `run()` entirely (it bypasses the default BFS/firewall orchestration). This proves the pattern works. `WSLContainerRunner` does the same — override `run()` with its own lifecycle:
`session → container → process → I/O → cleanup`. No changes to
`script_runner.rs` or `AppContainerScriptRunner` are required.

**Component A — WSLC FFI Bindings** (`wslc_bindings.rs`)
Rust FFI declarations for the WSLC SDK C API (v2.8.1). Hand-written `extern "C"`
blocks from `wslcsdk.h`. Key bindings (actual API names from the SDK):

Session APIs:
- `WslcCanRun()` — preflight: check if WSLC runtime is available
- `WslcGetVersion()` — verify connectivity to the WSL service
- `WslcInitSessionSettings()` / `WslcCreateSession()` — create a WSL2 micro-VM session
- `WslcSetSessionSettingsCpuCount()` / `WslcSetSessionSettingsMemory()` — resource limits
- `WslcSetSessionSettingsTimeout()` — session-level timeout
- `WslcSetSessionSettingsFeatureFlags()` — GPU passthrough (`WSLC_SESSION_FEATURE_FLAG_ENABLE_GPU`)
- `WslcListSessionImages()` — check if image already exists
- `WslcPullSessionImage()` — pull image from registry
- `WslcTerminateSession()` / `WslcReleaseSession()` — cleanup

Container APIs:
- `WslcInitContainerSettings()` / `WslcCreateContainer(session, settings)` / `WslcStartContainer()` — lifecycle
- `WslcSetContainerSettingsInitProcess()` — attach process settings before creation
- `WslcSetContainerSettingsNetworkingMode()` — `NONE` (isolated) or `BRIDGED` (NAT)
- `WslcSetContainerSettingsVolumes()` — mount Windows paths into Linux container
- `WslcSetContainerSettingsPortMappings()` — host↔container port forwarding (TCP only; UDP is declared in the header but returns `E_NOTIMPL` in the vendored SDK 2.8.1 runtime, so the MXC parser hard-rejects `"udp"` at config-validation time)
- `WslcSetContainerSettingsFlags()` — `AUTO_REMOVE`, `ENABLE_GPU`, `PRIVILEGED`
- `WslcGetContainerInitProcess()` — retrieve process handle after start
- `WslcStopContainer()` / `WslcDeleteContainer()` / `WslcReleaseContainer()` — teardown

Process APIs:
- `WslcInitProcessSettings()` — initialize process settings struct
- `WslcSetProcessSettingsCmdLine()` — command + arguments
- `WslcSetProcessSettingsCurrentDirectory()` — working directory inside container
- `WslcSetProcessSettingsEnvVariables()` — environment variables
- `WslcGetProcessIOHandle()` — get native Win32 HANDLEs for stdin/stdout/stderr
- `WslcGetProcessExitCode()` — retrieve exit code after process completes
- `WslcGetProcessExitEvent()` — get Win32 event HANDLE to wait on process exit
- `WslcReleaseProcess()` — cleanup

Key dependency: `windows-sys` crate for Win32 types (`HANDLE`, `HRESULT`). Link
against `wslcsdk.lib` at build time — `wslcsdk.lib` and `wslcsdk.h` are sourced
from the WSLC SDK NuGet package (`Microsoft.WSL.Containers.2.8.1.nupkg`),
extracted into `external/wslc-sdk/`. The `build.rs` script locates the lib by
architecture.

**Component B — WSLContainerRunner** (`wsl_container_runner.rs`)
Implements `ScriptRunner` trait. Orchestrates the full lifecycle using WSLC SDK:

1. `initialize()`:
   - Call `WslcCanRun()` — fail fast if WSLC runtime is not available
   - Call `WslcInitSessionSettings()` with storage path
   - Configure session: CPU count, memory, timeout from `ContainerConfig`
   - Call `WslcSessionCreate()` to start the WSL2 micro-VM
   - Check if image exists via `WslcSessionImageList()`; if not found, fail fast with a clear error message (MXC does not pull images — container management is handled externally)

2. `run_internal()`:
   - Initialize container settings from image name via `WslcContainerInitSettings()`
   - Apply policy: set networking mode, add volume mounts, configure port mappings
   - Configure init process: `WslcProcessInitSettings()` → `WslcProcessSettingsSetExecutable()` → `WslcProcessSettingsSetCmdLineArgs()` → `WslcProcessSettingsSetCurrentDirectory()` → `WslcProcessSettingsSetEnvVariables()`
   - Attach process to container: `WslcSetContainerSettingsInitProcess(containerSettings, processSettings)`
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
- The `timeout` config field is enforced via `WslcSetSessionSettingsTimeout()` at the session level, plus a Rust-side watchdog that calls `WslcStopContainer(WSLC_SIGNAL_SIGKILL)` if needed

**Path translation (Windows host → Linux container):**
- Volume mounts use `WslcSetContainerSettingsVolumes()` which accepts `WslcContainerVolume` structs with explicit `windowsPath` (PCWSTR) and `containerPath` (PCSTR) fields
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
| `readwritePaths: ["C:\\workspace"]` | `WslcSetContainerSettingsVolumes()` with `windowsPath: "C:\\workspace"`, `containerPath: "/mnt/c/workspace"`, `readOnly: false` |
| `readonlyPaths: ["C:\\data"]` | `WslcSetContainerSettingsVolumes()` with `windowsPath: "C:\\data"`, `containerPath: "/mnt/c/data"`, `readOnly: true` |
| `deniedPaths: ["C:\\secrets"]` | Simply not added as a volume — Linux container isolation means it's inaccessible by default |

**Path mapping rule:** Windows paths are converted to Linux mount points using the WSL2 convention: strip the drive letter, lowercase it, and prefix with `/mnt/`. For example, `C:\Projects\my-app` → `/mnt/c/Projects/my-app`, `D:\data` → `/mnt/d/data`. This means scripts running inside the container must use `/mnt/c/...` style paths. A future iteration could support explicit `{ windowsPath, containerPath }` pairs for custom mount points.

Network mapping:
| SandboxPolicy field | WSLC SDK equivalent |
|---|---|
| `defaultPolicy: "block"` | `WslcSetContainerSettingsNetworkingMode(WSLC_CONTAINER_NETWORKING_MODE_NONE)` |
| `defaultPolicy: "allow"` | `WslcSetContainerSettingsNetworkingMode(WSLC_CONTAINER_NETWORKING_MODE_BRIDGED)` |
| `allowedHosts / blockedHosts` | Post-start iptables rules via `WslcContainerExec()` (run iptables commands inside container). **Prerequisite:** the container image must include iptables, and the container must run with `WSLC_CONTAINER_FLAG_PRIVILEGED` or `NET_ADMIN` capability to modify network rules. Images without iptables will not support per-host filtering — only the all-or-nothing `defaultPolicy` applies. |

Port mapping (new capability enabled by WSLC SDK):
| Config field | WSLC SDK equivalent |
|---|---|
| `portMappings: [{ windowsPort: 8080, containerPort: 80, protocol: "tcp" }]` | `WslcSetContainerSettingsPortMappings()` with `WslcContainerPortMapping` structs (TCP only; `protocol` defaults to `"tcp"`. UDP is declared by the SDK header but returns `E_NOTIMPL` at runtime in the vendored SDK 2.8.1 and is rejected by the parser.) |

**WSLC SDK advantage:** The `WslcContainerVolume` struct directly models the Windows↔Linux path mapping with `windowsPath` (PCWSTR) and `containerPath` (PCSTR) fields. The runner applies the deterministic `/mnt/<drive>/...` mapping rule and the SDK's 9P filesystem handles the cross-OS bridging internally.

---

### Phase 5 — CLI Updates & Setup (Future Work)

**Status:** Setup script implemented (issue #165). CLI `--container` /
`--image` flags still pending.

**Goal:** Give users a simple way to invoke Linux container execution from the
command line, and a one-command setup for the WSLC SDK prerequisite.

**Planned changes:**

CLI (`wxc/src/main.rs` — Clap definition):
- Add `--container` flag — sets `containment: "wslc"` automatically
- Add `--image` optional flag to override the default container image
- Update `platform` command to show WSLC SDK status

Setup script (`scripts/setup-wslc.ps1`):
- ✅ Verifies WSLC SDK is installed via `WslcCanRun()` (inherited from
  `init_and_load_sdk`) before attempting any pull
- ✅ Pre-pulls the requested images via `wxc-exec.exe --setup-wslc`
- ✅ Honors a custom `-StoragePath` so caches outside `%TEMP%` are supported
- TODO: Run a smoke test after the pull (tracked separately)

**Current workaround:** Users write JSON configs with `"containment": "wslc"`
and run with `wxc-exec.exe --experimental --debug config.json`.

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

5. ~~**ScriptRunner refactor strategy**~~ — **Resolved.** The existing `WindowsSandboxScriptRunner` already overrides `run()` entirely, proving the pattern. `WSLContainerRunner` does the same. No refactoring of the base trait needed.

6. ~~**GPU passthrough**~~ — ~~Should we expose GPU support in the MXC config schema?~~
   **Decision: Yes.** Expose `"gpu": true` in the `container` config section. When enabled, `WSLContainerRunner` sets both `WSLC_SESSION_FLAG_ENABLE_GPU` on the session and `WSLC_CONTAINER_FLAG_ENABLE_GPU` on the container. Defaults to `false`. This enables CUDA and GPU compute workloads (ML inference, training) inside Linux containers.

7. **Session reuse** — Each `WSLContainerRunner.run()` currently creates and destroys a full WSL2 session (micro-VM). For rapid successive invocations, should we pool/reuse sessions to reduce startup overhead?

## Supported Image Sources

The WSLC backend supports three ways to provide a container image. MXC is
an execution layer and **does not pull images at run time** — registry
pulls are handled out of band, before the runner is invoked. If the
runner is asked to start a container against an image that is not in the
local cache, it fails fast with an actionable error pointing at the setup
script.

### 1. Pre-pulled image from DockerHub

The default path. Pre-pull the image via the setup script (or
`wxc-exec.exe --setup-wslc --image <name>` directly), then reference it
from the config:

```powershell
.\scripts\setup-wslc.ps1 -Image alpine:latest
```

```json
{
  "containment": "wslc",
  "process": { "commandLine": "echo hello" },
  "network": { "defaultPolicy": "block" },
  "experimental": {
    "wslc": {
      "image": "alpine:latest"
    }
  }
}
```

### 2. Pre-pulled image from a custom registry (no auth)

Specify the full registry URL as the image name. The WSLC SDK resolves
it during the pull. Currently only registries that do not require
authentication are supported; private registry auth is planned for a
future WSLC SDK release.

```powershell
.\scripts\setup-wslc.ps1 -Image mcr.microsoft.com/cbl-mariner/base/core:2.0
```

```json
{
  "containment": "wslc",
  "process": { "commandLine": "cat /etc/os-release" },
  "network": { "defaultPolicy": "allow" },
  "experimental": {
    "wslc": {
      "image": "mcr.microsoft.com/cbl-mariner/base/core:2.0"
    }
  }
}
```

**Setup:** Network access is required at pull time. No Docker Desktop or
local Docker daemon is needed — the WSLC SDK handles the pull internally.

**Tested registries:**
- `mcr.microsoft.com` (Microsoft Container Registry)
- `ghcr.io` (GitHub Container Registry, public images)
- `quay.io` (Red Hat Quay, public images)

> **Note on storage path:** the setup script and the runner must share
> the same `storage_path`. The runner default is
> `%TEMP%\mxc-wslc-sessions`; if your config sets
> `experimental.wslc.storagePath`, pass the same path to the setup
> script with `-StoragePath`.

### 3. Import from a local tar file

Use the `imageTarPath` config field to import a container image from a local
tar file instead of pulling from a registry. Both **rootfs tars** (`docker
export`) and **Docker image archives** (`docker save`) are supported — the
format is auto-detected.

```json
{
  "containment": "wslc",
  "process": { "commandLine": "echo 'Hello from tar!'" },
  "network": { "defaultPolicy": "block" },
  "experimental": {
    "wslc": {
      "image": "my-image:latest",
      "imageTarPath": "C:\\workspace\\alpine.tar"
    }
  }
}
```

> **Note:** The `image` field is required when using rootfs tars (`docker
> export`) — it provides the name under which the image is registered. For
> Docker image archives (`docker save`), the image name is extracted from
> the archive metadata automatically, but the `image` field is still
> required for the container settings.

**Option A — rootfs tar via `docker export`:**

```powershell
# 1. Pull the image in Docker Desktop
docker pull alpine:latest

# 2. Create a temporary container (does not start it)
docker run --name alpine-tmp alpine:latest true

# 3. Export the container filesystem as a flat rootfs tar
docker export alpine-tmp -o C:\workspace\alpine.tar

# 4. Clean up the temporary container
docker rm alpine-tmp
```

**Option B — Docker image archive via `docker save`:**

```powershell
# Save the image directly (multi-layer archive with manifest)
docker save alpine:latest -o C:\workspace\alpine.tar
```

**Format auto-detection:** MXC inspects the tar for a `manifest.json` entry.
If found, it uses the WSLC SDK's `WslcLoadSessionImageFromFile` (Docker image
format). If `manifest.json` is not present, MXC only treats the tar as a
rootfs image when it finds standard top-level directories (`bin/`, `etc/`,
`usr/`, etc.) and uses `WslcImportSessionImageFromFile`. Otherwise, MXC
reports an unrecognized tar format error.

If the tar file does not exist at the specified path, MXC fails fast with a
clear error message. MXC does not download or create tar files — image
management is the caller's responsibility.

## Prerequisites for End Users

- Windows 11 or Windows Server 2022/2025
- WSL2 enabled (VM Platform optional component)
- WSLC SDK MSI installed (`wsl.2.8.1.0.x64.msi` or ARM64 variant from the
  self-host package)
- COM initialized on calling thread (handled by the runner)
- `WslcGetVersion()` succeeds (verifies WSL service connectivity)

## Prerequisites for Building MXC with WSLC Support

- WSLC SDK NuGet package extracted into `external/wslc-sdk/` (provides
  `wslcsdk.h` and `wslcsdk.lib`)
- Build with `--features wslc` to enable WSLC code paths

## Risks

| Risk | Mitigation |
|---|---|
| `ScriptRunner::run()` hardcodes BFS/firewall (Windows-specific) | `WSLContainerRunner` overrides `run()` entirely — same pattern used by `WindowsSandboxScriptRunner` |
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
# One-time setup: install WSLC SDK MSI
msiexec /i wsl.2.8.1.0.x64.msi

# Verify WSLC is available
wslc container run hello-world

# Run a Linux command via MXC (requires --experimental)
wxc-exec.exe --experimental --debug wslc-config.json

# Or programmatically via SDK
spawnSandbox("python3 app.py", policy, { experimental: true })

# Existing Windows AppContainer usage is unchanged
wxc-exec.exe --debug windows-app.json
```

**Example: Running a Linux app with filesystem access**

Config file (`app-policy.json`):
```json
{
  "containment": "wslc",
  "process": {
    "commandLine": "python3 /mnt/c/Projects/my-app/app.py",
    "timeout": 60000
  },
  "wslc": {
    "image": "python:3.12"
  },
  "filesystem": {
    "readwritePaths": ["C:\\Projects\\my-app"],
    "readonlyPaths": ["C:\\Projects\\shared-data"]
  },
  "network": {
    "defaultPolicy": "allow",
    "blockedHosts": ["internal.corp.net"]
  }
}
```

Run with: `wxc-exec.exe --experimental --debug app-policy.json`

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
