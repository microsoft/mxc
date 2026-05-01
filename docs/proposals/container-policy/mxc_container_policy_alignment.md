# MXC ↔ ContainerPolicyThoughts Alignment

This document maps the MXC codebase (Rust source + TypeScript SDK) against the
design concepts in `ContainerPolicyThoughts.md`, identifying where the
implementation aligns, where gaps exist, and where the codebase has capabilities
the design document doesn't yet cover.

---

## Table of Contents

- [1. MXC Architecture Summary](#1-mxc-architecture-summary)
- [2. Containment Backends](#2-containment-backends)
- [3. Mapping to Sandboxing Mechanisms (§§1–5)](#3-mapping-to-sandboxing-mechanisms-15)
- [4. Mapping to Common Policy Dimensions (§6)](#4-mapping-to-common-policy-dimensions-6)
- [5. Mapping to JSON Policy Language (§8)](#5-mapping-to-json-policy-language-8)
- [6. Mapping to FlatBuffer Compiled Format (§9)](#6-mapping-to-flatbuffer-compiled-format-9)
- [7. Mapping to Policy Layers (§10)](#7-mapping-to-policy-layers-10)
- [8. Mapping to Backend Capability Profiles (§11)](#8-mapping-to-backend-capability-profiles-11)
- [9. Mapping to Container Lifecycle and Workload Cycling (§12)](#9-mapping-to-container-lifecycle-and-workload-cycling-12)
- [10. Where MXC Goes Beyond the Design Document](#10-where-mxc-goes-beyond-the-design-document)
- [11. Gap Summary](#11-gap-summary)

---

## 1. MXC Architecture Summary

MXC (Microsoft eXecution Containers) is a **Rust-based multi-backend sandboxing
framework** with a TypeScript SDK. It spawns untrusted scripts inside isolated
environments and captures their output.

```
┌──────────────────────────────────────────────────────────┐
│  TypeScript SDK (sdk/)                                   │
│  spawnSandbox() → locates wxc-exec, builds JSON config   │
└───────────────────┬──────────────────────────────────────┘
                    │ JSON config (file or base64)
┌───────────────────▼──────────────────────────────────────┐
│  wxc-exec / lxc-exec  (Rust, src/wxc/ and src/lxc/)     │
│  Parse JSON → validate → route to containment backend    │
└───────────────────┬──────────────────────────────────────┘
                    │
        ┌───────────┼───────────┬──────────────┐
        ▼           ▼           ▼              ▼
  ┌──────────┐ ┌─────────┐ ┌────────┐  ┌────────────┐
  │AppContain│ │ Windows  │ │  LXC   │  │  NanVix    │
  │er Runner │ │ Sandbox  │ │ Runner │  │  MicroVM   │
  │          │ │ Daemon + │ │        │  │            │
  │ BFS +    │ │ Guest    │ │ mounts │  │            │
  │ Firewall │ │ Agent    │ │ +      │  │            │
  │          │ │          │ │iptables│  │            │
  └──────────┘ └─────────┘ └────────┘  └────────────┘
       │            │           │            │
       ▼            ▼           ▼            ▼
   Windows OS   Hyper-V VM   Linux kernel  Lightweight VM
   APIs         (sandbox)    namespaces    (NanVix)
```

**13 Rust crates** in the workspace, **4 TypeScript packages** (SDK, CLI), and
**6 containment backends**.

### Key Source Files

| File | Purpose |
|---|---|
| `src/wxc_common/src/models.rs` | Core data types: `CodexRequest`, `ContainerPolicy`, `ContainmentBackend` |
| `src/wxc_common/src/config_parser.rs` | JSON config parsing (~1100 lines) |
| `src/wxc_common/src/script_runner.rs` | `ScriptRunner` trait — backend abstraction |
| `src/wxc_common/src/appcontainer_runner.rs` | AppContainer implementation (~570 lines) |
| `src/wxc_common/src/base_container_runner.rs` | BaseContainer / `CreateProcessInSandbox` (~360 lines) |
| `src/wxc_common/src/windows_sandbox_runner.rs` | Windows Sandbox client |
| `src/wxc_common/src/filesystem_bfs.rs` | BFS filesystem policy via `bfscfg.exe` |
| `src/wxc_common/src/network_manager.rs` | Windows Firewall + proxy management |
| `src/wxc_common/src/proxy_coordinator.rs` | Proxy lifecycle (elevated shim, loopback exemption) |
| `src/wxc_common/src/sandbox_protocol.rs` | Windows Sandbox control protocol (length-prefixed JSON) |
| `src/wxc_windows_sandbox_daemon/` | Host-side Windows Sandbox VM manager |
| `src/wxc_windows_sandbox_guest/` | Guest agent inside Windows Sandbox |
| `src/lxc_common/src/lxc_runner.rs` | LXC container execution |
| `src/lxc_common/src/filesystem_mounts.rs` | Linux mount-based filesystem policy |
| `src/lxc_common/src/network_iptables.rs` | Linux iptables network policy |
| `src/lxc_common/src/lxc_bindings.rs` | FFI bindings to `liblxc` C API |
| `src/generated/base_container_specification/` | FlatBuffer-generated `SandboxSpec` types |
| `sdk/src/sandbox.ts` | TypeScript SDK: `spawnSandbox()`, config building |
| `sdk/src/types.ts` | TypeScript policy types: `SandboxPolicy`, `ContainerConfig` |
| `sdk/src/platform.ts` | Platform detection (Windows build version, LXC availability) |

---

## 2. Containment Backends

MXC supports six containment backends, each using a different isolation strategy:

| Backend | Platform | §11 Isolation Model | Crate | Status |
|---|---|---|---|---|
| **AppContainer** | Windows | reduced-credentials | `wxc_common` (appcontainer_runner) | Production |
| **Windows Sandbox** | Windows | different-universe (Hyper-V VM) | `wxc_windows_sandbox_daemon` + `wxc_windows_sandbox_guest` | Experimental |
| **BaseContainer** | Windows | reduced-credentials (new OS API) | `wxc_common` (base_container_runner) | Experimental |
| **LXC** | Linux | different-universe (namespaces) | `lxc_common` | Production |
| **NanVix MicroVM** | Windows | different-universe (lightweight VM) | `nanvix_common` + `nanvix_binaries` | Experimental |
| **WSL Container SDK** | Windows→Linux | different-universe | `wslc_common` | Phase 3 (stub) |

All backends implement the `ScriptRunner` trait:

```rust
pub trait ScriptRunner {
    fn run(&mut self, request: &CodexRequest, logger: &mut Logger) -> ScriptResponse;
}
```

The `containment` field in the JSON config selects the backend:

```json
{ "containment": "appcontainer" | "windows_sandbox" | "lxc" | "microvm" | "wslc" | "vm" }
```

---

## 3. Mapping to Sandboxing Mechanisms (§§1–5)

### §1 Linux BubbleWrap

MXC's LXC backend (`lxc_common/`) uses the same kernel namespace primitives that
BubbleWrap uses — mount namespaces, PID namespaces, network namespaces. LXC
provides a higher-level abstraction over these primitives (full container
lifecycle management, distribution support) whereas BubbleWrap is a lower-level
building block.

| BubbleWrap Mechanism | MXC LXC Equivalent |
|---|---|
| Mount namespaces + bind mounts | `lxc_runner.rs` — LXC manages the mount tree |
| Network namespaces | LXC creates network namespace per container |
| `--seccomp` flag | Not used — LXC default seccomp profile (if any) |
| PID namespace | LXC creates PID namespace per container |

### §2 Seccomp-BPF

**Not directly used.** Neither the Windows nor Linux paths explicitly configure
seccomp filters. On Windows, AppContainer's capability model serves a roughly
analogous role (restricting what APIs the process can call). On Linux, LXC may
apply a default seccomp profile, but MXC does not configure or customize it.

### §3 Linux Landlock

**Not used.** The LXC path uses mount-based filesystem isolation rather than
Landlock self-restriction. Landlock could be added as a defense-in-depth layer
within the LXC container.

### §4 SELinux

**Not used.** The LXC path does not configure SELinux type enforcement. On
Fedora/RHEL systems where SELinux is enforcing, LXC containers would be subject
to whatever system SELinux policy applies, but MXC does not manage or customize
that policy.

### §5 Windows Equivalents

This is where MXC has the deepest implementation:

| §5 Mechanism | MXC Implementation | File |
|---|---|---|
| **AppContainer** | Full implementation: `CreateAppContainerProfile`, capability SIDs, LPAC mode (`PROCESS_CREATION_ALL_APPLICATION_PACKAGES_OPT_OUT`), console inheritance, auto-injected capabilities (`AgenticAppContainer`, conditional `internetClient`) | `appcontainer_runner.rs` |
| **Restricted Tokens** | Not directly used — relies on AppContainer SID instead | — |
| **Job Objects** | Not used — no CPU/memory/process-count limits | — |
| **Integrity Levels** | Present in the BaseContainer FlatBuffer spec (`integrity_level` field) but not in AppContainer path | `base_container_specification_generated.rs` |
| **Windows Sandbox (VM)** | Full implementation: daemon/guest architecture, Hyper-V VM lifecycle, TCP bridge, firewall lockdown, rendezvous discovery, idle timeout | `wxc_windows_sandbox_daemon/`, `wxc_windows_sandbox_guest/` |
| **Win32 App Isolation** | The BaseContainer path uses `Experimental_CreateProcessInSandbox` — a new Windows API in this space | `base_container_runner.rs` |

---

## 4. Mapping to Common Policy Dimensions (§6)

| §6 Policy Dimension | MXC Support | Implementation | Gap |
|---|---|---|---|
| **Filesystem access** | ✓ | BFS (`bfscfg.exe`) on Windows; mounts on Linux. Three path lists: readwrite, readonly, denied. | No per-operation granularity (read vs write vs execute vs create vs delete). No scope types (subtree vs exact vs pattern). No ephemeral, mask, or synthetic mounts in policy. |
| **Network access** | ✓ | Windows Firewall + AppContainer capabilities; iptables on Linux. Per-host allow/block with default policy. | No per-port or per-protocol filtering. No per-direction control in the config schema. |
| **Process visibility** | Partial | AppContainer SID boundaries (Windows); PID namespace (Linux) | Not configurable — implicit in the backend choice. No `allow_exec` allowlist, no signal control. |
| **IPC / messaging** | Implicit | AppContainer SID prevents cross-container IPC (Windows); IPC namespace (Linux) | Not configurable in policy. No service-level IPC rules. |
| **Syscall filtering** | ✗ | Not implemented on either platform | — |
| **Resource limits** | Timeout only | `script_timeout` in milliseconds, enforced via `WaitForSingleObject` (Windows) or process timeout (Linux) | No CPU, memory, process-count, or open-files limits. No Job Object integration. |
| **Device access** | ✗ | Not addressed | — |

---

## 5. Mapping to JSON Policy Language (§8)

MXC's JSON config schema (v0.4.0-alpha) covers similar ground to §8's proposed
language but at a coarser granularity.

### Filesystem

| §8 Proposed | MXC Actual |
|---|---|
| `rules[]` with `path`, `scope` (exact/subtree/prefix/pattern), `allow` (read/write/execute/create/delete), `ephemeral` | Three flat arrays: `readwritePaths[]`, `readonlyPaths[]`, `deniedPaths[]` |
| `mask[]` — paths to replace with empty/null | Not supported |
| `synthetic` — `/dev`, `/proc`, `/tmp` mount types | Not supported in policy (LXC handles internally) |

### Network

| §8 Proposed | MXC Actual |
|---|---|
| `mode` (none/full/rules), `rules[]` with direction/action/protocol/host/port | `defaultPolicy` (allow/block), `enforcementMode` (capabilities/firewall/both), `allowedHosts[]`, `blockedHosts[]` |
| `allow_dns`, `allow_localhost` | Not explicit (loopback exemption managed separately for proxy) |
| Per-port, per-protocol, per-direction rules | Not supported — per-host only |

### Process

| §8 Proposed | MXC Actual |
|---|---|
| `allow_fork`, `allow_exec[]`, `visibility`, `signals`, `hostname`, `die_with_parent` | `process.commandLine`, `process.cwd`, `process.env[]`, `process.timeout` — runtime config rather than security policy |

### Resources

| §8 Proposed | MXC Actual |
|---|---|
| `max_memory_mb`, `max_cpu_percent`, `max_processes`, `max_open_files`, `max_wall_time_seconds` | Only `timeout` (milliseconds) |

### Environment

| §8 Proposed | MXC Actual |
|---|---|
| `mode` (clean/inherit), `set` (key-value), `pass_through[]` | `process.env[]` as `KEY=VALUE` strings — simple passthrough, no clean/inherit mode |

### Platform Overrides

| §8 Proposed | MXC Actual |
|---|---|
| `platform.linux.seccomp`, `platform.macos.seatbelt_import`, `platform.windows.appcontainer` | Backend-specific config sections: `appContainer {}`, `lxc {}`, `wslc {}` — similar intent, different structure |

### MXC Additions Not in §8

MXC's config has features that §8's proposed schema does not cover:

| MXC Feature | Description |
|---|---|
| `containment` backend selector | Explicit backend choice (appcontainer, windows_sandbox, lxc, etc.) |
| `network.proxy` config | Per-AppContainer proxy policy (built-in test server or localhost proxy) |
| `network.enforcementMode` | Choose enforcement mechanism: capabilities only, firewall only, or both |
| `lifecycle.destroyOnExit` | Whether to tear down the container after execution |
| `lifecycle.preservePolicy` | Whether to keep BFS/firewall policy after exit |
| `appContainer.learningMode` | ETW tracing for policy discovery (debug builds only) |
| `lxc.distribution` / `lxc.release` | Linux distribution selection for LXC containers |
| `wslc.cpuCount`, `wslc.memoryMb`, `wslc.gpu` | VM resource allocation for WSL containers |

---

## 6. Mapping to FlatBuffer Compiled Format (§9)

**MXC already uses FlatBuffers.** The `generated/base_container_specification`
crate contains FlatBuffer-generated types for `SandboxSpec`:

```rust
pub struct SandboxSpec {
    version: String,
    app_container: bool,
    integrity_level: i32,
    ui_restrictions: i32,
    least_privilege: bool,
    capabilities: Option<String>,   // comma-joined
    fs_read_write: Option<Vec<String>>,
    fs_read_only: Option<Vec<String>>
}
```

This is used by `base_container_runner.rs` to serialize sandbox intent for
`Experimental_CreateProcessInSandbox`. It validates §9's architectural decision
(JSON for authoring, FlatBuffer for runtime consumption) but is much simpler
than §9's full schema:

| §9 FlatBuffer Schema | MXC FlatBuffer |
|---|---|
| 15+ tables covering filesystem, network, process, IPC, devices, resources, environment, platform, signature | 1 table: `SandboxSpec` with ~8 fields |
| `FileOps` bit-flags (read/write/execute/create/delete/metadata/truncate/ioctl) | Two path lists (read-write, read-only) |
| `NetRule` with direction/action/protocol/host/port | Not in FlatBuffer (network policy is applied externally) |
| Signature/integrity block | Not present |

---

## 7. Mapping to Policy Layers (§10)

| §10 Layer | MXC Coverage | Details |
|---|---|---|
| **L1: Code Requirements** | Minimal | `appContainer.capabilities[]` is a crude requirements manifest ("I need `internetClient`"). No abstract resource-type declarations. |
| **L2: Instance Binding** | Primary focus | `filesystem.readwritePaths`, `network.allowedHosts` bind concrete resources. The JSON config lives almost entirely at this layer. |
| **L3: User Consent** | Not modeled | Whoever writes the JSON config implicitly consents. No runtime permission prompts. |
| **L4: IT Admin Policy** | Not modeled | No GPO, MDM, or Intune integration. No mechanism for organizational constraints. |
| **L5: System Policy** | Minimal | `platform.ts` checks Windows build version (≥26100) and LXC availability. No awareness of WDAC, AppLocker, or other system security policies. |
| **L6: System Security Promises** | Minimal | Platform detection in `platform.ts` is a rudimentary form: "is this Windows build new enough?" and "is LXC installed?" No kernel capability probing. |
| **L7: Container Enforcement** | Implicit | The `containment` enum selects a backend, but there is no formal capability profile. Each `ScriptRunner` implementation hardcodes what it can enforce. |

---

## 8. Mapping to Backend Capability Profiles (§11)

### What Exists

MXC has the **architectural seams** that §11 describes but not the **formal
profile system**:

- The `ScriptRunner` trait is the backend abstraction point
- The `ContainmentBackend` enum names the backends
- Each runner implementation (`AppContainerScriptRunner`, `LxcScriptRunner`,
  etc.) knows what it can enforce — but this knowledge is embedded in Rust code,
  not expressed as a machine-evaluable profile

### What's Missing

| §11 Concept | MXC Status |
|---|---|
| **Primitive profiles** | ✗ Not formalized. Each runner is a monolithic composition (AppContainer + BFS + Firewall are wired together in `appcontainer_runner.rs`, not composed from independent primitives). |
| **Composition system** | ✗ Primitives (AppContainer, BFS, Firewall) are hardcoded together in each runner. Adding a new primitive (e.g., Job Objects) requires modifying Rust source. |
| **Named shorthands** | The `containment` enum serves this role — `"appcontainer"` selects a fixed composition. But it maps to hardcoded implementations, not to a list of primitives. |
| **Compiler evaluation** | ✗ No policy-vs-backend validation. If a policy requests per-port network rules, the AppContainer backend silently cannot enforce them. No warnings, no errors. |
| **Isolation model / assurance levels** | ✗ No distinction between `different-universe` (Windows Sandbox VM) and `reduced-credentials` (AppContainer). The user must know which backend provides what assurance. |
| **Auto-selection** | ✗ The user must choose the backend manually via the `containment` field. |
| **Lifecycle metadata** | ✗ No setup cost, per-workload cost, or warm-reuse metadata on backends. |

### What Each Backend Can Actually Enforce

If MXC were to formalize backend profiles, they would look like:

| Dimension | AppContainer | Windows Sandbox | LXC | BaseContainer |
|---|---|---|---|---|
| **Filesystem** | ✓ BFS (reduced-credentials) | ✓ VM boundary (different-universe) | ✓ mounts (different-universe) | ✓ via FlatBuffer spec |
| **Network** | ✓ Firewall + caps (guarded-doors + reduced-credentials) | ✓ Guest firewall lockdown (different-universe) | ✓ iptables (guarded-doors) | ✗ |
| **Process isolation** | Partial (SID boundaries) | ✓ Full (separate OS) | ✓ Full (PID namespace) | Partial (SID) |
| **Syscall filtering** | ✗ | N/A (separate kernel) | ✗ (possible via LXC) | ✗ |
| **Resource limits** | Timeout only | VM resource limits | Timeout only | Timeout only |
| **IPC isolation** | Partial (SID) | ✓ Full (separate OS) | ✓ Full (IPC namespace) | Partial (SID) |
| **Warm reuse** | Partial (`destroyOnExit: false`) | ✓ (daemon keeps VM warm) | ✗ (new container per run) | ✗ |

---

## 9. Mapping to Container Lifecycle and Workload Cycling (§12)

### Windows Sandbox: Warm Container Model

The Windows Sandbox daemon/guest architecture already implements §12's
two-lifecycle model:

**Container lifecycle** (expensive, once):
- `sandbox_vm.rs`: Generate `.wsb` config, launch `WindowsSandbox.exe`
- Guest boots, runs `wxc-windows-sandbox-guest.exe` as LogonCommand
- Guest writes rendezvous file with `ip:port`
- Host connects 4 TCP streams (control, stdin, stdout, stderr)
- Guest locks down firewall to host-only (`firewall.rs`)

**Workload lifecycle** (cheap, repeated):
- Host sends `Exec { script_code, working_directory, timeout_ms }` on control channel
- Guest spawns process, bridges stdio
- Guest sends `Exit { exit_code }` when done
- Guest re-accepts data connections for next workload

**Idle timeout**: Daemon tears down VM after configurable idle period (default
300 seconds). This maps directly to §12's warm pool `idle_timeout` concept.

### Gap: State Reset

The guest `executor.rs` contains a TODO noting that **state reset between
workloads is not implemented** — previous scripts' filesystem side effects
persist in the VM. This is exactly the gap §12's "State Reset Between Workloads"
subsection addresses. The VM would need overlay-discard or filesystem scrub
between executions.

### AppContainer: Simple Lifecycle

AppContainer uses the simple create→execute→cleanup model:

```
Create profile → Apply BFS → Apply Firewall → Run script → Cleanup → Delete
```

The `lifecycle.destroyOnExit: false` option keeps the AppContainer profile for
reuse, but BFS and firewall rules are typically removed. There is no
base-policy-vs-workload-policy split.

### LXC: Simple Lifecycle

LXC also uses create→execute→cleanup per invocation. The `destroy_on_exit` flag
controls whether the container is torn down, but there is no workload cycling.

---

## 10. Where MXC Goes Beyond the Design Document

Several MXC capabilities are not yet reflected in ContainerPolicyThoughts.md:

| MXC Capability | Description | Document Gap |
|---|---|---|
| **Network proxy integration** | Per-AppContainer WinHTTP proxy policy via elevated shim (`wxc_winhttp_proxy_shim`), loopback exemption via `CheckNetIsolation.exe`, built-in test proxy server | §8's network section has no proxy concept |
| **Enforcement mode selection** | `capabilities` / `firewall` / `both` — choose which Windows mechanisms to use for network policy | §11's backend profiles don't model multiple enforcement modes within a single primitive |
| **Learning mode** | ETW tracing to discover what policy a script needs (debug builds only, stripped in release) | The document doesn't discuss policy discovery/learning |
| **Guest agent architecture** | Windows Sandbox uses a host daemon + guest agent pattern with TCP bridge and rendezvous discovery | §12 discusses warm containers abstractly but doesn't detail the host/guest communication pattern |
| **Console inheritance** | AppContainer child shares parent's ConPTY — no explicit pipe relay | Not discussed in the document |
| **WSL Container SDK** | Future backend using WSL Container SDK C API for Linux containers from Windows | Not mentioned in the document |
| **NanVix MicroVM** | Lightweight VM backend with downloaded kernel/runtime binaries | Not mentioned in the document |
| **BaseContainer / `CreateProcessInSandbox`** | New Windows API with FlatBuffer spec for declarative sandbox creation | The document discusses FlatBuffers (§9) but doesn't mention this specific API |

---

## 11. Gap Summary

### Gaps in MXC Relative to the Design Document

| Priority | Gap | §§ Reference | Impact |
|---|---|---|---|
| **High** | No resource limits beyond timeout (no Job Objects, no cgroups) | §6, §8, §12 | Cannot enforce CPU/memory/process-count budgets |
| **High** | No policy-vs-backend validation | §11 | Silent enforcement failures when policy exceeds backend capabilities |
| **High** | No state reset between workloads in Windows Sandbox | §12 | Prior workload side effects leak to subsequent workloads |
| **Medium** | No per-operation filesystem granularity | §6, §8 | Cannot distinguish read vs write vs execute vs create vs delete |
| **Medium** | No per-port/per-protocol network rules | §6, §8 | Can only filter by host, not by port or protocol |
| **Medium** | No seccomp/Landlock integration on Linux | §§2–3 | Missing defense-in-depth layers in LXC path |
| **Medium** | No formal backend capability profiles | §11 | Backend capabilities are hardcoded, not machine-evaluable |
| **Medium** | No composition system for primitives | §11 | Adding a new primitive (e.g., Job Objects) requires modifying Rust code |
| **Low** | No macOS support | §§1, 7 | Seatbelt integration not started |
| **Low** | No SELinux integration | §4 | Missing on Fedora/RHEL LXC deployments |
| **Low** | No environment variable policy | §8 | env vars are passthrough, not policy-controlled |
| **Low** | No IPC service rules | §6, §8 | IPC isolation is implicit in backend choice |

### Gaps in the Design Document Relative to MXC

| Gap | MXC Feature | Suggested Addition |
|---|---|---|
| No proxy concept | Network proxy integration with elevated shim and loopback exemption | Add proxy configuration to §8 network section |
| No policy discovery | Learning mode with ETW tracing | Add policy discovery/learning section |
| No enforcement mode selection | Choose capabilities vs firewall vs both for network policy | Model enforcement mode in §11 primitive profiles |
| No host/guest communication pattern | Windows Sandbox daemon/guest with TCP bridge and rendezvous | Detail the host/guest architecture in §12 |
| No mention of `CreateProcessInSandbox` | BaseContainer backend with FlatBuffer-based declarative sandbox | Reference this API in §5 and §9 |
| No mention of WSL Container SDK or NanVix | Future/experimental backends | Add to §5 or a new cross-platform backend inventory section |
