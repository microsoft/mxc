<!--
Copyright (c) Microsoft Corporation.
Licensed under the MIT License.
-->

# Backend Support Probe API - Design & Discussion

> **Audience:** MXC developers

> **Status:** Design Proposal

## 1. Purpose

Provide a read-only Rust API that reports which containment backends the
current host can actually run. Callers can read at startup
to choose a backend without attempting an execution. 



```rust
// One host-available backend, plus its effective isolation tier (if any).
#[derive(Debug, Clone, serde::Serialize)]
pub struct AvailableBackend {
    /// Canonical wire name, e.g. "processcontainer", "seatbelt".
    pub backend: String,
    /// The highest-isolation tier the host supports for this backend, if the
    /// backend has a tier ladder. `None` for backends with no tiers. The string
    /// values are the canonical `IsolationTier::as_str()` names (not free-form),
    /// and the field is omitted from JSON when `None`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tier: Option<String>,
    /// Optional backend features usable on this host. Omitted when empty.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub capabilities: Vec<BackendCapability>,
    /// Why an optional capability is absent from `capabilities`. Omitted when
    /// empty. This is the only place the API says why something is *not*
    /// available, and it is scoped to optional capabilities — a backend that is
    /// unusable outright is still simply absent (§2).
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub warnings: Vec<String>,
}

/// Optional feature supported by a containment backend on the current host.
#[derive(Debug, Clone, Copy, serde::Serialize)]
#[non_exhaustive]
pub enum BackendCapability {
    /// Windows ProcessContainer denial capture.
    CaptureDenials,
    /// Bubblewrap proxy-only egress in a private network namespace.
    ProxyEnforcement,
}

/// Probe the host and return only the backends it can currently run.
/// An empty `Vec` means "no backend this API can currently affirm on this host"
/// (e.g. an unsupported platform, Linux with neither `bwrap` nor `lxc`, or
/// macOS without `sandbox-exec`) — it is a normal result, not an error.
pub fn available_backends() -> Vec<AvailableBackend>;
```

A backend is reported as available whenever it can run *at all*; an optional
capability it cannot provide on this host is reported by omission from
`capabilities` (with the reason in `warnings`), not by dropping the backend.
This keeps §2's "absence means unusable" rule intact while still letting a
caller pre-flight a policy that depends on an optional capability.

Example results:
> **"Stock Windows"** here means a clean Windows install with only the default
> optional features enabled (no BaseContainer, Windows Sandbox, etc.), so the
> process-container backend falls to its `appcontainer-dacl` floor. See
> [`docs/backends/process-container/os-version-support.md`](../../backends/process-container/os-version-support.md)
> for the per-release policy-support matrix that determines the reachable tier.

| Host | Result |
| --- | --- |
| Stock Windows | `[{ backend: "processcontainer", tier: Some("appcontainer-dacl") }]` |
| Windows w/ BaseContainer | `[{ backend: "processcontainer", tier: Some("base-container") }]` |
| macOS | `[{ backend: "seatbelt", tier: None }]` |
| Linux w/ bwrap + lxc | `[{ backend: "bubblewrap", tier: None }, { backend: "lxc", tier: None }]` |
## 2. Guiding principle
This API answers **"what can I use here?"**, not "what is the full capability
matrix of this machine?". 
- We return **only** host-available backends. Nothing is reported as `false`.
- A backend's **absence** means "not currently usable, **for any reason**"
- Capabilities list selected features supported by the reported tier:
  `captureDenials`, `filesystemDeniedPaths`, and `ingressHostLoopbackAllow`.
- A missing capability is unavailable or could not be detected.
- For per-backend **diagnostics and reasons**, the tool is `wxc-exec --probe`
- Each capability is **detected once, in Rust**, and the TypeScript SDK projects that result rather than re-checking.
## 3. Detection & isolation tiers

### 3.1 Detection methods used today (and their risks)

Four backends already have *some* presence check, but they are spread across two
layers and vary in how much they actually prove. Documenting them here so the
probe API can reuse the Rust ones and knowingly accept the risk of the shallower
ones.

| Backend | How presence is detected today | Where | Risk with this method |
| --- | --- | --- | --- |
| `base-container` | `BaseContainerRunner::is_base_container_api_present()` calls `IsApiSetImplemented` for the process-security-environment API set. It does not load `processmodel.dll`, create a security environment, or start a process. | Rust | This proves that Windows implements the API-set contract; request-specific support bits are queried separately when the policy requires them. |
| `windows_sandbox` | `isWindowsSandboxAvailable()` runs `dism /online /get-featureinfo `<br>`/featurename:Containers-DisposableClientVM ` and looks for `State : Enabled`<br>if DISM throws (usually non-elevated) it falls back to<br>`fs.existsSync(%SystemRoot%\\System32\\WindowsSandbox.exe)`; result cached. | TypeScript SDK | `dism /online` needs elevation, so a non-elevated caller can't tell *disabled* from<br>*no permission* and drops to the exe-existence checkwhich proves the feature is installed,<br>not that a sandbox VM can boot. (Dupe'd in Rust: `windows_sandbox_lifecycle::availability`) |
| `lxc` | `isLxcAvailable()` runs `lxc-ls --version`; a clean exit means available. | TypeScript SDK | Only proves the `lxc-ls` CLI is on `PATH`, not that liblxc is loadable or that the caller has<br>the privileges to actually start a container, so it can report available on a host where a real run fails.<br>(Dupe'd in Rust: `lxc_common::availability`) |
| `wslc` | `wslc_common::is_available()` confirms WSL2 and the WSLC runtime are present. | Rust | Resolving `wslcsdk.dll` alone is not sufficient and is not what this checks;<br>`WslcSdk::load()` still runs on the *execute* path. Feature-gated. |
| `isolation_session` | `IsoSessionOps` activates and reports a `LocalAgentUser` feature level above zero. Queries API-class registration rather than a build number (#761); a `CLASS_E_CLASSNOTAVAILABLE` / `REGDB_E_CLASSNOTREG` activation failure means unavailable. | Rust | |
| `hyperlight` | Has a hypervisor check on each supported host — `is_whp_available()` on Windows, `is_kvm_available()` on Linux — neither of which boots a VM. | Rust | |

### 3.2 Isolation tiers (process-container only)

Only the Windows process-container backend has a within-backend tier ladder. The
three tiers, and the **policy-free** checks that decide whether each is
reachable, already exist in `process_container_common`:

| Tier | Reachable when | Detector |
| --- | --- | --- |
| `base-container` | BaseContainer API is **usable** (not merely symbol-present) | `fallback_detector::is_base_container_usable()` (the cached wrapper) |
| `appcontainer-bfs` | built with the `tier2_bfs` feature | `cfg!(feature = "tier2_bfs")` |
| `appcontainer-dacl` | always (universal Windows floor) | — |


## 4. The probe gap today

### 4.1. Backends with no probe
- `microvm` needs a probe that checks for: (1) feature compiled, (2) NanVix runtime files staged, and (3) WHP usable on Windows or `/dev/kvm` readable/writable on Linux
- `vm` is an abstract intent that resolves to a 
  concrete backend per host and is never probed in its own right.

### 4.2 The parity rule: detect once, project into TS

Rust detects every backend that has a detector, but `getPlatformSupport()` still
runs its own `dism`/`lxc-ls`, so the two layers can disagree. The fix is: detect
each capability in exactly one place (Rust), and have TypeScript read that
result rather than compute its own.

| Step | What | Why it gives parity |
| --- | --- | --- |
| 1. Consolidate detectors in Rust — **landed** | The `windows_sandbox` and `lxc` checks live in Rust<br>(`windows_sandbox_lifecycle::availability`, `lxc_common::availability`), so `available_backends()` covers every backend with a detector. | Each backend has exactly one detector. |
| 2. TypeScript stops probing itself | `getPlatformSupport()` reads the native backend-availability result instead of running its own `dism`/`lxc-ls`.<br>The transport must be **side-effect-free**: `wxc-exec --probe` runs *after* `recover_orphaned_state()` (which can restore/prune DACL state on the host), so it cannot be extended unchanged without violating the read-only contract.<br>Instead, expose backend availability via a dedicated mode handled **before** DACL recovery (e.g. `wxc-exec --available-backends`), or directly through `mxc_ffi`. | TypeScript becomes a pure projection of the Rust result, without triggering host mutation. |
| 3. Names flow from serde | Backend names (`Containment`) and tier strings (`IsolationTier::as_str()`) are already Rust-serialized;<br>TypeScript consumes them as-is instead of hand-re-encoding. | Removes the wire-name drift class structurally. |

See §7.9 for why the canonical probe stays in Rust rather than moving into the TypeScript layer.

## 5. Testing
- Every returned `backend` is a valid
  `mxc_common::models::ContainmentBackend::wire_name()` value.
- On Windows the result contains `processcontainer` with a `tier` of one of the three known strings;
`appcontainer-dacl` is the floor when nothing higher is reachable.
- On non-Windows, `processcontainer` never appears.
- On macOS, `seatbelt` appears with `tier: None` when `/usr/bin/sandbox-exec` exists.
- A serde snapshot pins the camelCase JSON shape
(`{"backend":"…","tier":"…"}`) and verifies that `tier` is **omitted** when `None`
(`#[serde(skip_serializing_if = "Option::is_none")]`), never serialized as `null`.
- Every non-`None` `tier` is one of the canonical `IsolationTier::as_str()` strings,
guarding against drift between this API and the tier ladder. The canonical list is derived from
`IsolationTier::ALL`, and a further test asserts every tier is reachable from `select_tier`, so a
new tier cannot land without probe coverage.
- On Linux, `bubblewrap` and `lxc` each appear when their check passes (`bwrap --version` / `lxc-ls --version`).
- On Linux, `bubblewrap` carries the `proxyEnforcement` capability when the private-namespace
dependencies are present, and a `warnings` entry naming the missing dependency when they are not;
the backend itself still appears either way. Both directions are covered by exercising the pure
`bubblewrap_backend(Result<(), String>)` helper, so the assertion does not depend on whether the
test host happens to have `slirp4netns` installed.
- A serde snapshot pins the camelCase capability name (`"proxyEnforcement"`) and verifies that
`capabilities` and `warnings` are **omitted** when empty.
- `wslc` appears when `wslc_common::is_available()` confirms WSL2 and the WSLC runtime are present;
resolving `wslcsdk.dll` alone is not sufficient. Each backend declares a `ProbeCoverage` in
`mxc_engine::backend_registry`, naming either the targets it is detected on or why it has no
detector. The platform reporting functions take their host checks as parameters, so two tests run
the real reporting with every check forced to pass: one asserts every backend declared detected on
the current target is reported, the other that a backend declared `NotDetected` still never is.
Registering a backend as detected without adding a branch to `available_backends()` fails the first.
- The TypeScript `getPlatformSupport()` output matches the native probe (parity by projection, §4.2),
 guarding against the two layers drifting.

## 6. Follow-up work items

Remaining detector and TypeScript-projection work, one issue each. The
`windows_sandbox`, `isolation_session`, and `lxc` detectors have landed in Rust
and are registered as `ProbeCoverage::Detected`.

1. `microvm` - hypervisor-presence probe. `hyperlight` has one per host
(`is_whp_available()` / `is_kvm_available()`); `microvm`
is registered as `ProbeCoverage::NotDetected` until its detector lands.
2. TypeScript projection - make `getPlatformSupport()` read the native backend availability via a
side-effect-free transport (e.g. a new `wxc-exec --available-backends` mode handled **before**
`recover_orphaned_state()`, or `mxc_ffi`) instead of running its own `dism`/`lxc-ls`, so the two
layers can't drift (§4.2, step 2). Do **not** extend the existing `--probe` flag: it runs after
`recover_orphaned_state()`, which can restore/prune DACL state and would violate the read-only
contract of this API.

   **Partially landed (Linux).** `lxc-exec --available-backends` serializes
   `available_backends()` and exits, handled immediately after argument parsing so it stays
   read-only with respect to host state. The SDK uses it on Linux to populate
   `PlatformSupport.bubblewrapNetwork`.

   Still open: it is not yet the transport for the rest of `getPlatformSupport()` on Linux,
   so the drift risk in step 2 stands, and Windows is untouched.

---

## 7. Appendix - Decisions & Notes

### 7.1 Separate from `platform_support()`

`platform_support()` (in `mxc_engine::platform`) answers a deliberately
narrower question: "Which backends can the `mxc-sdk` library actually launch?"
Its `available_methods` list is contractually the subset the SDK can drive. On
Linux it may only ever report `bubblewrap`, and unit tests lock that down.
`available_backends()` answers the broader host-capability question, so it is
a separate function.

### 7.2 Single `tier: Option<String>`

The fallback detector selects exactly **one** tier, so a per-tier availability
vector is overkill for a menu. 

### 7.3 Effective tier is a ceiling, not a guarantee

The named tier is  the strongest isolation the host is capable
of. A real request can still end up **lower**: some policy options force a
weaker tier (e.g. `deniedPaths` on a host without `PSE_SUPPORT_FS_DENY`
support, or `preferBaseContainer=false`). 

### 7.4 Which tier gets named is based on precedence, not policy

A host can support several tiers at once. Rather than run your request to see
which one it would pick, the API just names the **strongest** tier the host can
do, by a fixed ranking. Because it never takes a request, it performs none of the
policy-dependent host permission checks that `fallback_detector::detect()` does
(and none of the later `DaclManager` ACE writes that real dispatch performs). It
is purely a reachability walk over the tier ladder.

### 7.5 The `base-container` tier uses `is_base_container_usable()`

This loads `processmodel.dll` and calls an OS capability/create API but it
never launches a process or VM to check.

### 7.6 `process` and `vm` are deliberately excluded

They are *abstract intents*, not backends with their own runner.

### 7.7 `base-container` detection caching

`fallback_detector::is_base_container_usable()` caches its result in a
`OnceLock`. So "fresh detection on every call" is not fully achievable for the
`base-container` tier, and a cached `true` can go **stale** if BaseContainer
enablement changes mid-process. Both are accepted and documented rather than
worked around.

### 7.8 Ordering

Results are returned in a stable order, but callers
should **match by `backend` name, not by position**, so the order is free to
change without breaking anyone.

### 7.9 Why Rust, not the TS layer

The decision to keep the probe in Rust comes down to one asymmetry: 
the *easy* checks are equally easy in Rust, while the *hard* Windows check
is Rust-only either way.

| Aspect | TS layer | Rust core |
| --- | --- | --- |
| Cheap CLI/feature checks (`lxc-ls`, `bwrap`, `dism`, build number) | Already present; ergonomic `execSync` | Equally cheap as `platform_support()` already<br>shells `bwrap --version` |
| Windows isolation **tier** | Cannot compute it:<br>`populateIsolationFromProbe()` shells out to `wxc-exec --probe`<br>and parses its JSON `tier` | Native — `is_base_container_usable()` loads<br>`processmodel.dll` and calls the OS API directly |
| Non-Node consumers (`mxc-sdk`, `mxc_ffi` → C# SDK, executor/CLI) | Must shell out to Node or duplicate the logic | First-class; call the API directly |
| Source of truth for wire names / tier strings | Hand-re-encoded from Rust → drift | Owns `Containment` and `IsolationTier::as_str()` |
| Existing drift | Widens it since TS reports `[lxc, bubblewrap]`, Rust reports `[bubblewrap]` | A single probe eliminates the disagreement |
| Stated architectural goal | Reverses the `platform.rs` goal of *"stop depending on the*<br>*TypeScript SDK for platform discovery"* | Advances it |



Decision: keep the canonical probe in Rust (single source of truth,
reused by `mxc-sdk` / `mxc_ffi` / CLI), and let the TS `getPlatformSupport()`
become a thin wrapper over the native probe instead of re-implementing the
checks.