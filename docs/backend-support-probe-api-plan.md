<!--
Copyright (c) Microsoft Corporation.
Licensed under the MIT License.
-->

# Backend Support Probe API - Design & Discussion

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
}

/// Probe the host and return only the backends it can currently run.
/// An empty `Vec` means "no backend this API can currently affirm on this host"
/// (e.g. an unsupported platform, Linux with neither `bwrap` nor `lxc`, or
/// macOS without `sandbox-exec`) — it is a normal result, not an error.
pub fn available_backends() -> Vec<AvailableBackend>;
```

Example results:
> **"Stock Windows"** here means a clean Windows install with only the default
> optional features enabled (no BaseContainer, Windows Sandbox, etc.), so the
> process-container backend falls to its `appcontainer-dacl` floor. See
> [`docs/process-container/os-version-support.md`](process-container/os-version-support.md)
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
| `base-container` | `fallback_detector::is_base_container_usable()` loads `processmodel.dll`<br>and calls an OS capability/create API.<br>No process or VM launch; result cached in a `OnceLock`. | Rust | A cached result (`true` **or** `false`) can go stale if BaseContainer enablement<br>changes mid-process, and the probe is not perfectly pure since it loads a DLL. |
| `windows_sandbox` | `isWindowsSandboxAvailable()` runs `dism /online /get-featureinfo `<br>`/featurename:Containers-DisposableClientVM ` and looks for `State : Enabled`<br>if DISM throws (usually non-elevated) it falls back to<br>`fs.existsSync(%SystemRoot%\\System32\\WindowsSandbox.exe)`; result cached. | TypeScript SDK | `dism /online` needs elevation, so a non-elevated caller can't tell *disabled* from<br>*no permission* and drops to the exe-existence checkwhich proves the feature is installed,<br>not that a sandbox VM can boot. (Will move to Rust) |
| `lxc` | `isLxcAvailable()` runs `lxc-ls --version`; a clean exit means available. | TypeScript SDK | Only proves the `lxc-ls` CLI is on `PATH`, not that liblxc is loadable or that the caller has<br>the privileges to actually start a container, so it can report available on a host where a real run fails.<br>(Will move to Rust) |
| `wslc` | `WslcSdk::load()` loads `wslcsdk.dll` from the executable's own directory;<br>validates that every required export resolves. | Rust (execute path) | Runs on the *execute* path, not as a cheap standalone probe:<br>it actually loads the DLL and resolves symbols. Proves the SDK runtime loads,<br>not that a WSL distro/runtime is functional. Feature-gated. |

### 3.2 Isolation tiers (process-container only)

Only the Windows process-container backend has a within-backend tier ladder. The
three tiers, and the **policy-free** checks that decide whether each is
reachable, already exist in `mxc-alpha-basecontainer-common`:

| Tier | Reachable when | Detector |
| --- | --- | --- |
| `base-container` | BaseContainer API is **usable** (not merely symbol-present) | `fallback_detector::is_base_container_usable()` (the cached wrapper) |
| `appcontainer-bfs` | built with the `tier2_bfs` feature | `cfg!(feature = "tier2_bfs")` |
| `appcontainer-dacl` | always (universal Windows floor) | — |



## 4. The probe gap today

### 4.1 Backends still missing a Rust detector

Four backends have no *probe-suitable* (cheap, no persistent host mutation, no
process/VM launch) host detector in Rust today, so a truthful availability signal
for them **cannot be built just yet**.

| Backend | What a real probe needs | What exists today | Risk if faked |
| --- | --- | --- | --- |
| `windows_sandbox` | DISM/registry check of the *Containers-DisposableClientVM* optional feature | only a private "is the `.exe` on disk" check | reports available when the feature is off → launch fails |
| `isolation_session` | activation of the in-proc `Windows.AI.IsolationSession.Preview` `IsoSessionOps` runtime class succeeds (the API class is registered on the OS **and** its OS feature gate is on) **and** the backend feature is compiled | as of #761, detection queries whether the API class is registered rather than gating on a build number; a `CLASS_E_CLASSNOTAVAILABLE` / `REGDB_E_CLASSNOTREG` activation failure means unavailable | none for false-availability now — a machine without the API registered fails activation cleanly; still needs a cheap probe seam so callers don't have to attempt a real activation |
| `microvm` | feature compiled, NanVix runtime files staged, and WHP usable on Windows or `/dev/kvm` readable/writable on Linux | nothing | checking only a hypervisor can report availability when required runtime files are missing |
| `hyperlight` | hypervisor present + feature compiled | nothing | same VM-boot risk |

### 4.2 The parity rule: detect once, project into TS

Detection is split by layer today : `base-container`/`wslc` are Rust-only, while
`windows_sandbox`/`lxc` are TypeScript-only, so the two layers can and already
do disagree. The fix is: detect each capability in exactly one place (Rust), and
have TypeScript read that result rather than compute its own.

| Step | What | Why it gives parity |
| --- | --- | --- |
| 1. Consolidate detectors in Rust | Port the two TypeScript-only checks (`windows_sandbox` DISM/feature check, `lxc-ls`) into Rust<br>so `available_backends()` covers every backend. | Each backend has exactly one detector. |
| 2. TypeScript stops probing itself | `getPlatformSupport()` reads the native backend-availability result instead of running its own `dism`/`lxc-ls`.<br>The transport must be **side-effect-free**: `wxc-exec --probe` runs *after* `recover_orphaned_state()` (which can restore/prune DACL state on the host), so it cannot be extended unchanged without violating the read-only contract.<br>Instead, expose backend availability via a dedicated mode handled **before** DACL recovery (e.g. `wxc-exec --available-backends`), or directly through `mxc_ffi`. | TypeScript becomes a pure projection of the Rust result, without triggering host mutation. |
| 3. Names flow from serde | Backend names (`Containment`) and tier strings (`IsolationTier::as_str()`) are already Rust-serialized;<br>TypeScript consumes them as-is instead of hand-re-encoding. | Removes the wire-name drift class structurally. |

See §7.9 for why the canonical probe stays in Rust rather than moving into the TypeScript layer.




## 5. Testing
- Every returned `backend` is a valid `mxc_alpha_wxc_common::wire::Containment` name.
- On Windows the result contains `processcontainer` with a `tier` of one of the three known strings;
`appcontainer-dacl` is the floor when nothing higher is reachable.
- On non-Windows, `processcontainer` never appears.
- On macOS, `seatbelt` appears with `tier: None` when `/usr/bin/sandbox-exec` exists.
- A serde snapshot pins the camelCase JSON shape
(`{"backend":"…","tier":"…"}`) and verifies that `tier` is **omitted** when `None`
(`#[serde(skip_serializing_if = "Option::is_none")]`), never serialized as `null`.
- Every non-`None` `tier` is one of the canonical `IsolationTier::as_str()` strings,
guarding against drift between this API and the tier ladder.
- On Linux, `bubblewrap` and `lxc` each appear when their check passes (`bwrap --version` / `lxc-ls --version`).
- `wslc` appears when `WslcSdk::load()` resolves `wslcsdk.dll`; the remaining VM group
(`windows_sandbox`, `isolation_session`, `microvm`, `hyperlight`) never appears until its detector lands.
- The TypeScript `getPlatformSupport()` output matches the native probe (parity by projection, §4.2),
 guarding against the two layers drifting.

## 6. Follow-up work items

Writing the missing detectors and wiring the TypeScript projection, one issue each:
1. `windows_sandbox` - optional-feature (DISM/registry) detector.
2. `isolation_session` - probe whether the `Windows.AI.IsolationSession.Preview` `IsoSessionOps` API class is registered on the OS (activation-factory resolvable), replacing the old build-number gate (see #761), and expose it to Rust.
3. `microvm` / `hyperlight` - hypervisor-presence probe.
4. `lxc` - port the `lxc-ls` presence check from TypeScript to Rust,
so the probe (not just the SDK) can report it (§4.2, step 1).
5. TypeScript projection - make `getPlatformSupport()` read the native backend availability via a
side-effect-free transport (e.g. a new `wxc-exec --available-backends` mode handled **before**
`recover_orphaned_state()`, or `mxc_ffi`) instead of running its own `dism`/`lxc-ls`, so the two
layers can't drift (§4.2, step 2). Do **not** extend the existing `--probe` flag: it runs after
`recover_orphaned_state()`, which can restore/prune DACL state and would violate the read-only
contract of this API.
---

## 7. Appendix - Decisions & Notes

### 7.1 Separate from `platform_support()`

`platform_support()` (in `mxc_alpha_mxc_engine::platform`) answers a deliberately
narrower question: "Which backends can the `mxc-alpha-mxc-sdk` library actually launch?"
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
weaker tier (e.g. `deniedPaths` on a host without `SANDBOX_CAP_FS_DENY`
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
| Non-Node consumers (`mxc-alpha-mxc-sdk`, `mxc_ffi` → C# SDK, executor/CLI) | Must shell out to Node or duplicate the logic | First-class; call the API directly |
| Source of truth for wire names / tier strings | Hand-re-encoded from Rust → drift | Owns `Containment` and `IsolationTier::as_str()` |
| Existing drift | Widens it since TS reports `[lxc, bubblewrap]`, Rust reports `[bubblewrap]` | A single probe eliminates the disagreement |
| Stated architectural goal | Reverses the `platform.rs` goal of *"stop depending on the*<br>*TypeScript SDK for platform discovery"* | Advances it |



Decision: keep the canonical probe in Rust (single source of truth,
reused by `mxc-alpha-mxc-sdk` / `mxc_ffi` / CLI), and let the TS `getPlatformSupport()`
become a thin wrapper over the native probe instead of re-implementing the
checks.