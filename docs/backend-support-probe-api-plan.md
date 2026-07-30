<!--
Copyright (c) Microsoft Corporation.
Licensed under the MIT License.
-->

# Backend Support Probe API - Design & Discussion

> **Status:** Design Proposal

## 1. Purpose

Provide a read-only Rust API that reports **which containment backends the
current host can actually run**. Callers can read at startup
to choose a backend without attempting an execution. For the Windows
process-container backend it also reports the **effective isolation tier** the
host supports.



```rust
// One host-available backend, plus its effective isolation tier (if any).
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
/// (e.g. an unsupported platform, Linux without `bwrap`, or macOS without
/// `sandbox-exec`) — it is a normal result, not an error.
pub fn available_backends() -> Vec<AvailableBackend>;
```

Example results:
| Host | Result |
| --- | --- |
| Stock Windows | `[{ backend: "processcontainer", tier: Some("appcontainer-dacl") }]` |
| Windows w/ BaseContainer | `[{ backend: "processcontainer", tier: Some("base-container") }]` |
| macOS | `[{ backend: "seatbelt", tier: None }]` |
| Linux w/ bwrap + lxc | `[{ backend: "bubblewrap", tier: None }, { backend: "lxc", tier: None }]` |
## 2. Guiding principle
This API answers **"what can I use here?"**, not **"what is the full capability
matrix of this machine?"**. 
- We return **only** host-available backends. Nothing is reported as `false`.
- A backend's **absence** means "not currently usable, **for any reason**"
- For per-backend **diagnostics and reasons**, the tool is `wxc-exec --probe`
## 3. Detection & isolation tiers

### 3.1 Detection methods used today (and their risks)

Four backends already have *some* presence check, but they are spread across two
layers and vary in how much they actually prove. Documenting them here so the
probe API can reuse the Rust ones and knowingly accept the risk of the shallower
ones.

| Backend | How presence is detected today | Where | Risk with this method |
| --- | --- | --- | --- |
| `base-container` (process-container tier) | `fallback_detector::is_base_container_usable()` loads `processmodel.dll` and calls an OS capability/create API — no process or VM launch; result cached in a `OnceLock`. | Rust | A cached result (`true` **or** `false`) can go stale if BaseContainer enablement changes mid-process, and the probe is not perfectly pure since it loads a DLL. |
| `windows_sandbox` | `isWindowsSandboxAvailable()` runs `dism /online /get-featureinfo /featurename:Containers-DisposableClientVM` and looks for `State : Enabled`; if DISM throws (usually non-elevated) it falls back to `fs.existsSync(%SystemRoot%\System32\WindowsSandbox.exe)`; result cached. | TypeScript SDK | `dism /online` needs elevation, so a non-elevated caller can't tell *disabled* from *no permission* and drops to the exe-existence check — which proves the feature is installed, not that a sandbox VM can boot. Rust callers get nothing. |
| `lxc` | `isLxcAvailable()` runs `lxc-ls --version`; a clean exit means available. | TypeScript SDK | Only proves the `lxc-ls` CLI is on `PATH` — not that liblxc is loadable or that the caller has the namespaces/cgroup/privileges to actually start a container, so it can report available on a host where a real run fails. Rust callers get nothing. |
| `wslc` | `WslcSdk::load()` loads `wslcsdk.dll` from the executable's own directory (anti-hijack) and validates that every required export resolves. | Rust (execute path) | Runs on the *execute* path, not as a cheap standalone probe: it actually loads the DLL and resolves symbols. Proves the SDK runtime loads, not that a WSL distro/runtime is functional. Feature-gated. |

### 3.2 Isolation tiers (process-container only)

Only the Windows process-container backend has a within-backend tier ladder. The
three tiers, and the **policy-free** checks that decide whether each is
reachable, already exist in `appcontainer_common`:

| Tier | Reachable when | Detector |
| --- | --- | --- |
| `base-container` | BaseContainer API is **usable** (not merely symbol-present) | `fallback_detector::is_base_container_usable()` (the cached wrapper) |
| `appcontainer-bfs` | built with the `tier2_bfs` feature | `cfg!(feature = "tier2_bfs")` |
| `appcontainer-dacl` | always (universal Windows floor) | — |



## 4. The probe gap today
Four backends have no *probe-suitable* (cheap, no persistent host mutation, no
process/VM launch) host detector in Rust today, so a truthful availability signal
for them **cannot be built just yet**. (`lxc` and `wslc` are handled separately —
their checks are documented in §3.1 and accepted as good enough.)

| Backend | What a real probe needs | What exists today | Risk if faked |
| --- | --- | --- | --- |
| `windows_sandbox` | DISM/registry check of the *Containers-DisposableClientVM* optional feature | only a private "is the `.exe` on disk" check | reports available when the feature is off → launch fails |
| `isolation_session` | build ≥ 26300.8553 **and** `IsoSessionApp.dll` resolvable **and** feature compiled | build gate lives **only in the TypeScript SDK** | wrong OS builds falsely pass |
| `microvm` | hypervisor (WHP) present | nothing | a naive check could **boot a VM** just to test |
| `hyperlight` | hypervisor present + feature compiled | nothing | same VM-boot risk |




## 5. Testing
- Every returned `backend` is a valid `wxc_common::wire::Containment` name.
- On Windows the result contains `processcontainer` with a `tier` of one of the three known strings;
`appcontainer-dacl` is the floor when nothing higher is reachable.
- On non-Windows, `processcontainer` never appears.
- On macOS, `seatbelt` appears with `tier: None` when `/usr/bin/sandbox-exec `exists.
- A serde snapshot pinning the camelCase JSON shape
(`{"backend":"…","tier":"…"}`), with `tier` **omitted** when `None`
(`#[serde(skip_serializing_if = "Option::is_none")]`)  never serialized as `null`.
- Every non-`None` `tier` is one of the canonical `IsolationTier::as_str() `strings,
guarding against drift between this API and the tier ladder.
- On Linux, `bubblewrap` and `lxc` each appear when their check passes (`bwrap --version` / `lxc-ls --version`).
- `wslc` appears when `WslcSdk::load()` resolves `wslcsdk.dll`; the remaining VM group
(`windows_sandbox`, `isolation_session`, `microvm`, `hyperlight`) never appears until its
detector lands.

## 6. Follow-up work items

Writing the missing detectors, one issue per backend:
1. `windows_sandbox` - optional-feature (DISM/registry) detector.
2. `isolation_session` - port the build-number + `IsoSessionApp.dll` gate from TypeScript to Rust.
3. `microvm` / `hyperlight` - hypervisor-presence probe.
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