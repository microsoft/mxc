# Windows OS-version policy support (`processcontainer`)

This is the authoritative reference for **which policy aspects the Windows
`processcontainer` backend can enforce on each Windows release**. It covers the
filesystem, network, and UI-restriction policy surfaces. **All releases in this
document are Windows 11**, and the minimum considered here is Windows 11 23H2.

For the enforcement mechanisms themselves see the
[UI policy schema](./UIPolicy_Schema.md) and the
[sandbox policy spec](../sandbox-policy/v1/policy.md).

## Windows 11 releases

| Windows 11 release | Build |
|--------------------|-------|
| 23H2 | 22631 |
| 24H2 | 26100 |
| 25H2 | 26200 |
| 25H2+ | 26600+ |

> **Product floor:** the [README](../../README.md#platforms) and
> [SDK README](../../sdk/README.md) state that `processcontainer`'s **minimum
> supported build is 26100 (24H2)**. The Rust code build-gates individual
> capabilities down to 23H2 (build 22631); the **23H2** column below therefore
> describes *what the code can enforce if run there* — it is below the
> officially supported floor and is not a support commitment.

## Enforcement tiers

The Windows backend selects one of three isolation tiers at runtime
(`src/backends/appcontainer/common/src/fallback_detector.rs`). Which tiers are
available bounds what policy can be enforced.

| Tier | Mechanism | 23H2 | 24H2 | 25H2 | 25H2+ |
|------|-----------|:--:|:--:|:--:|:--:|
| **T1** BaseContainer | `Experimental_CreateProcessInSandbox` (processmodel.dll) | ❌ | ❌ (no processmodel.dll) | ❌ (no processmodel.dll) | ✅ when the OS feature is enabled, else falls back to T3 |
| **T2** AppContainer + BFS | `bfscfg.exe`-driven filesystem policy | ❌ (not shipped) | ⚠️ present but `tier2_bfs` OFF | ⚠️ present but `tier2_bfs` OFF | ⚠️ present but `tier2_bfs` OFF |
| **T3** AppContainer + DACL | Host-side DACL ACE augmentation | ✅ | ✅ | ✅ | ✅ |

- **T1 (BaseContainer)** requires `processmodel.dll` to export
  `Experimental_CreateProcessInSandbox` *and* the OS feature to be enabled; this
  is a 25H2+ capability. Usability is resolved up front by
  `BaseContainerRunner::is_base_container_usable()` so tier selection never picks
  a T1 that cannot launch.
- **T2 (BFS)** is compiled out by default. `bfscfg.exe` ships only on 24H2 and
  later, but the `tier2_bfs` Cargo feature is **off** in all shipping builds
  because invoking `bfscfg.exe` can deadlock the host on 25H2. Treat T2 as
  unavailable.
- **T3 (AppContainer + DACL)** is the universal fallback and enforces
  filesystem policy via host path ACEs on every release.

## Filesystem policy

| Aspect | 23H2 | 24H2 | 25H2 | 25H2+ |
|--------|:--:|:--:|:--:|:--:|
| `readwritePaths` / `readonlyPaths` grants | ✅ (T3 DACL) | ✅ (T3 DACL) | ✅ (T3 DACL) | ✅ (T1 native, or T3 DACL) |
| `deniedPaths` | ✅ (T3 DENY ACE) | ✅ (T3 DENY ACE) | ✅ (T3 DENY ACE) | ✅ (T3; T1 only when `SANDBOX_CAP_DENY_PATHS` is set, otherwise rejected at launch and dispatched to T3) |
| BFS brokering (T2) | ❌ | ⚠️ disabled in shipping builds | ⚠️ disabled in shipping builds | ⚠️ disabled in shipping builds |

Notes:
- On 25H2+, T1 can grant `readwrite`/`readonly` paths natively via the FlatBuffer
  `SandboxSpec` (`fs_read_write` / `fs_read_only`). `deniedPaths` under T1
  additionally requires the `SANDBOX_CAP_DENY_PATHS` capability bit reported by
  `Experimental_QuerySandboxSupport`
  (`BaseContainerRunner::base_container_supports_deny_paths()`); when the bit is
  clear, `deniedPaths` is rejected and the run relies on default-deny plus
  explicit grants (or T3 DENY ACEs).
- On 23H2, 24H2, and 25H2 (and on 25H2+ hosts where T1 is unavailable), all
  filesystem policy — grants **and** denies — is enforced by T3 host-path DACLs.

## Network policy

| Aspect | 23H2 | 24H2 | 25H2 | 25H2+ |
|--------|:--:|:--:|:--:|:--:|
| Capabilities (`internetClient`) | ✅ | ✅ | ✅ | ✅ |
| Firewall rules (`netsh advfirewall`, needs admin) | ✅ | ✅ | ✅ | ✅ |
| Proxy via OS / BaseContainer (`appinfosvc`, FlatBuffer `network_policy.proxy`) | ❌ | ❌ | ❌ | ✅ (T1 only) |

Notes:
- Capability- and firewall-based network enforcement is an AppContainer
  primitive and works on every release.
- OS-configured WinHTTP proxy (passed in the FlatBuffer spec to
  `CreateProcessInSandbox`) is a T1-only path and therefore 25H2+ only.
- The earlier AppContainer WinHTTP proxy shim (`winhttp-proxy-shim.exe`) is
  being retired and is intentionally omitted here: the new WinHTTP cleanup APIs
  it depended on are not moving down-level, so it is not a forward-looking
  option.

## UI restrictions

UI restrictions map to Job Object `JOB_OBJECT_UILIMIT_*` flags plus the
`disallowWin32kSystemCalls` process mitigation. They are applied in **both** T1
and T3 (`src/backends/appcontainer/common/src/job_object.rs`), so they are
available regardless of tier — subject to per-flag build gating. The effective
mask is always `requested & supported`, so the kernel is never handed a flag it
would reject; `wxc-exec --probe` reports what a host can enforce.

| Restriction (`ui` field) | 23H2 | 24H2 | 25H2 | 25H2+ |
|--------------------------|:--:|:--:|:--:|:--:|
| `isolation` — HANDLES / GLOBALATOMS | ✅ | ✅ | ✅ | ✅ |
| `clipboard` — READCLIPBOARD / WRITECLIPBOARD | ✅ | ✅ | ✅ | ✅ |
| `systemSettings` — SYSTEMPARAMETERS / DISPLAYSETTINGS | ✅ | ✅ | ✅ | ✅ |
| `desktopSystemControl` — DESKTOP / EXITWINDOWS | ✅ | ✅ | ✅ | ✅ |
| `ime` — IME (`0x100`, ≥ 22621) | ✅ | ✅ | ✅ | ✅ |
| `injection` — INJECTION (`0x200`, ≥ 26100) | ❌ | ✅ | ✅ | ✅ |
| `disable` — `disallowWin32kSystemCalls` mitigation | ✅ | ✅ | ✅ | ✅ |

The single UI differentiator for 23H2 is **`injection`**
(`JOB_OBJECT_UILIMIT_INJECTION`), which the kernel accepts only on build 26100
and later (`MIN_BUILD_FOR_INJECTION_LIMIT`) and is therefore unavailable on
23H2. `ime` (`JOB_OBJECT_UILIMIT_IME`) requires build 22621
(`MIN_BUILD_FOR_IME_LIMIT`) and so is available on every supported release.

## Sources

- Tier selection: `src/backends/appcontainer/common/src/fallback_detector.rs`,
  `src/backends/appcontainer/common/src/dispatcher.rs`
- BaseContainer capability probing (`SANDBOX_CAP_*`,
  `Experimental_QuerySandboxSupport`) and FlatBuffer `SandboxSpec` construction:
  `src/backends/appcontainer/common/src/base_container_runner.rs`
- UI-limit build gating (`MIN_BUILD_FOR_IME_LIMIT`,
  `MIN_BUILD_FOR_INJECTION_LIMIT`, `supported_ui_limit_mask_for_build`):
  `src/backends/appcontainer/common/src/job_object.rs`
- FlatBuffer contract: `external/windows-sdk/BaseContainerSpecification.fbs`
- Product support floor: [README](../../README.md#platforms),
  [SDK README](../../sdk/README.md)
