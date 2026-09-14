# Windows OS-version policy support (`processcontainer`)

This is the authoritative reference for **which policy aspects the Windows
`processcontainer` backend can enforce on each Windows release**. It covers the
filesystem, network, and UI-restriction policy surfaces. **All releases in this
document are Windows 11**, and the minimum considered here is Windows 11 23H2.

For the enforcement mechanisms themselves see the
[UI policy schema](./UIPolicy_Schema.md) and the
[sandbox policy spec](../sandbox-policy/0.7.0/policy.md).

## Windows 11 releases

| Windows 11 release | Build |
|--------------------|-------|
| 23H2 | 22631 |
| 24H2 | 26100 |
| 25H2 | 26200 |
| 25H2+ | 26600+ |

> **Product floor:** the [README](../../README.md#platforms) and
> [SDK README](../../sdk/node/README.md) state that `processcontainer`'s **minimum
> supported build is 26100 (24H2)**. The Rust code build-gates individual
> capabilities down to 23H2 (build 22631); the **23H2** column below therefore
> describes *what the code can enforce if run there* — it is below the
> officially supported floor and is not a support commitment.

## Native ProcessContainer availability

The Windows backend requires the native PSEC process-security-environment
contract. There is no AppContainer, BFS, SBOX, or host-DACL fallback. Runtime
probing is authoritative: if PSEC is unavailable or cannot represent the
complete request, MXC fails before launch.

The PSEC probe requires:

- `CreateProcessSecurityEnvironment`
- `QueryProcessSecurityEnvironmentSupport`
- `CloseProcessSecurityEnvironment`

When `processContainer.captureDenials` is present, MXC additionally requires the official V2 Learning Mode exports:

- `StartLearningModeTrace`
- `StopLearningModeTrace`
- `CloseLearningModeTrace`

Internal validation builds are evidence for the probe implementation, not a public release-floor commitment.

## Filesystem policy

| Aspect | 23H2 | 24H2 | 25H2 | Current prerelease and later |
|--------|:--:|:--:|:--:|:--:|
| `readwritePaths` / `readonlyPaths` grants | ❌ | ❌ | ❌ | ✅ PSEC |
| `processContainer.filesystem.enumeratePaths` | ❌ | ❌ | ❌ | ⚠️ PSEC 1.1 only when `PSE_SUPPORT_FS_ENUMERATE` is reported |
| `deniedPaths` | ❌ | ❌ | ❌ | ⚠️ PSEC only when `PSE_SUPPORT_FS_DENY` is reported |

`processContainer.filesystem.enumeratePaths` permits directory queries and
listing under the caller's user access without granting file-content reads. It
is incompatible with `processContainer.leastPrivilege`; unsupported
combinations fail rather than broadening access.

## Network policy

Network policy is enforced only when the active PSEC contract advertises the
required capabilities. Schema 0.8 directional defaults, explicit egress rules,
proxy peer identity, host-loopback policy, and runtime proxy configuration fail
closed when the corresponding native support is unavailable.

## UI restrictions

UI restrictions map to Job Object `JOB_OBJECT_UILIMIT_*` flags plus the
`disallowWin32kSystemCalls` process mitigation. They are applied by the native
PSEC runner (`src/backends/process_container/common/src/job_object.rs`) —
subject to per-flag build gating. The effective mask is always
`requested & supported`, so the kernel is never handed a flag it would reject;
`wxc-exec --probe` reports what a host can enforce.

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

- Native dispatch: `src/backends/process_container/common/src/dispatcher.rs`
- BaseContainer PSEC capability probing and specification construction:
  `src/backends/process_container/common/src/base_container_runner.rs`,
  `src/backends/process_container/common/src/base_container_helpers.rs`
- UI-limit build gating (`MIN_BUILD_FOR_IME_LIMIT`,
  `MIN_BUILD_FOR_INJECTION_LIMIT`, `supported_ui_limit_mask_for_build`):
  `src/backends/process_container/common/src/job_object.rs`
- FlatBuffer contract: `external/windows-sdk/ProcessSecurityEnvironment.fbs`
- Product support floor: [README](../../README.md#platforms),
  [SDK README](../../sdk/node/README.md)
