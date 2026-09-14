# Windows OS support (`processcontainer`)

The Windows `processcontainer` backend uses only native BaseContainer
contracts:

- **PSEC** — `CreateProcessSecurityEnvironment`, preferred whenever its runtime
  probe succeeds and it can represent the complete request.
- **SBOX** — the transitional `Experimental_CreateProcessInSandbox` contract,
  used only when its capability query and policy-compatibility checks succeed.

MXC no longer provides AppContainer+BFS or AppContainer+DACL fallback tiers and
never mutates host filesystem DACLs to make a process-container request work.
If neither native contract can enforce the request, execution fails as
`backend_unavailable` before a child process starts.

## Windows releases

Support is determined by runtime probing, not by build number alone. Export
presence is insufficient because transitional Windows builds may expose an API
before its feature is enabled.

| Windows release | Build | ProcessContainer |
|---|---:|---|
| Windows 11 23H2 | 22631 | Unsupported |
| Windows 11 24H2 | 26100 | Unsupported |
| Windows 11 25H2 | 26200 | Unsupported unless a native contract is separately enabled |
| Current prerelease and later builds | 26600+ validation range | Supported when PSEC or SBOX runtime probing succeeds |

The build ranges above describe known Windows generations, not a substitute for
the runtime probe. `BaseContainerRunner::is_usable_for_request()` is
authoritative for an individual request.

## Contract selection

PSEC requires:

- `CreateProcessSecurityEnvironment`
- `QueryProcessSecurityEnvironmentSupport`
- `CloseProcessSecurityEnvironment`

SBOX requires `Experimental_CreateProcessInSandbox`; when
`Experimental_QuerySandboxSupport` is available, MXC also verifies the
capability bits needed by the request.

PSEC is preferred independently of schema version. MXC uses SBOX only when the
legacy FlatBuffer contract can preserve every requested policy field. Examples
that may require PSEC include schema 0.8 directional network rules, runtime
proxy configuration, proxy peer identity, and host-loopback control.

`processContainer.leastPrivilege` remains SBOX-only. If PSEC cannot represent a
request and SBOX is unavailable or incompatible, MXC fails closed.

## Filesystem policy

| Policy | PSEC | SBOX |
|---|:---:|:---:|
| `readwritePaths` | ✅ | ✅ |
| `readonlyPaths` | ✅ | ✅ |
| `deniedPaths` | ✅ when `PSE_SUPPORT_FS_DENY` is advertised | ✅ when `SANDBOX_CAP_FS_DENY` is advertised |

There is no filesystem fallback. An unsupported deny policy is rejected rather
than emulated with host DENY ACEs.

## Network policy

| Capability | PSEC | SBOX |
|---|:---:|:---:|
| Legacy default policy and capability mapping | ✅ | ✅ when representable |
| Schema 0.8 directional defaults | ✅ | Limited |
| Explicit egress IP/CIDR/port/protocol rules | ✅ | ❌ |
| Proxy peer identity / host-loopback policy | ✅ | ❌ |
| `runtimeConfig.networkProxy` | ✅ | ❌ |

PSEC owns WFP policy lifetime through workload completion. SBOX exposes no
equivalent schema 0.8 WFP lifetime handle, so unsupported requests fail rather
than silently dropping restrictions.

## UI restrictions

UI restrictions map to Job Object `JOB_OBJECT_UILIMIT_*` flags plus the
`disallowWin32kSystemCalls` mitigation and are shared by PSEC and SBOX.
`wxc-exec --probe` reports the restrictions accepted by the current kernel.

| Restriction | Minimum known build |
|---|---:|
| Handles, global atoms, clipboard, desktop, exit-Windows, system/display settings | 22631 |
| IME | 22621 |
| Input injection | 26100 |
| Win32k system-call disable | 22631 |

## Sources

- Native contract selection and capability checks:
  `src/backends/appcontainer/common/src/base_container_runner.rs`
- ProcessContainer dispatch:
  `src/backends/appcontainer/common/src/dispatcher.rs`
- UI-limit build gating:
  `src/backends/appcontainer/common/src/job_object.rs`
- SBOX FlatBuffer contract:
  `external/windows-sdk/BaseContainerSpecification.fbs`
