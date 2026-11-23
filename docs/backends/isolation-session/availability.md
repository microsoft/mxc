# IsolationSession availability

> **Audience:** MXC consumers and developers

The IsolationSession backend runs workloads in Windows isolation sessions. The
Windows build alone does not make isolation sessions available.

## Requirements

MXC can create isolation sessions only when all of these hold:

- The device runs a Windows build at or above the Session Isolation build
  listed for its release in
  [Windows OS-version support](../process-container/os-version-support.md#releases).
- Windows has enabled isolation sessions on the device. Windows can leave them
  disabled on a device that meets that build, so two devices on the same build
  can differ. MXC cannot enable them.
- The process that creates the isolation sessions runs under an interactive
  Windows sign-in, in that user's Windows session. Contexts that do not meet
  this requirement include:
  - A scheduled task that runs whether or not the user is signed in. Windows
    denies it access, and MXC reports isolation sessions unavailable.
  - Session 0, where Windows runs services. MXC reports isolation sessions
    available to a process running there as SYSTEM, but creating an isolation
    session fails.
- The MXC build includes the IsolationSession backend. Without it, MXC reports
  isolation sessions unavailable on every host.

## Checking availability

Check at run time, under the same sign-in as the process that will create the
isolation sessions. Backend discovery and platform support report isolation
sessions available by including the IsolationSession backend:

| SDK | Backend discovery | Platform support |
|---|---|---|
| Rust | `mxc_sdk::v1::available_backends` | `mxc_sdk::v1::platform_support` |
| .NET | `Microsoft.Mxc.Sdk.V1.MxcPlatform.GetAvailableBackends` | `Microsoft.Mxc.Sdk.V1.MxcPlatform.GetPlatformSupport` |
| Node | `@microsoft/mxc-sdk/v1::getAvailableBackends` | `@microsoft/mxc-sdk/v1::getPlatformSupport` |

The request probe reports the same answer: `isolation_session_available` in
Rust, `IsolationSessionAvailable` in .NET, and `isolationSessionAvailable` in
Node and in `wxc-exec --probe` output.

## When creating an isolation session fails

When a Windows call fails, the error names the call and, when Windows supplies
one, its error code:

| Error type | Field with the failing call | Field with the Windows error code |
|---|---|---|
| Rust `mxc_sdk::v1::Error` | `operation` | `native_code` |
| .NET `Microsoft.Mxc.Sdk.V1.MxcException` | `Operation` | `NativeCode` |
| Node `@microsoft/mxc-sdk/v1::MxcError` | `operation` | `nativeCode` |

`wxc-exec` prints both in its error message.

Two failures follow from the sign-in requirement:

| Failing call | Windows error code | Cause |
|---|---|---|
| `IsoSessionOps.ActivateInstance` | `0x80070005` | Windows denied the process access, as it does for a scheduled task that runs whether or not the user is signed in. |
| `IsoSessionOps.StartSessionAsync` | `0x80040233` | The process runs in Session 0. |
