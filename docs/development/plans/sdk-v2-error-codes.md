<!--
Copyright (c) Microsoft Corporation.
Licensed under the MIT License.
-->

# SDK v2 Error Codes

> **Audience:** MXC developers

> **Status:** WIP, tracked by [#1595](https://github.com/microsoft/mxc/issues/1595)

Failures are meant to be classified by the side that can fix them: the request
(`policy_validation`, exit `1`), the host (`backend_unavailable`, exit `-1`), or
the runtime (`backend_error`, exit `-1`). See the
[error contract](../architecture/versioning.md#error-contract).

The sites below still report their SDK v1 code, because changing it would break
published SDK callers. Each one has a `// SDK v2:` comment that names its
intended code. Move them together in the next major SDK version.

| Site | SDK v1 | SDK v2 |
|---|---|---|
| Shared validator: empty script, `enumeratePaths` off ProcessContainer | `backend_error` | `policy_validation` |
| Policy path checks (`FilesystemPolicyError::into_response`) | `backend_error` | `policy_validation`, or `backend_error` with phase `LaunchFailed` for host faults |
| Backend not compiled in (`mxc_engine` `run` and `dispatch`) | `unsupported_containment` | `backend_unavailable` |
| ProcessContainer: unenforceable field (`deniedPaths`, `enumeratePaths`, LPAC) | `backend_unavailable` | `policy_validation` |
| ProcessContainer: PSEC baseline unsupported | `policy_validation` | `backend_unavailable` |
| Bubblewrap: request refusals | `backend_error` | `policy_validation` |
| Bubblewrap: missing or too-old `bwrap`, no network support; proxy lookup failure | `backend_error` | `backend_unavailable`; phase `LaunchFailed` |
| LXC: request refusals | `backend_error` | `policy_validation` |
| LXC: tooling missing, streaming off Linux | `backend_error` | `backend_unavailable` |
| Seatbelt: refusals (`rejected_response`) | `backend_error` | `policy_validation` |
| WSLC: policy-path host faults | `policy_validation` | `backend_error` |
| IsolationSession one-shot: lifecycle refusals, `IsolationSessionError` conversion | `backend_error` | `policy_validation` / `backend_unavailable` |
| IsolationSession one-shot: `validate` and launch failures always use phases `Rejected` and `LaunchFailed` | as forced | the phase from the underlying error |
| IsolationSession relayed exec timeout | exit code `-1` | `backend_error` "script timed out" |

## Remaining work

- Switch each site to its SDK v2 code behind the v2 SDK surface, keeping v1 callers on the v1 codes.
- Update the Rust, .NET and Node references under `docs/api-reference/`, the backend guides and the host test scripts under `tests/scripts/`.
