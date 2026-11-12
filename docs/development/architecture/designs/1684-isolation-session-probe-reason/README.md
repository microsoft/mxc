# Feature design: report why the probe finds isolation sessions unavailable

> **Audience:** MXC developers

- **Status:** Proposed
- **Issue:** [#1684](https://github.com/microsoft/mxc/issues/1684)
- **Contributor:** @adpa-ms
- **Implementation PRs:** Not started.

This design adds an optional reason beside `isolationSessionAvailable` in the
Windows request probe. The reason uses the IsolationSession activation error
text, which the design rewrites, and new text for the feature-level checks.
Declarations and caller examples are in the [API proposal](api.md).

## Problem and scope

`wxc-exec --probe` and the SDK probe functions (Rust `mxc_sdk::v1::probe`,
.NET `MxcContainer.Probe` and Node `probe`) report only that isolation sessions
are unavailable. The caller cannot tell whether it can act, and a maintainer
cannot tell which check failed. In #1684, two PCs on the same Windows build
give different answers, and nothing in the output explains why.

Usage scenarios:

1. **Non-interactive sign-in.** A scheduled task that runs whether or not the
   user is signed in, without a stored password (an S4U sign-in), calls
   `wxc-exec --probe` on a host that supports isolation sessions. Windows
   denies activation, so the probe reports `false` with an access-denied reason
   and a remediation: run from an interactive Windows sign-in session.
2. **Unavailable host.** An app calls `MxcContainer.Probe()` on a device where
   isolation sessions are unavailable and logs the reason. The reason names
   the failed check and its HRESULT or feature level, which identifies the case
   without access to the device.

Not in scope:

- Discovery and platform support. Node's `getPlatformSupport()` does not add
  the reason to `unavailableReasons`, because Rust and .NET platform support
  have no per-backend reasons.
- Reasons for other backends.
- Which hosts support isolation sessions. Windows decides that.
- The error code that `wxc-exec` reports for a failed create-and-run, tracked
  by #1595.

## Proposed behavior

In a build with the `isolation_session` feature, the probe reports a reason
whenever `isolationSessionAvailable` is false. Otherwise the reason is absent.

| Case | Operation | HRESULT | Message | Remediation |
| --- | --- | --- | --- | --- |
| Activation returns `REGDB_E_CLASSNOTREG` or `CLASS_E_CLASSNOTAVAILABLE` | `IsoSessionOps.ActivateInstance` | Yes | `isolation sessions are not available on this host` | None |
| Activation returns `E_ACCESSDENIED` | `IsoSessionOps.ActivateInstance` | Yes | `Windows denied access to the IsolationSession runtime API` | `Run from an interactive Windows sign-in session.` |
| Activation returns another HRESULT | `IsoSessionOps.ActivateInstance` | Yes | `IsolationSession runtime API activation failed: {Windows' message}` | None |
| The `LocalAgentUser` feature level is 0 or below | `IsoSessionOps.GetFeatureLevel` | No | `isolation sessions are not available on this host (LocalAgentUser feature level {level})` | None |
| `GetFeatureLevel` fails | `IsoSessionOps.GetFeatureLevel` | Yes | `IsolationSession runtime API feature level query failed: {Windows' message}` | None |
| MXC cannot run the probe, for example because it cannot carry the caller's impersonation token to its worker thread | Existing | Existing | The existing MXC error | Existing |

When Windows supplies no message, the text ends at "failed".

Two errors differ from today's IsolationSession API failures: the access-denied
error carries a remediation written by MXC rather than the API, and the
feature-level-0 error has no HRESULT.

The reason holds the one-line text that `wxc-exec` prints for a failed
create-and-run. For example:

```text
Isolation Session service unavailable: IsoSessionOps.ActivateInstance: Windows denied access to the IsolationSession runtime API (HRESULT: 0x80070005) -- remediation: Run from an interactive Windows sign-in session.
```

The activation rows also apply when a container is created or used. `wxc-exec`
prints the same one-line text. The SDKs and container lifecycle operations
return the message and remediation as separate error fields, with the HRESULT
in `nativeCode`. Error codes, operations and HRESULTs do not change. The
feature-level rows apply only to the probe, because container creation does
not check the `LocalAgentUser` level.

## Execution and container lifecycle support

Activation failures report the new text in create-and-run execution, live
stdio streaming, PTY sessions and every container lifecycle operation. Nothing
else in execution or the lifecycle changes.

## Backend applicability and availability

| Backend | Planned support | Required host features and how they are checked | What the probe/availability API reports |
| --- | --- | --- | --- |
| IsolationSession | Yes | The IsolationSession runtime activates for the caller, and the `LocalAgentUser` feature level is above 0 | `isolationSessionAvailable`, and `isolationSessionUnavailableReason` when it is false |
| ProcessContainer | No; the probe's `error` already explains why it cannot serve a request | Unchanged | Unchanged |
| Hyperlight | No; reasons for other backends are out of scope | Unchanged | Unchanged |
| WSLC | No; the request probe does not report it | Unchanged | Unchanged |
| Windows Sandbox | No; the request probe does not report it | Unchanged | Unchanged |
| MicroVM | No; the request probe does not report it | Unchanged | Unchanged |
| LXC | Not applicable; the request probe runs only on Windows | Unchanged | Unchanged |
| Bubblewrap | Not applicable; the request probe runs only on Windows | Unchanged | Unchanged |
| Seatbelt | Not applicable; the request probe runs only on Windows | Unchanged | Unchanged |
| VM | Not applicable; it resolves to a concrete backend on each host | Unchanged | Unchanged |
| W365 Agents | Not applicable; it has no runtime backend | Unchanged | Unchanged |

- Can the backend run but lack support for this feature? No. The reason
  applies only when the backend cannot run.
- Experimental status: unchanged.
- Policy that cannot be enforced: unchanged. The probe does not evaluate
  IsolationSession requests.

## Contracts, APIs, and compatibility

- MXC request fields: No change.
- Public APIs: Yes. `ProbeFacts` gains an optional reason field in the Rust,
  .NET and Node V1 APIs, serialized as `isolationSessionUnavailableReason`.
  See the [API proposal](api.md).
- Runtime behavior: activation failures change only their message and
  remediation. Callers that match on message text see the new wording.

## Design and security

- The IsolationSession backend maps each case to its error. Its availability
  check keeps the error it hit and renders it as the reason.
- The engine's request probe sets `isolationSessionAvailable` and the reason
  from that one result, so they cannot disagree.
- `wxc-exec --probe` and the C exports `mxc_probe_request_json` and
  `mxc_probe_request_json_with_error` serialize the probe output as today.
- Security: No change. The probe runs under the calling thread's identity. As
  today, the process caches the first result, so a process that impersonates
  several users reports the first caller's result to all of them.
- Large refactor or new crate: No.
- Alternatives:
  - The probe's `error` field. Rejected: `error` means ProcessContainer cannot
    serve the request, and the SDKs reject `error` alongside a tier.
  - The probe's `warnings` list. Rejected: it holds ProcessContainer
    diagnostics, so callers would have to parse text to find the reason.
  - A structured error object. Rejected: every existing probe and discovery
    reason is a string, and a structured shape is a decision for all backends.

## Resource ownership and failure recovery

Not applicable. The probe creates no container, user or session, and leaves
nothing to clean up.

## Acceptance criteria and validation plan

Pass conditions:

- A build with the `isolation_session` feature reports a non-empty reason
  exactly when `isolationSessionAvailable` is false.
- Each case in [Proposed behavior](#proposed-behavior) produces its message,
  remediation, operation and HRESULT.
- The .NET and Node probe APIs return the reason, and reject an explicit null
  or a non-string value.
- Errors from creating or using a container keep their error codes,
  operations and HRESULTs.

Tests:

- Rust unit tests in the IsolationSession backend cover each case, the
  empty-message fallback, and that a probe that could not run is not cached.
- A Rust unit test in the engine checks that a reason is present exactly when
  `isolationSessionAvailable` is false, and is serialized only then.
- `feature_unavailable_returns_clean_error` in `manager.rs` checks the error's
  structure instead of its wording, so it passes whichever activation failure
  the host returns. The per-case unit tests check the wording.
- A proposed test in `src/mxc-sdk/tests/isolation_session.rs` calls
  `mxc_sdk::v1::probe(None)` and checks the first pass condition. It passes on
  hosts with and without isolation sessions.
- .NET and Node unit tests, and the .NET AOT smoke test, parse the field.
- A manual run on a host that supports isolation sessions: an interactive
  sign-in reports `true` with no reason, and an S4U scheduled task reports
  `false` with the access-denied reason.

CI:

- Rust: the `Test` step of `Build.Windows.Job.yml` on `windows-2025` (x64) and
  `windows-11-arm` (arm64), and the nightly IsolationSession job, which runs
  `mxc-sdk-isolation-session-tests.exe`.
- .NET, including the AOT publish: `SDK.Dotnet.Test.Job.yml`. Node:
  `SDK.Unit.Test.Job.yml`.

No CI job creates a non-interactive sign-in, so only the manual run tests the
access-denied case end to end. The proposed test covers whichever case each CI
host hits. One CI check is replaced: the wording check in
`feature_unavailable_returns_clean_error`.

## Delivery and documentation

- One implementation PR after this spec merges. The .NET and Node parsers
  reject unknown fields, so they must accept the field in the same change that
  makes the native library emit it.
- SDK references, READMEs and changelogs: listed in the
  [API proposal](api.md#validation-and-documentation).
- Developer docs: the error-mapping and structured failure fields tables in
  [state-aware-rust.md](../../backends/isolation-session/state-aware-rust.md).

## Open questions

1. **Is adding a field to `ProbeFacts` acceptable in V1?** It breaks Rust code
   that builds the struct with a struct literal or destructures it without
   `..`, and the versioning policy makes breaking public API changes major.
   #1406 added a field the same way in 1.0.1, after its review raised the same
   concern. Proposed answer: accept it in the next minor release. If
   maintainers decline, Rust's `ProbeFacts` stays unchanged: an engine type adds
   the field to the JSON, and Rust callers read the reason through a new
   function.

## Review checklist

- [ ] The issue has maintainer-applied `feature-accepted`; scope and contributor are agreed.
- [x] One or two meaningful usage examples, non-goals, defaults, and failure behavior are clear.
- [x] Every backend is considered, with explicit capability checks and probe/availability behavior.
- [x] Execution modes and container lifecycle support are explicit; exclusions are explained.
- [x] Resource ownership, partial failures, failed cleanup, and subsequent container creation are addressed.
- [x] Security, contract/API compatibility, and any breaking changes are addressed.
- [x] A separate API proposal is linked when public APIs change.
- [x] Acceptance criteria and the CI plan cover observable behavior.
- [ ] Delivery and documentation changes are scoped; material questions are resolved.
- [x] Answers are concise; diagrams explain the design without repeating the text.
- [ ] Maintainers have approved the spec and its status is Accepted before merge.
