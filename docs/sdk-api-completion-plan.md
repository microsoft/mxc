# SDK API completion plan

Status: working draft for review. Baseline: `origin/main` at `2aa6dece4`
(October 5, 2026). The initial SDK source audit was at `416a2725f`;
the baseline was refreshed for the merged Unix PTY support in #1384.
Node's Promise-based typed V1 update in #1398 is open, not part of this
baseline. Recheck both before implementation begins.

This document reconciles the accepted target in
[`ffi-json-ingress-plan.md`](ffi-json-ingress-plan.md), especially sections 3,
7, and 8, with the SDK APIs now on main. The older
[`version-aware-stack-plan.md`](version-aware-stack-plan.md) remains historical
where the JSON-only ingress plan supersedes it. Neither of those plan
documents is on main at the baseline commit. Main's `docs/reference/*/v1/`
describes the APIs actually exposed there; where it differs from the accepted
plan, this document calls out a decision rather than assuming either
description has silently replaced the other.

## 1. Current state

| Area | On main | Still needed against the accepted plan |
| --- | --- | --- |
| Contract targeting | All three typed V1 APIs own the published exact `1.0.0` target. `schemas/schema-version.json` has `sdkMajorTargets["1"] = "1.0.0"` while `1.1.0-alpha` remains development. | Keep the target tied to the latest *published stable* contract in the SDK major; do not retarget V1 merely because development opens. |
| Ingress and ownership | Namespace, exact-JSON FFI, Node/.NET mapper, private-binding cleanup, and Rust SDK authoring-type work from #1355 and #1349-#1353 have merged. Rust typed calls use a direct engine adapter; Node and .NET typed calls emit exact JSON before FFI. Shared `tests/policy/sdk-v1/` fixtures exist. | Maintain mapper/typed-equivalence coverage as the contract evolves. Do not confuse internal JSON/FFI entry points with public raw SDK APIs. |
| Typed execution | Each SDK exposes the six *operation categories*: one-shot and existing-container capture, pipe-backed spawn, and PTY-backed spawn. Typed provision/start/stop/deprovision and lifecycle validation also exist. One-shot PTY supports IsolationSession, Bubblewrap, LXC, and Seatbelt direct execution; existing-container PTY supports IsolationSession. | Prove each advertised mode on each supporting backend and refuse unsupported modes explicitly. Do not equate support for selecting a backend with support for every I/O mode. |
| Raw execution and lifecycle | Native JSON entry points and internal adapters exist, but none of the SDKs exposes the planned complete public six-operation raw family or public raw lifecycle phases. Rust's `mxc_sdk::__ffi` is explicitly internal; Node's package root exports no raw API. | Add the agreed public, caller-authored exact-JSON execution and lifecycle APIs under V1.Dev, reusing the existing FFI for Node/.NET and the in-process exact-JSON path for Rust. |
| Experimental high-level API | Node and .NET have no separate V1 experimental authoring surface. Raw native access to development contracts is not a public raw SDK API. | Implement the separately planned Node `/v1/experimental` and .NET `V1.Experimental` surfaces after their public contract is settled; they are not prerequisites for raw development access. |
| Results, handles, and async | Public typed APIs use `ExecutionResult`, `ExecutionRequest`, and `MxcPtyProcess`, rather than the plan's `Output`, `ExecRequest`, and `MxcPty`. Node has synchronous `run`/`spawn` plus `runAsync`/`spawnAsync`; .NET has synchronous PTY entry points. Rust captured output is bytes; Node and .NET captured results expose strings. | Decide which naming, placement, async, and byte-output contract to freeze, then align the SDKs and documentation without disguising behavioral changes as renames. |

This is an **API/source inventory**, not a claim that all modes have passed
host-dependent runtime or packaged-consumer verification. The merged API
references explicitly state that .NET and Node have no public raw-JSON launch
API (`docs/reference/dotnet/v1/api.md` and
`docs/reference/node/v1/api.md` on main). The source boundaries include
`src/core/mxc-sdk/src/lib.rs` (`v1` versus `__ffi`),
`sdk/node/src/index.ts` and `sdk/node/src/v1/`, and
`sdk/dotnet/Microsoft.Mxc.Sdk/V1/`. The current product/package version is a
separate question from targeting the `1.0.0` configuration contract.

### Typed operation inventory

| Mode | Rust | .NET | Node | Current limitation |
| --- | --- | --- | --- | --- |
| One-shot capture | `v1::run` | `MxcContainer.Run` / `RunAsync` | `run` / `runAsync` | Result and async semantics differ. |
| One-shot pipes | `v1::spawn` | `MxcContainer.Spawn` / `SpawnAsync` | `spawn` / `spawnAsync` | Confirm stream and cancellation contracts. |
| One-shot PTY | `v1::spawn_with_pty` | `MxcContainer.SpawnWithPty` | `spawnWithPty` | IsolationSession, Bubblewrap, LXC, and Seatbelt direct execution; .NET has no PTY `Async` variant in the current reference. |
| Existing-container capture | `v1::container::run_in_container` | `MxcLifecycle.RunInContainer` / `RunInContainerAsync` | `runInContainer` / `runInContainerAsync` | Preserve caller ownership of the container. |
| Existing-container pipes | `v1::container::spawn_in_container` | `MxcLifecycle.SpawnInContainer` / `SpawnInContainerAsync` | `spawnInContainer` / `spawnInContainerAsync` | Reject unsupported backend modes explicitly. |
| Existing-container PTY | `v1::container::spawn_in_container_with_pty` | `MxcLifecycle.SpawnInContainerWithPty` | `spawnInContainerWithPty` | Documented IsolationSession-only; terminal ownership needs end-to-end verification. |

The six rows count modes, not duplicate synchronous/async declarations. The
planned matching *public* raw methods are `run_json`, `spawn_json`,
`spawn_with_pty_json`, `run_in_container_json`, `spawn_in_container_json`,
and `spawn_in_container_with_pty_json`, with idiomatic C#/TypeScript casing.
Internal Rust `__ffi` helpers implement some corresponding paths under
different names, but do not satisfy these public SDK requirements.

### Agreed raw API scope (October 5, 2026)

- Expose all six raw execution operations **and** raw lifecycle operations,
  including provision, start, stop, and deprovision; include applicable
  validation/dry-run routes. The namespace is `mxc_sdk::v1::dev` in Rust,
  `Microsoft.Mxc.Sdk.V1.Dev` in .NET, and
  `@microsoft/mxc-sdk/v1/dev` in Node. This supersedes the earlier plan's
  package-root placement. `v1` names the SDK API shape, **not** a restriction
  on caller-authored exact contract versions.
- Each raw call accepts a complete caller-authored JSON **string**, including
  its exact version and, for existing-container exec, the phase and
  `sandboxId`. Do not accept an object and reserialize it, stamp an SDK
  version, or take a duplicate identity argument. Pass the document unchanged
  to native exact parsing.
- Experimental-backend authorization, cancellation, dry-run, and PTY
  invocation controls remain outside JSON. Entering the dev namespace does
  not implicitly authorize a backend. The raw APIs accept any backend in
  the registered exact contracts, including experimental ones; avoid a
  stable-V1 SDK backend whitelist. An experimental backend still needs
  explicit authorization. Native backend validation remains authoritative;
  reject unsupported requested modes or policy before launch rather than
  falling back to another mode. Validation returns validation results, not
  success-shaped execution output.
- Use the **existing FFI** for the first public raw API milestone, without
  changing `MxcRunResult` or introducing a new native byte-buffer ABI.
  Node raw APIs return `Promise<T>`, following the plain-verb conventions
  of #1398; a live-handle Promise resolves after startup, not after exit.
  Whether the complete raw surface gates the stable v1 release is still
  open; the commitment here is to implement the API.

### Initial result contract and remaining output work

The first milestone uses the native result and handle families that already
exist: `MxcRunResult` for captured one-shot and existing-container exec,
`MxcSandbox` for pipe/PTY handles, and `MxcStateAwareResult.response_json_utf8`
for non-exec lifecycle and validation. Rust high-level raw entry points
use the equivalent in-process exact-JSON SDK/engine path, not FFI. All
populated FFI results and handles must be released with their matching
destructors, including failures; nonzero workload exit remains a result,
not an API error. The initial limitations are deliberate and documented:

- Rust captured `ExecutionResult` has byte-vector stdout/stderr, but the FFI
  `MxcRunResult` uses NUL-terminated UTF-8 strings. Its `alloc_cstring`
  replaces invalid UTF-8 and embedded NUL bytes with U+FFFD before Node or
  .NET can read them. For the first milestone, Node and .NET captured
  stdout/stderr are **lossy text**, not binary-safe output. Never label
  them byte-preserving or add a result type implying otherwise. Rust still
  returns its existing bytes. See `src/core/mxc-sdk/src/sandbox.rs:234-249`
  and `src/ffi/mxc_ffi/src/lib.rs:249-259,320-329` at the baseline.
- Preserve the warnings and output metadata that the existing FFI exposes.
  A raw mapper must not funnel optional `output_metadata_json_utf8` through
  a stable-V1-only metadata decoder that rejects development fields or drops
  them; keep the available native JSON text accessible. Record any metadata
  that the native runtime itself cannot produce as a separate limitation.
  Decide the final public raw capture type without requiring a new FFI ABI.
- Reuse the existing owned `MxcProcess` and `MxcPtyProcess` handles for raw
  pipe and terminal modes where their contracts suffice; do not create a
  second lifecycle owner. PTY output is combined, not fabricated separate
  stdout/stderr. If a live handle offers only stable-V1-decoded metadata,
  expose the native metadata JSON to dev callers instead of discarding
  development-specific fields.

**Recommended lifecycle response:** return the complete native
`response_json_utf8` envelope as a UTF-8 string (`String` in Rust, `string`
in .NET, `Promise<string>` in Node) for provision, start, stop, deprovision,
and validation. Do not parse and reserialize it through stable V1 lifecycle
metadata; the caller can read the provisioned `sandboxId` from the response.
The FFI already provides the full envelope, while V1 provision parsers
reject unrecognized backend metadata and other V1 lifecycle results retain
only warnings. Surface native failure as an SDK error, not a success-shaped
JSON result. **This response type is a recommendation awaiting agreement,**
not an accepted decision.

A later, separate byte-preserving capture follow-up would require native
pointer-and-length output, `Buffer`/`byte[]` SDK results, explicit text
decoding, and binary/NUL tests. Do not imply that the first milestone has
completed that earlier end-state requirement.

### Node async behavior: baseline and agreed direction

The audited main Node API is **mixed**, not uniformly Promise-based:

| Typed V1 calls | Current behavior |
| --- | --- |
| `run`, `runInContainer` | Synchronous capture; block Node until completion. |
| `spawn`, `spawnInContainer` | Synchronous startup; return a live process. |
| Corresponding `runAsync` / `spawnAsync` calls | Return Promises. |
| `spawnWithPty`, `spawnInContainerWithPty` | Return Promises for ready PTY handles. |
| Provision/start/stop/deprovision and lifecycle validation | Return Promises. |

See `sdk/node/src/v1/container.ts:429-499` and
`sdk/node/src/v1/lifecycle.ts:190-478` at the baseline. #1398 is an open
PR to make typed V1's plain-verb execution methods Promise-returning, remove
the redundant blocking and `*Async` methods, and rename process
`waitAsync()` to `wait()`. The agreed dev API follows the Promise-returning
plain-verb convention; align its handle usage to the final #1398 API when
that PR lands:

```ts
run(request): Promise<ExecutionResult>       // after exit and output drain
spawn(request): Promise<MxcProcess>           // after successful startup
spawnWithPty(request): Promise<MxcPtyProcess> // after terminal startup
```

Apply the same mode-specific behavior to existing-container and all six
raw JSON execution calls; raw lifecycle calls also return Promises. Waiting
on a live handle remains separate from waiting for startup; use the final
process-wait name from #1398 (`wait()` in its current proposal). Node's
`child_process.spawn()` instead returns a handle immediately and reports
startup with events, but that model would require an MXC handle whose streams
and startup error are pending while sandbox provisioning runs. Awaiting a
ready handle is the simpler high-level contract here and avoids blocking the
event loop. Do not recreate synchronous dev operations or `*Async` aliases.
Use the Node binding's asynchronous native-call path for blocking FFI
operations; returning a Promise after a synchronous FFI call would still
block the event loop.
#1398 owns migration of existing typed V1 consumers; do not silently change
its approved PR from this planning branch.

### Raw entry points and native routing

The six public dev execution operations use the plan's existing
`*_json` / `*Json` names, under the chosen namespace. Native names do not
have to match the public SDK spelling:

| Mode | Rust | .NET | Node | Existing native FFI |
| --- | --- | --- | --- | --- |
| One-shot capture | `run_json` | `RunJson` | `runJson` | `mxc_run_json` |
| One-shot pipes | `spawn_json` | `SpawnJson` | `spawnJson` | `mxc_spawn_json` |
| One-shot PTY | `spawn_with_pty_json` | `SpawnWithPtyJson` | `spawnWithPtyJson` | `mxc_spawn_pty_json` |
| Existing-container capture | `run_in_container_json` | `RunInContainerJson` | `runInContainerJson` | `mxc_run_state_aware_exec_json` |
| Existing-container pipes | `spawn_in_container_json` | `SpawnInContainerJson` | `spawnInContainerJson` | `mxc_exec_state_aware_json` |
| Existing-container PTY | `spawn_in_container_with_pty_json` | `SpawnInContainerWithPtyJson` | `spawnInContainerWithPtyJson` | `mxc_state_aware_exec_pty` |

Rust calls its in-process exact-JSON adapters instead of the final column.
Captured calls complete with an outcome and text output on Node/.NET; pipe
and PTY calls return owned live handles after startup. The complete JSON
document includes the existing-container identity; do not also require a
`ContainerId` argument.

For non-exec lifecycle and dry-run, use `mxc_run_state_aware_json` with the
phase authored in the input document. This function **does not execute**
non-dry-run `exec`; the three existing-container rows above do. Proposed
public phase names are `provision_container_json`, `start_container_json`,
`stop_container_json`, and `deprovision_container_json` in Rust, with
PascalCase `...Json` in .NET and camelCase `...Json` in Node. Provide
phase-specific `validate_*_json`/`Validate*Json`/`validate*Json` entry
points using dry-run, including exec validation, and return the recommended
raw response envelope rather than a fake captured execution. The lifecycle
method spellings are proposed for review, not yet accepted.

All registered backends, including experimental ones, can be named in
caller-authored exact JSON without an SDK-side stable backend whitelist.
This is **not** a promise that every backend implements every mode or every
lifecycle phase. Native refuses unsupported modes/policy; for example, at
this baseline one-shot PTY supports IsolationSession, Bubblewrap, LXC, and
Seatbelt direct execution, while existing-container PTY is
IsolationSession-only. Experimental backends require an explicit
authorization option even when using a development contract. Do not fall
back from PTY to pipes or from pipes to capture.

## 2. Decisions to settle before freezing the public API

1. **Contract of record.** The raw API requirement and V1.Dev placement are
   accepted; both differ from main's "no public raw-JSON launch API" reference
   and the older plan's package-root placement. Resolve whether #1385
   replaces any *other* planned vocabulary or placement, then update the
   public references when the new APIs land.
2. **Names and placements.** Decide `ExecRequest` versus `ExecutionRequest`,
   `Output` versus `ExecutionResult`, `MxcPty` versus `MxcPtyProcess`, and
   where version-independent handles, errors, discovery, telemetry, and
   output belong; raw functions belong under V1.Dev. Keep distinct `ContainerId`,
   optional one-shot container name, and OS process ID concepts. Do not
   rename published wire fields such as `sandboxId` or backend product names.
3. **Invocation and asynchrony.** Node dev operations return Promises; #1398
   owns the corresponding typed V1 migration. Decide which .NET PTY `Async`
   methods are required. `run` means capture and wait, `spawn` returns a live
   process after startup, and PTY spawn returns an owned terminal, regardless
   of sync/async convention.
4. **Output and ownership.** Settle the recommended raw lifecycle response
   string and proposed phase method names. Reuse the current text-output FFI
   in the first milestone; define a separate byte-preserving capture follow-up
   with opt-in text decoding. Specify capture limits, partial output, timeout,
   cancellation after startup, wait/disposal, and failure cleanup.
   Do not make cancellation of an await silently leave an owned workload
   running. The blocking `mxc_run_json` capture entry point has no cancellation
   parameter; do not promise post-start termination without a supported
   handle-based path. Verify the PTY combined-output, resize, input, and
   termination contract against each supporting backend. An existing-container
   exec must never implicitly deprovision its caller-owned container.
5. **Experimental boundary.** Raw APIs accept registered backend selections
   including experimental ones, with explicit independent authorization.
   Separately settle how legacy `experimental` options on *stable typed*
   entry points behave. The stable mapper cannot admit development-only
   request shapes or identities such as `wsb:`; do not route the raw APIs
   through it or equate experimental authorization with a version selector.
6. **Release scope.** Confirm whether the plan's complete raw family is a
   stable v1 release gate and whether E/F remain follow-ups. If a requirement
   is deferred, amend the accepted plan and public references rather than
   marking the original exit criteria complete.

## 3. Remaining implementation work

1. **Reconcile the public contract.** Record the remaining response/name
   decisions above, inventory consumer-visible changes from #1385 and the
   final #1398, and add the V1.Dev signatures in Rust, .NET, and Node.
   Export Node's `./v1/dev` subpath and its supported type-resolution mapping;
   do not add a package-root raw alias.
   Update `docs/reference/`, SDK READMEs, and `docs/versioning.md` with the
   new dev surface; the latter still describes some pre-#1385 names and
   placements. Preserve each operation's capture/pipe/PTY behavior.
2. **Complete public raw exact-JSON execution and lifecycle.** Expose all six
   execution methods per SDK plus provision, start, stop, deprovision, and
   applicable validation/dry-run routes. Accept a complete caller-authored
   exact document unchanged, including its `version`, phase, and identity.
   Check operation/root/phase compatibility before allocation; pass backend
   authorization and terminal invocation controls separately. Use the
   existing FFI JSON exports and keep development-specific response metadata
   accessible rather than narrowing it to stable V1 types. Rust must expose
   a supported exact-JSON API rather than asking consumers to import `__ffi`;
   .NET and Node need public facades as well as native exports. Ensure the
   Node facade is non-blocking and Promise-returning.
3. **Close functional and semantic gaps.** Verify owned process/PTY handles,
   pipe closure, stream pressure, descendant-held endpoints, failed startup,
   repeated wait/disposal, backend-specific termination scope, and current
   capture/timeout behavior. Specify unavailable streams and fail unsupported
   requested modes without downgrading. Preserve FFI cleanup and panic
   containment. Separately scope byte-preserving native capture and any
   post-start cancellation guarantee the current blocking capture ABI cannot
   provide; neither is a claim of the first milestone.
4. **Add experimental convenience APIs independently.** Implement Node
   `@microsoft/mxc-sdk/v1/experimental` and .NET
   `Microsoft.Mxc.Sdk.V1.Experimental` against the co-shipped development
   contract, with explicit backend authorization and appropriate
   development-only lifecycle identities. Do not route those requests through
   the stable V1 mapper; document their absence of a compatibility promise.
   This work need not block the agreed public raw access.
5. **Close compatibility and release evidence.** Establish v1.0 external
   consumer/API baselines for Rust, .NET, and Node; include Rust constructors,
   .NET async signatures, Node import/require and supported module-resolution
   consumers. Compare compatible published minor contracts and normalized
   intent as the v1 line advances. Test the actual packaged SDK with matching
   native libraries, bindings, sidecars, and registered targets. Document
   unverified host combinations rather than counting skips as support.

## 4. Completion criteria

- The V1.Dev exports and documented result/ownership contracts agree in all
  three languages. Node dev operations return Promises, without duplicate
  blocking or `*Async` aliases. Every registered backend, including
  experimental ones, can reach native policy and capability validation
  through raw exact JSON, with authorization explicitly supplied. Each raw
  execution mode is exercised on its declared supporting backends; an
  unsupported mode rejects before launching, not by falling back.
- Raw tests cover every **currently registered** applicable exact contract,
  development fields, unsupported versions and request roots, unknown fields,
  lifecycle phase mismatches, and backend authorization independent of
  version. The baseline registry no longer includes pre-v0.9 contracts; do
  not claim those retired versions are supported.
- Mapping goldens and negative cases verify stable typed requests across
  Rust, .NET, and Node. Equivalent typed and exact-JSON requests normalize to
  equivalent enforcement intent, without implementing the Rust typed path
  through JSON.
- First-milestone output/ownership tests cover empty text output, pressure,
  timeout, terminal resize/input, failed-startup cleanup, repeated
  wait/disposal, and preservation of caller-owned containers. Test Node
  event-loop responsiveness and capture its actual lossiness for invalid
  UTF-8 and embedded NUL bytes; do not describe this as binary-output
  support. Byte-preserving capture and any additional cancellation/partial
  output guarantee need their own follow-up and tests before those claims
  can be made.
- Package/consumer and API-compatibility gates pass against the version
  intended for release; SDK and backend documentation states supported
  modes and host-dependent limitations precisely. Do not claim the stable
  v1 exit criteria have passed solely because the earlier ingress stack and
  six typed API categories have landed.
