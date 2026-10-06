# SDK API completion plan

Status: working draft for post-v1-publication work. Baseline: `origin/main`
at `a846837d8` (October 6, 2026). Since the previous `2aa6dece4` baseline,
#1398 (Promise-based Node V1 APIs), #1390 (consolidated Rust SDK), #1402 (no
experimental option on typed V1), #1400 (Node ProcessContainer PTY), #1403
(1.0.0 package versions), and #1399 (scenario-based samples) have landed.
Recheck the baseline before implementation begins.

The merged APIs and `docs/reference/*/v1/` on `origin/main` are the source
of truth for public names, types, and placement after #1385 and #1398. The
earlier [`ffi-json-ingress-plan.md`](ffi-json-ingress-plan.md) supplies the
exact-JSON ingress rationale and raw-mode requirements, but its superseded
API/type vocabulary, raw package-root placement, and pre-publication release
gate do not override main or the V1.Dev decisions below. The older
[`version-aware-stack-plan.md`](version-aware-stack-plan.md) is historical
where the ingress plan supersedes it. Neither older plan is on main at the
baseline commit.

## 1. Current state

| Area | On main | Still needed against the accepted plan |
| --- | --- | --- |
| Contract targeting | All three typed V1 APIs own the published exact `1.0.0` target. `schemas/schema-version.json` has `sdkMajorTargets["1"] = "1.0.0"` while `1.1.0-alpha` remains development. | Keep the target tied to the latest *published stable* contract in the SDK major; do not retarget V1 merely because development opens. |
| Ingress and ownership | Namespace, exact-JSON FFI, Node/.NET mapper, and private-binding cleanup have merged. #1390 moved the Rust SDK and its internal engine, contract, common, and backend modules into `src/mxc-sdk/`; Rust typed calls still adapt directly, while Node and .NET emit exact JSON before FFI. Shared `tests/policy/sdk-v1/` fixtures exist. | Maintain mapper/typed-equivalence coverage as the contract evolves. Do not confuse internal JSON/FFI entry points with public raw SDK APIs. |
| Typed execution | All three SDKs expose the six *operation categories*, plus typed lifecycle and validation. One-shot native PTY supports IsolationSession, Bubblewrap, LXC, and Seatbelt direct execution; existing-container PTY supports IsolationSession. Node additionally routes typed ProcessContainer PTY through `wxc-exec` and `node-pty` because its in-process PTY binding does not support that backend. | Prove each advertised mode on each supporting backend and refuse unsupported modes explicitly. Resolve whether raw ProcessContainer PTY can preserve the exact JSON string through an executor path or needs native support. |
| Raw execution and lifecycle | Native JSON entry points and internal adapters exist, but none of the SDKs exposes the planned complete public six-operation raw family or public raw lifecycle phases. Rust's `mxc_sdk::__ffi` is explicitly internal; Node's package root exports no raw API. | Add the agreed public, caller-authored exact-JSON execution and lifecycle APIs under V1.Dev, reusing the existing FFI for Node/.NET and the in-process exact-JSON path for Rust. |
| Experimental access | #1402 removed `experimental` from typed V1 options in all three SDKs. The current registered development contract is exactly `1.1.0-alpha`; its request types include experimental backends. There is no public raw SDK access to that contract. | Add V1.Dev calls that accept caller-authored `1.1.0-alpha` JSON for experimental features plus an explicit experimental-backend authorization option. Do not route such calls through typed V1. |
| Results, handles, and async | Public typed APIs use `ExecutionResult`, `ExecutionRequest`, and `MxcPtyProcess`, which are the naming baseline. #1398 made Node plain-verb execution and process waiting Promise-based and removed the redundant blocking/`*Async` execution calls. .NET has synchronous PTY entry points. Rust captured output is bytes; Node and .NET captured results expose strings. | Add Promise-based Node dev operations without restoring blocking aliases; make potentially lengthy .NET dev operations return `Task<T>`; settle captured-result/metadata handling and byte-output follow-up separately. |

This is an **API/source inventory**, not a claim that all modes have passed
host-dependent runtime or packaged-consumer verification. The merged API
references explicitly state that .NET and Node have no public raw-JSON launch
API (`docs/reference/dotnet/v1/api.md` and
`docs/reference/node/v1/api.md` on main). The source boundaries include
`src/mxc-sdk/src/lib.rs` (`v1` versus `__ffi`),
`sdk/node/src/index.ts` and `sdk/node/src/v1/`, and
`sdk/dotnet/Microsoft.Mxc.Sdk/V1/`. Rust, Node, and .NET package manifests
now say `1.0.0`; a manifest version does not by itself establish external
publication or consumer validation. This V1.Dev work will merge **after**
v1 is published, not gate that publication. Scenario-based samples have
also landed under `samples/`; add dev API examples when the surface exists.

### Typed operation inventory

| Mode | Rust | .NET | Node | Current limitation |
| --- | --- | --- | --- | --- |
| One-shot capture | `v1::run` | `MxcContainer.Run` / `RunAsync` | `run` | Result and cancellation semantics differ. |
| One-shot pipes | `v1::spawn` | `MxcContainer.Spawn` / `SpawnAsync` | `spawn` | Confirm stream and cancellation contracts. |
| One-shot PTY | `v1::spawn_with_pty` | `MxcContainer.SpawnWithPty` | `spawnWithPty` | Native: IsolationSession, Bubblewrap, LXC, Seatbelt direct execution. Node also supports ProcessContainer through an executor-backed path; the V1.Dev .NET operation will be asynchronous. |
| Existing-container capture | `v1::container::run_in_container` | `MxcLifecycle.RunInContainer` / `RunInContainerAsync` | `runInContainer` | Preserve caller ownership of the container. |
| Existing-container pipes | `v1::container::spawn_in_container` | `MxcLifecycle.SpawnInContainer` / `SpawnInContainerAsync` | `spawnInContainer` | Reject unsupported backend modes explicitly. |
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
- Experimental requests use the caller-authored **1.1.0 development
  contract**. On this baseline its exact registered `version` spelling is
  `1.1.0-alpha`, not `1.1.0`; the latter must be rejected until a stable
  `1.1.0` contract is actually registered. Production requests can use any
  other applicable registered exact contract. Typed V1 always uses its SDK
  target (`1.0.0` on this baseline) and cannot select experimental backends.
- Experimental-backend authorization, cancellation, dry-run, and PTY
  invocation controls remain outside JSON. Entering the dev namespace does
  not implicitly authorize a backend. For an experimental backend, **both**
  a caller-authored development-contract request and explicit authorization
  are required: the exact version selects the available JSON shape, while
  the separate option permits experimental backend selection. Neither alone
  grants the other. Avoid a stable-V1 SDK backend whitelist. Native backend
  validation remains authoritative; reject unsupported requested modes or
  policy before launch rather than falling back to another mode. Validation
  returns validation results, not success-shaped execution output.
- Use the **existing FFI** for the first public raw API milestone, without
  changing `MxcRunResult` or introducing a new native byte-buffer ABI.
  Node raw APIs return `Promise<T>`, following the plain-verb conventions
  of #1398; a live-handle Promise resolves after startup, not after exit.
  Potentially lengthy .NET dev calls return `Task<T>`, including both PTY
  spawns and lifecycle operations. This work merges after v1 publication;
  the raw family is **not** a prerequisite for the initial v1 release.

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
  returns its existing bytes. See `src/mxc-sdk/src/sandbox.rs:238-249`
  and `src/ffi/mxc_ffi/src/lib.rs:253-263,324-333` at the baseline.
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

**Agreed lifecycle response:** return the complete native
`response_json_utf8` envelope as a UTF-8 string (`String` in Rust, `string`
inside `Task<string>` in .NET, `Promise<string>` in Node) for provision,
start, stop, deprovision, and validation. Do not parse and reserialize it
through stable V1 lifecycle metadata; the caller can read the provisioned
`sandboxId` from the response. The FFI already provides the full envelope,
while V1 provision parsers reject unrecognized backend metadata and other
V1 lifecycle results retain only warnings. Surface native failure as an SDK
error, not a success-shaped JSON result.

A later, separate byte-preserving capture follow-up would require native
pointer-and-length output, `Buffer`/`byte[]` SDK results, explicit text
decoding, and binary/NUL tests. Do not imply that the first milestone has
completed that earlier end-state requirement.

### Node async behavior: merged V1 convention

#1398 has landed: typed V1 `run`, `spawn`, `runInContainer`,
`spawnInContainer`, and both PTY spawns return Promises. The blocking and
`*Async` execution duplicates are gone; `MxcProcess.wait()` returns a
Promise for exit. Provision/start/stop/deprovision and lifecycle validation
were already asynchronous. See `sdk/node/src/v1/container.ts:428-481`,
`sdk/node/src/v1/lifecycle.ts:187-319`, and
`sdk/node/src/v1/container-process.ts:200` at the baseline. The agreed dev
API uses the same plain-verb convention:

```ts
run(request): Promise<ExecutionResult>       // after exit and output drain
spawn(request): Promise<MxcProcess>           // after successful startup
spawnWithPty(request): Promise<MxcPtyProcess> // after terminal startup
```

Apply the same behavior to existing-container and all six raw JSON execution
calls; raw lifecycle calls also return Promises. Waiting on a live handle
with `wait()` remains separate from waiting for startup. Do not recreate
synchronous dev operations or `*Async` aliases.
Use the Node binding's asynchronous native-call path for blocking FFI
operations; returning a Promise after a synchronous FFI call would still
block the event loop. #1398 already owns migration of typed V1 consumers;
the dev implementation must use its merged API rather than obsolete names.

### Raw entry points and native routing

The six public dev execution operations use the merged V1 operation names
with a JSON suffix, under the chosen namespace. Rust follows snake_case,
.NET appends `JsonAsync` for potentially lengthy operations, and Node
appends `Json` to the Promise-returning plain verb. Native names do not
have to match the public SDK spelling:

| Mode | Rust | .NET | Node | Existing native FFI |
| --- | --- | --- | --- | --- |
| One-shot capture | `run_json` | `RunJsonAsync` | `runJson` | `mxc_run_json` |
| One-shot pipes | `spawn_json` | `SpawnJsonAsync` | `spawnJson` | `mxc_spawn_json` |
| One-shot PTY | `spawn_with_pty_json` | `SpawnWithPtyJsonAsync` | `spawnWithPtyJson` | `mxc_spawn_pty_json` |
| Existing-container capture | `run_in_container_json` | `RunInContainerJsonAsync` | `runInContainerJson` | `mxc_run_state_aware_exec_json` |
| Existing-container pipes | `spawn_in_container_json` | `SpawnInContainerJsonAsync` | `spawnInContainerJson` | `mxc_exec_state_aware_json` |
| Existing-container PTY | `spawn_in_container_with_pty_json` | `SpawnInContainerWithPtyJsonAsync` | `spawnInContainerWithPtyJson` | `mxc_state_aware_exec_pty` |

Rust calls its in-process exact-JSON adapters instead of the final column.
Captured calls return the existing `ExecutionResult` shape (`Task<ExecutionResult>`
in .NET, `Promise<ExecutionResult>` in Node), with lossy text on Node/.NET;
pipe and PTY calls return the existing `MxcProcess` and `MxcPtyProcess`
handles (`Task<T>` in .NET, `Promise<T>` in Node) after startup. The complete
JSON document includes the existing-container identity; do not also require
a `ContainerId` argument.

For non-exec lifecycle and dry-run, use `mxc_run_state_aware_json` with the
phase authored in the input document. This function **does not execute**
non-dry-run `exec`; the three existing-container rows above do. Proposed
Public phase names follow the existing V1 `provisionContainer`, `startContainer`,
`stopContainer`, and `deprovisionContainer` families with a JSON suffix:
`provision_container_json` (and corresponding phases) in Rust,
`ProvisionContainerJsonAsync` in .NET, and `provisionContainerJson` in Node.
Provide phase-specific `validate_*_json`/`Validate*JsonAsync`/
`validate*Json` calls using dry-run, including exec validation. These
return the agreed complete native response JSON string, never a fake
captured execution result. .NET returns `Task<string>` and Node returns
`Promise<string>` for the lifecycle and validation families.

All registered backends, including experimental ones, can be named in
caller-authored exact JSON without an SDK-side stable backend whitelist.
This is **not** a promise that every backend implements every mode or every
lifecycle phase. Native refuses unsupported modes/policy; for example, at
this baseline one-shot PTY supports IsolationSession, Bubblewrap, LXC, and
Seatbelt direct execution, while existing-container PTY is
IsolationSession-only. Experimental backends require a caller-authored
`1.1.0-alpha` document and explicit authorization. Do not fall back from
PTY to pipes or from pipes to capture.

**Node ProcessContainer PTY routing gap:** #1400 added typed one-shot
ProcessContainer PTY via `wxc-exec` and `node-pty` because
`mxc_spawn_pty_json` does not support that backend. Its current helper accepts
a generated stable `OneShotRequest`, runs `JSON.stringify`, and sends base64
to the executor (`sdk/node/src/bindings/process-container-pty.ts`). Raw dev
calls must not route through that stable type or reserialize caller JSON.
Choose and verify an exact-string-preserving executor route, add native PTY
support, or explicitly document that this mode remains unsupported by raw
dev calls despite typed Node support. Do not claim both "existing FFI only"
and raw PTY parity for ProcessContainer without resolving this gap.

## 2. Settled API contract and implementation questions

- **Source of truth and names:** Follow the merged `origin/main` V1 APIs after
  #1385 and #1398: `ExecutionRequest`, `ExecutionResult`, `MxcProcess`, and
  `MxcPtyProcess`, with language-idiomatic spelling. Do not reopen the older
  `ExecRequest`/`Output`/`MxcPty` naming proposal or move existing V1 types
  as part of the raw API. Dev operations live under V1.Dev; avoid redundant
  aliases and ambiguous .NET facade imports. Keep distinct `ContainerId`,
  optional one-shot container name, and OS process ID concepts. Do not
  rename published wire fields such as `sandboxId` or backend product names.
- **Asynchrony:** Node dev calls return Promises, matching merged V1.
  Potentially lengthy .NET dev operations return `Task<T>`, including PTY
  spawns, capture, provision, start, stop, deprovision, and validation.
  A `run` resolves after capture and completion; a `spawn` resolves with an
  owned live handle after startup, not after process exit. Rust stays
  synchronous like the merged V1 API.
- **Lifecycle responses:** Non-exec lifecycle and validation calls return
  the complete native response JSON string, not stable typed lifecycle
  metadata. This is an agreed response contract, not a pending choice.
- **Experimental and release boundary:** Experimental backend requests use
  caller-authored development JSON (`1.1.0-alpha` at this baseline), plus
  explicit authorization outside JSON; typed V1 calls stay stable and do
  not take that option. The V1.Dev work merges **after v1 publication**;
  the raw API family does not gate the initial v1 release. Separate typed
  experimental convenience APIs, if pursued later, are not part of this
  work.

The implementation must still resolve the following:

1. **Capture metadata and ownership.** Use the existing text-output FFI in
   the first milestone, while preserving warnings and development-specific
   metadata rather than narrowing through stable V1 decoders. Decide how
   to expose raw capture metadata without changing the chosen public V1
   result names. Define a separate byte-preserving capture follow-up with
   explicit text decoding. Specify capture limits, partial output, timeout,
   cancellation after startup, wait/disposal, and failed-startup cleanup.
   `mxc_run_json` has no cancellation parameter; do not promise post-start
   termination without a supported handle-based path. An existing-container
   exec must never implicitly deprovision its caller-owned container.
2. **Raw ProcessContainer PTY.** Resolve the Node executor-backed exception
   above before claiming raw parity with merged typed V1. An exact-string-
   preserving route must not widen backend policy or silently discard
   warnings or output metadata. Verify the PTY input, resize, combined-output,
   and termination contract against each supporting backend.
3. **.NET dev facade layout.** Follow V1 operation and type names, while
   arranging `Microsoft.Mxc.Sdk.V1.Dev` entry points so using typed and raw
   facades together does not create ambiguous class imports. Do not add
   redundant root-level raw aliases.

## 3. Remaining implementation work

1. **Add the dev public contract.** Follow `origin/main` names and types,
   add the V1.Dev signatures in Rust, .NET, and Node, and return complete
   native response JSON for lifecycle and validation calls.
   Export Node's `./v1/dev` subpath and its supported type-resolution mapping;
   do not add a package-root raw alias.
   Update `docs/reference/`, SDK READMEs, `docs/versioning.md`, and
   `samples/` with the new dev surface; preserve each operation's
   capture/pipe/PTY behavior.
2. **Complete public raw exact-JSON execution and lifecycle.** Expose all six
   execution methods per SDK plus provision, start, stop, deprovision, and
   applicable validation/dry-run routes. Accept a complete caller-authored
   exact document unchanged, including its `version`, phase, and identity.
   Check operation/root/phase compatibility before allocation; pass backend
   authorization and terminal invocation controls separately. Use the
   existing FFI JSON exports where they support the requested mode, and
   resolve the Node ProcessContainer PTY exception above. Keep
   development-specific response metadata accessible rather than narrowing
   it to stable V1 types. Rust must expose
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
4. **Verify experimental raw access.** Test caller-authored exact
   `1.1.0-alpha` documents against experimental backends and the separate
   authorization option. Verify that `1.0.0` cannot express their development
   request roots and that an unregistered literal `1.1.0` is rejected.
   Production backends remain usable through their registered exact
   contracts without experimental authorization. Keep typed V1 outside this
   route; do not introduce a separate experimental typed API in this work.
5. **Close post-v1 package and consumer evidence.** Compile external V1.Dev
   consumers for Rust, .NET `Task<T>` signatures, Node import/require and
   supported module-resolution modes. Test actual packaged SDKs with their
   matching native libraries, bindings, sidecars, and registered targets.
   Document unverified host combinations rather than counting skips as
   support. Do not make this a retroactive gate for v1 publication.

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
  and lifecycle phase mismatches. For experimental requests, verify both the
  exact `1.1.0-alpha` development version and separate explicit backend
  authorization; neither the unregistered `1.1.0` spelling nor the stable
  typed V1 mapper is an alternate path. The baseline registry no longer
  includes pre-v0.9 contracts; do not claim those retired versions work.
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
  modes and host-dependent limitations precisely. This post-publication
  dev API rollout does not block or retroactively define the initial v1
  publication criteria.
