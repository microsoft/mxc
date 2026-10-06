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
| Typed execution | All three SDKs expose the six *operation categories*, plus typed lifecycle and validation. One-shot native PTY supports IsolationSession, Bubblewrap, LXC, and Seatbelt direct execution; existing-container PTY supports IsolationSession. Node additionally routes typed ProcessContainer PTY through `wxc-exec` and `node-pty` because its in-process PTY binding does not support that backend. | Prove each advertised mode on each supporting backend and refuse unsupported modes explicitly. Forward raw ProcessContainer PTY JSON unchanged through the executor. |
| Raw execution and lifecycle | Native JSON entry points and internal adapters exist, but none of the SDKs exposes the planned complete public six-operation raw family or public raw lifecycle phases. Rust's `mxc_sdk::__ffi` is explicitly internal; Node's package root exports no raw API. | Add the agreed public, caller-authored exact-JSON execution and lifecycle APIs under V1.Dev. Rust uses in-process exact-JSON routing; Node/.NET use the existing FFI except Node ProcessContainer PTY, which launches `wxc-exec`. |
| Experimental access | #1402 removed `experimental` from typed V1 options in all three SDKs. The current registered development contract is exactly `1.1.0-alpha`; its request types include experimental backends. There is no public raw SDK access to that contract. | Add V1.Dev calls that accept caller-authored `1.1.0-alpha` JSON for experimental features plus an explicit experimental-backend authorization option. Do not route such calls through typed V1. |
| Results, handles, and async | Public typed APIs use `ExecutionResult`, `ExecutionRequest`, and `MxcPtyProcess`, which are the naming baseline. #1398 made Node plain-verb execution and process waiting Promise-based and removed the redundant blocking/`*Async` execution calls. .NET has synchronous PTY entry points. Rust captured output is bytes; Node and .NET captured results expose strings. | Reuse public V1 result/handle types and per-operation ownership and cancellation behavior; make Node dev calls Promise-based and .NET dev capture, pipe-backed spawn, and lifecycle calls return `Task<T>`. Keep .NET dev PTY spawns synchronous. Byte-preserving capture remains a separate follow-up. |

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
| One-shot PTY | `v1::spawn_with_pty` | `MxcContainer.SpawnWithPty` | `spawnWithPty` | Native: IsolationSession, Bubblewrap, LXC, Seatbelt direct execution. Node also supports ProcessContainer through an executor-backed path; V1.Dev .NET PTY stays synchronous. |
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
- Use the **existing FFI** for the first public raw API milestone, except
  Node ProcessContainer PTY, which launches `wxc-exec` with the original
  JSON as described below. Do not change `MxcRunResult` or introduce a new
  native byte-buffer ABI.
  Node raw APIs return `Promise<T>`, following the plain-verb conventions
  of #1398; a live-handle Promise resolves after startup, not after exit.
  Potentially lengthy .NET dev capture, pipe-backed spawn, and lifecycle
  calls return `Task<T>`. The two .NET dev PTY spawns remain synchronous,
  matching typed V1; do not add `*WithPtyJsonAsync` variants for now. This
  work merges after v1 publication; the raw family is **not** a prerequisite
  for the initial v1 release.

### Initial result contract and remaining output work

The first milestone uses the native result and handle families that already
exist: FFI `MxcRunResult` for one-shot capture, FFI `MxcSandbox` handles for
pipe/PTY and Node/.NET SDK in-container capture, and FFI
`MxcStateAwareResult.response_json_utf8` for non-exec lifecycle and
validation. Rust SDK raw entry points use the in-process exact-JSON
SDK/engine path, not FFI. All populated FFI results and handles must be
released with their matching destructors, including failures; nonzero
workload exit remains a result, not an API error. The initial limitations
are deliberate and documented:

- Rust captured `ExecutionResult` has byte-vector stdout/stderr, but the FFI
  `MxcRunResult` uses NUL-terminated UTF-8 strings. Its `alloc_cstring`
  replaces invalid UTF-8 and embedded NUL bytes with U+FFFD before Node or
  .NET can read them. For the first milestone, Node and .NET captured
  stdout/stderr are **lossy text**, not binary-safe output. Never label
  them byte-preserving or add a result type implying otherwise. Rust still
  returns its existing bytes. See `src/mxc-sdk/src/sandbox.rs:238-249`
  and `src/ffi/mxc_ffi/src/lib.rs:253-263,324-333` at the baseline.
- Return the existing public V1 `ExecutionResult` for captured dev execution
  and reuse the existing owned `MxcProcess` and `MxcPtyProcess` handles for
  pipe and terminal modes. Preserve warnings and the metadata MXC actually
  produces today (`captureDenials` and `captureDenialsError`) using the same
  public V1 `ExecutionMetadata` shape. This first milestone does **not**
  promise opaque access to future development-only execution metadata; if
  the native output model gains new fields, update the public SDKs before
  exposing them rather than silently dropping them. Raw non-exec lifecycle
  responses remain complete JSON, as agreed below. Do not create a second
  process owner. PTY output is combined, not fabricated separate stdout/stderr.

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
.NET appends `JsonAsync` to capture and pipe-backed operations but keeps the
two PTY spawns synchronous as `*WithPtyJson`, and Node appends `Json` to the
Promise-returning plain verb. Native names do not have to match the public
SDK spelling:

| Mode | Rust | .NET | Node | Existing native FFI |
| --- | --- | --- | --- | --- |
| One-shot capture | `run_json` | `RunJsonAsync` | `runJson` | `mxc_run_json` |
| One-shot pipes | `spawn_json` | `SpawnJsonAsync` | `spawnJson` | `mxc_spawn_json` |
| One-shot PTY | `spawn_with_pty_json` | `SpawnWithPtyJson` | `spawnWithPtyJson` | `mxc_spawn_pty_json`, except Node ProcessContainer uses `wxc-exec` |
| Existing-container capture | `run_in_container_json` | `RunInContainerJsonAsync` | `runInContainerJson` | `mxc_exec_state_aware_json` (Node/.NET SDKs spawn, drain, wait, dispose) |
| Existing-container pipes | `spawn_in_container_json` | `SpawnInContainerJsonAsync` | `spawnInContainerJson` | `mxc_exec_state_aware_json` |
| Existing-container PTY | `spawn_in_container_with_pty_json` | `SpawnInContainerWithPtyJson` | `spawnInContainerWithPtyJson` | `mxc_state_aware_exec_pty` |

The Rust SDK calls its in-process exact-JSON adapters instead of the FFI
exports in the final column. Captured calls return the existing
`ExecutionResult` shape (`Task<ExecutionResult>` in .NET,
`Promise<ExecutionResult>` in Node), with lossy text on Node/.NET;
pipe and PTY calls return the existing `MxcProcess` and `MxcPtyProcess`
handles after startup: .NET pipe spawns return `Task<MxcProcess>` and PTY
spawns return `MxcPtyProcess` synchronously; Node returns `Promise<T>` for
both. The complete JSON document includes the existing-container identity;
do not also require a `ContainerId` argument. The native FFI also exposes
`mxc_run_state_aware_exec_json`, but the Node/.NET SDK dev in-container
capture calls use the live FFI `mxc_exec_state_aware_json` handle to match
typed V1 stream draining, wait, disposal, and .NET cancellation behavior.

For non-exec lifecycle and dry-run, use `mxc_run_state_aware_json` with the
phase authored in the input document. This function **does not execute**
non-dry-run `exec`; the three existing-container rows above do. Public
phase names follow the existing V1 `provisionContainer`, `startContainer`,
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

**Node ProcessContainer PTY routing:** #1400 added typed one-shot
ProcessContainer PTY via the `wxc-exec` executor and `node-pty` because
the native FFI export `mxc_ffi::mxc_spawn_pty_json` does not support that
backend. For the public Node SDK method
`@microsoft/mxc-sdk/v1/dev::spawnWithPtyJson`, launch `wxc-exec` using
the caller's original JSON
string, UTF-8 encoded and base64-wrapped for its existing `--config-base64`
argument. This transport does not parse, stamp, default, or reserialize the
request; the executor's exact-contract parser remains authoritative. The
current typed helper instead accepts a generated stable `OneShotRequest`
and calls `JSON.stringify` (`sdk/node/src/bindings/process-container-pty.ts`);
do **not** reuse that mapping path for raw input. When the caller explicitly
authorizes experimental backends, pass the executor's `--experimental`
command-line flag; otherwise omit it. Do not infer authorization from the
JSON version or encode it as a JSON field. Keep `node-pty` responsible for
the terminal and live process handle; do not downgrade to ordinary pipes.
Test that numeric tokens, unknown fields, the exact version, and
development-only fields reach the executor unmodified. Preserve any
warnings or metadata the executor exposes;
document backend limitations where that channel does not provide them.

## 2. Settled API contract and implementation questions

- **Source of truth and names:** Follow the merged `origin/main` V1 APIs after
  #1385 and #1398: `ExecutionRequest`, `ExecutionResult`, `MxcProcess`, and
  `MxcPtyProcess`, with language-idiomatic spelling. Do not reopen the older
  `ExecRequest`/`Output`/`MxcPty` naming proposal or move existing V1 types
  as part of the raw API. Dev operations live under V1.Dev; avoid redundant
  package-root aliases. Keep distinct `ContainerId`,
  optional one-shot container name, and OS process ID concepts. Do not
  rename published wire fields such as `sandboxId` or backend product names.
- **Asynchrony:** Node dev calls return Promises, matching merged V1.
  .NET dev capture, pipe-backed spawn, provision, start, stop, deprovision,
  and validation return `Task<T>`. The two .NET dev PTY spawns return live
  `MxcPtyProcess` handles synchronously, matching typed V1; no PTY `Async`
  variants are planned in this milestone.
  Async `run` resolves after capture and completion; async `spawn` resolves
  with an owned live handle after startup, not after process exit. Synchronous
  .NET PTY spawns return the live handle after startup. Rust stays
  synchronous like the merged V1 API.
- **Lifecycle responses:** Non-exec lifecycle and validation calls return
  the complete native response JSON string, not stable typed lifecycle
  metadata. This is an agreed response contract, not a pending choice.
- **Execution results and ownership:** Return the existing V1
  `ExecutionResult`, `MxcProcess`, and `MxcPtyProcess` types, with the known
  execution metadata fields. Match the corresponding typed V1 operation's
  capture, timeout, cancellation, stream, wait, kill, and disposal semantics
  in each language. SDK wrappers free FFI results (including failures);
  callers own returned live handles. In-container exec never owns or
  deprovisions the persistent container.
- **.NET facade placement:** `Microsoft.Mxc.Sdk.V1.Dev` is sufficient to
  distinguish raw from typed SDK APIs. Follow the existing V1 facade names
  (`MxcContainer` for one-shot and `MxcLifecycle` for existing-container
  operations); when an example uses both namespaces, qualify the dev facade,
  for example `using Dev = Microsoft.Mxc.Sdk.V1.Dev;` and
  `Dev.MxcContainer.RunJsonAsync(...)`. Importing both namespaces and using
  an unqualified `MxcContainer` would be ambiguous, but is not an API design
  blocker.
- **Experimental and release boundary:** Experimental backend requests use
  caller-authored development JSON (`1.1.0-alpha` at this baseline), plus
  explicit authorization outside JSON; typed V1 calls stay stable and do
  not take that option. The V1.Dev work merges **after v1 publication**;
  the raw API family does not gate the initial v1 release. Separate typed
  experimental convenience APIs, if pursued later, are not part of this
  work.
- **Node ProcessContainer PTY:** The raw Node SDK launches the `wxc-exec`
  through `node-pty` for this mode and sends the original JSON through
  `--config-base64`, bypassing the typed stable mapper. Other applicable
  Node raw modes continue to use the existing FFI.

The implementation must verify these distinctions rather than inventing
stronger guarantees:

1. **Operation-specific cancellation and cleanup.** The typed .NET SDK's
   one-shot `MxcContainer.RunAsync` cancellation stops awaiting, not native
   execution; its dev `RunJsonAsync` mirrors that behavior with the existing
   FFI `mxc_run_json`. Request timeout still bounds execution. Typed .NET
   `MxcLifecycle.RunInContainerAsync` instead spawns an owned process and
   disposes it on cancellation; dev `RunInContainerJsonAsync` follows that
   handle-based path. Node's V1 run operations have no `AbortSignal`; dev
   run operations do not add one. Live Node/.NET dev process handles retain
   V1 `kill`, wait, stream, and disposal behavior; Rust dev run remains
   synchronous and in-process. A .NET `Task<T>` alone does not require a
   `CancellationToken`: dev lifecycle methods without typed async
   cancellation counterparts need not add one. Dev PTY methods stay
   synchronous like typed V1. Test timeout and partial
   output, concurrent stream draining, capture limits, failed-startup
   cleanup, and that in-container exec leaves its caller-owned container
   provisioned.

## 3. Remaining implementation work

1. **Add the dev public contract.** Follow `origin/main` names and types,
   add the V1.Dev signatures in Rust, .NET, and Node, and return complete
   native response JSON for lifecycle and validation calls.
   Export Node's `./v1/dev` subpath and its supported type-resolution mapping;
   do not add a package-root raw alias. Use qualified `.NET` dev facade names
   in examples that also import typed V1.
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
   use the agreed `wxc-exec` path for Node ProcessContainer PTY. Preserve
   complete JSON for non-exec lifecycle responses, and use existing V1
   output types for execution. Rust must expose a supported exact-JSON API
   rather than asking consumers to import `__ffi`;
   .NET and Node need public facades as well as native exports. Ensure the
   Node facade is non-blocking and Promise-returning.
3. **Verify functional parity.** Check owned process/PTY handles, pipe
   closure, stream pressure, descendant-held endpoints, failed startup,
   repeated wait/disposal, backend-specific termination scope, and the
   typed V1 capture/timeout/cancellation behavior per operation. Specify
   unavailable streams and fail unsupported requested modes without
   downgrading. Preserve FFI cleanup and panic containment. Separately
   scope byte-preserving native capture and any stronger post-start
   cancellation guarantee; neither is part of the first milestone.
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
