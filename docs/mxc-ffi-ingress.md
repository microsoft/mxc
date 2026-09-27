# MXC FFI ingress

`mxc_ffi` exposes typed and JSON ingress for both one-shot and state-aware
execution. The forms intentionally converge only after their caller-facing
contract has been validated.

## Entry-point matrix

| Execution model | Typed FFI | Raw exact JSON | Compatibility binding JSON |
| --- | --- | --- | --- |
| One-shot run to completion | `mxc_run_typed` | `mxc_run_json` | `mxc_run_request` |
| One-shot streaming | `mxc_spawn_typed` | `mxc_spawn_json` | `mxc_spawn_request` |
| Lifecycle envelope and validation | `mxc_state_aware_typed` | `mxc_state_aware_json` | `mxc_state_aware` (legacy export of the same exact-JSON path) |
| Lifecycle streaming exec | `mxc_state_aware_exec_typed` | `mxc_state_aware_exec_json` | `mxc_state_aware_exec` (legacy export of the same exact-JSON path) |
| Lifecycle attached exec | `mxc_state_aware_exec_attached_typed` | `mxc_state_aware_exec_attached_json` | `mxc_state_aware_exec_attached` (legacy export of the same exact-JSON path) |

The compatibility one-shot request is a private co-versioned binding document.
It is not an MXC configuration contract and must not be used for exact config
replay. It remains exported until the existing .NET and Node consumers migrate.

## Typed ABI

Typed calls use `#[repr(C)]` structures generated into the managed bindings.
Every top-level typed request carries:

- `abi_version`, currently `MXC_TYPED_ABI_VERSION_1`;
- `struct_size`, which must be at least the current structure size;
- fixed-width discriminants for containment, operations, network actions,
  protocols, UI values, and metadata kinds;
- borrowed UTF-8 byte slices and borrowed arrays;
- explicit presence fields for optional scalar values and authored lists.

Inputs are borrowed only for the duration of the call. The native library does
not retain any request pointer.

Typed one-shot calls adapt to `SandboxPolicy`, `Containment`, and
`SandboxRequest`, then enter `mxc_engine` through the direct Rust SDK path.
Typed lifecycle calls adapt to `ProvisionRequest`, `SandboxId`, `ExecRequest`,
and `OperationOptions`, then use the direct typed lifecycle entry points.
Neither typed path serializes its input to JSON or invokes an exact JSON parser.

The typed lifecycle ABI supports the stable v1 high-level backend set:
IsolationSession and WSLC. Windows Sandbox lifecycle remains available through
raw exact `1.1.0-alpha` JSON.

## Raw exact JSON

Raw JSON calls parse the public exact request selected by its `version`:

- one-shot JSON must contain a registered one-shot root;
- lifecycle JSON retains the exact envelope, including `phase` and
  `sandboxId`;
- parser paths, line/column diagnostics, and exact-contract migration errors
  remain intact.

One-shot and lifecycle JSON are separate entry points. Passing a lifecycle
envelope to `mxc_run_json` or `mxc_spawn_json` is rejected.

## Results and ownership

Run-to-completion calls fill `MxcRunResult`; release its owned strings with
`mxc_run_result_free`.

Typed lifecycle envelope calls fill `MxcTypedStateAwareResult`; release its
owned sandbox identity, warnings, metadata, and error strings with
`mxc_state_aware_typed_result_free`.

JSON lifecycle envelope calls fill `MxcStateAwareResult`; release it with
`mxc_state_aware_result_free`.

Streaming calls return `MxcSandbox`. The caller owns the handle and releases it
with `mxc_sandbox_free`. Transferred stream and closer handles retain their
existing dedicated free functions. Standalone `MxcErrorDetail` values are
released with `mxc_error_detail_free`.

Free functions are null-tolerant and idempotent for a result whose pointers
have already been cleared. Reusing output storage that still owns a live result
or handle is invalid.

## Failure behavior

Every exported function:

- validates mandatory output storage before starting an operation with side
  effects;
- clears handle out-parameters before request validation;
- rejects null pointers, invalid UTF-8, unknown discriminants, invalid boolean
  values, and unsupported ABI revisions with stable `MXC_STATUS_*` values;
- maps SDK errors to the same status code and structured detail fields used by
  the JSON and compatibility paths;
- contains panics with `catch_unwind`; no Rust panic crosses the C ABI.

Typed and raw requests have semantic-equivalence coverage at the normalized
engine boundary. Their production ingress implementations remain separate.

## Generated bindings

`src/ffi/mxc_ffi/build.rs` supplies every FFI source file to `csbindgen`.
`scripts/check-dotnet-bindings-codegen.js` regenerates the C# declarations,
checks the exported entry-point inventory and signatures, and verifies that
every generator input is included in Cargo's `rerun-if-changed` declarations.

The generated `NativeMethods.g.cs` file is not committed.

## Consumer migration

The high-level managed consumers now use the typed FFI lanes where their public
API is version-free:

1. .NET one-shot and lifecycle high-level calls marshal to typed entry points;
2. Node `spawnSandboxAsync` and the internal native streaming one-shot binding
   marshal `SandboxPolicy`/containment/process options to `mxc_run_typed` and
   `mxc_spawn_typed`;
3. Node state-aware `isolation_session` and `wslc` lifecycle calls marshal to
   `mxc_state_aware_typed`, and live/buffered exec marshal to
   `mxc_state_aware_exec_typed`;
4. explicit raw exact-config APIs stay on their existing raw path. In Node,
   `spawnSandbox` and `spawnSandboxFromConfig` remain executor-backed because
   their contract is to launch the packaged executor with PTY/child-process
   behavior and to replay caller-authored exact `ContainerConfig` JSON. Windows
   Sandbox lifecycle stays on the explicit raw JSON FFI lane
   (`mxc_state_aware_json` / `mxc_state_aware_exec_json`) because typed lifecycle
   v1 intentionally supports only IsolationSession and WSLC;
5. remove compatibility binding-JSON entry points only after all consumers
   have migrated and the removal has its own reviewed compatibility boundary.

Node transport inventory after migration:

| Node API | Before | After |
| --- | --- | --- |
| `spawnSandboxAsync` | `mxc_run_request` with private binding JSON | `mxc_run_typed` |
| Internal `spawnBindingSandboxProcess` | `mxc_spawn_request` with private binding JSON | `mxc_spawn_typed` |
| `spawnSandbox` | Executor process via `node-pty` | Executor process via `node-pty` |
| `spawnSandboxFromConfig` | Executor process (`node-pty` or `child_process`) with exact `ContainerConfig` JSON | Unchanged raw executor path |
| `provisionSandbox`, `startSandbox`, `stopSandbox`, `deprovisionSandbox` for IsolationSession/WSLC | `mxc_state_aware` JSON envelope | `mxc_state_aware_typed` |
| `execInSandbox` and non-dry-run `execInSandboxAsync` for IsolationSession/WSLC | `mxc_state_aware_exec` JSON envelope | `mxc_state_aware_exec_typed` |
| State-aware Windows Sandbox exact lifecycle | `mxc_state_aware` / `mxc_state_aware_exec` JSON envelope | `mxc_state_aware_json` / `mxc_state_aware_exec_json` |
