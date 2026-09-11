# SDK-to-Backend Call and Data Flow

Status: architecture analysis and refactoring proposal.

Date: 2026-09-11.

Baseline: `user/gudge/version_specific_config_parsers_phase9b` at
`aa53f607`, including its rewritten Phase 9a parent `37ced8c4` and antecedents.
This document distinguishes the architecture implemented on that baseline from
the proposed changes in the final sections.

## 1. Scope

This document traces the call and data flow from the three supported SDK
surfaces to the runtime `ExecutionRequest` and then to the following containment
backends:

- Windows ProcessContainer, including BaseContainer and AppContainer fallback
  tiers
- WSL Container (WSLC)
- Windows Sandbox
- IsolationSession
- LXC
- macOS Seatbelt

It covers:

- Rust SDK one-shot and state-aware entry points
- Node.js SDK one-shot and state-aware entry points
- .NET SDK one-shot and state-aware entry points
- exact version-specific configuration parsing
- state-aware typed payload binding introduced in Phase 9b
- engine and backend dispatch
- memory, speed, and maintainability costs
- public versus workspace-internal visibility
- a proposed direct Rust SDK-to-domain normalization design

## 2. Architectural summary

All execution paths ultimately converge on:

```text
wxc_common::models::ExecutionRequest
```

`ExecutionRequest` is the current version-neutral runtime representation of:

- process command, environment, working directory, and timeout
- selected containment backend
- normalized filesystem, network, UI, and ProcessContainer policy
- lifecycle settings
- backend-specific runtime configuration
- telemetry settings
- experimental, testing-only, and dry-run execution gates

There are two broad construction lanes.

### 2.1 Untrusted exact JSON lane

```text
raw JSON
  -> exact version probe
  -> exact version-specific request type
  -> version-specific adapter
  -> shared semantic normalization
  -> ExecutionRequest
```

This lane is used by:

- executor binaries invoked by the Node.js SDK
- state-aware .NET FFI calls
- Rust state-aware JSON entry points
- direct CLI configuration files and base64 configuration

The exact contract controls accepted JSON shape. The declared version does not
select an obsolete backend implementation or weaker backend validation.

### 2.2 Trusted typed SDK lane

For Rust and .NET one-shot requests, typed public SDK objects are converted into
an exact contract representation before reaching the same normalization path:

```text
typed SDK request
  -> version-specific contract builder
  -> version-specific adapter
  -> wire::MxcConfig
  -> shared semantic normalization
  -> ExecutionRequest
```

This preserves strong equivalence with the exact JSON contracts, but constructs
multiple in-memory representations of the same request.

## 3. Exact configuration parsing

Phase 9 made exact version-specific dispatch authoritative. The production
parser:

1. probes the required exact `version`
2. selects the registered contract
3. for development state-aware requests, probes `phase`
4. for provision, probes the selected state-aware containment
5. deserializes directly from the source into the selected exact request type
6. converts that type into the runtime normalization input

The registered versions on the Phase 9b baseline are:

```text
0.6.0-alpha -> published::v0_6_0_alpha
0.7.0-alpha -> published::v0_7_0_alpha
0.8.0-alpha -> published::v0_8_0_alpha
0.9.0-alpha -> dev
```

There is no fallback to a latest or rolling contract when a version is missing
or unsupported.

The contract crate remains dependency-light:

```text
mxc_config_contract
  - exact version identities
  - registry metadata
  - exact version and phase probes
  - immutable published request types
  - mutable development request types

No dependency on:
  - wxc_common
  - mxc_engine
  - backend crates
```

## 4. Phase 9b state-aware architecture

Phase 9b replaces the former production raw-payload bridge with typed
operations and checked backend binding.

### 4.1 Former Phase 9a state-aware flow

The Phase 9a implementation used:

```text
exact contract
  -> wire::MxcConfig
  -> raw experimental serde_json::Value
  -> retained complete source text
  -> ParsedStateAwareRequest
  -> resolve backend
  -> locate experimental.<backend>.<phase> in source
  -> deserialize backend config again
  -> clone ExecutionRequest
  -> backend
```

That flow retained two complete forms of backend data and reparsed the
backend-specific phase fragment at dispatch time.

### 4.2 Phase 9b flow

Phase 9b uses:

```text
raw JSON
  -> exact version/phase/backend request type
  -> exact adapter
       |
       +-- common fields -> wire::MxcConfig
       |
       `-- backend payload -> StateAwareOperation
  -> normalize common fields once
  -> ParsedStateAwareRequest
       - private ExecutionRequest
       - private StateAwareOperation
  -> resolve backend
  -> bind_<backend>
  -> BoundStateAwareRequest<B>
  -> generic typed dispatcher
  -> StatefulSandboxBackend
```

The normalized operation is the sole phase and routing authority:

```rust
pub enum StateAwareOperation {
    Provision(StateAwareProvision),
    Start { sandbox_id: String },
    Exec { sandbox_id: String },
    Stop { sandbox_id: String },
    Deprovision { sandbox_id: String },
}
```

Provision retains backend-specific configuration:

```rust
pub enum StateAwareProvision {
    IsolationSession(Option<IsolationSessionProvisionConfig>),
    WindowsSandbox,
    Wslc(Option<WslcProvisionConfig>),
}
```

This representation preserves meaningful distinctions between:

- an absent backend configuration
- a present but empty backend configuration
- an explicitly empty string
- a populated configuration

### 4.3 Checked binding

The engine resolves the backend and invokes the corresponding binding helper:

```text
IsolationSession -> bind_isolation_session
Windows Sandbox  -> bind_windows_sandbox
WSLC             -> bind_wslc
```

Binding verifies:

- the resolved `ContainmentBackend`
- the backend implementation's `BACKEND_KEY`
- the backend implementation's `ID_PREFIX`
- the neutral provision payload variant
- the backend implementation's associated configuration types

It then produces:

```rust
BoundStateAwareRequest<B>
```

whose operation contains configuration typed for exactly `B`.

### 4.4 Consuming dispatch

The generic dispatcher consumes the bound request:

```text
BoundStateAwareRequest<B>
  -> ExecutionRequest
  -> BoundStateAwareOperation<B>
       - owned sandboxId
       - owned Option<B::PhaseConfig>
```

Configuration is borrowed for validation and then moved into the backend
method. The dispatcher no longer clones the complete `ExecutionRequest` or
deserializes configuration.

### 4.5 Removed production costs

Successful production requests no longer retain:

- complete decoded source text
- `experimental_raw: serde_json::Value`
- a second backend JSON subtree
- source-fragment navigation maps
- a generic dispatch-time `deserialize_config<C>()` path

The legacy implementation remains under `#[cfg(test)]` as migration evidence
in:

```text
src/core/wxc_common/src/config_parser/legacy_payload_reference.rs
src/core/wxc_common/src/config_parser/legacy_state_aware_request.rs
```

It has no production runtime cost and is intended for removal after replacement
coverage is established.

## 5. Rust SDK flow

### 5.1 Current one-shot construction

The Phase 9b one-shot construction path is:

```text
PUBLIC RUST SDK

SandboxPolicy
Containment
command: &str
container_name: Option<&str>
        |
        v
mxc_sdk::build_request[_with_containment]
        |
        v
mxc_engine::policy::exact::build_request
        |
        +-- parse exact ContractVersion
        +-- validate policy/containment combinations
        +-- select legacy or directional network format
        +-- prepare container ID
        |
        v
version-specific builder
        |
        +-- policy::exact::v0_6::build
        +-- policy::exact::v0_7::build
        +-- policy::exact::v0_8::build
        `-- policy::exact::v0_9::build
        |
        v
exact version-specific contract request
        |
        v
ExactOneShotContract
        |
        v
load_one_shot_request_from_contract
        |
        v
version-specific contract adapter
        |
        v
wire::MxcConfig
        |
        v
convert_wire_config
        |
        v
ExecutionRequest
        |
        v
SandboxRequest { private inner: ExecutionRequest }
```

No JSON serialization occurs in this path. The cost is in cloning and moving
request fields through multiple Rust object graphs:

```text
SDK strings/vectors
  -> contract strings/vectors
  -> wire strings/vectors
  -> ExecutionRequest strings/vectors
```

### 5.2 Current one-shot execution

The public Rust SDK executes through the streaming abstraction:

```text
mxc_sdk::spawn_sandbox
  -> mxc_engine::spawn
  -> dispatch::spawn_runner
  -> backend SandboxBackend::spawn
  -> Box<dyn SandboxProcess>
  -> mxc_sdk::Sandbox
```

`mxc_sdk::run` is:

```text
spawn_sandbox
  -> Sandbox::wait_with_output
  -> concurrent stdout/stderr drain
  -> Output
```

It does not use the engine's run-to-completion `ScriptRunner` path.

The one-shot Rust SDK streaming surface currently supports:

- ProcessContainer
- Bubblewrap
- Seatbelt
- WSLC

Windows Sandbox, IsolationSession, and LXC do not expose a one-shot
`SandboxProcess` through this API.

### 5.3 Current state-aware Rust SDK flow

The public state-aware Rust API remains JSON-oriented:

```text
run_state_aware_json
exec_sandbox
exec_attached
        |
        v
mxc_engine state-aware JSON entry point
        |
        v
exact parser
        |
        v
ParsedStateAwareRequest
        |
        v
resolve + checked bind
        |
        v
BoundStateAwareRequest<B>
        |
        v
StatefulSandboxBackend
```

Phase 9b makes the internal part typed, but callers still serialize a
state-aware request to JSON.

## 6. Node.js SDK flow

### 6.1 One-shot

The Node.js one-shot path is:

```text
SandboxPolicy
  -> createConfigFromPolicy
  -> ContainerConfig
  -> JSON.stringify
  -> UTF-8 base64
  -> --config-base64 command-line argument
  -> wxc-exec / lxc-exec / mxc-exec-mac
  -> base64 decode
  -> exact version-specific parser
  -> contract adapter
  -> wire::MxcConfig
  -> ExecutionRequest
  -> mxc_engine
  -> backend
```

The default launch uses `node-pty`, giving the executor inherited terminal
handles and combining stdout and stderr.

With `usePty: false`, the SDK uses `child_process.spawn` and separate standard
streams.

Node performs SDK-side mapping and validation for earlier errors, including:

- registered version validation
- containment/version compatibility
- platform compatibility
- experimental and testing-feature gates
- policy-to-backend mapping
- Linux network-mode defaults

The native parser and backend then validate independently. This catches errors
early but duplicates policy knowledge across TypeScript and Rust.

### 6.2 State-aware

The typed TypeScript lifecycle API builds an exact request envelope:

```text
typed phase-specific TypeScript config
  -> buildStateAwareEnvelope
  -> JSON.stringify
  -> base64
  -> new executor process
  -> exact Rust state-aware parser
  -> StateAwareOperation
  -> checked binding
  -> backend
```

Every phase starts a fresh executor process. For daemon-backed state-aware
backends, the complete path is:

```text
Node process
  -> short-lived executor process
  -> backend daemon
  -> VM/container
```

The daemon is necessary to retain live backend state. The per-phase executor
process is a transport choice rather than a backend requirement.

## 7. .NET SDK flow

### 7.1 One-shot

The .NET one-shot path is:

```text
SandboxPolicy / SandboxRequest POCO
  -> System.Text.Json
  -> managed JSON string
  -> NUL-terminated UTF-8 byte buffer
  -> mxc_ffi
  -> FFI RequestSpec
  -> Rust SDK SandboxPolicy + Containment
  -> version-specific exact contract builder
  -> exact contract adapter
  -> wire::MxcConfig
  -> ExecutionRequest
  -> mxc_sdk::run or spawn_sandbox
  -> backend
```

The request passes through these representations:

1. managed policy/request objects
2. managed JSON string
3. UTF-8 byte buffer
4. FFI `RequestSpec`
5. Rust SDK policy and containment
6. exact version-specific contract
7. `wire::MxcConfig`
8. `ExecutionRequest`

Run output then travels through:

```text
Rust Vec<u8>
  -> allocated NUL-terminated C string
  -> managed string
```

`RunAsync` currently uses `Task.Run` around the blocking native invocation. It
uses a thread-pool thread and cannot cancel an already-running native call.

### 7.2 State-aware

.NET state-aware APIs construct the actual wire envelope:

```text
typed StateAware*Options
  -> JsonObject envelope
  -> JSON string
  -> NUL-terminated UTF-8
  -> mxc_state_aware*
  -> exact Rust parser
  -> StateAwareOperation
  -> checked binding
  -> backend
```

This path is more direct than .NET one-shot because it does not pass through the
separate one-shot FFI `RequestSpec`.

## 8. Engine execution paths

### 8.1 One-shot run-to-completion

Executor binaries use:

```text
ExecutionRequest
  -> mxc_engine::resolve_runner or mxc_engine::run
  -> Box<dyn ScriptRunner>
  -> ScriptRunner::run
       - validate_common
       - backend validation
       - dry-run check
       - execute
```

Windows `wxc-exec` uses `resolve_runner` because it must separately manage the
ProcessContainer DACL guard for signal cleanup. Linux and macOS executors can
use the convenience `run` path.

### 8.2 One-shot streaming

The Rust SDK and .NET FFI streaming paths use:

```text
ExecutionRequest
  -> mxc_engine::spawn
  -> dispatch::spawn_runner
  -> backend SandboxBackend::spawn
  -> Box<dyn SandboxProcess>
```

For a backend implementing `SandboxBackend`, the generic `Runner<B>` adapter can
provide the run-to-completion `ScriptRunner` behavior.

### 8.3 State-aware execution

State-aware engine routing uses:

```text
ParsedStateAwareRequest
  -> resolve backend
       - provision: declared containment
       - later phases: sandboxId prefix
  -> experimental/availability gate
  -> bind operation to backend type
  -> generic typed dispatcher
  -> backend validate_<phase>
  -> backend <phase>
```

Relayed exec uses:

```text
BoundStateAwareRequest<B>
  -> backend.exec(..., ExecStdio::Relayed)
  -> relay or backend-owned relay
  -> exit code
```

Streaming exec uses:

```text
BoundStateAwareRequest<B>
  -> backend.exec(..., ExecStdio::Piped)
  -> ExecHandle
  -> ExecSandboxProcess
  -> SandboxProcess
```

IsolationSession supports both forms. Windows Sandbox and WSLC currently
support relayed exec only.

## 9. Backend flows

### 9.1 ProcessContainer and BaseContainer

```text
ExecutionRequest {
    containment: ProcessContainer
}
  -> appcontainer_common::dispatcher
  -> select_backend_with_fallback
       |
       +-- Tier 1: BaseContainer
       |     - prefer PSEC when available and request-compatible
       |     - otherwise consider legacy SBOX contract
       |
       +-- Tier 2: AppContainer + BFS
       |
       `-- Tier 3: AppContainer + host DACL augmentation
  -> selected SandboxBackend
  -> process creation
```

The same selection function is shared by streaming and run-to-completion. This
prevents the isolation tiers from drifting between SDK and executor paths.

The dispatcher also owns:

- DACL guard lifetime
- capture-denials provider selection
- degradation diagnostics
- selected-tier reporting

### 9.2 WSLC one-shot

```text
ExecutionRequest
  -> WSLContainerRunner
  -> validate WSLC policy
  -> initialize COM and load WSLC SDK
  -> create session/container/process
  -> SDK callbacks deliver stdout/stderr
  -> wait/timeout/teardown
```

Streaming and run-to-completion share the internal `start_container` lifecycle.
The WSLC SDK exposes no process-input API, so one-shot streaming has no stdin.

### 9.3 WSLC state-aware

```text
BoundStateAwareRequest<WslcStateAwareRunner>
  -> runtime WslcProvisionConfig or phase operation
  -> DaemonClient
  -> owner-only named pipe
  -> wxc-wslc-daemon
  -> apartment-affine WSLC session/container handles
```

Every phase opens a fresh daemon connection. The daemon owns persistent WSLC
objects because the SDK cannot reattach to them across executor processes.

Exec currently streams daemon output directly to the executor's stdout/stderr
and returns a completed sentinel `ExecHandle`. It cannot return pipes to an
embedded caller.

### 9.4 Windows Sandbox one-shot

```text
ExecutionRequest
  -> WindowsSandboxRunner
  -> plan policy and mapped folders
  -> acquire host VM slot
  -> create secured per-run scratch
  -> generate .wsb file
  -> launch VM
  -> authenticate guest connection
  -> execute command
  -> ownership-scoped teardown
```

The one-shot backend creates a fresh disposable VM per invocation.

### 9.5 Windows Sandbox state-aware

```text
Provision
  -> persist sandbox record

Start
  -> acquire transition lock
  -> launch persistent daemon
  -> daemon launches/owns the single Windows Sandbox VM
  -> persist Started state

Exec
  -> find and validate live daemon
  -> stream command through daemon to guest

Stop/Deprovision
  -> stop daemon/VM
  -> update or remove persistent record
```

The backend currently supports relayed exec only.

### 9.6 IsolationSession one-shot

```text
ExecutionRequest
  -> IsolationSessionRunner
  -> add agent user
  -> start isolation session
  -> create process
  -> stop session
  -> remove agent user
```

The entire lifecycle occurs inside one process and is cleaned up before the
one-shot invocation returns.

### 9.7 IsolationSession state-aware

```text
Provision
  -> add agent user
  -> encode identity and appId into sandboxId

Start/Exec/Stop/Deprovision
  -> decode sandboxId
  -> reconstruct IsolationSessionManager
  -> invoke OS-side session operation
```

Piped exec returns real process handles and supports streaming callers. Relayed
exec retains the backend's richer ConPTY and console behavior.

### 9.8 LXC

```text
ExecutionRequest
  -> LxcScriptRunner
  -> create/select LXC container
  -> apply filesystem and network setup
  -> attach and execute
  -> wait and lifecycle cleanup
```

LXC currently implements run-to-completion `ScriptRunner`, not
`SandboxBackend`, so it is available through `lxc-exec` but not the in-process
Rust/.NET one-shot streaming API.

### 9.9 Seatbelt

```text
ExecutionRequest
  -> SeatbeltScriptRunner
  -> validate Seatbelt-specific policy
  -> start optional cooperative proxy
  -> build Seatbelt profile
  -> fork/exec or open launch
  -> sandbox_init
  -> wait/timeout/process-group cleanup
```

Seatbelt implements `SandboxBackend`. The macOS executor obtains
run-to-completion behavior through the generic `Runner<B>` adapter, while the
Rust/.NET SDKs can use its streaming handle directly.

## 10. Current strengths

The current architecture has several strong properties.

### 10.1 Schema version does not select backend behavior

Every supported contract maps to the current runtime model and current backend
validation. Old versions preserve input compatibility without preserving old
security bugs or obsolete execution implementations.

### 10.2 Exact contracts are isolated

Published contracts are independent Rust modules and do not depend on runtime
or backend crates. Adapters, rather than immutable contract modules, absorb
runtime evolution.

### 10.3 Backend dispatch is centralized

`mxc_engine` is the single backend selection layer used by executors and
in-process SDKs.

### 10.4 ProcessContainer fallback is shared

BaseContainer/AppContainer tier selection is shared between streaming and
run-to-completion.

### 10.5 State-aware dispatch is typed

Phase 9b removes dispatch-time JSON interpretation and makes phase/payload
contradictions unrepresentable after normalization.

### 10.6 Backend validation remains authoritative

Typed construction does not skip backend support checks. Requests built
directly by SDK code still reach shared and backend-specific validation.

## 11. Remaining costs and complexity

### 11.1 `wire::MxcConfig` remains a production middle layer

Exact adapters construct a version-neutral rolling wire object before semantic
normalization. State-aware adapters create mostly empty `wire::MxcConfig`
instances and explicitly set irrelevant fields to `None`.

This is now the largest internal representation cost left by the parser
migration.

### 11.2 Rust typed requests create redundant object graphs

The Rust SDK builds an exact contract only to adapt it back into a common wire
model and then into `ExecutionRequest`.

This gives strong equivalence by construction, but it clones request-owned
strings and vectors multiple times.

### 11.3 Node transport starts an executor for every call

Node pays for:

- JSON serialization
- base64 expansion
- another full byte buffer
- command-line argument construction
- executor process startup
- native base64 decode
- native JSON parsing

State-aware daemon-backed calls also pay for an executor-to-daemon hop.

### 11.4 .NET one-shot has a separate binding request contract

.NET one-shot converts from its POCO model through an FFI-specific `RequestSpec`
before reaching Rust SDK policy types and the exact contract builder.

### 11.5 Backend identity is duplicated

Backend name and routing information appears in:

- `ContainmentBackend`
- `StateAwareProvision`
- `StatefulSandboxBackend::BACKEND_KEY`
- `StatefulSandboxBackend::ID_PREFIX`
- binding helper literals
- `backend_from_prefix`
- Node prefix maps
- .NET constants and maps
- platform discovery
- engine dispatch matches

### 11.6 Engine state-aware dispatch is repeated

Envelope dispatch and streaming exec each repeat the backend match, binding,
runner construction, and feature-gate structure.

### 11.7 Workspace-internal APIs appear public

Cross-crate compilation requires public Rust visibility for several types that
are not intended as supported application APIs:

- `ExecutionRequest`
- `ParsedStateAwareRequest`
- `StateAwareOperation`
- `BoundStateAwareRequest`
- state-aware binding functions
- backend traits
- runtime backend configuration structs
- engine runner-resolution functions

Private fields protect important invariants, but the visible API surface still
suggests broader stability than intended.

## 12. Proposed direct Rust SDK normalization

The trusted Rust SDK path should avoid constructing exact-contract and rolling
wire object graphs at runtime.

### 12.1 Proposed flow

```text
PUBLIC RUST SDK

┌────────────────────────────────────────────────────────────┐
│ mxc_sdk::SandboxPolicy                                     │
│                                                            │
│ - version                                                  │
│ - filesystem                                               │
│ - network                                                  │
│ - ui                                                       │
│ - timeout                                                  │
└──────────────────────────┬─────────────────────────────────┘
                           │ plus Containment, command,
                           │ and optional container name
                           v
┌────────────────────────────────────────────────────────────┐
│ build_request_with_containment                             │
└──────────────────────────┬─────────────────────────────────┘
                           │
                           v
PRIVATE ENGINE CONSTRUCTION

┌────────────────────────────────────────────────────────────┐
│ ContractVersion::parse_exact                               │
└──────────────────────────┬─────────────────────────────────┘
                           │
                           v
┌────────────────────────────────────────────────────────────┐
│ VersionSemantics                                           │
│                                                            │
│ Small static descriptor, not a request object:             │
│ - exact version                                            │
│ - supported containments                                   │
│ - available policy syntax                                  │
│ - version-specific defaults and presence rules             │
└──────────────────────────┬─────────────────────────────────┘
                           │
                           v
┌────────────────────────────────────────────────────────────┐
│ SdkRequestInput<'a>                                        │
│                                                            │
│ - policy: &'a SandboxPolicy                                │
│ - containment: &'a Containment                             │
│ - command: &'a str                                         │
│ - container_name: Option<&'a str>                          │
│ - version: ContractVersion                                 │
│                                                            │
│ Borrowed view; no policy-field cloning.                    │
└──────────────────────────┬─────────────────────────────────┘
                           │
                           v
SHARED DOMAIN NORMALIZATION

┌────────────────────────────────────────────────────────────┐
│ DomainRequestInput<'a>                                     │
│                                                            │
│ - process input                                            │
│ - filesystem input                                         │
│ - network input                                            │
│ - UI input                                                 │
│ - containment input                                        │
│ - lifecycle input                                          │
│ - telemetry input                                          │
│ - field-presence metadata                                  │
└──────────────────────────┬─────────────────────────────────┘
                           │
                           v
┌────────────────────────────────────────────────────────────┐
│ DomainNormalizer::normalize                               │
│                                                            │
│ - command/environment validation                           │
│ - version/backend compatibility                            │
│ - abstract containment resolution                          │
│ - filesystem precedence                                    │
│ - network normalization                                    │
│ - capability derivation                                    │
│ - presence/default semantics                               │
│ - backend runtime configuration                            │
└──────────────────────────┬─────────────────────────────────┘
                           │ allocate owned values once
                           v
┌────────────────────────────────────────────────────────────┐
│ ExecutionRequest                                           │
└──────────────────────────┬─────────────────────────────────┘
                           │
                           v
┌────────────────────────────────────────────────────────────┐
│ SandboxRequest { private inner: ExecutionRequest }         │
└────────────────────────────────────────────────────────────┘
```

The shortened data path is:

```text
SandboxPolicy + Containment + command
  -> borrowed SdkRequestInput
  -> shared DomainRequestInput
  -> DomainNormalizer
  -> ExecutionRequest
```

### 12.2 Parallel exact JSON lane

Exact contracts remain authoritative for untrusted JSON:

```text
UNTRUSTED JSON                         TRUSTED RUST SDK

raw JSON                              SandboxPolicy
   |                                      |
   v                                      v
exact version contract              borrowed SDK adapter
   |                                      |
   v                                      |
version-specific adapter                  |
   |                                      |
   +-------------> DomainRequestInput <---+
                         |
                         v
                 DomainNormalizer
                         |
                         v
                 ExecutionRequest
```

This preserves:

- exact structural validation for JSON
- typed construction for Rust callers
- identical semantic normalization
- identical backend validation

### 12.3 Possible internal interfaces

Illustrative interfaces:

```rust
pub(crate) struct SdkRequestInput<'a> {
    pub policy: &'a SandboxPolicy,
    pub containment: &'a Containment,
    pub command: &'a str,
    pub container_name: Option<&'a str>,
    pub version: ContractVersion,
}

pub(crate) struct DomainRequestInput<'a> {
    pub version: ContractVersion,
    pub process: ProcessInput<'a>,
    pub filesystem: Option<FilesystemInput<'a>>,
    pub network: Option<NetworkInput<'a>>,
    pub ui: Option<UiInput<'a>>,
    pub containment: ContainmentInput<'a>,
    pub lifecycle: LifecycleInput,
    pub telemetry: Option<TelemetryInput>,
    pub presence: PresenceFlags,
}

pub(crate) struct DomainNormalizer<'log> {
    logger: &'log mut Logger,
}

impl DomainNormalizer<'_> {
    pub fn normalize(
        &mut self,
        input: DomainRequestInput<'_>,
        semantics: &'static VersionSemantics,
    ) -> Result<ExecutionRequest, MxcError>;
}
```

These names are illustrative. The important properties are:

- borrowed SDK input where possible
- one version-neutral semantic input
- one semantic normalizer
- final ownership allocated once
- exact contract adapters and SDK adapters converge before normalization

### 12.4 Equivalence testing

The version-specific SDK contract builders should remain as test oracles until
publication/freeze coverage replaces them:

```text
                         test-only equivalence

SandboxPolicy -------------------------------+
    |                                        |
    v                                        v
direct SDK adapter                 exact contract builder
    |                                        |
    |                              exact contract adapter
    |                                        |
    +---------- compare DomainRequestInput --+
                         |
                         v
                 DomainNormalizer
                         |
                         v
                 ExecutionRequest
```

This verifies that each SDK version means the same thing as its exact JSON
contract without paying for the contract and wire object graphs during every
production call.

## 13. Recommended refactorings

### 13.1 Replace production `wire::MxcConfig`

Introduce a purpose-built common normalization input and have exact adapters
map directly into it:

```text
exact contract
  -> CommonRequestInput + optional StateAwareOperation
  -> shared domain normalization
  -> ExecutionRequest
```

One-shot and state-aware adapters should share the same process, filesystem,
network, UI, lifecycle, and telemetry normalization components.

After rolling-parser retirement, `wire::MxcConfig` should be test/codegen-only
or removed.

### 13.2 Build typed Rust requests directly

The Rust SDK should map borrowed policy data directly into the shared domain
normalizer. Exact-contract equivalence should be a test and publication gate,
not a production allocation path.

### 13.3 Remove legacy state-aware references

After direct exact-contract fixtures and typed dispatch tests replace their
evidence, remove the test-only legacy payload and state-aware request
implementations.

This primarily reduces source complexity and test compile time.

### 13.4 Resolve the state-aware backend once

Current state-aware dispatch resolves the backend before selecting a binding
helper, and binding resolves it again.

Introduce a private resolved request:

```rust
struct ResolvedStateAwareRequest {
    backend: StateAwareBackendKind,
    parsed: ParsedStateAwareRequest,
}
```

Then:

```text
resolve once
  -> execution/availability gate
  -> checked bind using resolved token
  -> dispatch
```

Binding should still verify payload compatibility without repeating sandbox-ID
prefix parsing.

### 13.5 Centralize backend identity

Introduce one state-aware backend descriptor:

```rust
enum StateAwareBackendKind {
    IsolationSession,
    WindowsSandbox,
    Wslc,
}

impl StateAwareBackendKind {
    const fn containment(self) -> ContainmentBackend;
    const fn wire_name(self) -> &'static str;
    const fn id_prefix(self) -> &'static str;
}
```

Generate or derive:

- Rust routing and binding
- sandbox-ID prefix resolution
- experimental status
- platform/feature availability metadata
- Node prefix metadata
- .NET containment metadata

### 13.6 Consolidate engine state-aware matches

Envelope dispatch and streaming exec repeat:

- backend matching
- feature availability gates
- binding
- runner construction
- generic dispatcher invocation

Generate both paths from a shared registry or macro while retaining static
generic dispatch and associated configuration types.

### 13.7 Add typed Rust state-aware APIs

Do not expose `StateAwareOperation` directly. Add an ergonomic public SDK layer
that constructs exact typed lifecycle requests without serializing JSON:

```rust
let provision = IsolationSessionProvisionRequest::new(network_ack)
    .app_id(...);

let id = lifecycle.provision(provision)?;
lifecycle.start(&id)?;
let process = lifecycle.exec(&id, ExecRequest::new(command))?;
```

The public builders should converge on the same exact adapters and domain
normalizer as JSON input.

### 13.8 Add an optional in-process Node transport

For non-PTY one-shot calls and state-aware calls, a Node native addon over
`mxc_ffi` would remove:

- executor startup
- base64 encoding and decoding
- command-line length constraints
- the extra executor-to-daemon hop

Retain the executable transport for:

- PTY ownership
- crash isolation
- deployment fallback

### 13.9 Replace base64 command-line transport

Where Node continues to spawn executors, pass configuration through a dedicated
inherited pipe or handle rather than `--config-base64`.

Do not reuse ordinary stdin because interactive workload input must remain
available.

### 13.10 Improve .NET async and FFI buffers

Implement asynchronous execution as:

```text
Spawn
  -> asynchronous concurrent stream drain
  -> asynchronous wait
  -> cancellation calls Kill
  -> await teardown
```

Use pointer-plus-length byte buffers rather than NUL-terminated strings for
stdout and stderr. This avoids scans, preserves embedded NUL bytes, and avoids
unnecessary text conversion when callers need bytes.

### 13.11 Normalize environment values structurally

Replace:

```rust
Vec<String> // "KEY=VALUE"
```

with an internal representation such as:

```rust
Vec<(String, String)>
```

Preserve ordering and duplicate-key semantics. Render the platform-specific
environment block only at the final OS/backend boundary.

### 13.12 Optimize policy hashing only if measured

Typed state-aware policy hashing currently constructs a temporary
`serde_json::Value`, clones selected strings, serializes canonical JSON, and
then hashes it.

This runs only when telemetry or diagnostics requires a policy hash. If
profiling identifies it as significant, hash typed framed fields directly
rather than constructing a temporary JSON tree.

## 14. Visibility recommendations

### 14.1 Supported public surface

The supported Rust API should be centered on:

```text
mxc-sdk
  - SandboxPolicy
  - Containment
  - SandboxRequest
  - Sandbox
  - typed state-aware lifecycle facade
  - public errors and output types
```

### 14.2 Workspace-internal backend SPI

Types needed across engine/backend crate boundaries should not implicitly become
supported application APIs.

Preferred structure:

```text
mxc_backend_api
  publish = false

  - ExecutionRequest
  - backend traits
  - state-aware operation and binding types
  - logger/error interfaces needed by backends
```

Then:

```text
mxc_config_contract
  -> exact external contracts

mxc_backend_api
  -> private backend SPI

mxc_engine
  -> private orchestration and backend registry

mxc-sdk
  -> supported public Rust API
```

If a new crate is not warranted, mark the corresponding `wxc_common` modules
and types `#[doc(hidden)]` and explicitly document that they are
workspace-internal and not semver-stable.

### 14.3 Runtime backend configuration

Runtime types such as:

- `IsolationSessionProvisionConfig`
- `WslcProvisionConfig`

should not act as alternative public wire contracts.

Prefer:

- private fields
- controlled internal constructors
- public read-only accessors required by backend crates
- no `Deserialize` implementation unless a demonstrated runtime consumer
  requires it

Exact contract modules should remain the only external JSON-shape authority.

## 15. Priority order

1. Replace production `wire::MxcConfig` with direct contract-to-domain
   normalization.
2. Build Rust SDK requests directly through the shared domain normalizer.
3. Remove the test-only rolling/raw state-aware reference after replacement
   evidence is established.
4. Resolve and register state-aware backends through one descriptor path.
5. Reduce public visibility of engine and backend SPI types.
6. Add typed Rust state-aware SDK requests.
7. Improve Node and .NET transport and asynchronous execution.
8. Optimize policy hashing and small remaining clones only when supported by
   profiling.

## 16. Conclusion

Phase 9b resolves the most important state-aware representation problem:

- exact parsing is authoritative
- backend payloads are parsed once
- successful requests retain no raw backend JSON or source text
- phase cannot disagree with operation
- backend binding is checked
- dispatch consumes owned values

The largest remaining internal simplification is removing the rolling
`wire::MxcConfig` representation from production normalization. The desired end
state is one strongly validated `ExecutionRequest`, one backend execution
engine, exact contracts for untrusted JSON, and a shared domain normalizer used
by both exact adapters and trusted typed SDKs.
