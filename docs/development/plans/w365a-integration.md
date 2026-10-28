# Windows 365 for Agents ready-to-use pools backend

> **Audience:** MXC developers
>
> **Status:** Experimental demo and initial-selfhost integration proposal, building on the
> native preview in `users/vishnu/w365-native-preview` at `df8ead05`.
> Existing behavior and remaining integration work are distinguished below.
> This plan-only review proposal does not add the preview backend to `main`
> or claim production readiness.
>
> **Review scope (2026-10-28):** Pool discovery and selection belong to the
> caller, as do token acquisition and refresh. Retain the existing pool,
> endpoint, identity-field, and bearer-token inputs. MXC-side Graph discovery,
> remote pool-access probing, and authentication-provider integration are
> deferred. Runtime experimental opt-in remains required for every phase.

## 1. Goal and scope

Integrate the existing `w365_agents` backend with a caller-selected Windows 365
for Agents ready-to-use pool, reserve a Cloud PC using the user's identity,
execute commands through the native DesktopControl.Exec relay, and release it.
Keep the same Cloud PC and guest context across repeated executions through
MXC's container lifecycle architecture.

The initial delivery is scoped to a **demo and initial selfhost**, not a
production release. The caller discovers and selects the pool and supplies
the existing pool and service configuration. MXC does not list pools, select
the first result, rank capacity, or fall back to another pool.

The required flow is:

1. The caller selects an accessible pool outside MXC.
2. The caller supplies its pool ID and approved control/data-plane coordinates
   through the existing configuration inputs.
3. Check out a Cloud PC and retain its session identity.
4. Wait for readiness and run multiple commands through DesktopControl.Exec
   in that session, relaying stdin, stdout, stderr, and the remote exit code.
5. Check the session in through the session API's delete operation.

Deleting a session releases a reservation. It must never delete the Cloud PC
through Graph, delete the pool, or alter a provisioning policy.

Confirmed requirements are the flow above, delegated human-user identity,
demo/initial-selfhost scope, and caller-owned discovery and selection.
Reuse Vishnu's backend, development contract, and execution transport rather
than introducing a second backend or execution API for this flow.
No new authentication provider or client-platform restriction is introduced
for this milestone.

### Non-goals

- Creating, resizing, assigning, or deleting pools.
- MXC-side Graph discovery, automatic pool selection, remote pool-access
  probing, multi-pool failover, and capacity ranking.
- MXC-owned sign-in, account brokering, consent, token acquisition or refresh,
  and a new authentication SDK API.
- Application-only credentials, managed identity, or substituting an Agent 365
  agent user for the human user.
- Local hypervisor management, RDP clients, or copying local user credentials
  into the Cloud PC.
- Screen sharing and human takeover in the initial implementation.
- Automatic replacement of a lost Cloud PC, workflow scheduling, or preserving
  desktop state after checkin.
- SDK-owned piped process handles, PTY support, or stronger remote
  cancellation guarantees than the native relay implements.

### Existing native preview

The baseline already implements `StatefulSandboxBackend`, development
`1.1.0-alpha` lifecycle contracts, engine dispatch, checkout, readiness polling,
native command execution, and checkin. Its key identifiers are:

| Item | Existing implementation |
| --- | --- |
| Containment / Cargo feature | `w365_agents` |
| Backend module | `src/mxc-sdk/src/backends/w365agents/common/` |
| Request section | `w365Agents.<phase>` |
| Container identity | `w365:{poolId}:{computerId}`, with GUID segments |
| Native execution capability | `microsoft.mxc-exec` |
| Stop semantics | Terminal checkin; the released session is not restartable |

The preview accepts explicit pool/endpoint/token settings and `W365A_*`
environment settings. Retain this configuration path. User token acquisition,
refresh, discovery, and selection are caller responsibilities for this
milestone, not missing backend features.

### Backend onboarding checklist: validated gaps

The assessment below was performed on 2026-10-28 in the original plan worktree,
`users-tbyfield-urban-garbanzo`. That worktree was fast-forwarded to preview
[`df8ead05`](https://github.com/microsoft/mxc/commit/df8ead0515876415bac176da5ab6f9e546847d05),
including backend documentation (`8b3a823e`) and the binding-test compile fix
(`df8ead05`). This plan-only branch starts from `main`, which does not include
that backend or its guide. References to preview implementation and documentation
are pinned to that commit below; the backend tests were not rerun on this branch.
The discarded discovery worktree is not part of this integration baseline.

| Onboarding requirement | Validated status | Remaining action |
| --- | --- | --- |
| Participation and lifecycle trait | Implemented: lifecycle-only `W365AgentsRunner`, phase types, validation, terminal release. | Preserve existing semantics; do not add create-and-run support. |
| Engine registration and ID routing | Implemented: `ContainmentBackend::W365Agents`, checked binding, `w365:` routing, feature-unavailable error. | No new routing layer needed. |
| Experimental authorization | Implemented: registry `experimental: true`; engine checks runtime opt-in before lifecycle dispatch. CLI checks below confirm all five phases. | Retain `--experimental`; feature compilation and development contract alone must not authorize execution. |
| Development contract and generated artifacts | Implemented in `1.1.0-alpha`, including phase adapters, schema, generated TypeScript, and contract tests. | Preserve published contracts; regenerate only if authoritative types change. |
| Published SDK support | Typed V1 targets remain `1.0.0` and do not expose W365 configuration; relayed exec cannot return piped process handles. | Use the native executor for the initial milestone. Aligned versioned typed APIs and any new FFI execution shape are separate follow-on work. |
| Consumer backend guide | Included in the preview: [W365 backend guide](https://github.com/microsoft/mxc/blob/df8ead0515876415bac176da5ab6f9e546847d05/docs/backends/w365-agents/w365-agents.md), plus schema, policy, lifecycle, and architecture links. | Preserve and update the existing guide as behavior changes. |
| Feature-enabled unit validation | Binding-test compile fix is included. W365-filtered library tests, experimental-filtered tests, and all-backend lifecycle gate test pass. | Keep these suites in feature-enabled CI. |
| Protocol functional tests | Three W365 loopback integration suites pass: 10 tests. | Keep these in feature-enabled CI; they do not prove a real reservation lifecycle. |
| Feature-enabled CI and artifacts | Current build workflows do not enable `w365_agents`; scheduled catalog/dispatchers have no W365 entry. Cargo features exist for `mxc-sdk`, `wxc`, and `mxc_ffi`. | Add explicit feature-enabled validation and a documented build/artifact path for the experimental demo; no new build-script architecture is required. |
| Real-host and real-pool validation | DesktopControl interop test exists but skips without `DC_EXEC_EXE`; no live tenant run was performed for this assessment. | Prove provision/start, repeated exec retaining guest state, nonzero exits, terminal release, and error cleanup on the target deployment; wire suitable scheduled validation. |
| Crash-safe checkout recovery | Existing checkout marks ambiguous outcomes `possiblySucceeded`; it does not send a caller-retained checkout key. | Confirm the service contract and document operator reconciliation. Do not promise safe automatic checkout retry. |

These are onboarding and evidence gaps, not a finding that loopback success
proves tenant interoperability. Caller-owned discovery and authentication do
not need implementation inside MXC to complete this scope.

### Experimental opt-in and validation evidence

Keep all three independent requirements: compile with Cargo feature
`w365_agents`, use development contract `1.1.0-alpha`, and explicitly authorize
the experimental backend at runtime. The executor uses `--experimental`;
configuration JSON cannot grant that authorization.

Historical validation on 2026-10-28 in the original plan worktree at the preview
baseline above, with Cargo commands run from `src/` (not rerun on this plan-only
branch):

| Command or check | Result |
| --- | --- |
| `cargo build --locked -q -p wxc --features w365_agents --bin wxc-exec` | Passed. |
| `cargo test --locked -q -p mxc-sdk --features w365_agents --test w365agents_cp_loopback --test w365agents_loopback --test w365agents_correlation_loopback` | Passed, 10 tests. |
| `cargo test --locked -q -p mxc-sdk --features w365_agents --test mxc_contract_v1_1_0_alpha w365_agents` | Passed, 8 tests. |
| `cargo test --locked -q -p mxc-sdk --features w365_agents --lib w365` | Passed, 143 tests after updating to `df8ead05`. |
| `cargo test --locked -q -p mxc-sdk --features w365_agents --lib experimental` | Passed, 16 tests after updating to `df8ead05`; the earlier compile blocker is resolved. |
| `cargo test --locked -q -p mxc-sdk --features w365_agents --lib every_backend_and_phase_keeps_required_gates_before_binding` | Passed, 1 test after updating to `df8ead05`. |
| Feature-enabled `wxc-exec.exe --operation <phase> --dry-run --config-base64 <synthetic-config>` for provision/start/exec/stop/deprovision | Each phase refused without `--experimental`; each passed with it. Non-provision phases also supplied a synthetic `--container-id`. No service calls were made. |

Real DesktopControl interop and live W365 checkout were not run. The offline
CLI checks validate authorization and dry-run routing, not remote execution
or token validity.

### Discovery prototype evidence

The separately supplied `MXC-PoolDiscovery-E2E-Kit` contains an older .NET
`PoolDiscovery.exe`, PowerShell wrappers, and a bundled native executor.
Static inspection and decompilation on 2026-10-23 established the behavior
below; the application was not executed and no live tenant flow was validated.

| Component | Observed behavior | Design use |
| --- | --- | --- |
| User discovery | `GET /me/cloudPcPools` with delegated `CloudPC.Read`; follows `@odata.nextLink` in response order. | Reference for callers; not part of this MXC integration milestone. |
| Authentication | `Azure.Identity` browser/device-code credentials, developer-tool credentials, or supplied tokens; Graph, control-plane, and data-plane tokens acquired separately. | Reuse the resource separation and request sequence, not copied tokens or developer-tool account selection. |
| Endpoint resolution | Extracts pool regions and constructs regional hosts from environment presets; does not consume `poolUrl`. | Evidence of the demo deployment layout, not a general endpoint-discovery contract. |
| Lifecycle driver | Starts `wxc-exec.exe` for provision, start, exec, and deprovision; attempts release in `finally` after a successful provision result. | Reference for integration order; preserve native engine ownership and improve recovery/result handling. |

The prototype does not filter supported pool types, bind one selected account
across independently acquired service credentials, or refresh captured token
strings before later phases. Its endpoint/tenant presets are deployment-specific.
It does not replace the identity, trust, and recovery requirements below.

The current Rust implementation is authoritative when the older sample differs:
retain development contract `1.1.0-alpha`, control-plane API `2.0`, and
data-plane API `1.0`. Do not copy the sample's provision override
`cpApiVersion: "1.0"` or downgrade native defaults.

## 2. Service contracts and readiness

Public documentation and the supplied prototype identify the integration
points below. Public references and prototype code were inspected on
2026-10-23; prototype behavior is not proof of target-service availability.
Preview contracts must be reconfirmed against the target tenant.

| Plane | Documented contract | MXC use |
| --- | --- | --- |
| User pool discovery (caller-owned) | Prototype uses `GET {graphBase}/me/cloudPcPools` with delegated `CloudPC.Read` | Optional caller implementation; not an MXC requirement or permission. |
| Administrative pool discovery | Documented Graph beta `GET /deviceManagement/virtualEndpoint/cloudPcPools` and `GET /deviceManagement/virtualEndpoint/cloudPcPools/{id}` | Administrative reference, not an automatic fallback for the user flow. |
| Endpoint discovery (caller-owned) | `cloudPcAgentPool.poolUrl` | Caller resolves approved coordinates into existing MXC inputs; MXC does not consume Graph metadata. |
| Checkout | Session API `POST /api/pools/{poolId}/sessions?api-version=2.0` | Reserve a Cloud PC; current client reports ambiguous outcomes without automatic retry. |
| Checkin | Session API `DELETE /api/sessions/{sessionId}?api-version=2.0` | Release only the reserved session. |
| Native command execution | Existing TLS HTTP-upgrade relay to `/computers/{computerId}/microsoft.mxc-exec` | Send `EXEC_START`, relay process I/O, and return the remote exit code. |

The prototype's user path requests delegated `CloudPC.Read`. The documented
administrative list/get methods instead require `CloudPC.Read.All`; do not
transfer their permission requirements or query limitations to `/me/cloudPcPools`
without checking its contract. Do not escalate to the administrative API or
request `CloudPC.ReadWrite.All` when user discovery is denied. The demo targets
work/school accounts, not personal Microsoft accounts.
The documented administrative beta methods are available for
the global service only, and Microsoft does not support Graph beta APIs for
production applications. These restrictions apply to callers choosing that
discovery path; MXC does not request Graph permissions in this milestone.
The W365 backend retains its existing experimental gate.
Production readiness is a later milestone and
requires an explicitly supported service contract.

### Contract differences that must be resolved

The Learn session API guide describes a direct `HumanUser` session using
`user-object-id`. The Windows 365 for Agents GitHub integration guide instead
describes the Agent 365 tooling gateway and a distinct agent-user identity.
Those are not interchangeable authentication recipes.

This proposal targets the **direct session API using the logged-in human**.
Before live implementation, the service owner must confirm that ready-to-use
pools support that model, the approved client registration, delegated
audiences/scopes, consent, Conditional Access, and user assignment requirements.
If only agent-user access is supported, report the incompatibility: do not
silently switch identities or replace direct pool selection with the gateway.

The Graph example returns a `poolUrl` ending in `/sessions`, while the Learn
runtime examples describe `/api/pools/{poolId}/sessions`. The endpoint
composition rule is consequently a caller integration question, not string
concatenation for MXC to guess. For this milestone the caller provides already
resolved coordinates through existing inputs; no Graph adapter is required.

The direct guide describes a UUID v4 `x-ms-sessionId` checkout idempotency
header, but the current client does not send one. Confirm target-service
requirements before treating this as an implementation requirement; no safe
checkout replay is claimed. Existing checkin sends that header with the
service session ID in the delete path. Native relay requests use
`x-ms-computerId` matching the computer ID in the request path.

## 3. Architecture and ownership

Extend the Rust backend under
`src/mxc-sdk/src/backends/w365agents/common/`, inside `mxc-sdk`.
Preserve containment `w365_agents`, the `w365Agents` request section, and the
`w365:` container ID prefix. `mxc_engine` owns authorization and dispatch;
`mxc_common` contains only shared request models, contracts, and binding.
The engine owns session routing; executors remain thin. Pool discovery is
caller-owned and is not added to the backend or language SDKs in this milestone.
The older .NET application is a reference harness that launches the executor,
not a second backend to publish. Its discovery and authentication behavior is
optional caller reference material, not code to port into MXC in this milestone.

```mermaid
flowchart LR
    app["Rust, .NET, or Node caller"]
    engine["MXC engine and lifecycle dispatch"]
    backend["Rust W365 backend"]
    identity["Caller-owned authentication provider"]
    graph["Microsoft Graph: optional caller discovery"]
    sessions["W365 session API: checkout/checkin"]
    relay["RemotingInterface relay"]
    exec["Cloud PC: DesktopControl.Exec"]

    app --> graph
    app --> identity
    app -->|"Supplied pool and service configuration"| engine --> backend
    backend --> sessions
    backend --> relay --> exec
```

### Initial client and deployment

The provided demo kit targets Windows. Use a feature-enabled native executor
and a compatible target Cloud PC for the initial demonstration. Runtime
credentials come from the caller; this scope does not select an MXC account
broker or make new cross-platform authentication promises. The backend's
remote transport does not require local virtualization.

### No new session daemon required

`W365AgentsRunner` is stateless between calls. W365 owns the reservation and
guest state; each exec opens a new relay connection to the same Cloud PC.
Persisting context does not require a persistent host connection or a new
W365 daemon. The caller retains the container ID and controls checkin.

The caller owns its identity library, account cache, and credential delivery.
Retain the existing phase fields or per-process environment inputs; no new
daemon is needed for authentication or guest context in this scope.

## 4. Caller-supplied runtime identity and credentials

The caller selects the user, obtains resource-specific tokens, and refreshes
them before later operations. MXC neither signs in nor prompts for consent,
scrapes account caches, or refreshes tokens. Being logged into Windows does
not automatically authorize Graph or W365.

Retain the existing credential inputs:

| Phase | Request field | Environment alternative |
| --- | --- | --- |
| Provision | `w365Agents.provision.cpBearerToken` | `W365A_CP_TOKEN` |
| Start | `w365Agents.start.dpBearerToken` | `W365A_DP_TOKEN` |
| Exec | `w365Agents.exec.bearerToken` | `W365A_DP_TOKEN` |
| Stop | `w365Agents.stop.cpBearerToken` | `W365A_CP_TOKEN` |
| Deprovision | `w365Agents.deprovision.cpBearerToken` | `W365A_CP_TOKEN` |

For the intended human-user flow, the caller supplies
`w365Agents.provision.userType: "HumanUser"` and the corresponding
`userObjectId`. These fields describe checkout intent; they do not
authenticate the user. The existing auxiliary `agentUserToken` support does
not change this milestone into an agent-user flow.

The caller must keep the original reservation's user, authorized control-plane
principal, deployment, and token audiences consistent across phases. The
backend ID does not encode or persist an account association; the service
enforces authorization. Do not claim that MXC independently verifies a
Windows login or prevents all account switches locally.

The older harness acquires Graph, control-plane, and data-plane tokens
independently, and some presets use different resource tenants. Confirm the
approved runtime principals and audiences for the target selfhost; do not
copy preset tenant IDs or substitute an unrelated identity silently. Graph
authentication remains entirely outside MXC.

Per-phase JSON and environment variables contain secrets when used for tokens.
Keep them out of source control, persistent example files, command-line
arguments, logs, and telemetry. A caller may set a restricted child process's
environment rather than embedding tokens in a config file or base64 argument;
environment delivery is not a secret store and still needs protection.
Preserve the existing redaction and host/token pairing rules.

Token expiry is a runtime failure, not a trigger for hidden sign-in or command
replay. The caller must be able to obtain a valid control-plane token for final
release, including after a long exec. Do not add OAuth exchanges, a new SDK
authentication operation, or an account registry in this scope. Guest
application SSO is a separate service capability and is not promised.

## 5. Caller-supplied pool and endpoint trust

Discovery, pool selection, and mapping discovery metadata into service
coordinates are caller responsibilities. Preserve the existing inputs:

| Input | Existing configuration |
| --- | --- |
| Selected pool | `w365Agents.provision.poolId` |
| Control-plane host | Phase `cpBaseUrl` or `W365A_CONTROLPLANE_URL` |
| Data-plane suffix | Phase `dpSuffix` or `W365A_DP_SUFFIX` |
| Runtime credentials | Existing per-phase bearer-token fields or `W365A_CP_TOKEN` / `W365A_DP_TOKEN`; caller obligations are described in section 4. |

MXC does not require `poolUrl`, a Graph token, or a Graph permission. It does
not choose a different pool when checkout fails. The caller retains its
selected pool and deployment coordinates across the reservation and any safe
checkout retry. Capacity and authorization are established by the runtime
services, not by accepting a pool ID.

Preserve the backend's input validation, host/token pairing rules, TLS
certificate validation, and native target construction from pool ID, computer
ID, and the supplied data-plane suffix. Do not derive missing coordinates
from region names, substitute a Graph endpoint or `connectivityUrl`, or
redirect an ambient token to a caller-selected host. Approved token audiences
are configuration, not instructions obtained from a remote URL.

The caller retains trusted deployment coordinates with the owning account
context. A later request or service redirect must not send
credentials or session deletion to an unrelated origin. Reject malformed
identifiers, credential-bearing URLs, and unsupported endpoint forms before
remote actions. These requirements do not introduce a new discovery contract.

### Backend availability remains unchanged

The existing Rust `v1::available_backends()`, .NET
`MxcPlatform.GetAvailableBackends()`, and Node `getAvailableBackends()` report
local host capabilities. The registry marks W365 `ProbeCoverage::NotDetected`;
absence from this list does not determine remote pool access.

Do not add Graph calls, authentication prompts, or trial checkout to these
probes. An authenticated remote pool-access check is deferred with MXC-side
discovery and is not required for this integration milestone. See the
[probe design](backend-support-probe-api.md) for the existing API.

## 6. Lifecycle mapping

Preserve the native preview's lifecycle mapping. Checkout reserves the Cloud
PC, start polls readiness, and repeated exec calls address that reservation.
Unlike a suspendable backend, **stop checks the Cloud PC in and is terminal**.

| MXC operation | W365 behavior | Result and ownership |
| --- | --- | --- |
| Pool selection (caller) | Supply pool ID and approved service coordinates | No MXC discovery or reservation is performed. |
| `provision` | Validate policy, identity, and supplied configuration; check out from the specified pool once | Return opaque container ID and checkout metadata; caller now owns cleanup. |
| `start` | Poll the data-plane status endpoint until `Ready` | Return readiness and the native exec capability. |
| Process `exec` | Run DesktopControl.Exec through `microsoft.mxc-exec` | Relay I/O synchronously and preserve guest context for later execs. |
| `stop` | Delete the session through the control plane | Request terminal checkin; the reservation cannot restart. |
| `deprovision` | Issue the same checkin as an idempotent safety net | Release even if stop was skipped; no claim that reset has completed. |

Do not stop between commands when context must be retained. After stop, a new
deliberate provision is required for another Cloud PC; start never reacquires
one implicitly. Deprovision does not require a successful stop first.

The Learn runtime guide documents checkin returning `204 No Content` before
cleanup finishes. Existing stop/deprovision metadata uses
`releaseRequested: true` and `restartable: false`. Do not replace it with the
previously proposed `releaseStatus` field. The runner retains no local
release-state registry, so later calls depend on the service's response. Do not
report the PC reset, sanitized, or available to another user until the service
provides evidence for those states.

### Per-phase configuration and metadata

| Operation | Proposed input | Proposed output |
| --- | --- | --- |
| Authentication (caller) | Approved account, app registration, and runtime audiences | Valid CP/DP tokens supplied through existing inputs; no new MXC authentication operation. |
| Provision | Caller-supplied `w365Agents.provision.poolId` and existing control-plane settings | Existing container ID and checkout metadata; selected pool is encoded in the ID. |
| Start | Container ID, existing readiness/poll settings, authenticated data-plane settings | `Ready`, optional connection URLs, and exec capability. |
| Exec | Container ID, existing `process` fields and `w365Agents.exec` settings | Relayed stdout/stderr, stdin forwarding, and remote exit code. |
| Stop | Container ID and existing authenticated control-plane settings | `releaseRequested: true`, `restartable: false`. |
| Deprovision | Container ID and existing authenticated control-plane settings | Same release metadata as stop. |

Retain the existing credential fields and phase timeout options; do not add a
new authentication-reference contract. An omitted backend phase configuration remains distinct from a
present empty object through parsing; required-field validation happens before
checkout. Reject unused phase payloads.

`provision-session` and `deprovision-session` are **not** used. Existing MXC
session operations represent WSLc placement sessions and accept WSLc-specific
configuration. A W365 service session is this backend's container reservation,
not a reason to reuse or broaden those operations.

### Idempotence and concurrency

The existing checkout request does not accept or send a caller-retained
idempotency key. A timeout or unusable success response can leave the outcome
unknown; the backend reports `possiblySucceeded` and emits reconciliation
audit context. Do not retry checkout automatically or claim crash-safe
allocation. Confirm the documented `x-ms-sessionId` replay contract with the
service before adding a key or changing retry behavior in a separate slice.

Repeated start performs another readiness poll; it is not a locally tracked
`already_started` transition. Stop and deprovision share the release path,
which treats service 404 as already released rather than `already_stopped`.

The demo caller runs commands sequentially against one reservation and waits
for each relay to complete before releasing it. The preview does not enforce
a per-reservation desktop mutex; do not claim that concurrent exec is refused.
Checkin may terminate in-flight work, so the caller must not race normal
cleanup with a command it wants to finish. Release remains independent of
the exec channel, including when that channel is broken.

Repeated checkin is successful only when the service confirms acceptance or
the authenticated session is already gone. Preserve the difference between
accepted release and unknown release outcome.

## 7. Container identity and recovery

Preserve `W365SandboxId` and its existing `w365:{poolId}:{computerId}` format.
Both segments are validated GUIDs. The pooled path requires computer ID to
equal session ID; checkout rejects a supplied conflicting computer ID.
The ID contains no credentials or endpoints. Callers treat it as opaque.

The earlier versioned-payload proposal is superseded. Do not introduce a
second parser or embed account identity into a new ID format for the demo.
The caller retains the owning account/tenant association separately and
supplies suitable credentials for later calls; the current ID and stateless
runner do not themselves enforce this association.

Persisting the returned container ID is the caller's responsibility. The
current implementation provides no caller-retained checkout recovery key.
Credentials and trusted deployment coordinates are supplied
for each operation. Native exec opens a fresh relay to the retained computer
ID; checkin does not require a live exec channel or an earlier runner object.
Confirm the service permits exec reattachment after client failure. Never
repeat checkout merely to recover a relay connection.

The ID protects addressing, not guest work. W365 reset or idle eviction loses
desktop state. Callers checkpoint useful work outside the Cloud PC.

### Liveness

The service currently documents a 30-minute inactivity timeout and no fixed
maximum active duration. Token lifetime is independent of session lifetime.
These are service properties, not MXC guarantees.

Do not enable hidden indefinite keepalive. Initially the caller owns activity.
Confirm that the service's inactivity rules account for native relay traffic,
including commands that run without producing output. The initial demo keeps work
bounded and releases explicitly; it does not require a new heartbeat service.
Do not promise multi-day retention based solely on repeated native exec.

## 8. Native command execution

Use the existing `StatefulSandboxBackend::exec` implementation and native
process protocol:

1. Parse the container ID and resolve the authenticated data-plane target.
2. Connect over TLS and perform the existing HTTP upgrade for
   `microsoft.mxc-exec`.
3. Send `EXEC_START` with command line, working directory, explicit environment,
   and timeout from `mxc_common::models::ExecutionRequest`.
4. Run the duplex relay, forwarding host stdin and remote stdout/stderr.
5. Return the remote exit code when the command completes, leaving the Cloud
   PC checked out for another exec.

Reuse `exec/transport.rs`, `exec/frame.rs`, `exec/payload.rs`, and
`exec/relay.rs`; do not add another command runner. The target deployment
must expose the compatible DesktopControl.Exec host and relay capability.
Pool availability alone does not prove that this capability is installed.

### Supported execution shape

The current implementation runs synchronously under `ExecStdio::Relayed`.
It performs I/O itself, then returns an `ExecHandle` with null pipe sentinels
and a waiter containing the completed exit code. Those null handles describe
internal relay, not SDK-owned pipes or lost output.

`ExecStdio::Piped` is rejected through `unsupported_piped_exec` before execution;
PTY is unsupported through the trait's default refusal. Do not advertise
SDK-owned streaming handles, nonblocking spawn, or PTY capability.
The returned terminator is a no-op after completion, not a live remote kill
handle. The transport's documented disconnect/kill-on-close behavior requires
real-host validation, especially for descendants and network failures.

`w365_exec_demo` exercises the relay using caller-supplied connection details.
It simulates checkout and is not the integrated identity/lifecycle
demo. Keep its optional plaintext transport a local test seam, not the live
deployment connection path.

The separate `PoolDiscovery.exe` harness drives the native executor through
child processes and attempts release in `finally` after provision returns.
Its self-test uses a local Graph mock and native dry-run phases; this does not
prove live token acquisition, checkout, or guest command execution.
Reuse the integration sequence, not its success-shaped result fallback:
preserve actual nonzero command exits and reject missing or malformed results.
Normal demo completion and failure both attempt bounded final cleanup; retain
both the primary failure and any cleanup failure.

## 9. Policy and containment

The isolation boundary is the W365 Cloud PC and its tenant-managed policy.
MXC must not imply that selecting a pool makes local filesystem, network,
or UI restrictions enforceable remotely.

| Field or capability | Provision | Start / exec / stop / deprovision |
| --- | --- | --- |
| Host filesystem path policy and mounts | Rejected | Rejected |
| MXC workload network policy, host allow/deny rules, or runtime proxy | Rejected | Rejected |
| MXC UI/clipboard restrictions | Rejected | Rejected |
| Explicit command environment and working directory | Not applicable | Forwarded in exec payload; not host mounts or identity delegation |
| Remote-policy acknowledgment | No additional field in the preview | No additional field |
| Timeout | Existing checkout timeout | Existing readiness and exec timeout fields; bounded release HTTP timeout |

Reuse `honor_matrix_check` and the development contract's field rejection.
The earlier `policyMode: "poolManaged"` proposal is not needed for the demo
and is not part of the preview contract. Unsupported policy fails rather
than being silently ignored or converted into an all-allow claim. Explicit
exec environment variables are data sent to the remote process; do not add
automatic forwarding of host credentials or the host environment.

The control client's HTTPS access to Graph/W365 is separate from the Cloud
PC's workload egress policy. Do not reinterpret workload network grants as
control-plane connectivity configuration.

Pool administrative policy can constrain the Cloud PC, but discovery metadata
alone does not prove its effective enforcement. Do not hash pool IDs as proof
of security settings. Extend policy identity only for declared, non-secret
facts, explicitly recording that guest policy is externally managed; document
the lack of effective-policy attestation.

## 10. Errors, retries, and cleanup

Reuse the existing closed `MxcErrorCode` set. Put service-specific reasons and
bounded retry hints in `details`; use `ApiFailure` to identify the operation and
HTTP/service status. Sanitize messages and never attach whole HTTP responses.

| Failure | MXC result | Behavior |
| --- | --- | --- |
| Invalid request or unsupported fields | `malformed_request` | Reject before any reservation. |
| Unenforceable policy | `policy_validation` | No checkout. |
| Missing experimental opt-in or build feature | `backend_unavailable` | Reject before backend execution; no fallback. |
| Invalid/expired credentials or service authorization denial | Existing `backend_error` with operation-specific `auth_denied` / `pool_authorization_denied` | Caller obtains suitable credentials; MXC does not prompt, refresh, broaden permissions, or select a different pool. |
| Missing pool or pool endpoint not ready | `backend_error`, reason `pool_not_found` or `pool_not_ready` | No allocation. |
| Capacity exhausted or 429 | `backend_error`, reason `capacity_unavailable` or `throttled` | Bounded retry only when safe; honor valid retry hints. |
| Invalid container identity | `malformed_id` | Reject malformed IDs before remote action. The service, not an MXC account registry, authorizes the supplied principal. |
| Missing/expired service session | Existing operation-specific mapping; release 404 is accepted as already released | Do not promise uniform `stale_id` mapping or reacquire automatically. |
| Exec before readiness | Existing service/runner error | Caller starts and waits for readiness before exec. |
| SDK-owned piped exec | Existing `unsupported_piped_exec` (`backend_error`) | Reject before running anything. |
| PTY | `unsupported_phase` | No remote command runs. |
| Uncertain checkout/exec/release outcome | Preserve existing transport outcome and `possiblySucceeded` checkout details | Retain returned IDs and reconciliation context; never replay checkout or commands automatically. |

The caller supplies refreshed credentials when needed. MXC performs no token
refresh or automatic command replay. A timeout, disconnection,
or generic 5xx after sending an exec request is not proof that it did not run.
Do not automatically replay commands. Audit the existing relay's
transport-close/sentinel and timeout behavior before claiming that every
returned code is a confirmed remote completion; do not invent stronger
guarantees in the integration.

Use bounded deadlines for checkout, readiness, actions, and release.
Respect service throttling without unbounded retries. An ambiguous checkout
is not automatically retried; verify any future replay contract with the
service before implementing recovery retries.

Preserve the existing native relay timeout and disconnect behavior. Closing
the client connection is not proof of rollback or process-tree termination.
Do not advertise a caller-owned cancellation handle that the synchronous
relay cannot provide.
Cleanup uses a separate bounded deadline rather than inheriting an already
canceled action token.

If checkout succeeds but local result construction fails, attempt checkin
with the same account and preserve both failures. A failure after the caller
has received its container ID retains the reservation for explicit cleanup.
Process death during checkout remains an uncertain outcome requiring
service-supported reconciliation; no caller-retained recovery key exists today.
The service's idle eviction is a last resort, not successful cleanup evidence.

## 11. Contracts, SDKs, build, and packaging

The backend is already registered in the mutable `1.1.0-alpha` development
contract under containment `w365_agents` and section `w365Agents`. Reuse its
per-phase types, adapters, binding, and engine dispatch. The caller supplies
`poolId` and service coordinates through the existing configuration. Do not
introduce another containment or new discovery inputs.

No new discovery or authentication contract is required for this milestone.
Any necessary lifecycle contract additions belong only in the development
contract. Preserve optional presence and backend-owned defaults.
Regenerate schema/TypeScript artifacts when authoritative types change.
Never modify released contracts or hand-edit generated artifacts.

Keep contract publication, runtime experimental authorization, Cargo feature
availability, identity readiness, and pool capacity as distinct checks.
Preserve the existing engine registration and experimental gate. Do not
add fallback from generic `process` intent to a billable remote reservation.

The current typed V1 SDKs emit published `1.0.0`, which cannot describe this
backend. Development starts through versioned MXC request JSON entry points
using the registered development contract. Do not silently change V1's target
or publish typed APIs that emit an incompatible older contract.

At publication, add aligned versioned Rust, .NET, and Node APIs for provision,
supported execution shapes, and cleanup. Account acquisition, pool discovery,
and remote-access APIs are outside this milestone.
Compare names, units, optional fields, ownership, and results across all three
references. .NET cancellation tokens come last; all JSON types and options
are registered in `MxcJsonContext`, use `MxcJson`, and gain AOT smoke coverage.

Use the existing opt-in Cargo feature `w365_agents`. From `src/`, the native
executor can be built with `cargo build -p wxc --features w365_agents`.
Do not claim a `build.bat --with-w365` flag or `wxc-w365-broker` binary exists.
No new MXC session daemon is required by this design.

Language packages that expose this preview need matching feature-enabled
native artifacts. Validate architecture,
version compatibility, and required signatures through existing packaging.
No package contains a tenant credential. The Windows demo does
not imply the existing transport is Windows-only or remove its loopback
coverage on other hosts.

## 12. Validation and delivery slices

The demo/selfhost acceptance path is one signed-in user with caller-supplied
pool and deployment configuration, checking out one Cloud PC, running multiple
native commands with retained guest context, and explicitly releasing it.
No Graph discovery or pool-selection test is required in MXC.
Caller-supplied credential handling, endpoint trust, explicit errors, and reliable release
remain required even for this milestone.

Broad SDK publication and the full production-readiness matrix below are
follow-on work, not prerequisites for demonstrating the initial flow.
Implementation slices still need the repository's applicable functional CI
coverage; a successful manual demo does not replace it.

### Functional acceptance scenarios

| Scenario | Required assertion |
| --- | --- |
| Caller-supplied configuration | Existing pool and endpoint inputs reach the native lifecycle without Graph calls or automatic pool selection; invalid or missing required inputs fail before checkout. |
| Pool failures and retries | An unavailable supplied pool does not trigger fallback; a safe retry retains the same pool and deployment coordinates. |
| Availability probes | Existing host probes remain local and account-free; no remote pool-access check is added. |
| Identity boundary | Service rejects unauthorized runtime credentials; the caller retains suitable owner credentials for cleanup. No independent local account binding is claimed. |
| Reservation persistence | Provision/start, execute a command that writes a marker in the guest, then read it through a later exec process on the same container ID. Exactly one checkout occurs. |
| Terminal stop | Stop requests checkin and returns `restartable: false`; no later start silently checks out a replacement. Deprovision remains a safe cleanup attempt. |
| Explicit release | Checkin deletes only the session, uses the required header, reports acceptance, and eventually restores capacity on the test pool. |
| Retry safety | A lost checkout response reports possible success without automatic reallocation; a lost action response does not replay that action. |
| Faults | Client restart, token expiry, throttling, capacity exhaustion, relay failure, and ambiguous deletion surface failures with available cleanup/reconciliation context. |
| Credential continuity | Separate CP/DP tokens are supplied by the caller; refreshed credentials can be supplied for a later release without MXC sign-in or automatic command replay. |
| Prototype compatibility | Use native control-plane API `2.0` and data-plane API `1.0`; missing supplied endpoints do not trigger guessed regional hosts; nonzero command exits and cleanup failures are preserved. |
| Policy | Unsupported filesystem/network/UI requests fail before checkout; no new policy acknowledgment is required. |
| Trust and privacy | Host/token pairing and TLS validation remain enforced; diagnostics redact tokens and credential-bearing URLs. Remote stdout/stderr and the existing reservation reconciliation audit records remain intentional outputs. |
| Native relay | Compatible DesktopControl.Exec host executes real commands, forwards stdin/stdout/stderr, and reports nonzero exit codes; SDK-owned piped exec and PTY fail before execution. |
| Eviction and liveness | Validate native exec idle/eviction behavior with the service; no automatic reacquisition or hidden background keepalive. |
| SDK/packaging (follow-on) | Each exposed SDK operation uses feature-enabled native artifacts without falsely promising piped spawn; new .NET serialization paths have native AOT coverage. |

Extend the existing `w365agents_loopback`, `w365agents_cp_loopback`, and
`w365agents_correlation_loopback` tests with configuration/credential coverage.
Use `w365agents_e2e_desktopcontrol` against an actual compatible host for
native process interop; it is opt-in through `DC_EXEC_EXE` and skips when that
binary is absent. Neither loopback nor local host interop proves real pool
access, delegated identity, or production relay deployment.
Wire a W365 suite through the existing backend validation dispatchers and
`scripts/ci/validation-test-matrix.json` onto suitable scheduled hosts.

Live validation needs a dedicated non-production tenant/pool, spending and
concurrency limits, and an approved delegated test identity capable of
caller-owned unattended renewal under the tenant's actual policies. Do not bypass MFA or
Conditional Access to make CI green. If no compliant test identity is
available, live validation is blocked and must be reported as such.

Each live scenario records bounded reconciliation context, retains a returned
container ID immediately, and attempts
release in final cleanup, even after assertion failure. Collect bounded,
redacted service request IDs and release outcomes. Reconcile leaked test
reservations using service-supported lookup; never delete the shared pool
as cleanup.

### Reviewable implementation sequence

1. **Verify the direct-user service and native execution contracts.** Record supported account flow,
   resource-tenant mapping, least-privilege runtime scopes, approved supplied
   coordinates, ambiguous-checkout reconciliation, readiness, and checkin
   semantics. Prove checkout with caller-supplied configuration, one
   DesktopControl.Exec command, and release in the target demo/selfhost tenant.
   Confirm the compatible exec capability is deployed there.

2. **Complete feature-enabled build and validation wiring.** Enable W365 explicitly in the
   relevant test/build jobs, verify opt-in refusal and feature-unavailable
   behavior, and provide feature-enabled demo artifacts. Keep W365 experimental.

3. **Validate caller configuration and recovery.** Preserve existing pool,
   endpoint, credential, and phase inputs. Verify caller-owned continuity,
   credential failures, and explicit unknown checkout outcomes without adding
   authentication providers, Graph calls, or changing host probes.

4. **Complete the integrated command demo.** Reuse readiness polling and the
   native relay for sequential commands in the same reservation, then terminal
   stop/deprovision. Show stdin/output/exit status and retained guest state.
   Wire the live scenario into scheduled CI.

5. **Publish aligned SDK support.** After a supported contract publishes,
   advance SDK targets through the normal versioning process, expose typed
   APIs, and update the three SDK references, examples, and AOT checks.

## 13. Decisions required before implementation

| Decision | Why it matters |
| --- | --- |
| Is delegated human-user access supported for these ready-to-use pools? | Non-negotiable identity requirement; agent-user-only access does not satisfy it. |
| Which caller app registration, runtime audiences/scopes, and resource-tenant mapping are approved? | Deployment prerequisite for valid caller-supplied tokens, not a requirement to add an MXC identity provider. |
| Which supplied service origins are approved for the target environment? | Caller discovery is outside MXC; prototype presets are not a general trust contract. Retain the later Rust defaults: control-plane `2.0`, data-plane `1.0`. |
| Does the target pool deploy the compatible `microsoft.mxc-exec` capability? | Required for native command execution. |
| What native exec reattach, idle, timeout, and disconnect guarantees does the service provide? | Determines context retention and cancellation claims. |
| Does the target service require a checkout key, and what reconciliation is available for ambiguous outcomes? | Current client does not send a key or guarantee safe replay; resolve any required service change before live use. |
| What guest policy evidence is available? | Determines whether any future MXC policy can be enforced or attested. |
| What compliant delegated CI identity and dedicated pool are available? | Required for meaningful scheduled backend validation. |

## References

### MXC

- [Agent instructions](../../../AGENTS.md)
- [Repository instructions](../../../.github/copilot-instructions.md)
- [Repository architecture](../architecture/repository-architecture.md)
- [Container lifecycle and backend plug-in guide](../architecture/container-lifecycle.md)
- [WSLc lifecycle and daemon ownership](../../backends/wslc/wslc-state-aware.md)
- [Versioning](../architecture/versioning.md)
- [Feature authoring](../guides/authoring-a-new-feature.md)
- [Validation infrastructure](../build-and-test/ci-validation-infrastructure.md)
- [Existing W365 runner (preview baseline)](https://github.com/microsoft/mxc/blob/df8ead0515876415bac176da5ab6f9e546847d05/src/mxc-sdk/src/backends/w365agents/common/runner.rs)
- [W365 backend usage and prerequisites (preview baseline)](https://github.com/microsoft/mxc/blob/df8ead0515876415bac176da5ab6f9e546847d05/docs/backends/w365-agents/w365-agents.md)
- [Native exec transport and relay (preview baseline)](https://github.com/microsoft/mxc/blob/df8ead0515876415bac176da5ab6f9e546847d05/src/mxc-sdk/src/backends/w365agents/common/exec/mod.rs)
- [Connection-driven exec demo (preview baseline)](https://github.com/microsoft/mxc/blob/df8ead0515876415bac176da5ab6f9e546847d05/src/mxc-sdk/examples/w365_exec_demo.rs)
- [DesktopControl.Exec interop test (preview baseline)](https://github.com/microsoft/mxc/blob/df8ead0515876415bac176da5ab6f9e546847d05/src/mxc-sdk/tests/w365agents_e2e_desktopcontrol.rs)

### Windows 365 and Microsoft Graph

- [Windows 365 for Agents overview](https://learn.microsoft.com/en-us/windows-365/agents/introduction-windows-365-for-agents)
- [Graph pool list and permissions](https://learn.microsoft.com/en-us/graph/api/virtualendpoint-list-cloudpcpools?view=graph-rest-beta)
- [Graph pool get](https://learn.microsoft.com/en-us/graph/api/cloudpcpool-get?view=graph-rest-beta)
- [Agent pool resource and `poolUrl`](https://learn.microsoft.com/en-us/graph/api/resources/cloudpcagentpool?view=graph-rest-beta)
- [Direct session API overview](https://learn.microsoft.com/en-us/windows-365/agents/mcp-tool-overview)
- [Agent session lifetime and release](https://learn.microsoft.com/en-us/windows-365/agents/agent-session-lifecycle)
- [Agent 365 identity model: distinct from the proposed human-user flow](https://github.com/microsoft/windows-365-for-agents/blob/main/docs/authentication.md)
- [Agent 365 gateway API: distinct from the proposed direct session path](https://github.com/microsoft/windows-365-for-agents/blob/main/docs/api-reference.md)
