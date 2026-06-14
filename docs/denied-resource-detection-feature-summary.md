# Denied-Resource Detection & Permission-Asking — Feature Summary

> Accurate, source-derived summary of the denied-resource detection / permission-asking
> feature as it exists on branch `feature/denied-resource-capture`. Every capability
> below was read from the actual code; where the companion architecture document
> ([`denied-resource-detection-architecture.md`](denied-resource-detection-architecture.md))
> overstates what is implemented, the discrepancy is flagged explicitly in
> [§9](#9-known-limitations--future-work) and the
> [discrepancy callouts](#discrepancies-vs-the-architecture-doc).

## Table of contents

1. [Overview](#1-overview)
2. [Capabilities](#2-capabilities)
3. [Architecture](#3-architecture)
4. [Resource / capability support matrix](#4-resource--capability-support-matrix)
5. [API reference (SDK)](#5-api-reference-sdk)
6. [Windows service & install](#6-windows-service--install)
7. [Platform support](#7-platform-support)
8. [Testing done](#8-testing-done)
9. [Known limitations / future work](#9-known-limitations--future-work)
10. [References](#10-references)

---

## 1. Overview

The denied-resource detection feature lets an MXC sandbox caller discover exactly which
resources a sandboxed process was *denied* access to, surface them as structured data,
let a user approve specific ones, and regenerate a relaxed `SandboxPolicy` that grants
the approved resources — turning the previous manual "run → guess → edit policy → re-run"
trial-and-error loop into a "run → detect → approve → re-run" workflow. Detection is
**tiered**: a kernel-accurate ETW path (a Windows service that decodes access-check
events and serves them over a per-user named pipe) is preferred, with regex-based parsing
of process stdout/stderr as an always-available fallback. Approved file paths are merged
into `filesystem.readonlyPaths` / `readwritePaths` and approved network hosts into
`network.allowedHosts[]`, with system-critical paths and managed policies rejected.

---

## 2. Capabilities

### 2.1 SDK (TypeScript, `sdk/src/`)

**`denied-resources.ts` — output parsing (`parseDeniedResources`)**

- `parseDeniedResources(output: string): DeniedResourceInfo[]` scans interleaved
  stdout/stderr against a library of **17 regex patterns** (12 filesystem + 5 network).
- Filesystem patterns cover Python (`PermissionError`, `OSError`…`Access is denied`),
  Node.js (`EACCES`, `EPERM`), PowerShell (`Access to the path '…' is denied`,
  `UnauthorizedAccessException`), .NET (`IOException`…access denied), native Windows
  ("Access is denied" before/after a drive-letter path), Linux (`permission denied: /…`),
  a generic `cannot open/access/read/write/create/delete` matcher, and Rust
  (`Os { code: 5, … }`).
- Network patterns cover Node `ECONNREFUSED`, Python `ConnectionRefusedError`, a generic
  `Connection refused`, DNS failures (`getaddrinfo ENOTFOUND` / `DNS lookup failed`), and
  `WinHttpSendRequest` errors.
- Every parsed result is `source: 'output_parsing'`, `confidence: 'low'` (output can be
  faked), deduplicated by normalized path (or `network:<host>`), with `matchedLine` /
  `matchedPattern` for diagnostics. Performance is bounded: a 1 MiB total cap, an 8 KiB
  per-line cap, and a single keyword pre-filter regex before the full pattern sweep.
- **Supported resource types are exactly `'file' | 'network'`** (the `DeniedResourceInfo.resourceType`
  union). There are no registry/COM patterns.

**`denial-service.ts` — ETW service client**

- `isDenialServiceRunning(): boolean` — probes the per-user pipe with `fs.accessSync`
  (namespace presence, not an exclusive handle); classification is delegated to the
  exported helper `pipeProbeErrorIndicatesRunning(err)` (`ENOENT` → down, any other errno
  → up, no code → fail-closed).
- `readDeniedResources(filter: DenialFilter): Promise<DeniedResourceInfo[]>` — one-shot
  `snapshot` query; validates and maps each event; returns `[]` on any failure (graceful
  fallback).
- `subscribeToDenials(filter, callback): () => void` — opens a `stream` subscription
  (sends `mode: 'stream'` **and** legacy `subscribe: true`), invokes `callback` per
  validated event, returns a dispose function; no-op when the service is unavailable.
- `getServiceBinaryPath(): string | null` — locates `mxc-diagnostic-console.exe` across
  SDK-bundled (`bin/<triple>/`) and dev build-output (`src/target/...`) locations, for
  **both** `x86_64-pc-windows-msvc` and `aarch64-pc-windows-msvc` (triple chosen from
  `os.arch()`).
- `validateDenialEvent(value): value is DenialEvent` — structural type-guard that
  defensively checks every field (non-empty `path` ≤ 32 KiB, enum membership for
  `resourceType`/`accessType`, integer ≥ 0 `pid`, string `containerName`/`timestamp`,
  optional finite `eventId`). The pipe peer is not cryptographically authenticated, so
  this runs on every received event.
- `mapEventToResourceInfo(event): DeniedResourceInfo | null` — maps a wire `DenialEvent`
  to a `DeniedResourceInfo` with `source: 'etw_service'`, `confidence: 'high'`. **Returns
  `null` for any `resourceType` other than `'file'` or `'network'`** (i.e. `'other'` —
  registry/unclassified — is discarded, never actionable).
- Types: `DenialEvent` (`path`, `resourceType: 'file'|'network'|'other'`, `accessType`,
  `containerName`, `pid`, `timestamp`, optional `eventId`), `DenialFilter`
  (`pid?` — **primary key**, `containerName?` secondary, `since?`), `DenialRequest`
  (`mode: 'snapshot'|'stream'`, plus optional `containerName`/`pid`/`since`/`subscribe`).
- Security posture: `getDenialServicePipeName()` **fails closed** — it returns `null` on
  non-Windows and whenever the current user's SID can't be resolved (via `whoami /user`),
  so the SDK never connects to an un-SID-qualified pipe.

**`tiered-detection.ts` — unified "tiered" API**

- `getDeniedResources(options: DetectionOptions): Promise<DetectionResult>` queries the
  two tiers in priority order — **Tier 1 ETW service** (only when `pid` or
  `containerName` is supplied *and* the service is running) then **Tier 2 output
  parsing** (`options.output`) — and merges with `deduplicateDenials` (ETW > output
  parsing). `DetectionResult` reports `deniedResources`, `sourcesUsed`,
  `serviceAvailable`, and a `serviceInstallHint` string when the service is down.
- `generateUpdatedPolicyFromDetection(originalPolicy, detectionResult, approvedPaths, options?)`
  wraps `generateUpdatedPolicy`, **throws** if `policyMode === 'managed'`, and additionally
  routes approved **network** denials into `network.allowedHosts[]` (setting
  `allowOutbound = true`, host extracted from `host:port` incl. IPv6 bracket form,
  deduplicated).
- `deduplicateDenials` is exported from this module but **not re-exported** from the
  package root (`index.ts`).

**`policy-regen.ts` — policy regeneration**

- `generateUpdatedPolicy(originalPolicy, approvedPaths: ApprovedPath[], options?): PolicyGenerationResult`
  deep-clones the policy, merges approved paths into `readonlyPaths`/`readwritePaths`
  (readwrite supersedes readonly), deduplicates (case-insensitive on Windows), and
  reports `{ policy, rejected, addedCount }`.
- Safety: **rejects symlinks/junctions** (TOCTOU), canonicalizes existing paths via
  `realpathSync`, and (unless `rejectSystemCriticalPaths: false`) rejects system-critical
  locations — Windows dir, Program Files / (x86), ProgramData, other users' profiles, UNC
  paths, System Volume Information; on Linux `/bin`, `/usr/bin`, `/etc`, `/proc`, etc.
- `PolicyGenerationOptions`: `rejectSystemCriticalPaths` (default `true`),
  `useParentDirectories` (default `false`). `ApprovedPath`: `{ path, accessLevel:
  'readonly' | 'readwrite' }`.

### 2.2 Rust (`src/tools/mxc_diagnostic_console/src/`)

**`denial_event.rs` — wire format & query matching**

- `enum ResourceType { File, Network, Other }` (lowercase serde). **There is no
  `Registry` or `Com` variant.** `ResourceType::from_object_type(obj_type)` maps
  `"File"` → `File`, `""` (empty) → `Network`, **and everything else — including `"Key"`
  (registry) — → `Other`.**
- `enum AccessType { Read, Write, Execute, Unknown }`.
- `struct DenialEvent` (camelCase serde): `container_name`, `pid: u32`,
  `resource_type`, `object_name` (serialized as `path`), `access_requested` (as
  `accessType`), `timestamp`, `event_id: u16`. PID is the documented primary correlation
  key; `container_name` is a best-effort label and may be empty.
- `struct DenialQuery` (`mode`/`container_name`/`pid`/`since`/legacy `subscribe`) with
  `resolved_mode()` precedence (explicit `mode` > legacy `subscribe: true` > default
  `Snapshot`) and `DenialEvent::matches_query()` (PID exact; non-empty container exact;
  `since` lexicographic on fixed-width ISO-8601). `struct DenialResponse { events,
  service_version }`.

**`etw.rs` — ETW consumer & extraction**

- Subscribes to two providers: the MXC OS-side TraceLogging provider
  `{f6ec123e-314e-400b-9e0a-151365e23083}` and Microsoft-Windows-Kernel-General
  `{a68ca8b7-004f-d7b6-a698-07e2de0f1f5d}` (AccessCheckLog etc.).
- `build_denial_from_access_check()` is the **only** function that produces a
  `DenialEvent` for the denial pipe, and **only for `ObjectType == "File"`** — registry
  (`Key`), network, and other object types map to `ResourceType::Other` and are **not
  emitted**. `container_name` is left empty (only a numeric LowBox number is available);
  PID (from the event header) is the correlation key.
- Access type is inferred from the first available access-mask property
  (`DesiredAccess` → `AccessMask` → `GrantedAccess`), parsed as hex or decimal, then
  classified write > execute > read > unknown by Win32 file-rights bits.
- `LEARNING_MODE_VIOLATION_EVENT_ID = 27` events are **explicitly not forwarded** to the
  denial pipe (`try_send_denial_event` returns early); they remain visible only on the
  interactive console / collect display path.

**`denial_pipe.rs` — per-user named-pipe server**

- Pipe name prefix `\\.\pipe\mxc-denials`, full name `\\.\pipe\mxc-denials-{SID}`
  (`denial_pipe_name()`). Serves `Snapshot` (respond + disconnect) and `Stream`
  (newline-delimited JSON until disconnect) modes.
- Bounds: per-PID buffer ≤ 1024 events (`MAX_EVENTS_PER_KEY`), ≤ 10 000 total
  (`MAX_TOTAL_EVENTS`), age eviction at 1 h (`MAX_KEY_AGE_SECS`), ≤ 32 subscribers,
  ≤ 64 client threads, 64 KB buffers, container-name length cap 256. **`BufferKey` is
  keyed on `pid` only** (container name is *not* part of the key).

**`service.rs` — Windows service integration**

- Registers `MxcDiagnosticService` (display "MXC Diagnostic Service") as
  `ServiceType::OWN_PROCESS`, `AutoStart`, account `NT AUTHORITY\LocalService`, launched
  with `--service`. `install_service` / `uninstall_service` / `run_as_service`.
- Documented deployment caveat: as `LocalService` (SID `S-1-5-19`) the service creates
  `mxc-denials-S-1-5-19`, reachable only by SYSTEM/service-context callers; an
  interactive SDK (running as the logged-in user) must instead talk to the **console**
  instance, which creates the pipe under the user's SID.

**`pipe_utils.rs` — shared pipe security/util**

- `build_pipe_sddl()` builds the SDDL from the **current process token's SID**:
  `D:(D;;GA;;;S-1-15-2-1)(A;;GRGW;;;{user_sid})(A;;GA;;;SY)(A;;GA;;;BA)` — i.e. **deny
  ALL_APP_PACKAGES**, grant the *specific current user* generic read/write, grant SYSTEM
  and Built-in Administrators generic-all. Returns `None` (refuse to create the pipe) if
  the SID can't be resolved.
- `create_pipe_with_sddl()` creates message-mode pipes with `FILE_FLAG_FIRST_PIPE_INSTANCE`
  (anti-squatting). `run_accept_loop()` resolves the **client PID server-side** via
  `GetNamedPipeClientProcessId` (never trusts a client-supplied PID) and enforces the
  max-client cap.

**`src/core/wxc_common/src/models.rs` — `DeniedResource`**

- `struct DeniedResource { path, resource_type: String, access_denied: String, confirmed:
  bool }`. Doc-comments enumerate `resource_type` values `"file"`, `"directory"`,
  `"registry"` and `access_denied` values incl. `"read_write"`, and `confirmed`
  distinguishes AccessCheck-confirmed (`true`) from heuristic/output-parsed (`false`).
  **This struct is defined but not wired into the ETW/denial-pipe path** (that path uses
  `DenialEvent`, not `DeniedResource`); it is a latent model. See the discrepancy notes.

### 2.3 Confirmed vs heuristic

| Detection | Confidence | confirmed |
|---|---|---|
| ETW AccessCheckLog (File only) | `high` (kernel-verified) | yes |
| Output parsing (file or network) | `low` (output can be faked) | no |

### Discrepancies vs the architecture doc

The architecture document is **aspirational** and describes a larger surface than the
code actually ships. Verified mismatches (real supported set is **file + network only**):

1. **Resource set.** The doc repeatedly claims file/network/**registry**/**COM**
   coverage (§1, §5, §8 matrix). The code supports only **file** (ETW + output) and
   **network** (output-parsing only). The Rust `ResourceType` enum has no `Registry`/`Com`
   variant; the SDK union is `'file' | 'network'`.
2. **`"Key"` mapping.** Doc §5.4 says `ObjectType "Key"` → `ResourceType::Registry`; the
   code maps `"Key"` → `Other` (and `Other` is discarded).
3. **ETW network/registry.** `build_denial_from_access_check` emits **only** `File`;
   network ("" object type) and registry denials are computed then dropped. So Tier-1 ETW
   never yields network or registry events despite §8's "Network ✅ ETW".
4. **Learning-mode events.** Doc §5.4 references a `build_denial_from_learning_mode()`
   that forwards Event ID 27; no such function exists and event 27 is explicitly **not**
   forwarded to the pipe.
5. **Pattern count / runtimes.** Doc §4/§7 claims "21 regex patterns" across Python,
   Node, PowerShell, .NET, Rust, Go, C/C++, Java, Ruby. Actual: **17 patterns**, file +
   network only, with **no** Go/Java/Ruby/C++-specific patterns.
6. **Buffer key.** Doc §5.5 says the buffer is keyed by container name + PID; the code
   keys on **PID only**.
7. **Pipe SDDL.** Doc §6.1/§11 says "Authenticated Users"; the actual SDDL grants the
   **specific current-user SID** (GRGW) plus SYSTEM/Administrators (GA) and denies
   ALL_APP_PACKAGES — no Authenticated-Users ACE.
8. **Timestamp format.** Doc wire examples show fractional seconds
   (`…T16:30:00.000Z`); the code requires fixed-width `YYYY-MM-DDTHH:MM:SSZ` for the
   lexicographic `since` comparison to be correct.
9. **`DeniedResource`/`directory`.** Doc and the `models.rs::DeniedResource` doc-comments
   mention a `directory` resource type and a `read_write` access value; these are not
   exercised by the live pipeline.

---

## 3. Architecture

```
 sandboxed process attempts access
            │  (denied — sandbox stays fully enforced)
            ▼
 Windows kernel  ── AccessCheckLog (Event 4907) ETW event
            │
            ▼
 mxc-diagnostic-console (ETW consumer, etw.rs)
   build_denial_from_access_check()  →  DenialEvent  (File only)
            │  mpsc
            ▼
 denial pipe server (denial_pipe.rs)
   per-PID ring buffer, snapshot + stream modes
            │  \\.\pipe\mxc-denials-{SID}   (SID-qualified, restrictive SDDL)
            ▼
 SDK client (denial-service.ts)
   validateDenialEvent → mapEventToResourceInfo
            │
            ▼  (merged with Tier-2 output parsing in tiered-detection.ts)
 getDeniedResources()  →  DetectionResult
            │  user approves paths/hosts
            ▼
 generateUpdatedPolicyFromDetection() / generateUpdatedPolicy()
            │
            ▼
 relaxed SandboxPolicy  →  re-run sandbox
```

**Data flow.** A denied access produces a kernel ETW AccessCheckLog event; the diagnostic
console's ETW consumer decodes File denials into `DenialEvent`s and forwards them over an
mpsc channel to the denial-pipe server, which buffers them per-PID and serves them over a
per-user, SID-qualified named pipe (`\\.\pipe\mxc-denials-{SID}`). The SDK client connects,
sends a JSON `DenialRequest` (`snapshot` or `stream`), structurally validates each
newline-delimited JSON event, and maps it to a `DeniedResourceInfo`. `tiered-detection.ts`
merges these high-confidence ETW results with low-confidence output-parsing results,
deduplicating ETW-over-output. After the caller collects user approvals, policy
regeneration emits a relaxed `SandboxPolicy` for the re-run.

**Wire protocol.** Named pipe `\\.\pipe\mxc-denials-{SID}`, `PIPE_TYPE_MESSAGE |
PIPE_READMODE_MESSAGE`, newline-delimited JSON. Request = `DenialQuery`; snapshot
responses stream matching events then disconnect; stream stays open. PID is the primary
match key, `containerName`/`since` are secondary filters.

**Security model.** *Fail-closed* — the SDK never targets a non-SID-qualified pipe and
returns "service unavailable" if the SID can't be resolved; the server refuses to create a
pipe if its own SID can't be resolved. *Restrictive SDDL* denies AppContainer
(ALL_APP_PACKAGES) tokens so sandboxed processes can't inject or read denial events, and
grants only the current user + SYSTEM + Administrators. *Server-side PID resolution* via
`GetNamedPipeClientProcessId` (clients are never trusted for their PID). *Structural
validation* of every received event (the peer is not cryptographically authenticated;
Node cannot call `GetNamedPipeServerProcessId`, so server identity is mitigated by
SID-qualification + validation rather than verified). *SID qualification* gives per-user
isolation on shared machines. The feature only enables `learningModeLogging`
(observability); it never sets `permissiveLearningMode`, so the sandbox stays fully
enforced.

**Reference doc & diagrams.** Full design:
[`denied-resource-detection-architecture.md`](denied-resource-detection-architecture.md).
Diagrams in [`docs/diagrams/`](diagrams/):

- [`denied-resource-architecture.svg`](diagrams/denied-resource-architecture.svg) — high-level architecture
- [`etw-pipeline-flow.svg`](diagrams/etw-pipeline-flow.svg) — ETW capture pipeline
- [`wire-protocol-payload.svg`](diagrams/wire-protocol-payload.svg) — pipe wire protocol & payloads
- [`threading-model.svg`](diagrams/threading-model.svg) — service threading model
- [`interactive-approval-flow.svg`](diagrams/interactive-approval-flow.svg) — interactive approval flow
- [`approval-scoreboard.svg`](diagrams/approval-scoreboard.svg) — final approval scoreboard

---

## 4. Resource / capability support matrix

| Resource type | Detection method | Confirmed? | Notes |
|---|---|---|---|
| File (read) | ETW AccessCheckLog (`ObjectType="File"`) | ✅ yes | `accessType` from access mask; → `readonlyPaths` |
| File (write) | ETW AccessCheckLog | ✅ yes | write bits in mask; → `readwritePaths` |
| File (read/write) | Output parse (Python/Node/PowerShell/.NET/native/Linux/Rust regex) | ❌ no | `confidence: 'low'`; → `readonly`/`readwrite` per `ApprovedPath` |
| Network (host:port) | Output parse only (ECONNREFUSED / refused / DNS / WinHTTP regex) | ❌ no | → `network.allowedHosts[]` (+`allowOutbound`); host extracted, port stripped |
| Network (host:port) | ETW | — not emitted | `""` object type maps to `Network` but `build_denial_from_access_check` returns `None` for non-File, so never produced |
| Registry (`Key`) | — | — not actionable | maps to `ResourceType::Other` in Rust, discarded by `mapEventToResourceInfo`; no policy field |
| COM | — | — not actionable | not detected by any code path; no policy field |

---

## 5. API reference (SDK)

Authoritative export list from [`sdk/src/index.ts`](../sdk/src/index.ts) (lines 113–146).

| Symbol | Kind | Module | Purpose |
|---|---|---|---|
| `parseDeniedResources` | function | `denied-resources.ts` | Regex-parse process output → `DeniedResourceInfo[]` (file + network). |
| `DeniedResourceInfo` | interface | `denied-resources.ts` | A detected denial: `path`, `resourceType:'file'|'network'`, `source`, `confidence`, optional `accessType`/`matchedLine`/`matchedPattern`. |
| `isDenialServiceRunning` | function | `denial-service.ts` | True if the per-user denial pipe exists (probe). |
| `readDeniedResources` | function | `denial-service.ts` | Snapshot read of ETW denials matching a `DenialFilter` (empty on failure). |
| `subscribeToDenials` | function | `denial-service.ts` | Stream ETW denials to a callback; returns a dispose fn. |
| `mapEventToResourceInfo` | function | `denial-service.ts` | Map a wire `DenialEvent` → `DeniedResourceInfo` (or `null` for non file/network). |
| `validateDenialEvent` | function | `denial-service.ts` | Type-guard / structural validator for a received event. |
| `DenialEvent` | interface | `denial-service.ts` | Wire event: `path`, `resourceType`, `accessType`, `containerName`, `pid`, `timestamp`, `eventId?`. |
| `DenialFilter` | interface | `denial-service.ts` | Query filter: `pid?` (primary), `containerName?`, `since?`. |
| `DenialRequest` | interface | `denial-service.ts` | Request sent over the pipe: `mode`, `pid?`, `containerName?`, `since?`, `subscribe?`. |
| `getServiceBinaryPath` | function | `denial-service.ts` | Locate bundled/dev `mxc-diagnostic-console.exe` (x64 + arm64) or `null`. |
| `generateUpdatedPolicy` | function | `policy-regen.ts` | Merge `ApprovedPath[]` into a policy's filesystem paths (safety-checked). |
| `ApprovedPath` | interface | `policy-regen.ts` | `{ path, accessLevel:'readonly'|'readwrite' }`. |
| `PolicyGenerationOptions` | interface | `policy-regen.ts` | `rejectSystemCriticalPaths?`, `useParentDirectories?`. |
| `PolicyGenerationResult` | interface | `policy-regen.ts` | `{ policy, rejected[], addedCount }`. |
| `getDeniedResources` | function | `tiered-detection.ts` | Unified tiered detection (ETW + output) → `DetectionResult`. |
| `generateUpdatedPolicyFromDetection` | function | `tiered-detection.ts` | Policy regen incl. network hosts; throws on `managed` policy. |
| `DetectionOptions` | interface | `tiered-detection.ts` | `containerName?`, `pid?`, `output?`, `serviceTimeout?`. |
| `DetectionResult` | interface | `tiered-detection.ts` | `deniedResources`, `sourcesUsed`, `serviceAvailable`, `serviceInstallHint?`. |

> Not re-exported from the package root (module-level only): `deduplicateDenials` and
> `pipeProbeErrorIndicatesRunning` (exported from their modules for testing).

---

## 6. Windows service & install

### `mxc-diagnostic-console.exe` CLI

From [`main.rs`](../src/tools/mxc_diagnostic_console/src/main.rs) (`clap`-parsed `Cli`):

| Flag | Behavior |
|---|---|
| `--service` | Run headless under the SCM (`run_as_service`); not for manual use. |
| `--install` | Register `MxcDiagnosticService` with the SCM, then exit (`install_service`). |
| `--uninstall` | Stop + delete the service registration, then exit (`uninstall_service`). |
| `--verbose` | Interactive console: show all ETW event properties (default minified). |
| `--collect` | Interactive console: capture verbose + minified logs to a zipped `%TEMP%` folder. |
| *(none)* | Interactive diagnostic console (existing behavior). |

Service identity (`service.rs`): name `MxcDiagnosticService`, display "MXC Diagnostic
Service", `AutoStart`, account `NT AUTHORITY\LocalService`, launched with `--service`.

### `scripts/Install-MxcDiagnosticService.ps1`

- `#Requires -RunAsAdministrator`.
- Default binary location is the **trusted, admin-only**
  `%ProgramFiles%\MXC\DiagnosticService\mxc-diagnostic-console.exe`.
- `-AllowDevPath` opts in to user-writable build-output discovery
  (`sdk\bin\<triple>\`, `src\target\<triple>\{release,debug}\`, default `src\target\…`)
  and **supports both x64 and arm64, preferring the native architecture first**
  (`PROCESSOR_ARCHITECTURE -eq 'ARM64'` reorders the triple list).
- Refuses a binary resolved under a user-writable root (USERPROFILE/TEMP/LOCALAPPDATA/…)
  unless `-AllowDevPath` is passed.
- **Signature gate:** runs `Get-AuthenticodeSignature`; if status ≠ `Valid` it refuses
  unless `-AllowUnsigned` is passed (loudly warned — dev builds are unsigned because
  codesigning happens at release time).
- On success: runs `<binary> --install`, then `Start-Service MxcDiagnosticService`.
- [`scripts/Uninstall-MxcDiagnosticService.ps1`](../scripts/Uninstall-MxcDiagnosticService.ps1)
  is the inverse (stop + `--uninstall`).

> Deployment caveat (documented in `service.rs`): the service runs as `LocalService`
> (`S-1-5-19`) and therefore serves `mxc-denials-S-1-5-19` for SYSTEM/service-context
> callers. An **interactive SDK** running as the logged-in user computes a different,
> user-SID-qualified pipe name and must talk to the **console** instance instead.

---

## 7. Platform support

**Windows only.** The entire ETW capture path, the per-user named-pipe server, the
restrictive SDDL, and the Windows service integration are Windows-specific, and detection
targets AppContainer/BaseContainer sandboxes. The SDK fails closed on non-Windows:
`getDenialServicePipeName()` returns `null` when `os.platform() !== 'win32'`, so
`isDenialServiceRunning()` is `false` and the ETW tier is skipped — only Tier-2 output
parsing remains (and its filesystem-path heuristics are themselves Windows/Unix aware).
The `mxc-diagnostic-console` crate links Win32 APIs (`windows`/`windows-service`) and only
builds for Windows targets.

---

## 8. Testing done

All commands below were executed on this branch and the **real** output is reproduced.

### 8.1 SDK unit tests — VERIFIED

`cd C:\local\sources\mxc\sdk; npm test` (Node built-in test runner, run with
`--test-concurrency=1`). Summary line:

```
ℹ tests 255
ℹ suites 65
ℹ pass 251
ℹ fail 0
ℹ cancelled 0
ℹ skipped 4
ℹ todo 0
ℹ duration_ms 5479.1465
```

The run covers the whole SDK suite (`sandbox`, `policy`, `logger`, `errors`,
`state-aware*`, `platform`) plus the three new files:

- **`tests/unit/denied-resources.test.ts`** — `parseDeniedResources` across Python,
  Node.js, PowerShell, .NET, Windows-native, Linux, generic, Rust and network patterns;
  deduplication (incl. case-insensitive on Windows); edge cases (empty/no-denial output,
  `matchedLine`, `source = 'output_parsing'`); plus `generateUpdatedPolicy` merging,
  dedup, system-critical rejection, `useParentDirectories`, and field preservation.
- **`tests/unit/tiered-detection.test.ts`** — `getDeniedResources` (output-only when
  service down, empty options, network from output); `deduplicateDenials` (ETW priority,
  distinct resource types); `generateUpdatedPolicyFromDetection` (managed-policy throw,
  network host add with port stripped, dedup against existing `allowedHosts`, no network
  when none approved, filesystem approvals, `serviceInstallHint`).
- **`tests/unit/denial-service.test.ts`** — `isDenialServiceRunning`,
  `pipeProbeErrorIndicatesRunning` (EBUSY/ENOENT/EACCES/EPIPE/no-code branches),
  `readDeniedResources` graceful fallback, `mapEventToResourceInfo` (file/network/`'other'
  → null`/all access types), `validateDenialEvent` (well-formed, missing `eventId`,
  rejections), and a mock-pipe-server round-trip.

> **Test caveat:** the suite is run with `--test-concurrency=1` (see `sdk/package.json`
> `test:unit`). The denial pipe name is global per-user, and Node's test runner runs files
> concurrently by default, so a real listening pipe in one file could leak into another —
> serial execution avoids this cross-file named-pipe race. The 4 skipped tests are
> platform-conditional cases (e.g. the Linux/Unix-path output-parsing case skipped on
> Windows).

### 8.2 Rust unit tests — VERIFIED

`cd C:\local\sources\mxc\src; cargo test -p mxc_diagnostic_console`:

```
running 25 tests
...
test result: ok. 25 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.00s
```

`#[cfg(test)]` modules in the new files:

- `denial_event.rs` — serialization round-trip, `from_object_type` mapping,
  `matches_query` (PID/container/empty-container/`since`), `resolved_mode` precedence,
  camelCase + lowercase-enum JSON.
- `denial_pipe.rs` — pipe-name prefix & difference from the diagnostic pipe, `BufferKey`
  equality, request-mode resolution (explicit/default/legacy-`subscribe`/empty-object),
  PID-primary matching, age-based eviction, dead-subscriber reaping, slow-consumer
  drop/fan-out, per-key max-events eviction.
- `etw.rs` — `access_type_from_props` precedence, hex/decimal `parse_access_mask`,
  `access_type_from_mask` priority, and `build_denial_only_emits_file_with_empty_container_name`
  (asserts the File-only / empty-container contract).
- `pipe_utils.rs` — SDDL contains the current-user ACE and denies ALL_APP_PACKAGES;
  `create_pipe_with_sddl` yields a valid handle.

### 8.3 Build verification — VERIFIED

- `cargo build -p mxc_diagnostic_console` — succeeds (compiled as part of `cargo test`).
- `cargo build -p wxc` — succeeds (`Finished dev profile`; the only output is an unrelated
  "PowerShell 7 not found" test-prereq warning).
- SDK `npm run build` (`tsc`) — succeeds.
- Example `examples/denied_resource_approval` `npm run build` (`tsc`) — succeeds
  (exit 0), confirming the example compiles against the SDK's public types.

### 8.4 What was NOT exercised

The following require admin rights and built binaries on a real Windows host and were
**not** run here (no live verification):

- **Live ETW capture** of real AccessCheckLog denials.
- **Actual service registration** / start (`--install`, `Start-Service`,
  `Install-MxcDiagnosticService.ps1` signature/path gates against a real binary).
- **Sandbox runtime** end-to-end (`wxc-exec` launching a contained process, the real
  named pipe carrying real events, and the interactive approval re-run).

These paths are covered only by unit tests with mocked pipes / synthetic events.

---

## 9. Known limitations / future work

- **Resource set is file + network only.** Registry (`Key`) and COM denials are **not
  actionable** — they map to `ResourceType::Other` and are discarded; there is no
  `registry`/`com` policy schema field. (The architecture doc's registry/COM claims are
  aspirational — see the [discrepancy callouts](#discrepancies-vs-the-architecture-doc).)
- **ETW emits File only.** Network denials come exclusively from Tier-2 output parsing;
  ETW network/registry denials are computed and dropped. Learning-mode violations
  (Event 27) are not forwarded to the pipe.
- **No native pipe-server identity check.** Node can't call
  `GetNamedPipeServerProcessId`, so the SDK cannot cryptographically verify the pipe
  server is SYSTEM/the service. It mitigates by failing closed on un-SID-qualified pipe
  names and structurally validating every event — but a same-user process could still
  stand up a matching pipe.
- **Service vs interactive pipe mismatch.** A service running as `LocalService` serves
  `mxc-denials-S-1-5-19`, unreachable by an interactive user-SID SDK; the interactive
  console instance is required for the SDK path.
- **Sandboxed inner PID not directly observable.** `spawnSandbox` returns the `wxc-exec`
  launcher PID, not the inner sandboxed PID (the primary match key). Callers must supply
  `pid` from another source or rely on the weaker `containerName` filter.
- **Example is interactive-only.** `examples/denied_resource_approval` uses `readline`
  prompts; there is no non-interactive / env-driven auto-approve path implemented.
- **arm64 release packaging.** Binary discovery handles both x64 and arm64 (native
  preferred), but dev builds are unsigned (codesigning is a release-time step), which is
  why `-AllowUnsigned` exists on the install script.
- **`DeniedResource` (Rust) is latent.** `wxc_common::models::DeniedResource` (with its
  `directory`/`registry`/`read_write` values and `confirmed` flag) is defined but not
  wired into the live ETW/pipe pipeline, which uses `DenialEvent`.
- **HTTPS / cert-store caveat & per-host enforcement** (from the architecture doc): TLS
  may need certificate-store (registry) access that has no policy field, and per-host
  `allowedHosts` only takes effect under `firewall`/`both` network enforcement modes.

---

## 10. References

- Architecture: [`docs/denied-resource-detection-architecture.md`](denied-resource-detection-architecture.md)
- Diagrams: [`docs/diagrams/denied-resource-architecture.svg`](diagrams/denied-resource-architecture.svg),
  [`etw-pipeline-flow.svg`](diagrams/etw-pipeline-flow.svg),
  [`wire-protocol-payload.svg`](diagrams/wire-protocol-payload.svg),
  [`threading-model.svg`](diagrams/threading-model.svg),
  [`interactive-approval-flow.svg`](diagrams/interactive-approval-flow.svg),
  [`approval-scoreboard.svg`](diagrams/approval-scoreboard.svg)
- Example: [`examples/denied_resource_approval/`](../examples/denied_resource_approval/)
  (`src/index.ts`, `src/test_all_resources.ts`, `README.md`)
- Install scripts: [`scripts/Install-MxcDiagnosticService.ps1`](../scripts/Install-MxcDiagnosticService.ps1),
  [`scripts/Uninstall-MxcDiagnosticService.ps1`](../scripts/Uninstall-MxcDiagnosticService.ps1)
- SDK source: [`sdk/src/denied-resources.ts`](../sdk/src/denied-resources.ts),
  [`sdk/src/denial-service.ts`](../sdk/src/denial-service.ts),
  [`sdk/src/tiered-detection.ts`](../sdk/src/tiered-detection.ts),
  [`sdk/src/policy-regen.ts`](../sdk/src/policy-regen.ts),
  [`sdk/src/index.ts`](../sdk/src/index.ts)
- SDK tests: [`sdk/tests/unit/denial-service.test.ts`](../sdk/tests/unit/denial-service.test.ts),
  [`denied-resources.test.ts`](../sdk/tests/unit/denied-resources.test.ts),
  [`tiered-detection.test.ts`](../sdk/tests/unit/tiered-detection.test.ts)
- Rust source: [`src/tools/mxc_diagnostic_console/src/`](../src/tools/mxc_diagnostic_console/src/)
  (`denial_event.rs`, `denial_pipe.rs`, `etw.rs`, `service.rs`, `pipe_utils.rs`, `main.rs`),
  [`src/core/wxc_common/src/models.rs`](../src/core/wxc_common/src/models.rs) (`DeniedResource`)

*Document generated from source on branch `feature/denied-resource-capture`.*
