# Learning-mode capture: architecture

Status: **MVP complete on Windows BaseContainer (Phases A–E + descendant filter fix + shim security hardening).**
Related: [`consumer-guide.md`](./consumer-guide.md) (application integration contract and gotchas), `docs/contoso-integration.md` (consumer-facing wire format), `docs/host-prep.md` (shim install/uninstall).

> **Update — SDK orchestration removed (native-driven model).** The SDK
> no longer ships a learning-mode surface (`spawnSandboxWithRetry`,
> `parseDenialStream`, `regenerateSandboxPolicy`, the denial-channel
> side-channel transport). The native `wxc-exec` binary streams denials directly
> (0x1E-framed NDJSON on stderr, or on an anonymous inherited
> handle passed via `--denials-fd` in PTY mode) and the **consumer
> owns** parsing, consent, and the
> re-spawn-per-round loop. The "Box 1 / Box 2" logic below is therefore
> a description of the *consumer-side* responsibilities, not SDK code;
> a reference implementation lives in the native E2E test harness
> (`src/testing/wxc_e2e_tests/src/denial_consumer.rs`, exercised by
> `tests/e2e_windows_capture_denials.rs`). `wxc-exec` does a single
> run per invocation and never authors policy.

This document describes how the captureDenials feature is laid out
after the **three-boxes** rearchitecture. It complements the
consumer-facing docs by explaining *why* the code lives where it
does, so future Linux / macOS implementations have a clear seam to
slot into.

---

## The three boxes

```
┌──────────────────────────────────────────────────────────────────┐
│ Box 2: Learning Mode Module (orchestration, OS-agnostic)         │
│   - re-spawn loop, policy expansion, dispatch (consumer-owned)  │
│   - LearningModeBackend trait                                    │
│   - SDK + Rust orchestrator pick the right OS adapter            │
│                       │ dispatches to         ^ returns          │
│                       v begin_capture()       │ Handle+Summary   │
│   ┌────────────────────────────────────────────────────────────┐ │
│   │ Box 3: OS-specific learning-mode adapters                  │ │
│   │   ┌──────────────────┬──────────────────┬─────────────┐    │ │
│   │   │ windows          │ linux  (stub)    │ macos (stub)│    │ │
│   │   │  ETW collector   │ unimplemented    │ unimplemented│   │ │
│   │   │  shim client     │  (planned:       │  (planned:  │    │ │
│   │   │  child observer  │   fanotify+audit)│  EndpointSec)│   │ │
│   │   │  learningMode-   │                  │             │    │ │
│   │   │  Logging cap     │                  │             │    │ │
│   │   └──────────────────┴──────────────────┴─────────────┘    │ │
│   │                                                            │ │
│   │                       │ emits denials via                  │ │
│   │                       v                                    │ │
│   │ ┌────────────────────────────────────────────────────────┐ │ │
│   │ │ Box 1: Denial Channel (cross-platform transport)       │ │ │
│   │ │   - DeniedResource type + NDJSON wire format           │ │ │
│   │ │   - NDJSON parser (consumer-owned)                    │ │ │
│   │ │   - Transports: stderr (xplat, implicit in parser),    │ │ │
│   │ │     anonymous HANDLE (Windows), unix-socket (planned)   │ │ │
│   │ └────────────────────────────────────────────────────────┘ │ │
│   └────────────────────────────────────────────────────────────┘ │
└──────────────────────────────────────────────────────────────────┘
```

Two design goals:

1. **OS-agnostic orchestration** — the retry loop, policy
   regeneration, and dispatch logic must not know whether the
   underlying capture is ETW (Windows), fanotify (Linux), or
   EndpointSecurity (macOS).
2. **Identical wire format everywhere** — the `DeniedResource`
   JSON shape, the NDJSON framing, and the SDK-facing summary line
   are platform-independent so SDK consumers write one consumer
   that works on every host the feature lands on.

---

## Rust crate layout

| Crate | Box | Platform | Purpose |
|---|---|---|---|
| `src/core/denial_channel/` | 1 | xplat | Cross-platform `DeniedResource`, `ResourceType`, `AccessType` types + serde JSON shape. |
| `src/core/learning_mode_core/` | 2 (split) | xplat | `LearningModeBackend` trait + `CaptureOptions` / `CaptureSummary` / `CaptureHandle` / `LearningModeError`. Split out from `learning_mode` to break a cargo dependency cycle (`learning_mode -> learning_mode_<os> -> learning_mode`). |
| `src/core/learning_mode/` | 2 | xplat | Re-exports everything in `learning_mode_core` plus the `orchestrator::current_backend()` dispatcher. **Consumers depend on this crate.** |
| `src/backends/learning_mode/windows/` | 3 (Windows) | Windows | ETW kernel-audit session, TDH event decoders, shim RPC wire format, path canonicalisation, NDJSON stderr writer, child-process Toolhelp observer. Impls `LearningModeBackend` as `WindowsLearningModeBackend`. |
| `src/backends/learning_mode/linux/` | 3 (Linux) | xplat (compiles everywhere, only meaningful on Linux) | Stub. `is_available()` returns `false`; `begin_capture()` returns `Err(NotSupported)`. Future: fanotify + audit. |
| `src/backends/learning_mode/macos/` | 3 (macOS) | xplat | Stub. Same pattern. Future: EndpointSecurity framework. |
| `src/host/mxc_learning_mode_shim/` | 3 (Windows host) | Windows | Privileged Windows service that loans an ETW trace handle to `wxc-exec`. Binary: `mxc-learning-mode-shim.exe`. Service name: `MxcLearningModeShim`. Pipe: `\\.\pipe\mxc-learning-mode-shim`. |
| `src/host/wxc_host_prep/src/learning_mode_shim/` | 3 (Windows host) | Windows | Install / uninstall / inspect logic for the shim service. Invoked via the `install-learning-mode-shim` / `uninstall-learning-mode-shim` / `dump-learning-mode-shim` subcommands on `wxc-host-prep`. |

The dependency graph (omitting unrelated crates):

```
                ┌────────────────────┐
                │  denial_channel    │  (types, xplat)
                └──────────△─────────┘
                           │
                ┌──────────┴──────────┐
                │  learning_mode_core  │  (trait + types, xplat)
                └──────────△──────────┘
                           │
        ┌──────────────────┼─────────────────────┐
        │                  │                     │
┌───────┴──────────┐ ┌─────┴──────────┐ ┌────────┴─────────┐
│ learning_mode_   │ │ learning_mode_ │ │ learning_mode_   │
│ windows          │ │ linux (stub)   │ │ macos (stub)     │
└───────△──────────┘ └─────△──────────┘ └────────△─────────┘
        │                  │                     │
        └─────────┬────────┴─────────────────────┘
                  │  (cfg(target_os) dispatch)
        ┌─────────┴─────────┐
        │   learning_mode   │  ← consumers import this
        └───────────────────┘
```

The split of `learning_mode_core` from `learning_mode` is a pure
cargo-cycle workaround: cargo computes cycles across all targets
even for `cfg(target_os)`-gated deps, so `learning_mode` cannot
both depend on the OS backends and host the trait the backends
implement. Consumers don't see this split — `learning_mode`
re-exports everything.

### Why the Box 3 adapters live under `backends/learning_mode/`

`backends/` hosts **two families** of backend, distinguished by the
trait they implement — they are *not* the same thing:

- **Containment backends** (`appcontainer`, `windows_sandbox`,
  `isolation_session`, `lxc`, `seatbelt`, …) implement `ScriptRunner`
  and *are the sandbox*. Each ships inside a `wxc-exec` / `lxc-exec` /
  `mxc-exec-mac` binary.
- **Learning-mode capture adapters** (`learning_mode/{windows,linux,
  macos}`) implement `LearningModeBackend`. They have **no binary of
  their own** — they're libraries linked into `wxc-exec` that observe
  denials *inside* whatever containment backend is running.

They share a home because both are per-OS, platform-dependency-heavy
implementations selected behind a backend trait, and the repo rule is
"platform-coupled code lives in `backends/`, the cross-platform
foundation lives in `core/`" (so the ETW/TDH/`windows`-crate code can't
sit in `core/`). They are **nested** under `backends/learning_mode/`
rather than flat alongside the containment backends precisely so the
"containment backend" story stays clean: the nesting signals "this is
a different backend family, not another sandbox." Both families obey
the same one-way edge — `backends/* → core/*`, never the reverse.

---

## Consumer-side layout

The parsing / loop / policy-expand logic is **no longer in the SDK** —
it is consumer-owned. The shapes below describe what a consumer
implements (the native E2E test harness
`src/testing/wxc_e2e_tests/src/denial_consumer.rs` is a reference port):

| Responsibility | Box | Purpose |
|---|---|---|
| NDJSON denial parser | 1 | Demux the 0x1E-framed NDJSON stream (`parseDenialStream`-equivalent): materialise `DeniedResource` records, apply default noise filters, strip the `\??\` prefix, and surface the summary terminator (which carries the consolidated `deniedResources` list). Stream-agnostic — feed it `child.stderr` (pipe mode) or the `--denials-fd` anonymous pipe read end (PTY mode). |
| Anonymous-pipe transport (Windows) | 1 | An anonymous inherited-handle transport for PTY mode, where the workload owns the terminal so denials can't share stderr. The consumer creates an anonymous pipe with a non-inheritable read end and inheritable write end, spawns `wxc-exec` with handle inheritance enabled, passes the write HANDLE as `--denials-fd <handle>`, then closes its own write copy so the read end sees EOF when the child exits. |
| Policy expansion | 2 | Given an existing `SandboxPolicy` and the denials the user approved, produce a relaxed policy (additive, refuses system-critical paths). |
| Re-spawn loop | 2 | Drive the loop: spawn `wxc-exec` → parse stream → prompt for consent → expand policy → respawn. One run per `wxc-exec` invocation; the consumer owns the cadence. |

The SDK retains only the **generic** spawn surface
(`createConfigFromPolicy`, `spawnSandboxFromConfig`) and the
`captureDenials` policy/config field, which maps straight through to
the native binary. Consumers build a config, set `captureDenials`, and
spawn `wxc-exec` directly.

---

## End-to-end call path (Windows)

For a consumer driving `wxc-exec` directly:

```
┌──────────────────────────────────────────────────────────┐
│ Consumer (owns consent + the re-spawn loop)             │
│   build config (captureDenials: true) → spawn wxc-exec  │
└────────────────────────┬─────────────────────────────────┘
                         │
                         v
┌──────────────────────────────────────────────────────────┐
│ Consumer denial parser + loop (Box 1 + Box 2)           │
│   - spawn child (wxc-exec via spawnSandboxFromConfig)    │
│   - read child.stderr or --denials-fd anonymous pipe      │
│   - parse the 0x1E NDJSON stream into DeniedResource[]   │
│   - prompt the user per denial / on the batch summary    │
│   - expand policy with approved paths                    │
│   - re-spawn wxc-exec with the expanded config           │
└────────────────────────┬─────────────────────────────────┘
                         │ read stderr ->     ^ denials + summary
                         v parse NDJSON       │ next round
┌──────────────────────────────────────────────────────────┐
│ wxc-exec.exe — appcontainer / base_container runner      │
│   - spawn workload CREATE_SUSPENDED                      │
│   - attach workload to Job Object (no breakaway)         │
│   - learning_mode_windows::session::open_via_shim(pid)   │
│       └──> RPC to mxc-learning-mode-shim service         │
│   - wire IOCP listener on the Job Object:                │
│       on JOB_OBJECT_MSG_NEW_PROCESS:                     │
│         1. NtSuspendProcess(descendant)                  │
│         2. extend_via_shim(session, [root, descendant…]) │
│         3. insert descendant PID into user-mode filter   │
│         4. NtResumeProcess(descendant)                   │
│   - learning_mode_windows::denial_stream::*              │
│       (NDJSON writer thread, writes stderr or denials fd) │
│   - learning_mode_windows::child_process_observer        │
│       (Toolhelp poll, defence-in-depth descendant count) │
│   - resume root workload                                 │
│   - drain at exit, emit summary line                     │
└────────────────────────┬─────────────────────────────────┘
                         │ named pipe RPC
                         │
┌────────────────────────┴─────────────────────────────────┐
│ mxc-learning-mode-shim service (LocalSystem)             │
│   - per-connection: ImpersonateNamedPipeClient +         │
│     read caller's user SID                               │
│   - OpenDenialSession: under caller's impersonation,     │
│     OpenProcess(target_pid, PROCESS_QUERY_LIMITED_INFO)  │
│     -- if caller can't open it, reject `unauthorized`    │
│   - records (session_name -> caller_sid) on success      │
│   - ExtendDenialSession: caller SID must match recorded  │
│     session owner; each PID must also pass the same      │
│     impersonate-then-OpenProcess check                   │
│   - StartTraceW with 256 × 128 KB buffer ceiling (~32MB) │
│   - EnableTraceEx2 with EVENT_FILTER_TYPE_PID            │
│   - ExtendDenialSession: re-applies PID filter with the  │
│     full [root, descendants…] list each extend call      │
│   - DuplicateHandle trace handle into wxc-exec           │
│   - disconnects                                          │
└──────────────────────────────────────────────────────────┘
```

Future cross-platform consumers (e.g. a Linux runner) would replace
the bottom two boxes — everything above stays put because the boxes
above are OS-agnostic.

---

## Descendant tracking (Windows, BaseContainer)

ETW's per-PID filter (`EVENT_FILTER_TYPE_PID`) does not follow
descendants. A workload like `cmd /c findstr abc <denied>` spawns
findstr as a child of cmd, and the kernel-audit ETW provider will
only emit events for PIDs in the active filter — so a naive
implementation captures cmd's denials but loses findstr's.

The runner closes this gap with a Job-Object + IOCP +
suspend-on-spawn + lockstep filter-extend pipeline:

```
spawn workload CREATE_SUSPENDED
attach to Job Object (JOB_OBJECT_LIMIT_BREAKAWAY_OK = false)
associate IOCP via JOBOBJECT_ASSOCIATE_COMPLETION_PORT_INFORMATION
open ETW session via shim (PID filter = [root])
spawn listener thread on the IOCP
resume workload
                              │
                              v
  every time a descendant joins the job, the kernel posts
  JOB_OBJECT_MSG_NEW_PROCESS to the IOCP; listener thread:
    1. OpenProcess(PROCESS_SUSPEND_RESUME, descendant_pid)
    2. NtSuspendProcess(descendant)             ← descendant is frozen
    3. extend_via_shim(session, [root, …, descendant])
                                                ← kernel-side filter
                                                  now covers descendant
    4. allowed_pids.insert(descendant_pid)      ← user-mode filter
                                                  now covers descendant
    5. NtResumeProcess(descendant)              ← descendant runs;
                                                  its first audit event
                                                  is already in scope
```

Two independent PID filters must be kept in sync, or descendant
events are silently dropped:

| Layer | Where | Updated by |
|---|---|---|
| **Kernel-side** | ETW session's `EVENT_FILTER_TYPE_PID` list | `extend_via_shim` RPC to the shim, which calls `EnableTraceEx2` with the full PID list |
| **User-mode** | `CallbackContext.allowed_pids: Arc<Mutex<HashSet<u32>>>` inside `session.rs`'s event callback | The IOCP listener inserts each new PID immediately after a successful `extend_via_shim` |

The user-mode filter exists as defense-in-depth — if a future ETW
provider ever ignored the PID filter, the callback would still
restrict captured events to the workload's process tree. But this
means both filters must always be extended in lockstep. The
runner-side IOCP callback in `base_container_runner.rs` does both,
in order, on every descendant spawn.

`NtSuspendProcess` and `NtResumeProcess` are not in the public
Windows headers; they're loaded from ntdll via `GetProcAddress`
(cached in a `OnceLock`). The pair has been stable since Vista and
is used by debuggers. Suspending the descendant briefly during the
extend RPC closes most of the spawn-to-audit race window; what
remains is the gap between `PspInsertProcess` (kernel posts the
IOCP message) and `NtSuspendProcess` returning — typically
single-digit milliseconds.

The summary line reports `descendantPidsCovered` (count of PIDs
successfully extended) alongside `childProcessesObserved` (count
from the defense-in-depth Toolhelp poll). When the two diverge,
the SDK warns that tracking may be lagging or failing.

### ETW kernel buffer sizing

Adding descendant PIDs to the filter increases per-workload event
volume linearly. The shim sizes the ETW session for headroom:

- **MaximumBuffers**: 256 (was 64)
- **BufferSize**: 128 KB per buffer (was ~64 KB default)
- **Total ceiling**: ~32 MB (was ~4 MB)

With the default buffers, even a single-descendant workload would
consistently lose ~1.3k kernel events. The bumped ceiling makes
`events_lost = 0` the common case for typical workloads. Very
heavy workloads (large parallel builds) can still saturate the
user-mode consumer because TDH decode + dedupe run synchronously
in the ETW callback; this is signaled via `deniedResourcesTruncated`
on the summary line and is tracked as a follow-up.

---

## Shim security model

The shim runs as `LocalService` with `SeSystemProfilePrivilege` and
hosts the named pipe `\\.\pipe\mxc-learning-mode-shim`. The pipe
ACL (SDDL `D:(A;;GA;;;IU)(A;;GA;;;BA)`) admits Interactive Users
and Built-in Administrators — i.e., any program a logged-in user
runs can attempt to connect. Two attack surfaces are mitigated by
in-process security checks:

| Attack | Mitigation |
|---|---|
| Information disclosure via `OpenDenialSession(victim_pid)` | After `ImpersonateNamedPipeClient`, the shim calls `OpenProcess(target_pid, PROCESS_QUERY_LIMITED_INFORMATION)` under the caller's token. If the caller can't open the target via Windows ACLs, the shim returns `unauthorized` and never starts a session. |
| Session hijack via `ExtendDenialSession(known_session, [pid])` | The shim records `(session_name → caller_sid)` in an in-memory `Arc<Mutex<HashMap>>` when a session is opened. Extend requests must come from the same SID; mismatches return `unauthorized`. Each PID in the extend list is also re-validated through the same impersonate-then-OpenProcess check. |

The client (`learning_mode_windows::session::open_pipe_with_retry`)
opens the pipe with `SECURITY_SQOS_PRESENT | SECURITY_IMPERSONATION`
so the server-side `ImpersonateNamedPipeClient` succeeds. Without
those flags, the call fails with `ERROR_CANNOT_IMPERSONATE` (0x558)
and the security check would silently degrade. The client also
retries on `ERROR_FILE_NOT_FOUND` because the shim's serial accept
loop has a brief gap between closing one pipe instance and creating
the next.

### Why impersonate-then-OpenProcess, not SID equality or parent-PID

Earlier iterations tried two simpler checks. Both failed in
practice against sandboxed workloads:

- **Parent-PID walking** (caller must be an ancestor of the target):
  `Experimental_CreateProcessInSandbox` reparents the workload to a
  system host process, so the caller is not actually the parent.
- **SID equality** (target's user SID must equal caller's SID):
  sandboxed workloads run under a restricted token whose user SID
  differs from the caller's. The check would block all legitimate
  sandbox audits.

`ImpersonateNamedPipeClient` + `OpenProcess` delegates the
"who can audit whom" question to Windows itself, which already
models sandbox tokens, RDP sessions, multi-user boxes, and every
other case the security boundary covers.

### Test coverage

- **Unit** (`pipe_server.rs::tests`): 3 rejection-path cases —
  inaccessible target PID, unknown session name, mismatched caller
  SID. Use synthetic `CallerContext` + dummy pipe handle.
- **Functional negative-path** (`src/tools/shim_security_test/`):
  standalone Rust binary deployed alongside the shim that drives
  hostile requests over the real wire and asserts the expected
  rejection codes. Both negative-path scenarios pass on the VM.
- **Functional happy-path**: validated via `descendant-spawn-diagnostic`
  harness — security checks fire transparently in production
  workloads.

### Not in scope (deliberately)

- **Per-caller session quota**. The previously-considered "max N
  sessions per SID" check would defend against a buggy or
  malicious same-user caller spamming session creates to exhaust
  ETW slots. But Windows already enforces a system-wide ETW user-mode
  session ceiling (~64), which bounds the damage; and an attacker
  who controls the user account can simply spawn many `wxc-exec`
  processes to bypass any shim-side per-caller limit. The added
  state isn't worth the complexity unless we also restrict the
  pipe ACL to a process-trust SID (see below).
- **Restricting the pipe ACL to wxc-exec only**. Would require
  baking a process-trust SID into wxc-exec's binary via code
  signing. Tracked as a hardening follow-up; today's defense rests
  on the per-call impersonation checks rather than caller identity.

---

## CLI subcommand names

The user-facing surface on `wxc-host-prep` matches the internal
naming:

- `install-learning-mode-shim`
- `uninstall-learning-mode-shim`
- `dump-learning-mode-shim`

The rearchitecture initially kept the older `*-denial-shim` names
for UX continuity, but they were renamed in a follow-up commit
(clean break, no aliases) to keep operator-visible commands
consistent with the internal crate / service / pipe naming
(`mxc_learning_mode_shim`, `MxcLearningModeShim`,
`\\.\pipe\mxc-learning-mode-shim`). Operator scripts that still
reference the old `*-denial-shim` names must be updated to the
new commands.

---

## Status and future work

**Done (this rearchitecture):**

- Box 1 (`denial_channel`) extracted from former `denial_capture` crate.
- Box 2 (`learning_mode_core` + `learning_mode`) created with trait,
  types, error, and OS dispatcher.
- Box 3 Windows backend (`learning_mode_windows`) implements the
  trait via `WindowsLearningModeBackend`; absorbed the former
  `denial_capture` ETW pieces plus the `denial_stream` and
  `child_process_observer` modules from `appcontainer_common`.
- Box 3 Linux + macOS stubs implement the trait with
  `Err(NotSupported)`.
- SDK reorganised into `denial-channel/` and `learning-mode/`
  subdirectories; public exports unchanged.
- `mxc_denial_shim` → `mxc_learning_mode_shim` rename
  (crate / binary / service / pipe / docs).
- `wxc_host_prep/src/denial_shim/` → `learning_mode_shim/`
  module rename.
- **Descendant tracking (Phases A–E)** on Windows BaseContainer:
  Job Object + IOCP listener + suspend-on-spawn + dual-layer
  PID-filter extend (kernel + user-mode in lockstep). Surface
  signal: `descendantPidsCovered` on the summary line.
- **ETW kernel buffer sizing** bumped to 256 × 128 KB ceiling
  (`mxc_learning_mode_shim/src/etw_session.rs`), eliminating
  `events_lost` for typical workloads.
- **Shim security hardening** (`caller_context` module + ownership
  map in `pipe_server.rs`): impersonate-then-OpenProcess for
  caller/target access checks; in-memory session-ownership map
  for ExtendDenialSession. Pipe client adds
  `SECURITY_SQOS_PRESENT | SECURITY_IMPERSONATION` flags. E2E
  negative-path test binary `shim_security_test` validates both
  rejection scenarios against the live shim.

**Open follow-ups (not blocking):**

- Descendant tracking on AppContainer (T2 fallback): same Job
  Object pipeline, not yet wired into `appcontainer_runner.rs`.
  Until done, AppContainer workloads report
  `descendantPidsCovered: 0` even when `childProcessesObserved`
  is non-zero.
- Move TDH decode + dedupe off the ETW callback thread into a
  worker pool. The 32 MB kernel buffer ceiling masks most
  user-mode pressure, but very heavy workloads can still
  saturate it (signal: `deniedResourcesTruncated: true` on the
  summary).
- Restrict pipe ACL to a wxc-exec process-trust SID. Requires
  code-signing infrastructure we don't have today; for now the
  per-call impersonation checks are the load-bearing defense.
- Cross-user (multi-tenant) E2E security test. The unit-tested
  SID-mismatch rejection path can't be exercised end-to-end in a
  single-user test environment.
- Real Linux backend (fanotify + kernel audit).
- Real macOS backend (EndpointSecurity framework).
- Network/WFP denial capture (tracked as `cap-future-network-denials`).
- Runner refactor to call `learning_mode::orchestrator::current_backend()`
  instead of `learning_mode_windows::*` directly. Deferred because
  the appcontainer / base_container runners are already
  `#[cfg(target_os = "windows")]`-gated — the direct call is
  simpler than going through the trait until a cross-platform
  runner appears.
