# MXC Learning Mode (captureDenials), GA

**Status**: draft for review
**Owner**: saulg

## Overview

MXC sandboxes are default-deny: when a workload tries to read a
file, registry key, or other resource that the policy does not
grant, the access is blocked and the OS returns the usual
"Access is denied" error. For non-trivial workloads this is
operationally brittle — the agent author has to enumerate every
path the workload will ever touch up front, or hand the operator
a stack trace and ask them to guess.

**Learning Mode** (surfaced to the SDK as `captureDenials: true`)
turns those denied accesses into structured events the consumer
can react to. Every blocked file / registry access is captured,
deduplicated, and streamed back to the caller as **NDJSON
(Newline-Delimited JSON: one self-contained JSON object per
line, terminated by `\n`)**. The consumer can use that stream
to drive an "ask the user to grant access, then retry" UX on
top of the default-deny policy, or just log the denials for
post-hoc analysis.

This document covers the **GA scope** for the General Availability
release.

## GA Goal

Give SDK consumers a portable, low-overhead way to observe
sandboxed-workload denials in real time so they can build
permission-prompt UX without giving up the default-deny posture.
The schema is shared across all sandbox backends. Enforcement —
how denials are observed at the OS level — varies by backend, the
same way network enforcement does.

**GA commitment**: the SDK consumer writes one config
(`captureDenials: true`) and one consumer (`parseDenialStream`)
and gets denial events on any backend that supports the feature.
A backend that cannot observe denials (or that has not implemented
the feature yet) reports `captureDenialsActive: false` on the
summary line so consumers can warn the user that the prompt loop
will be inert on this host, rather than silently dropping
denials.

## GA Commitments: what flows where

The captureDenials feature has three orthogonal pieces:

1. **Capture** — the OS-level mechanism that observes a denied
   access. Per-backend. Examples: ETW kernel-audit on Windows,
   fanotify + audit on Linux (future), EndpointSecurity on macOS
   (future).
2. **Transport** — how the denial event reaches the SDK
   consumer. Cross-platform NDJSON. Two transports for GA:
   stderr (default) and a Windows anonymous inherited handle (`--denials-fd`).
3. **Orchestration** — the SDK-side retry loop
   (`spawnSandboxWithRetry`) that consumes the stream, calls
   `onDenied`, regenerates the policy with the user-granted paths,
   and respawns. OS-agnostic.

Three architectural boxes own these pieces respectively:

```
Box 1: denial_channel          — types + NDJSON wire format (xplat)
Box 2: learning_mode           — trait + orchestrator (xplat)
Box 3: learning_mode_<os>      — per-OS capture adapters
```

See `docs/learning-mode/architecture.md` for the full diagram and
crate layout.

## Denial event shape

Every denial surfaces as a `DeniedResource`. The wire shape is the
same on every backend so SDK consumers write one parser:

```json
{
  "type": "denial",
  "path": "C:\\Users\\AdminUser\\Documents\\file_x.txt",
  "resourceType": "file",
  "accessType": "read",
  "pid": 12345,
  "filetime": 133745928450000000
}
```

| Field | Type | Notes |
|---|---|---|
| `path` | string | Resource identifier in the platform's user-visible form (drive-letter paths on Windows, POSIX paths on Linux/macOS). |
| `resourceType` | `"file"` \| `"registry"` \| `"network"` \| `"ui"` \| `"other"` | Discriminated union. `"network"` and `"ui"` are reserved for future use; GA emits `"file"` / `"registry"` / `"other"` only. |
| `accessType` | `"read"` \| `"write"` \| `"execute"` \| `"delete"` \| `"create"` \| `"other"` | Lossy mapping from OS-specific access masks. |
| `pid` | uint32 | Process that attempted the access. Useful for telling the workload's own denials apart from denials in child processes (see D2 — descendant denials surface as their child PID; the per-PID ETW filter is dynamically extended to include each descendant as it spawns). Consumers can also use the PID to correlate with their own process-tree telemetry. |
| `filetime` | uint64 | Kernel-emitted timestamp of when the denial occurred, copied verbatim from `EVENT_RECORD.EventHeader.TimeStamp` on Windows. Format: Windows FILETIME (100-ns ticks since 1601-01-01 UTC). **Not** used by the prompt UX — events arrive in occurrence order so consumers don't need a timestamp to order them. Surfaced for two reasons: (1) **forensic correlation** — Windows Event Viewer and most kernel-side audit tools use the same FILETIME format, so a denial in MXC's stream can be matched to the corresponding line in the system log; (2) **pipeline-lag diagnostics** — if `filetime` is significantly older than wall-clock time at the consumer, the pipeline is back-pressured and the denial-prompt UX is racing the workload. Cross-platform consumers can convert to ms-since-epoch via `(filetime - 116444736000000000) / 10000`. |

The wire stream wraps each event in a single-line NDJSON envelope
prefixed with ASCII Record Separator (0x1E):

```text
\x1e{"type":"denial","path":"...","resourceType":"file","accessType":"read","pid":123,"filetime":...}\n
\x1e{"type":"denial",...}\n
\x1e{"type":"summary","exitCode":1,"totalDenials":2,"deniedResourcesTruncated":false,"captureDenialsActive":true,"childProcessesObserved":0,"descendantPidsCovered":0}\n
```

The terminating `summary` line is the end-of-stream signal. It
carries the workload's exit code, the total number of unique
denials streamed, a truncation flag, and the `captureDenialsActive`
signal that tells the consumer whether the capture pipeline was
actually attached for this invocation.

## Outbound stream routing

Default stance: when `captureDenials: true`, the runner emits the
NDJSON stream **on stderr**. The 0x1E framing means consumers can
demultiplex the stream cleanly from the workload's own stderr
writes (0x1E effectively never appears in legitimate console
output). Each line is one envelope; `parseDenialStream(child.stderr)`
in the SDK does the demux.

**Side-channel path** (Windows only, GA): when the workload owns
the PTY (interactive REPL, color-aware build tool, progress-bar
TUI), sharing stderr would corrupt the user's terminal. The launcher
creates a Windows anonymous pipe with an inheritable write HANDLE and
a non-inheritable read HANDLE, spawns `wxc-exec` with handle inheritance
enabled, and passes the write HANDLE value as `--denials-fd <handle>`.
The Rust side adopts that handle and reroutes the NDJSON stream from
stderr to the anonymous pipe; the launcher reads the pipe and parses
the stream the same way. After spawning, the launcher closes its own
write-handle copy so the read end reaches EOF when `wxc-exec` exits.
The workload's PTY stays clean, and the sandboxed workload never
receives the denial handle because the runner restricts inherited
handles to stdio.

Use `spawnSandboxWithSideChannel(config, { usePty: true })` to
get this flow end-to-end. The anonymous pipe has no object-namespace
name, so no other process can open or squat the channel; only a process
holding the inherited handle can write.

## Proposed Schema

The `captureDenials` flag is a top-level boolean on the SDK
`SandboxPolicy` and the wire-format `ContainerConfig`:

```json
{
  "version": "0.7.0-dev",
  "filesystem": {
    "readwritePaths": ["C:\\workspace"],
    "readonlyPaths": []
  },
  "captureDenials": true
}
```

**Field semantics**:

| Field | Type | Default | Notes |
|---|---|---|---|
| `captureDenials` | bool | `false` | Opt-in per request. When `true`, the runner attaches a per-PID capture session before the workload runs. When the host backend cannot capture (no shim, unsupported OS), the flag is a no-op — the workload runs, the NDJSON stream is empty, and the summary line reports `captureDenialsActive: false`. |

No other schema fields. The SDK side gets a richer surface for
the orchestrator.

### Division of responsibility

The SDK ships the **mechanism**: it captures denials, runs the
retry loop, regenerates the sandbox policy with the user-granted
paths, and respawns the workload. **It does not ship a UI.** The
consuming application (a CLI like `gh copilot`, an IDE extension
like VS Code, a TUI like a Copilot inline prompt, etc.) supplies
the prompt UI by implementing the `onDenied` callback. Whatever
the user-facing prompt looks like — a console y/n, a modal
dialog, a notification with an "Allow" button — lives entirely in
the application.

In other words: the SDK says "here are the resources the workload
just got blocked on, what do you want me to do?"; the app says
"grant these, deny those, retry as-is, or give up."

### Example: console prompt

```ts
import { spawnSandboxWithRetry } from '@microsoft/mxc-sdk';
import { createInterface } from 'readline/promises';
import { stdin, stdout } from 'process';

const rl = createInterface({ input: stdin, output: stdout });

const result = await spawnSandboxWithRetry(policy, {
  onDenied: async (denials, attemptIndex, summary) => {
    // ----- app-supplied UI starts here -----
    console.log(`Attempt ${attemptIndex}: workload was blocked on:`);
    for (const d of denials) console.log(`  ${d.accessType} ${d.path}`);
    const answer = await rl.question('Grant these and retry? [y/N] ');
    // ----- app-supplied UI ends here -----

    if (answer.toLowerCase() === 'y') {
      return { decision: 'grant', paths: denials.map(d => d.path) };
    }
    return { decision: 'deny' };
  },
  maxAttempts: 5,
});
```

An IDE extension would substitute its own dialog; a non-interactive
CI runner would auto-deny (or auto-grant from a static allow-list)
without ever asking the user.

`onDenied` returns one of:
- `{ decision: 'grant', paths: string[] }` — add these paths to
  the policy and respawn.
- `{ decision: 'deny' }` — give up; resolve with the last
  attempt's exit code + denials.
- `{ decision: 'retry' }` — respawn with the same policy (rare;
  for "user fixed something on the filesystem" scenarios).

## Design decisions

### D1: Default-off; opt-in per request

**Decision**: Learning mode is off by default. A workload that
doesn't set `captureDenials: true` runs with zero capture overhead
and produces zero captureDenials output.

**Why**: Capture has a non-zero cost (kernel ETW buffer, an extra
RPC to the shim, a worker thread per invocation, dedup HashSet
allocations). Most workloads don't need it. Opt-in keeps the
default cheap and lets consumers choose when to pay.

**Limitation**: Consumers that flip the flag on for every
invocation pay the cost on every invocation. That's their choice
and is the right call when the consumer is interactive and
permission-prompting is part of the UX.

### D2: Per-PID scoping

**Decision**: Each capture session is scoped to the root workload
PID (the process the runner spawned). Concurrent sandboxes get
independent sessions.

**Why**: A long-running ETW session that observes all access
denials on the box would (a) consume kernel buffer space whether
or not any MXC workload is running, (b) require a privileged
always-on daemon, and (c) couple unrelated workloads (one
workload's denial spam would back-pressure another's stream).
Per-PID sessions keep the privileged window to a few
milliseconds per invocation and avoid cross-workload coupling.

**Original limitation (now mostly closed on BaseContainer)**:
ETW's per-PID filter does not follow descendants. A workload that
spawns children (`cargo build`, `npm run`, etc.) would naïvely see
denials only from the root PID. To cover descendants, MXC pairs
the per-PID ETW session with a Job-Object-based descendant tracker
(landed for BaseContainer; AppContainer T2 still pending). The
runner also spawns a child-process observer (Toolhelp on Windows)
and reports `childProcessesObserved` on the summary line as a
defence-in-depth signal that lets the SDK warn the user if
tracking ever drops events.

The summary line also carries `descendantPidsCovered` — the
number of descendant PIDs the runner successfully added to the
ETW filter during the workload's lifetime. A non-zero value is
positive confirmation that descendant capture is working;
`childProcessesObserved > descendantPidsCovered` is the
SDK's signal that tracking is lagging or failing and the denial
list may be incomplete.

**How we solve this on BaseContainer (shipped)**: the descendant
tracker pipeline is:

1. **Job Object wraps the workload** before resume. The
   AppContainer / BaseContainer runner already creates a Job
   Object today (used for UI restrictions in
   `src/backends/appcontainer/common/src/job_object.rs`). The
   descendant-tracking work extends that existing job by
   (a) attaching the workload via `AssignProcessToJobObject`
   *before* the suspended workload resumes, and (b) leaving
   `JOB_OBJECT_LIMIT_BREAKAWAY_OK = false` so descendants
   cannot escape.

2. **IOCP notification** on `JOB_OBJECT_MSG_NEW_PROCESS`. The
   runner associates a completion port with the job and a
   listener thread dispatches each new-process message
   (filtering out the root PID).

3. **Suspend-on-spawn**. For each descendant, the listener
   opens the descendant with `PROCESS_SUSPEND_RESUME` and
   calls `NtSuspendProcess` (resolved from ntdll via
   `GetProcAddress`) before doing anything else. The
   descendant is held suspended for the duration of step 4.

4. **Extend ETW filter** via shim RPC. The listener sends an
   `ExtendDenialSession` request to the `mxc-learning-mode-shim`
   service over its named pipe. The shim calls
   `ControlTraceW(QUERY)` to recover the session handle by
   name, then re-invokes `EnableTraceEx2` with the new PID
   list (root + all previously-extended descendants + the new
   PID). The shim is stateless across requests; it does not
   need to remember which session belongs to which workload.

5. **Resume descendant**. `NtResumeProcess` is called from the
   guard's `Drop`, so the descendant gets to run user code
   only after its PID is already in the ETW filter. The race
   window from spawn-to-audit is bounded by the
   suspend-resume bracket (~few ms on a quiet system) and is
   fully closed in the happy path.

   Graceful degradation: if any step fails (descendant
   already exited, OpenProcess denied, shim unreachable) the
   runner logs and continues. The descendant runs unaudited;
   the summary line lets the consumer detect that case.

The SDK consumer (e.g. `gh copilot`) does not need to be in the
job — only the sandboxed workload does. The job exists below
the wxc-exec boundary; the SDK side is entirely unaware of it.
This is the same shape as the existing UI-restrictions job,
which has shipped for releases.

**A second axis of improvement** that landed alongside Job-Object
tracking: the shim's ETW kernel buffer ceiling was raised from
the default (~4 MB total) to **256 × 128 KB = ~32 MB**. On the
representative `cmd /c findstr <denied-file>` workload, the
unbumped buffers consistently lost ~1.3k kernel events while a
descendant was being audited (the extra PID roughly doubled the
event rate the single-threaded ETW callback had to drain). With
the bumped ceiling, the same workload shows
`deniedResourcesTruncated: false` and a populated denial list.
Very heavy workloads (`cargo build` with many parallel `rustc`
invocations) may still saturate the user-mode consumer; the
defensive ceiling guarantees the bottleneck is downstream of the
kernel ring buffer when it does happen.

**Remaining options for future work**:

1. **Package-SID filter** (`EVENT_FILTER_TYPE_PACKAGE_ID`).
   AppContainer-only — does not help BaseContainer at all. The
   AppContainer SID is shared by the parent and every child
   spawned inside the sandbox, so a single ETW session filtered
   on the SID captures the whole tree with zero race window.
   Useful as a **complementary** optimisation for AppContainer
   (T2) fallback workloads: they could skip the Job-Object
   machinery and get race-free tree capture. Not a substitute
   for the BaseContainer path.

2. **Move TDH decode + dedupe off the ETW callback thread.**
   The user-mode consumer in the shim currently decodes and
   dedupes synchronously inside `EVENT_RECORD_CALLBACK`. For
   very heavy workloads this can still cause user-mode buffer
   pressure even with the 32 MB kernel headroom. Moving the
   decode + dedupe into a worker pool would let the callback
   return immediately and consume kernel buffers as fast as
   the kernel produces them.

3. **Suspend-on-spawn launcher shim.** Replace common parent
   processes (`cmd.exe`, `cargo`, `npm`) with a thin wrapper
   that creates each child `CREATE_SUSPENDED`. The current
   Job-Object pipeline already implements suspend-on-spawn at
   the OS level, so this option is now redundant unless the
   IOCP latency proves unacceptable in some workload.
   **Deliberate non-goal.**

4. **Kernel-mode driver.** A dedicated minifilter / kernel
   driver that observes process creation in ring 0 and
   atomically attaches descendants to the sandbox's session.
   Zero race window, fully general, works for every Windows
   backend. Cons: WHQL signing, ring-0 attack surface,
   separate install / uninstall flow, doesn't ship
   cross-platform. **Deliberate non-goal** unless the
   Job-Object + suspend pipeline proves insufficient at scale.

**On Linux and macOS the problem is largely a non-problem.** The
sandbox boundary on both platforms is already a process-tree
boundary, so a single subscription scoped to that boundary
captures descendants for free:

- **Linux (WSLc / LXC / Bubblewrap)** — these backends already
  put the workload in its own **PID namespace + cgroup**.
  Descendants are automatically inside the same namespace and
  cgroup (the kernel enforces this; a child process cannot
  escape its parent's namespace). The natural capture mechanism
  is **fanotify** with a per-mount mark plus eBPF/LSM hook
  filtered on the workload's cgroup ID — every denial under the
  cgroup surfaces, regardless of depth. Alternative: the older
  Linux audit subsystem with rules filtered on `auid` (audit
  user ID, inherited transitively). Either path captures the
  whole tree in a single subscription. No race window, no
  per-descendant filter updates, no Job Object machinery.

- **macOS (Seatbelt)** — Seatbelt profiles are inherited by
  descendants by default (a child `posix_spawn`'d from a
  sandboxed parent inherits the parent's profile unless
  explicitly disinherited). The natural capture mechanism is
  the **EndpointSecurity (ES) framework**, which delivers
  events with an `audit_token_t` from which you can derive both
  the process's PID **and** its responsible parent. ES
  subscriptions can filter on `audit_token` or on a sandbox /
  responsible-process ancestry chain, so a single subscription
  captures the whole tree. Cons: ES requires the consumer to
  be a signed, entitled system extension, which is a separate
  install / signing story but a one-time setup.

The Windows descendant gap exists specifically because **ETW
per-PID filtering predates AppContainer / sandbox tree concepts**
and there's no kernel-level "this whole sandbox" filter primitive
without inventing one. Linux and macOS designed the audit
primitives around the sandbox model from the start.

This asymmetry is why the spec emphasises the Windows-side
options (1–4 above) and treats the Linux/macOS landings as
descendant-aware by default. When the post-GA Linux backend ships
with `fanotify + cgroup` capture, it does not need an option-1
or option-2 equivalent — the kernel already does the tree
filtering for us.

### D3: Streaming NDJSON on stderr, not batch-at-exit

**Decision**: Denials are streamed as they occur (one NDJSON
envelope per event, 0x1E-prefixed) rather than returned as a
single batch in `ScriptResponse.deniedResources`. The batch is
also returned for callers that don't want to deal with the stream,
but the streaming protocol is the GA primary.

**Why**: Long-running workloads (`cargo build`, an LSP daemon,
anything iterative) might be blocked by a denial in the first 200
ms and the user should be able to grant it immediately, not wait
until the workload exits hours later. Batch-at-exit only works
for short-lived workloads.

**Limitation**: Stderr is now load-bearing for the protocol. The
ASCII RS prefix means real-world workload stderr won't collide,
but PTY mode merges stdout+stderr into one channel which **would**
corrupt the demux. PTY callers must route the stream through the
side-channel pipe (see D5).

### D4: Per-PID dedupe in the runner; semantic filtering in the SDK

**Decision**: The runner deduplicates raw ETW events by
`(path, accessType)` before streaming so the consumer sees each
unique denial once. Semantic filtering (suppressing System32
loader noise, registry chatter, etc.) lives in the SDK as
`defaultDenialFilters` and can be replaced or disabled by the
caller.

**Why**: Dedupe is on the hot path — a single `cmd /c type one_file.txt`
generates 650+ raw ETW events for ~8 unique resources because the
locale code re-reads `\REGISTRY\USER\.DEFAULT\Control Panel\International`
on every `printf`. Doing dedupe in the SDK would mean 650 NDJSON
writes to stderr per workload, ~99% wasted bandwidth.

Filtering is a different concern: it encodes consumer policy
("Contoso doesn't care about Win32 loader probes"), not a
correctness invariant. Putting it in the SDK lets consumers tune
the filter list without rebuilding wxc-exec, and lets debug
sessions see the raw stream by passing `filters: 'none'`.

### D5: Stderr is the default transport; anonymous inherited handle is the PTY escape hatch

**Decision**: Two transports for GA: stderr (cross-platform,
default) and a Windows anonymous inherited handle (`--denials-fd`,
opt-in via `spawnSandboxWithSideChannel`).

**Why**: Stderr is universal — every OS and every runner can use
it. But stderr is a shared channel with the workload, and PTY
mode merges it with stdout. When the workload is interactive
(needs a real TTY for color, REPL, progress bars), the consumer
must be able to give the workload an unrestricted PTY without
losing the denial stream. An anonymous pipe write handle inherited by
`wxc-exec` via `--denials-fd` is that out-of-band channel.

**Limitation**: GA ships the anonymous-pipe transport on Windows only.
Linux/macOS PTY consumers will need a Unix-domain-socket
equivalent; that's tracked as a follow-up. Today, Linux/macOS
PTY consumers can use stderr (the workload's PTY doesn't merge
stderr unless explicitly requested) or fall back to non-PTY.

### D6: Cross-platform wire format; per-OS capture mechanism

**Decision**: The `DeniedResource` shape, NDJSON framing, summary
line, and SDK consumer API are platform-independent. The OS-level
capture mechanism is backend-specific and lives behind the
`LearningModeBackend` trait.

**Why**: Portable intent — consumers write one `parseDenialStream`
and one `onDenied` callback and get the same prompt UX on every
host. The trait keeps the orchestrator OS-agnostic so a future
Linux backend slots in without churning SDK consumers.

**Reality**: Capture fidelity varies. Windows ETW captures
file + registry + LearningModeLogging events; Linux fanotify will
likely cover file only (registry has no equivalent); macOS
EndpointSecurity covers files but not all OS-level denies. Where
a backend cannot capture a resourceType, it simply emits no events
of that type; the wire format is still valid.

### D7: Discriminated union from day one

**Decision**: `DeniedResource.resourceType` is a discriminated
union (`"file" | "registry" | "network" | "ui" | "other"`) even though
GA emits only `"file"` / `"registry"` / `"other"`. The `"network"` and
`"ui"` variants are reserved for future WFP / firewall and UI-policy
denial capture.

**Why**: Consumers that switch on `resourceType` today will keep
working when `"network"` denials appear later. If we'd shipped
with a string-only `path` field, adding network (which has a
shape like `{ host, port, protocol, direction }`) would be a
breaking change.

### D8: Backend hardness, not always-on capture

**Decision**: The capture mechanism (per-PID ETW, future fanotify,
future EndpointSecurity) is the security boundary, not the
streaming protocol. A workload that floods stderr with 0x1E bytes
to spoof denial envelopes only spoofs **its own** denial stream
in **its own** sandbox. The runner ignores stdin from the
workload and writes to stderr from a separate thread; the consumer
sees a clean stream from the runner side, plus whatever the
workload also wrote to stderr. Demux on 0x1E (which the workload
controls) means a hostile workload can fabricate fake denials in
its own stream — but it cannot suppress real ones the runner
emits, and it cannot leak denial events into another sandbox.

**Limitation**: Consumers should not treat the streamed denials
as cryptographically authenticated. They are a UX surface, not
an attestation. Use them for permission-prompt UX, not for audit.

## GA Scope by Backend

GA includes all backends for which an OS-level capture mechanism
is in scope. The shape of the consumer-visible API is identical;
enforcement varies.

### Process containers (Windows AppContainer / BaseContainer): GA enforcement

Default stance: `captureDenials: false` (off). When `true`, the
runner attaches a per-PID ETW kernel-audit session before the
suspended workload resumes.

| Configuration concept | Enforcement mechanism | Notes |
|---|---|---|
| Per-PID capture | ETW `Microsoft-Windows-Kernel-Audit` + `MXC-LearningModeLogging` providers, filtered by `EVENT_FILTER_TYPE_PID` | Session created by the privileged `mxc-learning-mode-shim` service; the trace handle is `DuplicateHandle`d into `wxc-exec` and the shim disconnects. |
| Resource types | file, registry, other | LearningModeViolation events (event 27) cover BFS file/registry denials; AccessCheckLog (event 4907) covers everything else. |
| Per-sandbox scoping | PID + AppContainer SID; LowBoxNumber in the event payload is used to dedupe concurrent sandboxes when the kernel does not honor the PID filter | |
| Streaming | NDJSON on stderr (default) or an anonymous inherited write handle passed via `--denials-fd` (used by `spawnSandboxWithSideChannel`) | |
| Descendant processes | Job Object + IOCP `JOB_OBJECT_MSG_NEW_PROCESS` + `NtSuspendProcess` + shim `ExtendDenialSession` RPC. Count reported as `descendantPidsCovered` on the summary. | Closes the per-PID-filter-doesn't-follow-descendants gap on BaseContainer (the GA-preferred backend). AppContainer (T2) still falls back to the observer-only path; tracker wiring there is a follow-up. |
| Child processes (defence in depth) | Toolhelp snapshot poll, reported as `childProcessesObserved` on the summary | Belt-and-braces signal alongside descendant tracking: if `childProcessesObserved > descendantPidsCovered`, the SDK warns the user that some children escaped the filter. |
| ETW kernel buffer | 256 × 128 KB = ~32 MB ceiling on the shared `mxc-denials-*` session | Default Windows ETW buffer (~4 MB) was insufficient once descendant tracking ~doubled per-workload event volume. The bumped ceiling guarantees the kernel ring is not the bottleneck for typical workloads. |
| Privileged operations | `StartTraceW` / `EnableTraceEx2` via the shim service | Shim runs as `LocalService` with `SeSystemProfilePrivilege`; `wxc-exec` is unelevated. |
| Bypass resistance | High. Kernel-enforced ETW. Bypass requires kernel compromise or shim takeover. | Workload can spoof denial envelopes in its own stream but cannot suppress runner-emitted ones or leak into other sandboxes. |

**Implementation doc**: `docs/learning-mode/architecture.md`.
Service install: `wxc-host-prep install-learning-mode-shim`.

### WSLc, LXC, Bubblewrap: GA enforcement (deferred)

Default stance: `captureDenials: false`. When `true`, the runner
returns `captureDenialsActive: false` on the summary line —
capture is not yet implemented on Linux.

The `learning_mode_linux` crate exists as a stub that surfaces
`LearningModeError::NotSupported { reason: "planned: fanotify + audit" }`.
The seam is wired so a real implementation can land without
touching the SDK or the orchestrator.

| Configuration concept | Enforcement mechanism | Notes |
|---|---|---|
| Per-PID capture | Planned: `fanotify` (file) + kernel audit subsystem (security-relevant denials) | Not in GA. |
| Resource types | file (planned) | No registry on Linux. |
| Per-sandbox scoping | Network namespace + PID | |
| Streaming | NDJSON on stderr (cross-platform) | Side-channel transport will use a Unix domain socket; not in GA. |

### macOS (Seatbelt): GA enforcement (deferred)

Default stance: `captureDenials: false`. Same shape as Linux:
`captureDenialsActive: false` on the summary, stub crate exists.

| Configuration concept | Enforcement mechanism | Notes |
|---|---|---|
| Per-PID capture | Planned: EndpointSecurity framework | Not in GA. Requires entitlement + signing. |
| Resource types | file (planned) | |
| Per-sandbox scoping | Seatbelt profile + PID | |
| Streaming | NDJSON on stderr | Unix domain socket side-channel TBD. |

### Other backends

- **Windows Sandbox**: Not in scope. The guest-side runner has no
  access to host ETW; surfacing denials would require a
  guest-to-host transport that does not exist today.
- **Isolation Session**: Not in scope. The session lifecycle is
  state-aware; learning-mode integration is a follow-up.
- **Hyperlight, Nanvix**: Not in scope (no filesystem to deny
  against).

## Gaps and limitations

**What GA cannot do**:

- **Network / WFP denials**: GA captures file + registry only.
  Network outbound denials are blocked by the WFP rules described
  in the network spec; observing them is a separate ETW provider
  with a different event shape and is tracked as
  `cap-future-network-denials`. The discriminated-union shape of
  `DeniedResource` keeps the door open for additive expansion.

- **Linux and macOS capture**: GA ships the trait + stub crates +
  cross-platform wire format. The actual `fanotify` and
  `EndpointSecurity` implementations are not in this release.
  Consumers on Linux/macOS will see `captureDenialsActive: false`
  on the summary line and an empty denial list.

- **Descendant denials on AppContainer (T2) fallback**: GA ships
  descendant tracking (Job Object + IOCP + suspend-on-spawn +
  shim `ExtendDenialSession`) for **BaseContainer**, the
  GA-preferred Windows backend. The AppContainer fallback path
  does not yet wire the same tracker — workloads that fall back
  to AppContainer and spawn children will see `descendantPidsCovered: 0`
  on the summary while `childProcessesObserved` may be non-zero.
  Wiring the tracker into the AppContainer runner is a follow-up.

- **Descendant suspend-resume race**: even on BaseContainer, the
  tracker depends on opening the descendant for
  `PROCESS_SUSPEND_RESUME` quickly enough to suspend it before
  user code runs. The IOCP notification is delivered after
  `PspInsertProcess`, so the window is small but non-zero. A
  descendant that exits before the runner can open it (very
  short-lived helper) is logged as a degraded case and its
  denials are not captured. A kernel-mode minifilter would close
  this window; it remains a deliberate non-goal.

- **Very heavy workloads still saturate the user-mode consumer**:
  the 32 MB kernel buffer ceiling handles typical workloads, but
  workloads that emit tens of thousands of audit events per
  second (large parallel builds) can still back up because the
  shim decodes and dedupes synchronously inside the ETW
  callback. The summary line's `deniedResourcesTruncated` flag
  signals this case to the SDK. Moving decode + dedupe off the
  callback thread is tracked as a follow-up.

- **Cross-process tamper resistance of the stream content**: The
  stream is a UX surface, not an audit log. A workload that
  fabricates 0x1E-prefixed JSON in its own stderr can mislead
  its own consumer (about its own denials). It cannot inject
  events into another sandbox's stream. Consumers that need
  audit-grade evidence must use OS-level auditing, not this
  feature.

- **Side-channel transport on Linux/macOS**: GA ships the named
  pipe transport on Windows only. Linux/macOS PTY consumers can
  still use stderr (PTY behavior on those platforms differs
  enough that stderr-on-its-own-fd is often viable). A
  Unix-domain-socket transport is tracked as a follow-up.

## Industry Precedent

We could not find a published open-source equivalent of MXC's
per-PID learning-mode capture. Adjacent systems exist but none
ship the exact "block-by-default + stream denials for
permission-prompt UX" loop:

- **Anthropic Claude Code (sandbox-runtime)**: Default-deny
  filesystem with operator approval flows, but the approval
  request is generated from the agent's reasoning, not from
  observed OS denials. The sandbox blocks; the agent re-plans
  with a different tool or asks the user via a separate
  channel. There is no equivalent of streaming `DeniedResource`
  events to a consumer.

- **OpenAI Codex (local agent runtime)**: Similar shape —
  default-deny, agent-side prompting. No published OS-denial
  capture surface for consumers.

- **Vicente's prior `MxcDiagnosticService` branch** (internal,
  Microsoft): An always-on Windows service that held one ETW
  session open and brokered reads to clients. We diverged from
  this to per-PID on-demand capture (`mxc-learning-mode-shim`)
  for the reasons in D2 above — lower idle cost, smaller
  privilege footprint, no cross-workload coupling.
  `files/captureDenials-vs-vicente.md` covers the full diff.

**Key takeaways**:

1. **Permission-prompt UX is becoming a standard agent
   pattern**. Both Anthropic and OpenAI surface the equivalent
   to the user as part of the agent loop, but neither exposes a
   structured OS-denial stream that another consumer can
   subscribe to. MXC's `parseDenialStream` is the differentiator.
2. **Per-PID capture is the right per-invocation cost shape**.
   Always-on daemon designs (the diagnostic-service pattern) trade
   simplicity for idle privilege footprint and cross-workload
   coupling. The per-PID approach scales linearly with
   captureDenials-enabled invocations and adds zero cost when off.
3. **Cross-platform wire format pays for itself only once the
   second backend lands**. We've paid the abstraction tax for
   GA so that the Linux and macOS landings are mechanical.

## References

- Architecture: `docs/learning-mode/architecture.md`
- Schema: `docs/schema.md` (the `captureDenials` field)
- Host install: `docs/host-prep.md`
  (`install-learning-mode-shim` / `uninstall-learning-mode-shim` /
  `dump-learning-mode-shim`)
- SDK API: `sdk/README.md` and the JSDoc on `spawnSandboxWithRetry`,
  `spawnSandboxWithSideChannel`, `parseDenialStream`
- Internal: `files/captureDenials-vs-vicente.md` (Vicente
  comparison + divergence rationale)
- Investigation notes: `files/pty-investigation-plan.md`
  (the PTY + side-channel error 203 root cause and fix)
