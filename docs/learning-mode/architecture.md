# Learning-mode capture: architecture

Status: **active rearchitecture, P-A + P-B complete.**
Related: `docs/contoso-integration.md` (consumer-facing wire format), `docs/host-prep.md` (shim install/uninstall).

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
│   - spawnSandboxWithRetry, policy-regen, retry loop, dispatch    │
│   - LearningModeBackend trait                                    │
│   - SDK + Rust orchestrator pick the right OS adapter            │
│                       │                                          │
│                       v dispatches to                            │
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
│   │ │   - parseDenialStream (parser)                         │ │ │
│   │ │   - Transports: stderr (xplat, implicit in parser),    │ │ │
│   │ │     named-pipe (Windows), unix-socket (planned)        │ │ │
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
| `src/core/learning_mode_api/` | 2 (split) | xplat | `LearningModeBackend` trait + `CaptureOptions` / `CaptureSummary` / `CaptureHandle` / `LearningModeError`. Split out from `learning_mode` to break a cargo dependency cycle (`learning_mode -> learning_mode_<os> -> learning_mode`). |
| `src/core/learning_mode/` | 2 | xplat | Re-exports everything in `learning_mode_api` plus the `orchestrator::current_backend()` dispatcher. **Consumers depend on this crate.** |
| `src/backends/learning_mode_windows/` | 3 (Windows) | Windows | ETW kernel-audit session, TDH event decoders, shim RPC wire format, path canonicalisation, NDJSON stderr writer, child-process Toolhelp observer. Impls `LearningModeBackend` as `WindowsLearningModeBackend`. |
| `src/backends/learning_mode_linux/` | 3 (Linux) | xplat (compiles everywhere, only meaningful on Linux) | Stub. `is_available()` returns `false`; `begin_capture()` returns `Err(NotSupported)`. Future: fanotify + audit. |
| `src/backends/learning_mode_macos/` | 3 (macOS) | xplat | Stub. Same pattern. Future: EndpointSecurity framework. |
| `src/host/mxc_learning_mode_shim/` | 3 (Windows host) | Windows | Privileged Windows service that loans an ETW trace handle to `wxc-exec`. Binary: `mxc-learning-mode-shim.exe`. Service name: `MxcLearningModeShim`. Pipe: `\\.\pipe\mxc-learning-mode-shim`. |
| `src/host/wxc_host_prep/src/learning_mode_shim/` | 3 (Windows host) | Windows | Install / uninstall / inspect logic for the shim service. Invoked via the `install-denial-shim` / `uninstall-denial-shim` / `dump-denial-shim` subcommands on `wxc-host-prep`. (CLI subcommand names kept as-is for UX continuity.) |

The dependency graph (omitting unrelated crates):

```
                ┌────────────────────┐
                │  denial_channel    │  (types, xplat)
                └──────────△─────────┘
                           │
                ┌──────────┴──────────┐
                │  learning_mode_api  │  (trait + types, xplat)
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

The split of `learning_mode_api` from `learning_mode` is a pure
cargo-cycle workaround: cargo computes cycles across all targets
even for `cfg(target_os)`-gated deps, so `learning_mode` cannot
both depend on the OS backends and host the trait the backends
implement. Consumers don't see this split — `learning_mode`
re-exports everything.

---

## SDK layout

| File | Box | Purpose |
|---|---|---|
| `sdk/src/denial-channel/stream.ts` | 1 | `parseDenialStream` (NDJSON parser), `DeniedResource` / `DenialAccessType` / `DenialResourceType` types, `defaultDenialFilters`, `stripNtPrefix`, `DENIAL_STREAM_MARKER`. The parser is stream-agnostic — pass it any `Readable`, including `child.stderr` for the implicit stderr transport. |
| `sdk/src/denial-channel/transports/named-pipe.ts` | 1 (Windows) | Windows named-pipe server (`createDenialPipeServer`). Used when the workload owns the PTY so the denial stream can't share stderr. |
| `sdk/src/denial-channel/index.ts` | 1 | Internal barrel; re-exports the two files above. |
| `sdk/src/learning-mode/policy-regen.ts` | 2 | `regenerateSandboxPolicy` — given an existing `SandboxPolicy` and a list of `DeniedResource` events, produces a relaxed policy. |
| `sdk/src/learning-mode/spawn-with-retry.ts` | 2 | `spawnSandboxWithRetry` — drives the retry loop (spawn → parse stream → call `onDenied` → regen policy → respawn). |
| `sdk/src/learning-mode/index.ts` | 2 | Internal barrel. |

External callers see no path changes: `sdk/src/index.ts` re-exports
everything from the new locations with the same names as before, so
`import { spawnSandboxWithRetry } from '@microsoft/mxc-sdk'`
continues to work.

---

## End-to-end call path (Windows)

For an SDK consumer doing `spawnSandboxWithRetry`:

```
┌──────────────────────────────────────────────────────────┐
│ Consumer (Node) — @microsoft/mxc-sdk                     │
│   spawnSandboxWithRetry(policy, { onDenied: cb })        │
└────────────────────────┬─────────────────────────────────┘
                         │
                         v
┌──────────────────────────────────────────────────────────┐
│ sdk/src/learning-mode/spawn-with-retry.ts (Box 2)        │
│   - spawn child (wxc-exec)                               │
│   - hand child.stderr to parseDenialStream               │
│   - on each event, optionally call onDenied              │
│   - on retry, regen policy via learning-mode/policy-regen│
└────────────────────────┬─────────────────────────────────┘
                         │
                         v
┌──────────────────────────────────────────────────────────┐
│ sdk/src/denial-channel/stream.ts (Box 1)                 │
│   - read NDJSON from stderr                              │
│   - dedupe, materialise DeniedResource records           │
│   - emit summary line on terminator                      │
└────────────────────────△─────────────────────────────────┘
                         │ stderr (NDJSON, RS-prefixed)
                         │
┌────────────────────────┴─────────────────────────────────┐
│ wxc-exec.exe — appcontainer / base_container runner      │
│   - spawn workload CREATE_SUSPENDED                      │
│   - learning_mode_windows::session::open_via_shim(pid)   │
│       └──> RPC to mxc-learning-mode-shim service         │
│   - learning_mode_windows::denial_stream::*              │
│       (NDJSON writer thread, writes stderr lines)        │
│   - learning_mode_windows::child_process_observer        │
│       (Toolhelp poll, tracks descendants)                │
│   - resume workload                                      │
│   - drain at exit, emit summary line                     │
└────────────────────────┬─────────────────────────────────┘
                         │ named pipe RPC
                         │
┌────────────────────────┴─────────────────────────────────┐
│ mxc-learning-mode-shim service (LocalSystem)             │
│   - validates request                                    │
│   - StartTraceW + EnableTraceEx2 + PID filter            │
│   - DuplicateHandle trace handle into wxc-exec           │
│   - disconnects                                          │
└──────────────────────────────────────────────────────────┘
```

Future cross-platform consumers (e.g. a Linux runner) would replace
the bottom two boxes — everything above stays put because the boxes
above are OS-agnostic.

---

## Why CLI subcommands kept the `denial-shim` name

The user-facing surface on `wxc-host-prep` is:

- `install-denial-shim`
- `uninstall-denial-shim`
- `dump-denial-shim`

These were intentionally **not renamed** to `install-learning-mode-shim`
during the rearchitecture. The reasoning:

- They are operator commands embedded in install scripts and CI
  pipelines. Renaming them would silently break those workflows
  without giving any architectural benefit.
- The CLI surface is the natural boundary for "what users see" vs
  "how we implement it". Internal names are free to change; CLI
  verbs are a contract.

The internal implementation (crate name `mxc_learning_mode_shim`,
service name `MxcLearningModeShim`, pipe name
`\\.\pipe\mxc-learning-mode-shim`) all use the new naming so
operators reading service-control output or pipe enumeration see a
consistent story.

---

## Status and future work

**Done (this rearchitecture):**

- Box 1 (`denial_channel`) extracted from former `denial_capture` crate.
- Box 2 (`learning_mode_api` + `learning_mode`) created with trait,
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

**Open follow-ups (not blocking):**

- Real Linux backend (fanotify + kernel audit).
- Real macOS backend (EndpointSecurity framework).
- Network/WFP denial capture (tracked as `cap-future-network-denials`).
- Runner refactor to call `learning_mode::orchestrator::current_backend()`
  instead of `learning_mode_windows::*` directly. Deferred because
  the appcontainer / base_container runners are already
  `#[cfg(target_os = "windows")]`-gated — the direct call is
  simpler than going through the trait until a cross-platform
  runner appears.
