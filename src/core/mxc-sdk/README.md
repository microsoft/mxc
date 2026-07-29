# `mxc-sdk`

An importable Rust library for starting [MXC](../../../README.md) sandboxes
**in-process**, without ever allocating a pty.

Build a `SandboxRequest` from a [`SandboxPolicy`], then either **run it to
completion** with [`run`] (capturing stdout/stderr in one call) or hand it to
[`spawn_sandbox`] for a live handle you can stream, feed stdin, and kill.
Either way it selects the right containment backend for the host and runs the
sandboxed process — no pty is ever allocated.

## Usage

```rust,no_run
use mxc_sdk::{build_request, run, SandboxPolicy, WaitOutcome};

// Describe what to restrict, turn it into a request, fill in the command.
let policy = SandboxPolicy {
    version: "0.7.0-alpha".to_string(),
    filesystem: None,
    network: None,
    ui: None,
    timeout_ms: Some(10_000),
};
let mut request = build_request(&policy, None)?;
request.set_script("echo hello");

// Run to completion and capture the output.
let output = run(request)?;
assert_eq!(output.outcome, WaitOutcome::Exited(0));
assert_eq!(String::from_utf8_lossy(&output.stdout), "hello\n");
# Ok::<(), Box<dyn std::error::Error>>(())
```

[`run`] is the run-to-completion convenience (spawn + `wait_with_output`); use
[`spawn_sandbox`] when you need to drive the process live (see
[Live stdio + kill](#live-stdio--kill-streaming) below).

[`build_request`] is the Rust port of the SDK's `createConfigFromPolicy`. It
resolves the host's containment backend (Seatbelt on macOS, Bubblewrap on
Linux, ProcessContainer on Windows) and mirrors the SDK's field mapping and
network validation, building the same wire config internally and running it
through the shared parser. The returned [`SandboxRequest`] has an empty
command line — set the command with [`SandboxRequest::set_script`] (and any
working directory / env) before spawning.

Filesystem-policy discovery helpers (ports of the SDK's `policy.ts`) are also
available to feed a policy: [`available_tools_policy`] (PATH + tool/SDK env
dirs), [`user_profile_policy`], and [`temporary_files_policy`].

[`platform_support`] is the Rust port of `getPlatformSupport` — reports host
support and the available containment backends.

## Live stdio + kill (streaming)

[`spawn_sandbox`] returns a [`Sandbox`] you can drive
while it runs — persistent bidirectional stdio plus termination. No pty is
allocated; the streams are ordinary pipes.

```rust,no_run
use std::io::{Read, Write};
use mxc_sdk::{build_request, spawn_sandbox, SandboxPolicy, WaitOutcome};

let policy = SandboxPolicy {
    version: "0.7.0-alpha".to_string(),
    filesystem: None,
    network: None,
    ui: None,
    timeout_ms: None,
};
let mut request = build_request(&policy, None)?;
request.set_script("cat"); // echoes stdin until EOF

let mut proc = spawn_sandbox(request)?;
let mut stdin = proc.take_stdin().unwrap();
let mut stdout = proc.take_stdout().unwrap();

stdin.write_all(b"hello\n")?;
drop(stdin);                      // close -> child sees EOF
let mut out = String::new();
stdout.read_to_string(&mut out)?; // "hello\n"

let outcome = proc.wait()?;       // any untaken stream is drained and discarded
assert_eq!(outcome, WaitOutcome::Exited(0));
# Ok::<(), Box<dyn std::error::Error>>(())
```

The handle is modelled on [`std::process::Child`]:

- `take_stdin()` → `Box<dyn Write + Send>`, `take_stdout()` / `take_stderr()`
  → `Box<dyn Read + Send>` (drive them yourself; you own draining any stream
  you take, to avoid the child blocking on a full pipe).
- `id()` returns the child's OS process id, for external monitoring or a
  caller-driven process-tree kill.
- `try_wait()` for a non-blocking exit check.
- `warnings()` returns policy security warnings detected while spawning the
  sandbox, such as `permissiveLearningMode` weakening deny-by-default.
- `kill()` terminates the sandboxed process **and its descendants** (a
  process-tree kill): on Unix the child leads its own process group and the
  whole group is signalled (an immediate `SIGKILL`, no graceful `SIGTERM`);
  on Windows the child's job object is terminated.
- `wait()` blocks until exit (honouring `scriptTimeout`, where `0` waits
  forever), drains and discards any **untaken** stdout/stderr so the child
  can't block on a full pipe, and returns a `WaitOutcome` —
  `Exited(code)` or `TimedOut` if the timeout elapses (`Err` is reserved for an
  actual OS/wait failure).
- `wait_with_output()` consumes the handle and returns an `Output` with the
  `WaitOutcome`, policy security `warnings`, and captured `stdout`/`stderr` — it
  drains both streams concurrently for you, the safe alternative to
  `take_stdout()` + `take_stderr()` (reading one to EOF before the other can
  deadlock an output-heavy child).
- `stdout_closer()` / `stderr_closer()` → `Option<StreamCloser>`: a
  closer that makes an in-flight or subsequent read on the taken stream return
  EOF promptly **without** killing the child — for abandoning a stream a
  backgrounded descendant is holding open past the foreground command's exit (a
  plain `kill()` would also take that descendant down). Returns `None` for
  non-streamed stdio.

Streaming is implemented for **Seatbelt (macOS)**, **Bubblewrap (Linux)**, and
**Windows ProcessContainer (AppContainer + BaseContainer)** — i.e. every
backend the library supports.

> **Windows note:** the ProcessContainer backend resolves to a concrete
> isolation tier by host capability, using the **same** three-tier fallback as
> the `wxc-exec` executor: BaseContainer (native OS sandbox API) when usable,
> otherwise AppContainer + BFS (`bfscfg.exe`) when available, otherwise
> AppContainer + DACL. The streaming handle owns any host-DACL guard, so ACE
> restore outlives the child. A host with none of the tiers available surfaces a
> clear error rather than silently running unsandboxed.

## State-aware lifecycle

Beyond the one-shot `run` / `spawn_sandbox` paths, the SDK exposes the
state-aware sandbox lifecycle from a wire-format request JSON string:

- `run_state_aware_json(request_json, dry_run)` drives the **envelope phases** —
  `provision`, `start`, `stop`, `deprovision` (and a dry run of any phase) — and
  returns the response-envelope JSON string.
- `exec_sandbox(request_json)` runs the `exec` phase as a **live streaming**
  `Sandbox` (the same handle `spawn_sandbox` returns).

```rust,no_run
use mxc_sdk::{run_state_aware_json, exec_sandbox};

// Envelope phase: provision returns { "result": { "sandboxId": ... } }.
let provisioned = run_state_aware_json(
    r#"{"phase":"provision","containment":"isolation_session"}"#,
    false,
)?;

// Exec phase: a live streaming handle.
let mut proc = exec_sandbox(
    r#"{"phase":"exec","sandboxId":"iso:...","process":{"commandLine":"echo hi"}}"#,
)?;
let _ = proc.wait();
# Ok::<(), Box<dyn std::error::Error>>(())
```

The only in-tree state-aware backend, IsolationSession, is Windows-only and
experimental (it needs its OS-side service); on a host/build without it these
return an `Error` with `ErrorCode::UnsupportedPhase`.

## Supported backends

The backend is chosen by the `containment` field in the request (or the host
default):

| Host    | Backend(s)                                             |
|---------|--------------------------------------------------------|
| Linux   | Bubblewrap                                             |
| macOS   | Seatbelt                                               |
| Windows | ProcessContainer (AppContainer + BaseContainer)        |

Any other backend (Windows Sandbox, IsolationSession, MicroVM, Hyperlight,
WSLC, LXC) returns an [`Error`] with [`ErrorCode::UnsupportedContainment`]; drive the standalone
executor binaries for those.

## Telemetry consent

MXC only ever collects telemetry on Windows, and only after the end user has
explicitly opted in — a persisted, MXC-owned consent flag gates every
emission (never a Windows-level setting like Diagnostics & feedback). See
[`docs/telemetry/telemetry-consent-design.md`](../../../docs/telemetry/telemetry-consent-design.md)
for the full design.

The crate is UI-agnostic: it does not render a prompt. Call
`needs_consent_prompt()` once at first sandbox run, show your own UI, then
record the answer — and let a settings surface flip it at any later time.

```rust,no_run
use mxc_sdk::telemetry;

if telemetry::needs_consent_prompt() {
    // Show your own consent UI, then record the user's choice:
    telemetry::set_consent(user_opted_in, "prompt")?;
}

// Anywhere later, e.g. a settings toggle:
let _state = telemetry::get_consent();
telemetry::set_consent(false, "settings-toggle")?;
# Ok::<(), Box<dyn std::error::Error>>(())
```

Off Windows `get_consent()` always returns `ConsentState::NotApplicable`,
`needs_consent_prompt()` is always `false`, and `set_consent(..)` always
fails — MXC neither collects nor offers consent for telemetry there, so a
host can call these unconditionally without special-casing the platform.

`ConsentState` and `PolicyState` are SDK-owned types, so the public API never
leaks the internal `wxc_common` foundation crate. The *decision logic* behind
them is not duplicated: every function here delegates to
`wxc_common::telemetry`, the same code the `wxc-exec` CLI flags, the C# SDK
(via `mxc_ffi`), and the Node SDK all resolve consent through. There is
deliberately no Rust-SDK-specific consent logic to drift.

### Administrative policy

An IT administrator can block MXC telemetry device-wide via MXC's own
Group Policy / MDM setting. `telemetry::get_policy()` reports the result:

```rust,no_run
use mxc_sdk::telemetry::{self, PolicyState};

if telemetry::get_policy() == PolicyState::Blocked {
    // Don't show a consent toggle; telemetry is unavailable on this device.
}
```

Two things worth designing around:

- The policy is a **ceiling, never a grant**. `PolicyState::Allowed` does not
  mean telemetry is on — the user must still consent. Only
  `ConsentState::Granted` *and* a non-blocking policy result in collection.
- When the policy blocks, `needs_consent_prompt()` is `false`, because asking
  for permission an administrator has already refused is a meaningless
  question. Word any UI as "telemetry is unavailable on this device" rather
  than blaming the user's own choice.

It never fails: any unreadable or unrecognized value reads back as
`PolicyState::Blocked`. Off Windows it is always `PolicyState::NotApplicable`.
`telemetry::is_blocked_by_policy()` is the convenience predicate. See
[`docs/telemetry/telemetry-policy.md`](../../../docs/telemetry/telemetry-policy.md).

## No pty

The child's stdio is always wired to ordinary pipes — the library never
allocates a pty (the executor binaries, by contrast, stream live: LXC via a
pty, Seatbelt/Bubblewrap/AppContainer by inheriting the executor's stdio
directly — a TTY when the executor has one). Output the caller doesn't
take is drained and discarded by `wait()`.

## Relationship to `mxc_engine` and the executor binaries

Backend dispatch, host probing, and config building live in the internal
`mxc_engine` crate; this crate is a thin streaming facade that re-exports the
curated engine surface and wraps the engine's streaming handle in [`Sandbox`].

The `wxc-exec`, `lxc-exec`, and `mxc-exec-mac` binaries do not (yet) depend on
this crate. The engine reuses the same backend crates they do; on Windows both
the streaming and the run-to-completion paths share
`appcontainer_common::dispatcher`'s tier selection (`select_backend_with_fallback`),
so they agree on the BaseContainer / AppContainer + BFS / AppContainer + DACL
tier and spawn the appropriate handle.
