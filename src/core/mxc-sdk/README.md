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
  `WaitOutcome` plus the captured `stdout`/`stderr` — it drains both streams
  concurrently for you, the safe alternative to `take_stdout()` + `take_stderr()`
  (reading one to EOF before the other can deadlock an output-heavy child).
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
