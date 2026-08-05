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

To target a specific backend instead of the host default, use
[`build_request_with_containment`] with a [`Containment`] — the same choice the
TypeScript SDK makes with `createConfigFromPolicy(policy, containment)`.

Filesystem-policy discovery helpers (ports of the SDK's `policy.ts`) are also
available to feed a policy: [`available_tools_policy`] (PATH + tool/SDK env
dirs), [`user_profile_policy`], and [`temporary_files_policy`].

[`platform_support`] is the Rust port of `getPlatformSupport` — reports host
support and the available containment backends. Each platform probes the
dependency that actually fails at spawn time: `/usr/bin/sandbox-exec` on macOS,
a real namespace-creating `bwrap` run on Linux, and the host OS build against
the 26100 (24H2) floor on Windows.

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
- `output_metadata()` returns structured feature outputs after a terminal wait.
  For `captureDenials`, it contains the generated JSON file path and summary.
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
  also includes structured `output_metadata` produced during backend teardown.
  The method
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

| Host    | Backend(s)                                      | Selected by             |
|---------|-------------------------------------------------|-------------------------|
| Linux   | Bubblewrap                                      | `Containment::Process`  |
| macOS   | Seatbelt                                        | `Containment::Process`  |
| Windows | ProcessContainer (AppContainer + BaseContainer) | `Containment::Process`  |
| Windows | WSLC (WSL Container)                            | `Containment::Wslc`     |

Any other backend (Windows Sandbox, IsolationSession, MicroVM, Hyperlight, LXC)
returns an [`Error`] with [`ErrorCode::UnsupportedContainment`]; drive the
standalone executor binaries for those.

### WSLC (experimental)

WSLC runs a Linux container on a Windows host through the WSLC SDK. It is
opt-in on two axes: build this crate with its **`wslc` feature**, and call
[`SandboxRequest::set_experimental(true)`] on the request (the library-side
equivalent of the executor's `--experimental`). Its settings — image, vCPUs,
memory, GPU, storage path, port forwards — are carried by the [`WslcSection`]
inside [`Containment::Wslc`], mirroring the SDK's `experimental.wslc` block, and
go through the same parser the executor uses — so a rejected value (e.g. a port
mapping with a zero or duplicated host port) fails at build time, not at spawn.

```rust,no_run
use mxc_sdk::{build_request_with_containment, run, Containment, SandboxPolicy, WslcSection};

# let policy = SandboxPolicy {
#     version: "0.7.0-alpha".to_string(),
#     filesystem: None, network: None, ui: None, timeout_ms: None,
# };
let wslc = WslcSection { image: "python:3.12".to_string(), ..Default::default() };
let mut request = build_request_with_containment(&policy, &Containment::Wslc(wslc), None)?;
request.set_script("python3 -c 'print(42)'").set_experimental(true);
let output = run(request)?;
# Ok::<(), mxc_sdk::Error>(())
```

Two WSLC-specific limits follow from the SDK's surface: the container has no
stdin (`Sandbox::take_stdin()` returns `None`), and its process has no host
process id (`Sandbox::id()` is `0`) — `kill()` stops the whole container.
[`platform_support`] reports `"wslc"` only on a host that can actually run it.

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
