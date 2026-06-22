# `mxc-sdk`

An importable Rust library for starting [MXC](../../../README.md) sandboxes
**in-process**, without ever allocating a pty.

Build a `SandboxRequest` from a [`SandboxPolicy`], then hand it to
[`spawn_sandbox`]: it selects the
right containment backend for the host and spawns the sandboxed process —
returning a handle for live bidirectional stdio and termination.

## Usage

```rust,no_run
use std::io::Read;
use mxc_sdk::{build_request, spawn_sandbox, SandboxPolicy};

// Describe what to restrict, turn it into a request, fill in the command.
let policy = SandboxPolicy {
    version: "0.7.0-alpha".to_string(),
    filesystem: None,
    network: None,
    ui: None,
    timeout_ms: Some(10_000),
};
let mut request = build_request(&policy, None)?;
request.set_script_code("echo hello");

let mut proc = spawn_sandbox(request)?;
let mut stdout = proc.take_stdout().unwrap();
let mut out = String::new();
stdout.read_to_string(&mut out)?; // "hello\n"
let exit_code = proc.wait()?;     // drains/discards any untaken stream, returns exit code
assert_eq!(exit_code, 0);
# Ok::<(), Box<dyn std::error::Error>>(())
```

[`build_request`] is the Rust port of the SDK's `createConfigFromPolicy`. It
resolves the host's containment backend (Seatbelt on macOS, Bubblewrap on
Linux, ProcessContainer on Windows) and mirrors the SDK's field mapping and
network validation, building the same wire config internally and running it
through the shared parser. The returned [`SandboxRequest`] has an empty
command line — set the command with [`SandboxRequest::set_script_code`] (and any
working directory / env) before spawning.

Filesystem-policy discovery helpers (ports of the SDK's `policy.ts`) are also
available to feed a policy: [`available_tools_policy`] (PATH + tool/SDK env
dirs), [`user_profile_policy`], and [`temporary_files_policy`].

[`platform_support`] is the Rust port of `getPlatformSupport` — reports host
support and the available containment backends.

## Live stdio + kill (streaming)

[`spawn_sandbox`] returns a [`SandboxProcess`] you can drive
while it runs — persistent bidirectional stdio plus termination. No pty is
allocated; the streams are ordinary pipes.

```rust,no_run
use std::io::{Read, Write};
use mxc_sdk::{build_request, spawn_sandbox, SandboxPolicy};

let policy = SandboxPolicy {
    version: "0.7.0-alpha".to_string(),
    filesystem: None,
    network: None,
    ui: None,
    timeout_ms: None,
};
let mut request = build_request(&policy, None)?;
request.set_script_code("cat"); // echoes stdin until EOF

let mut proc = spawn_sandbox(request)?;
let mut stdin = proc.take_stdin().unwrap();
let mut stdout = proc.take_stdout().unwrap();

stdin.write_all(b"hello\n")?;
drop(stdin);                      // close -> child sees EOF
let mut out = String::new();
stdout.read_to_string(&mut out)?; // "hello\n"

let exit_code = proc.wait()?;     // any untaken stream is drained and discarded
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
  whole group is signalled (graceful `SIGTERM`, escalating to `SIGKILL` after
  a short grace period); on Windows the child's job object is terminated.
- `wait()` blocks until exit (honouring `scriptTimeout`, where `0` waits
  forever), drains and discards any **untaken** stdout/stderr so the child
  can't block on a full pipe, and returns the exit code (`ErrorKind::TimedOut`
  if the timeout elapses).
- `stdout_closer()` / `stderr_closer()` → `Option<Box<dyn StreamCloser>>`: a
  closer that makes an in-flight or subsequent read on the taken stream return
  EOF promptly **without** killing the child — for abandoning a stream a
  backgrounded descendant is holding open past the foreground command's exit (a
  plain `kill()` would also take that descendant down). Returns `None` for
  non-streamed stdio.

Streaming is implemented for **Seatbelt (macOS)**, **Bubblewrap (Linux)**, and
**Windows ProcessContainer (AppContainer + BaseContainer)** — i.e. every
backend the library supports.

> **Windows note:** streaming does not use the AppContainer-BFS /
> AppContainer-DACL fallback. Experimental / newer-schema configs that select
> BaseContainer require the native BaseContainer API; on a host without it,
> `spawn_sandbox` fails closed with a clear error rather than
> falling back to an AppContainer tier.

## Supported backends

The backend is chosen by the `containment` field in the request (or the host
default):

| Host    | Backend(s)                                             |
|---------|--------------------------------------------------------|
| Linux   | Bubblewrap                                             |
| macOS   | Seatbelt                                               |
| Windows | ProcessContainer (AppContainer + BaseContainer fallback) |

Any other backend (Windows Sandbox, IsolationSession, MicroVM, Hyperlight,
WSLC, LXC) returns [`MxcError::unsupported_containment`]; drive the standalone
executor binaries for those.

## No pty

The child's stdio is always wired to ordinary pipes — the library never
allocates a pty (the executor binaries, by contrast, stream live: LXC via a
pty, Seatbelt/Bubblewrap/AppContainer by inheriting the executor's stdio
directly — a TTY when the executor has one). Output the caller doesn't
take is drained and discarded by `wait()`.

## Relationship to the executor binaries

The `wxc-exec`, `lxc-exec`, and `mxc-exec-mac` binaries do not depend on this
crate. It reuses the same backend crates they do (and, on Windows, the shared
`appcontainer_common::dispatcher::dispatch_with_fallback` primitive), but
spawns its own streaming handles.
