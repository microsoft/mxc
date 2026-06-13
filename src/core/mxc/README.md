# `mxc`

An importable Rust library for starting [MXC](../../../README.md) sandboxes
**in-process**, without ever allocating a pty.

It takes the same JSON config the executor binaries (`wxc-exec`, `lxc-exec`,
`mxc-exec-mac`) consume, selects the right containment backend for the host,
and spawns the sandboxed process — returning a handle for live bidirectional
stdio and termination.

## Usage

```rust,no_run
use std::io::Read;
use mxc::{spawn_sandbox, SpawnOptions};

// `config` is the same JSON the SDK serialises from a SandboxPolicy
// (a ContainerConfig). Pass `is_base64: true` to supply it base64-encoded.
let config = r#"{
    "version": "0.7.0-alpha",
    "containment": "seatbelt",
    "process": { "commandLine": "echo hello", "timeout": 10000 },
    "filesystem": { "readwritePaths": ["/tmp"] }
}"#;

let mut proc = spawn_sandbox(config, &SpawnOptions::default())?;
let mut stdout = proc.take_stdout().unwrap();
let mut out = String::new();
stdout.read_to_string(&mut out)?; // "hello\n"
let exit_code = proc.wait()?;     // drains/discards any untaken stream, returns exit code
assert_eq!(exit_code, 0);
# Ok::<(), Box<dyn std::error::Error>>(())
```

`SpawnOptions` mirrors the executor CLI knobs (minus anything pty-related):
`is_base64`, `experimental`, `dry_run`, `working_directory`, `command`
(override `process.commandLine`), and `env` (merged into `process.env`).

For callers that already hold a parsed `ExecutionRequest`, use
[`spawn_streaming_from_request`].

## Building a config from a policy (no TypeScript SDK needed)

Instead of constructing the wire config in the `@microsoft/mxc-sdk` TypeScript
module, build it in Rust from a [`SandboxPolicy`]:

```rust,no_run
use mxc::{build_request, spawn_streaming_from_request, Containment, SandboxPolicy};

let policy = SandboxPolicy {
    version: "0.7.0-alpha".to_string(),
    filesystem: None,
    network: None,
    ui: None,
    timeout_ms: Some(10_000),
};

let mut request = build_request(&policy, Containment::Process, None)?;
request.script_code = "echo hi".to_string();
let mut proc = spawn_streaming_from_request(request)?;
# Ok::<(), mxc::MxcError>(())
```

[`build_request`] is the Rust port of the SDK's `createConfigFromPolicy`,
restricted to the backends the crate runs (`Containment::Process` resolves to
Seatbelt on macOS, Bubblewrap on Linux, ProcessContainer on Windows;
`Containment::Bubblewrap` forces Bubblewrap). It mirrors the SDK's field
mapping and network validation, building the same wire config internally and
running it through the shared parser.

Filesystem-policy discovery helpers (ports of the SDK's `policy.ts`) are also
available to feed a policy: [`available_tools_policy`] (PATH + tool/SDK env
dirs), [`user_profile_policy`], and [`temporary_files_policy`].

[`platform_support`] is the Rust port of `getPlatformSupport` — host support,
available backends, and (on Windows) isolation tier / UI capabilities from the
in-process probe.

## Live stdio + kill (streaming)

`spawn_sandbox` is the handle-based counterpart: instead of running to
completion it returns a [`SandboxProcess`] you can drive while it runs —
persistent bidirectional stdio plus termination. No pty is allocated; the
streams are ordinary pipes.

```rust,no_run
use std::io::{Read, Write};
use mxc::{spawn_sandbox, SpawnOptions};

let config = r#"{
    "version": "0.7.0-alpha",
    "containment": "seatbelt",
    "process": { "commandLine": "cat", "timeout": 0 },
    "filesystem": { "readwritePaths": ["/tmp"] }
}"#;

let mut proc = spawn_sandbox(config, &SpawnOptions::default())?;
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

Streaming is implemented for **Seatbelt (macOS)**, **Bubblewrap (Linux)**, and
**Windows ProcessContainer (AppContainer + BaseContainer)** — i.e. every
backend the library supports.

> **Windows note:** streaming does not use the AppContainer-BFS /
> AppContainer-DACL fallback. Experimental / newer-schema configs that select
> BaseContainer require the native BaseContainer API; on a host without it,
> `spawn_sandbox` fails closed with a clear error rather than falling back to
> an AppContainer tier.

## Supported backends

The backend is chosen by the `containment` field in the config (or the host
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
allocates a pty (the executor binaries, by contrast, stream live: Seatbelt/LXC
via a pty, AppContainer by inheriting the host fds). Output the caller doesn't
take is drained and discarded by `wait()`.

## Relationship to the executor binaries

This crate is purely additive: the `wxc-exec`, `lxc-exec`, and `mxc-exec-mac`
binaries do not depend on it. It reuses the same backend crates they do (and,
on Windows, the shared `appcontainer_common::dispatcher::dispatch_with_fallback`
primitive), but spawns its own streaming handles.
