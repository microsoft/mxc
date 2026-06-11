# `mxc`

An importable Rust library for starting [MXC](../../../README.md) sandboxes
**in-process** — the Rust analogue of the SDK's `spawnSandboxFromConfig` with
`usePty: false`.

It takes the same JSON config the executor binaries (`wxc-exec`, `lxc-exec`,
`mxc-exec-mac`) consume, selects the right containment backend for the host,
runs the sandboxed process **without ever allocating a pty**, and returns the
captured stdout/stderr and exit code.

## Usage

```rust
use mxc::{spawn_sandbox_from_config, SpawnOptions};

// `config` is the same JSON the SDK serialises from a SandboxPolicy
// (a ContainerConfig). Pass `is_base64: true` to supply it base64-encoded.
let config = r#"{
    "version": "0.7.0-alpha",
    "containment": "seatbelt",
    "process": { "commandLine": "echo hello", "timeout": 10000 },
    "filesystem": { "readwritePaths": ["/tmp"] }
}"#;

let result = spawn_sandbox_from_config(config, &SpawnOptions::default())?;
assert_eq!(result.exit_code, 0);
println!("{}", result.standard_out); // "hello\n"
# Ok::<(), mxc::MxcError>(())
```

`SpawnOptions` mirrors the executor CLI knobs (minus anything pty-related):
`is_base64`, `experimental`, `dry_run`, `working_directory`, `command`
(override `process.commandLine`), and `env` (merged into `process.env`).

For callers that already hold a parsed `ExecutionRequest`, use
[`spawn_sandbox_from_request`].

## Live stdio + kill (streaming)

`spawn_sandbox` is the handle-based counterpart: instead of running to
completion it returns a [`SandboxProcess`] you can drive while it runs —
persistent bidirectional stdio plus termination. No pty is allocated; the
streams are ordinary pipes.

```rust
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

let result = proc.wait()?;        // exit code (+ any untaken streams)
# Ok::<(), Box<dyn std::error::Error>>(())
```

The handle is modelled on [`std::process::Child`]:

- `take_stdin()` → `Box<dyn Write + Send>`, `take_stdout()` / `take_stderr()`
  → `Box<dyn Read + Send>` (drive them yourself; you own draining any stream
  you take, to avoid the child blocking on a full pipe).
- `try_wait()` for a non-blocking exit check.
- `kill()` requests termination (Unix: graceful `SIGTERM`, escalating to
  `SIGKILL` after a short grace period).
- `wait()` blocks until exit (honouring `scriptTimeout`, where `0` waits
  forever), drains any **untaken** stdout/stderr, and returns the exit code
  plus captured output. With no streams taken, `spawn_sandbox(..).wait()`
  behaves like a run-to-completion capture.

Streaming is currently implemented for **Seatbelt (macOS)**; other backends
return [`MxcError::unsupported_containment`] from `spawn_sandbox` for now.

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

## Output capture (no pty)

The library always sets `ExecutionRequest::capture_output`, so the child's
stdout/stderr are captured into the returned `ScriptResponse` rather than
streamed to the host's stdio, and **no pty is allocated** for any backend.
This differs from the executor binaries, which stream live (Seatbelt/LXC via a
pty, AppContainer by inheriting the host fds). The `capture_output` flag
defaults to `false`, so the binaries' behaviour is unchanged.

## Relationship to the executor binaries

Backend runner selection lives in [`dispatch::select_runner`] and is shared
with the `wxc-exec`, `lxc-exec`, and `mxc-exec-mac` binaries, which delegate
their backend arms here so the selection logic has a single home.
