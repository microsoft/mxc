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
    capture_denials: None,
};
let mut request = build_request(&policy, None)?;
request.set_script("echo hello").set_telemetry_enabled(true);

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

Telemetry remains off unless `SandboxRequest::set_telemetry_enabled(true)` is
called. Enabling that per-invocation switch still requires persisted user
consent and a permitting administrative policy.

To target a specific backend instead of the host default, use
[`build_request_with_containment`] with a [`Containment`] — the same choice the
TypeScript SDK makes with `createConfigFromPolicy(policy, containment)`.

Filesystem-policy discovery helpers (ports of the SDK's `policy.ts`) are also
available to feed a policy: [`available_tools_policy`] (PATH + tool/SDK env
dirs), [`user_profile_policy`], and [`temporary_files_policy`].

## Discovering host backends

Two read-only probes answer "what can I run here?" — for two different
questions:

- [`platform_support`] — the Rust port of `getPlatformSupport`. Reports whether
  MXC is supported on this host and the backends **this SDK can actually
  launch** (the subset in [Supported backends](#supported-backends)). Use it to
  decide whether `run` / `spawn_sandbox` will work before building a request.
- [`available_backends`] — a broader **host-capability** probe. Reports every
  containment backend the *host* can run, including ones only the executor
  binaries (`wxc-exec` etc.) can currently drive — Windows Sandbox,
  IsolationSession, LXC — each with its effective isolation **tier** (for the
  Windows ProcessContainer ladder). Use it for capability discovery, not as a
  launchability guarantee.

```rust,no_run
use mxc_sdk::{available_backends, platform_support, BackendCapability};

// Will run()/spawn_sandbox() work here, and with which backends?
let support = platform_support();
if support.is_supported {
    println!("SDK-launchable: {:?}", support.available_methods);
} else {
    println!("unsupported: {:?}", support.reason);
}

// What can the host run at all, and at what isolation-tier ceiling?
for backend in available_backends() {
    let capture_denials = backend
        .capabilities
        .contains(&BackendCapability::CaptureDenials);
    match backend.tier {
        Some(tier) => println!(
            "{} (tier: {tier}, captureDenials: {capture_denials})",
            backend.backend
        ),
        None => println!("{}", backend.backend),
    }
}
```

The reported `tier` is a **ceiling** — the strongest isolation the host can
reach for that backend; a policy can still force a weaker tier at dispatch.
`capabilities` reports optional features that passed the host probe, including
the ProcessContainer's `CaptureDenials`. These are advisory: callers must still
handle `ErrorCode::BackendUnavailable` if availability changes before launch.
And a backend appearing in `available_backends()` is a host-capability signal,
**not** a guarantee this SDK can launch it — cross-check [`platform_support`]
for that.

> **Before / after.** Host-and-backend discovery previously lived only in the
> TypeScript SDK (`getPlatformSupport`), so Rust callers and the executor
> binaries had no in-process way to ask "what backends does this host support?"
> and could only learn a backend was unusable by trying to launch it. Now the
> engine answers both in-process — [`platform_support`] for the SDK-launchable
> subset and [`available_backends`] for the full host-capability set with tiers —
> with no TypeScript dependency and no trial spawn.

## Denial capture (Windows)

`SandboxPolicy::capture_denials` enables the Windows ProcessContainer's
learning-mode capture: the runner records every access the policy does not
grant and writes them to a JSON denials document.

```rust
use mxc_sdk::policy::{CaptureDenialsMode, CaptureDenialsSection};
use mxc_sdk::SandboxPolicy;

let policy = SandboxPolicy {
    version: "0.8.0-alpha".to_string(),
    filesystem: None,
    network: None,
    ui: None,
    timeout_ms: None,
    capture_denials: Some(CaptureDenialsSection {
        // `Block` (the default) keeps deny-by-default and records the denial;
        // `Allow` runs permissively and records what *would* have been denied.
        mode: CaptureDenialsMode::Block,
        // Absolute path; a per-run id is stamped into the stem
        // (`denials.json` -> `denials.<run-id>.json`). `None` uses a managed temp.
        output_path: None,
    }),
};
```

`Allow` relaxes containment for the run — it is reported through `warnings()`.
Read the resulting file path and denial summary from `output_metadata()` after
the process terminates. The section is ignored on Linux and macOS, whose
backends have no learning-mode API.

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
    capture_denials: None,
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

## Telemetry consent

MXC only ever collects telemetry on Windows, and only after the end user has
explicitly opted in — a persisted, MXC-owned consent flag gates every
emission (never a Windows-level setting like Diagnostics & feedback). See
[`docs/telemetry/telemetry-consent-design.md`](../../../docs/telemetry/telemetry-consent-design.md)
for the full design.

The crate is UI-agnostic: it does not render a prompt. Call
`needs_consent_prompt()` once at first sandbox run, show your own UI, then
record the answer — and let a settings surface flip it at any later time.

Telemetry is also off per invocation unless the request explicitly enables it
with `SandboxRequest::set_telemetry_enabled(true)`. This stable switch does not
require `set_experimental(true)` and cannot bypass consent or administrative
policy.

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
