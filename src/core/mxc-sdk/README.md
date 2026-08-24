# `mxc-sdk`

An importable Rust library for starting [MXC](../../../README.md) sandboxes
**in-process**.

Build a `SandboxRequest` from a [`SandboxPolicy`], then either **run it to
completion** with [`run`] (capturing stdout/stderr in one call) or hand it to
[`spawn_sandbox`] for a live handle you can stream, feed stdin, and kill.
Either way it selects the right containment backend for the host and runs the
sandboxed process over ordinary pipes, with no pty. The state-aware
[`exec_attached`] path is the one exception — see *Pty allocation*.

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

## Diagnosing a failure

Every fallible **entry point** — [`build_request`],
[`build_request_with_containment`], [`run`], [`spawn_sandbox`],
[`exec_sandbox`], [`exec_attached`], [`run_state_aware_json`] — returns an
[`Error`] carrying a closed [`ErrorCode`] and a message, plus, when the failure
came from an underlying platform API, the call that failed and its status.

The live [`Sandbox`] handle is the deliberate exception: `wait`, `try_wait`,
`wait_with_output` and `kill` return [`std::io::Result`], mirroring
[`std::process::Child`]. An `Err` from those is an actual OS wait or signal
failure — a timeout is [`WaitOutcome::TimedOut`], not an error.

```rust,no_run
# fn report(error: mxc_sdk::Error) {
if let Some(operation) = &error.operation {
    eprintln!("{operation} failed with {:?}", error.native_code);
}
if let Some(hint) = &error.remediation {
    eprintln!("  try: {hint}");
}
# }
```

[`Error::operation`] and [`Error::native_code`] are **absent** for a failure
raised before any API call was reached — a malformed policy, say — so their
presence tells you which side of the boundary the failure came from. An API that
names the call it failed in without supplying a status is a normal, tested
shape. [`Error::remediation`] is present whenever the failure has an actionable
hint.

[`Error`] is `#[non_exhaustive]` — read its fields freely, but build one with
[`Error::new`] rather than by literal, so a field added later costs you nothing.

`Display` appends the operation — and the status when there is one — to the
message, so a consumer that only logs the error does not silently lose them:

```text
backend_error: The provision was not found. [IsoSessionOps.StopSessionAsync 0x80070490]
```

The same three fields cross the C ABI (`mxc_ffi`) and surface on the C# SDK's
`MxcException` as `Operation` / `NativeCode` / `Remediation`, so a diagnosis
made here reads the same from every binding.

## Discovering host backends

Two read-only probes answer "what can I run here?" — for two different
questions:

- [`platform_support`] — the Rust port of `getPlatformSupport`. Reports whether
  MXC is supported on this host and the backends **this SDK can actually
  launch** (the subset in [Supported backends](#supported-backends)). Use it to
  decide whether `run` / `spawn_sandbox` will work before building a request.
- [`available_backends`] — a broader **host-capability** probe. Reports every
  containment backend the *host* can run, including ones this SDK cannot drive
  one-shot — LXC, Windows Sandbox, and IsolationSession — each with its
  effective isolation **tier**.

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

On Linux, [`platform_support`] additionally reports `bubblewrap_network`: whether
this host can enforce **proxy-only egress** (schema `0.8.0-alpha`+ proxy mode,
which runs the sandbox in a private network namespace). That mode has no
fallback, so check it before building a proxy request:

```rust,no_run
use mxc_sdk::{platform_support, ProxyEnforcement};

if let Some(network) = platform_support().bubblewrap_network {
    if network.proxy_enforcement != ProxyEnforcement::Supported {
        println!("proxy mode unavailable: {:?}", network.warnings);
    }
}
```

Reported fail-closed: when the probe cannot run, the result is `Unsupported`
with the reason in `warnings`. The field is absent only when Bubblewrap itself
is unavailable, which [`PlatformSupport::reason`] explains.

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
        // Preserve the sealed ETL and report its path in output metadata.
        retain_etl: false,
    }),
};
```

`Allow` relaxes containment for the run — it is reported through `warnings()`.
Read the resulting file path and denial summary from `output_metadata()` after
the process terminates. When `retain_etl` is enabled, the capture output's
`etl_path` identifies the retained trace. If post-seal finalization fails,
`capture_denials_error` carries the failure and retained path. Dropping a
sandbox without a terminal wait deletes the internal trace even when retention
was requested. After deleting a retained ETL, callers should also remove its
now-empty per-run parent directory. The section is ignored on Linux and macOS,
whose backends have no learning-mode API.

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
  For `captureDenials`, it contains the generated JSON file path and summary,
  plus the retained ETL path when requested. Post-seal failures expose
  `capture_denials_error` with the failure and retained path.
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

- `run_state_aware_json(request_json, dry_run, experimental)` drives the
  **envelope phases** — `provision`, `start`, `stop`, `deprovision` (and a dry
  run of any phase) — and returns the response-envelope JSON string.
- `exec_attached(request_json, experimental)` runs the `exec` phase **attached
  to this process's stdio**, blocking until the workload exits and returning a
  `WaitOutcome`. See *Pty allocation* for the terminal requirement and what each
  backend does with the streams.
- `exec_sandbox(request_json, experimental)` runs the same `exec` phase as a
  **live streaming** `Sandbox` (the same handle `spawn_sandbox` returns), for a
  caller that drives the pipes itself. The child sees no TTY and this process's
  console is left untouched.

Both take the same request JSON and differ only in where the workload's stdio
goes.

Every state-aware backend is experimental, so `experimental` is the in-process
equivalent of the executor's `--experimental` flag: without it the request is
refused with `ErrorCode::BackendUnavailable` before any work happens. It is an
API parameter, not a field in the request JSON.

The example needs this crate's `isolation_session` feature and a host running the
OS-side service.

```rust,no_run
use mxc_sdk::{run_state_aware_json, exec_attached};

// Provision. IsolationSession accepts only the canonical unrestricted-network
// acknowledgment; an absent policy defaults to `block`, which it refuses.
let provisioned = run_state_aware_json(
    r#"{"phase":"provision","containment":"isolation_session",
        "network":{"defaultPolicy":"allow","allowLocalNetwork":true}}"#,
    false, // dry_run
    true,  // experimental
)?;
// The returned `sandboxId` is opaque — carry it forward, never parse it.

// Start. The exec phase runs against a started session.
run_state_aware_json(
    r#"{"phase":"start","sandboxId":"..."}"#,
    false, // dry_run
    true,  // experimental
)?;

// Exec phase, attached: an interactive shell on this console.
let outcome = exec_attached(
    r#"{"phase":"exec","sandboxId":"...","process":{"commandLine":"powershell.exe"}}"#,
    true, // experimental
)?;
# Ok::<(), Box<dyn std::error::Error>>(())
```

Three backends implement the state-aware lifecycle — IsolationSession, WSLc and
Windows Sandbox. Only IsolationSession serves `exec_sandbox`.

`exec_attached` is verified against **IsolationSession** only.

What an unavailable backend returns differs, so branch on the code rather than
assuming one: a build without the `wslc` or `isolation_session` feature answers
`ErrorCode::BackendUnavailable` for that backend, while a backend with no
state-aware arm on the path you called answers `ErrorCode::UnsupportedPhase`.
Windows Sandbox is compiled in unconditionally on Windows; IsolationSession and
WSLc each need their engine feature, both of which this crate forwards.

**IsolationSession is refused from a single-threaded apartment.** Call it from an
MTA thread or one with no apartment of its own.

## Supported backends

The backend is chosen by the `containment` field in the request (or the host
default):

| Host    | Backend(s)                                      | Selected by                      |
|---------|-------------------------------------------------|----------------------------------|
| Linux   | Bubblewrap                                      | `Containment::Process`           |
| macOS   | Seatbelt                                        | `Containment::Process`           |
| Windows | ProcessContainer (AppContainer + BaseContainer) | `Containment::Process`           |
| Windows | WSLC (WSL Container)                            | `Containment::Wslc`              |

`Containment` is `#[non_exhaustive]`, so a `match` on it needs a wildcard arm.
Constructing the listed variants is unaffected.

`Containment::IsolationSession` names that backend, but no entry point taking a
`Containment` serves it: `run` and `spawn_sandbox` both return
[`ErrorCode::UnsupportedContainment`]. Reach it through the state-aware
lifecycle — `run_state_aware_json` plus `exec_attached` or `exec_sandbox`.

Backends with no variant at all — Windows Sandbox, MicroVM, Hyperlight, LXC —
cannot be named from this crate; use the executor binaries. Windows Sandbox is
still reachable here through the state-aware lifecycle.

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

## Pty allocation

Every entry point except `exec_attached` wires the child's stdio to ordinary
pipes and allocates no pty; output the caller does not take is drained and
discarded by `wait()`.

Under `exec_attached`, IsolationSession allocates a pseudo-console and forwards
stdin, so interactive shells render and resize. A pseudo-console has one output
stream, so the sandbox's stderr arrives merged into stdout.

`exec_attached` refuses with `MalformedRequest` unless this process's stdout and
stdin are both terminals; use `exec_sandbox` for a workload with no terminal.

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
