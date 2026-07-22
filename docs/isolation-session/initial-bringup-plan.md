# MXC IsolationSession Backend — Initial Bringup Plan

## Problem

MXC supports several sandboxing backends, but none of them runs the workload as a 
freshly-provisioned, per-execution Windows user account inside a dedicated OS-managed
session. Use cases that need this — per the broader claw-on-MXC scenario — call for:

- **per-execution OS-isolated identity** so the workload's actions cannot
  pollute the calling user's NTFS / registry / token state,
- **OS-managed session lifecycle** that the OS-side service tears down cleanly when
  the calling process exits, and
- a **path toward stateful execution** where one provisioned user and session
  can host multiple sequential exec calls without re-paying the registration /
  provisioning / session-start cost each time.

## Proposed Solution

Add an **IsolationSession runner** to `wxc-exec.exe`, behind `--experimental`.
When the JSON config specifies `"containment": "isolation_session"` and the
experimental flag is set, the binary routes to a new `IsolationSessionRunner`
(implementing the existing `ScriptRunner` trait). The runner orchestrates the
full lifecycle against the OS-side Isolation Session API: register the
calling app, provision an agent user, start a session, run the script
(capturing stdout / stderr / exit code into `ScriptResponse`), then stop the
session, deprovision the agent, and unregister. All of this happens through
Rust bindings auto-generated from a private WinMD; the OS-side API is gated
on an internal Windows feature flag.

This v0.1 implementation is a **one-shot runner** — every `wxc-exec`
invocation pays the full lifecycle cost. A two-layer architecture
(`IsolationSessionManager` for lifecycle methods, `IsolationSessionRunner`
for the one-shot ScriptRunner glue) keeps the option open for a future
stateful API where the manager's methods can be invoked separately.

## How It Works

```
User: wxc-exec.exe --experimental config.json
       (config.json sets containment = "isolation_session")
   │
   ▼
wxc-exec.exe (Rust — single binary, multiple backends)
   ├── Parses JSON config → sees containment = "isolation_session"
   ├── Checks --experimental flag → instantiates IsolationSessionRunner
   ├── Calls IsolationSessionManager methods 1:1 with the OS-side service:
   │     register_client(regId)              → Step 0
   │     provision_agent_user(...)           → Step 1 — creates agent user
   │     start_session(..., configId)        → Step 2 — boots session
   │     create_process(..., path, args, opts) → Step 3 — launches in session
   │     [Read stdout + stderr handles]      → drives ScriptResponse
   │     [WaitForExitAsync + ExitCode]       → drives exit_code
   │     stop_session(...)                   → Step 4
   │     deprovision_agent_user(...)         → Step 5
   │     unregister_client(regId)            → Step 6
   └── Returns ScriptResponse with stdout, stderr, exit_code
```

The OS-side service does the heavy lifting: it provisions a Windows agent user account
(named `<CallingUser>-IEB-<NNN>`), launches an `IsolationProxy.exe` per
session, and exposes the running script as an `IIsolationSessionWorkerProcess`
from which the runner reads pipe handles for I/O.

## Architecture

This backend follows the existing single-binary, multiple-backend pattern.
Dispatch in `wxc/src/main.rs`:

```rust
let mut runner: Box<dyn ScriptRunner> = match request.containment {
    ContainmentBackend::AppContainer => Box::new(AppContainerScriptRunner::new()),
    // ... existing stable + experimental backends ...
    ContainmentBackend::IsolationSession => {
        if !request.experimental_enabled {
            eprintln!("Error: IsolationSession is experimental. Use --experimental.");
            process::exit(1);
        }
        Box::new(IsolationSessionRunner::new(/* ... */))
    }
};
```

The runner is split into two layers:

- **`IsolationSessionManager`** — reusable, lifecycle methods that map 1:1
  to the OS-side API. Methods: `new`, `register_client`,
  `provision_agent_user`, `start_session`, `create_process`, `stop_session`,
  `deprovision_agent_user`, `unregister_client`.
- **`IsolationSessionRunner`** — thin one-shot `ScriptRunner` impl that
  drives the manager's methods in order. Disposable when a stateful path
  lands.

This split is forward-looking: a future stateful API (deferred to follow-up
work) can host the manager directly and let the caller invoke methods
explicitly across multiple exec calls without changing the manager's
interface.

## File Map

**New files:**

| File | Purpose |
|---|---|
| `external/windows-sdk/isolation-session/README.md` | WinMD provenance, version-coupling notes |
| `external/windows-sdk/isolation-session/GENERATION_INFO.toml` | Machine-readable provenance (`windows-bindgen` version, target `windows` crate version, generated date) |
| `src/backends/isolation_session/bindings/Cargo.toml` | Bindings crate manifest |
| `src/backends/isolation_session/bindings/build.rs` | Verifies `windows` crate version matches the recorded provenance |
| `src/backends/isolation_session/bindings/src/lib.rs` | Re-exports the generated module |
| `src/backends/isolation_session/bindings/src/bindings.rs` | Generated by `windows-bindgen` (committed) |
| `src/backends/isolation_session/common/src/` (`one_shot.rs`, `manager.rs`, etc.) | `IsolationSessionManager` + `IsolationSessionRunner` |

**Modified files:**

| File | Change |
|---|---|
| `src/Cargo.toml` | Add `isolation_session_bindings` to workspace members |
| `src/core/wxc_common/Cargo.toml` | Add optional dependency on `isolation_session_bindings` |
| `src/core/wxc_common/src/lib.rs` | Add `pub mod isolation_session_runner` (cfg-gated) |
| `src/core/wxc_common/src/models.rs` | Add `IsolationSession` to `ContainmentBackend`; add `IsolationSessionConfig` |
| `src/core/wxc_common/src/config_parser.rs` | Parse `"isolation_session"` containment and the `experimental.isolation_session` section |
| `src/core/wxc/Cargo.toml` | Add `isolation_session` Cargo feature |
| `src/core/wxc/src/main.rs` | Dispatch `IsolationSession` behind `--experimental`; call `CoInitializeEx(COINIT_MULTITHREADED)` at top of `main` (required for any WinRT activation, benign for other backends) |

## Configuration

```json
{
    "version": "0.6.0-alpha",
    "containerId": "MyIsolationSessionRun",
    "containment": "isolation_session",
    "process": {
        "commandLine": "echo hello & whoami",
        "cwd": "C:\\Windows",
        "env": ["MYVAR=hello"],
        "timeout": 30000
    },
    "experimental": {
        "isolation_session": {
            "configurationId": "small"
        }
    }
}
```

The only `experimental.isolation_session` knob is `configurationId`, which
selects the OS-side session size: `"small"` (1, default), `"medium"` (2),
`"large"` (3), or `"commandline"` (4). Other process options (`cwd`, `env`,
`timeout`) read from the existing top-level `process` section, matching the
contract every other backend honors.

Run with: `wxc-exec.exe --experimental config.json`.

## OS API Dependency

The runner calls into the WinRT API namespaced
`Windows.AI.IsolationEnvironment.Session`, exposed by the OS-side Isolation
Session service (running as SYSTEM via `svchost.exe`). The API is gated
on an internal Windows feature flag.

Activation goes through
`RoGetActivationFactory(RuntimeClass_Windows_AI_IsolationEnvironment_Session_IsolationSessionClient)`.
Activation requires `RoInitialize(RO_INIT_MULTITHREADED)` (handled in
`main.rs` at startup, applied unconditionally because it's benign for other
backends).

The API surface includes seven lifecycle methods plus
`IIsolationSessionWorkerProcess` (the running-process handle). The runner
uses a minimal subset of the worker-process surface: stdout pipe, stderr
pipe, `WaitForExitAsync`, `ExitCode`. It does not use stdin, terminate,
control signals, or interactive ConPTY mode.

## Bindings Workflow

**Why a private WinMD.** The OS-side API ships its WinMD
(`windows.ai.isolationenvironment.winmd`) as part of an internal Windows OS
build. There is no public NuGet or release distribution today. MXC stores
generated Rust bindings in the workspace and tracks their provenance.

**Future direction.** The OS API is expected to land in the public Windows
SDK eventually, at which point the `windows` crate (auto-generated from
the public Windows SDK metadata) will pick it up automatically. When that
happens, MXC can drop this private bindings crate and consume the API
through the standard `windows` crate dependency. That milestone is
currently far off — the private bindings remain the working approach for
the foreseeable future.

**Generated bindings are committed.**
`src/backends/isolation_session/bindings/src/bindings.rs` is a checked-in artifact.
The WinMD itself is **not** committed (binary, frequently updated). All
provenance lives in `GENERATION_INFO.toml`.

**Regeneration.** When the OS-side API changes (or the consumed OS build
moves), the bindings must be regenerated by a Microsoft engineer with
access to the private WinMD. `windows-bindgen` X.Y generates code that
targets the `windows` X.Y crate, so a regenerator must use a
`windows-bindgen` release whose major.minor matches the workspace
`windows` crate. For avoidance of doubt: although earlier draft text in
this document may refer to the WinRT namespace
`Windows.AI.IsolationEnvironment.Session`, the generated bindings and the
Rust code in this repo use `Windows.AI.IsolationSession` (for example,
`IsoSessionOps`), and that is the naming to use when diagnosing
regeneration or version-coupling issues. The build-time check below
catches the most common slip — bumping the workspace `windows` crate
without regenerating — by comparing the workspace version against the
recorded `target_windows_crate`.

**`build.rs` version check.** `isolation_session_bindings/build.rs` reads
the expected `windows` crate version from `GENERATION_INFO.toml`
(`target_windows_crate`) and compares against the actual workspace
`Cargo.lock`. A mismatch panics the build with a message naming both
versions and stating that the bindings must be regenerated.

## v0.1 Scope

**Implemented:**

- Single-shot `register → provision → start → run → stop → deprovision →
  unregister` lifecycle, gated by `--experimental`.
- `process.commandLine` (the script command, wrapped via `cmd.exe /c "..."`
  — the same pattern the LXC runner uses with `/bin/sh -c`).
- `process.cwd` (working directory inside the session).
- `process.env` (environment variables forwarded via
  `IIsolationSessionWorkerProcessCreateOptions::SetEnvironmentVariables`).
- `process.timeout` (forwarded to the OS-side per-process timeout
  enforcement).
- `experimental.isolation_session.configurationId`
  (Small / Medium / Large / CommandLine).
- `lifecycle.destroyOnExit` (mapped to the OS-side `LifetimePolicy`: `true` →
  `CallerProcess`, `false` → `Indefinite`; matches how other backends
  interpret this field).
- Stdout / stderr capture and exit code propagation into `ScriptResponse`.

**Deferred to follow-up work:**

- **Stateful API.** Hosting `IsolationSessionManager` directly so a single
  provisioned agent + session can host multiple `wxc-exec` invocations
  without re-paying the lifecycle cost. The manager / runner split exists
  precisely to make this migration straightforward later.
- **TypeScript SDK exposure.** Lifting `experimental.isolation_session`
  into `SandboxSpawnOptions` so the SDK can spawn isolation-session
  workloads programmatically. Today the backend works only via JSON.
- **Interactive ConPTY** (no plans currently). The OS-side
  `InteractiveConsole` flag, console resize, and control signals
  (CtrlC / CtrlBreak / CtrlClose) are not used by fire-and-forget script
  execution.

## Test Plan

**Automated (`cargo test`, runs on any machine including CI):**

| Category | Count | Location | What it verifies |
|---|---:|---|---|
| Config parsing | ~8 | `config_parser.rs` | `"isolation_session"` containment value, `experimental.isolation_session` section, `configurationId` values + defaults |
| Policy validation | ~15 | `isolation_session_runner.rs` | Phase-specific behaviour: provision accepts `readwritePaths` / `readonlyPaths` and rejects `deniedPaths`; non-provision phases reject every filesystem field; network and proxy are rejected at every phase |
| Option building | ~6 | `isolation_session_runner.rs` | `ExecutionRequest` → `ProcessOptions` mapping (timeout, cwd, env vars, redirect flags) |
| Feature unavailable | 1 | `isolation_session_runner.rs` | Runner returns a clean error on machines without the IsolationSession feature enabled, so the test passes everywhere |

These ~22 backend-specific tests run alongside the existing workspace tests
(287 total currently passing). The feature-unavailable test is what runs in
CI, since CI machines do not have a Windows build with the IsolationSession feature enabled.

**Integration tests (require a Windows host with the IsolationSession feature enabled):**

Two end-to-end configs live under `tests/configs/`:

- `isolation_session_hello.json` — happy path. Prints `USERNAME`,
  `MYVAR`, `CWD`, and `whoami` from inside the session. Validates the
  agent identity (`<calling-user>-IEB-<NNN>`), env-var pass-through,
  working-directory pass-through, and that the running account differs
  from the caller.
- `isolation_session_exit42.json` — runs `exit 42` and validates that
  exit code 42 propagates to `ScriptResponse.exit_code`.

A test runner at `tests/scripts/run_isolation_session_tests.ps1` invokes
both configs via `wxc-exec.exe --experimental`, validates exit codes and
expected output substrings, and reports a pass/fail summary. Pattern
follows the existing per-backend integration scripts (e.g.
`run_microvm_tests.ps1`, `run_wslc_all_tests.ps1`).

The script must run **interactively** on the test host. The OS-side service's
calling-process identity check rejects network-logon tokens, so
PSSession-driven invocations fail with `Access Denied`. Intended workflow:
build a release
`wxc-exec.exe` (the repo's `.cargo/config.toml` already configures
`+crt-static` for Windows MSVC, so the binary has no `vcruntime140.dll`
dependency on the test host), copy it plus the two test configs and the
test script to the host, then run the script directly in `cmd.exe` or
PowerShell on that host.

CI does not run these tests today — there is no CI agent provisioned with
the OS-side Isolation Session service. The feature-unavailable behavior is what runs
in CI (via the automated unit test in `cargo test`).

## Known Issues observed in v0.1

The following were observed during VM testing and are accepted for v0.1.

- **`StopSessionAsync` teardown delay.** Initially observed as ~30s on an
  earlier OS build. Appeared substantially shorter on the current OS build
  (qualitatively, not quantitatively measured). Documented for awareness;
  if it regresses materially, the runner can be reshaped to return the
  `ScriptResponse` ahead of teardown.
- **`DeprovisionAgentUserAsync` returning status 1.** Initially observed as
  a stderr warning on an earlier OS build. No longer surfacing on the
  current OS build. Cleanup proceeds via the OS-side process-exit callback
  when `LifetimePolicy: CallerProcess` is used, so the warning was
  non-functional even when present.
- **Intermittent `IdentityNotFound` (status 4) immediately after VM boot.**
  Observed once, resolved by a VM restart. Cause unconfirmed; suspected to
  be an Isolation Session service initialization race. Re-runs on a settled VM
  are reliable.

## Risks

| Risk | Mitigation |
|---|---|
| Bindings tied to a specific OS API version | `GENERATION_INFO.toml` records the `windows-bindgen` version and target `windows` crate version; `build.rs` panics if the workspace `windows` crate drifts from the recorded `target_windows_crate`. Regeneration is a manual step performed by a Microsoft engineer with WinMD access |
| OS API not present on older Windows builds | the IsolationSession feature is OS-side; runner reports a clean error when the activation factory fails. Feature-unavailable test exercises this on CI |
| New Cargo feature increases coupling | The `isolation_session` feature is off by default in the workspace; default builds and existing CI are unaffected |
| Manual VM testing required | The OS-side service has the same constraint for any consumer (it rejects network-logon tokens). Automated suite covers what it can without the OS-side service |
| One-shot lifecycle is heavy (full register → provision → start per call) | Accepted for v0.1; experimental flag indicates rough edges. Stateful API is the planned mitigation |
| `ProvisionAgentUserAsync` re-provision hang under `Indefinite` lifetime | Manager calls `GetAgentUser` first and skips a redundant provision when the user already exists |
| `DeprovisionAgentUserAsync` failure under `Indefinite` lifetime | Manager re-provisions with `CallerProcess` lifetime as part of teardown so the OS-side process-exit callback handles cleanup naturally |

## Prerequisites

**For end users:**

- A Windows build with the IsolationSession feature enabled.
- `IsolationProxy.exe` present in `%SystemRoot%\System32\` (ships with
  Windows as part of the OS-side service).
- WinRT initialized as MTA (handled by `wxc-exec`).

**For developers:**

- Standard Rust toolchain.
- `cargo build --features isolation_session` to build the feature into
  `wxc-exec`. Default builds skip it — no impact on existing workflows.
- A private WinMD only when **regenerating** bindings. As long as the OS
  API hasn't changed, no regen is needed.

## End-User Experience

```powershell
# Minimal config: print the agent identity inside the session
wxc-exec.exe --experimental hello.json
```

`hello.json`:

```json
{
  "version": "0.6.0-alpha",
  "containerId": "Hello",
  "containment": "isolation_session",
  "process": {
    "commandLine": "whoami",
    "timeout": 30000
  },
  "experimental": {
    "isolation_session": { "configurationId": "small" }
  }
}
```

Expected stdout: `<host>\<caller>-ieb-<nnn>` (the freshly-provisioned agent
user, distinct from whichever account ran `wxc-exec`).

## Supported Workloads

The IsolationSession backend is **language-agnostic and image-free** — the
workload runs as a normal Windows process inside a system-managed isolated
user session. Any executable accessible to the agent account
(path-resolvable, includes `cmd.exe`, `powershell.exe`, etc.) can be the
entry point.

### Supported

- Fire-and-forget script execution (`cmd.exe /c "..."`,
  `powershell.exe -c "..."`).
- Compiled executables that exit on their own and produce stdout/stderr.
- File processing pipelines using `cmd` redirection inside the session.
- Workloads that interact with files inside `cwd` or paths the agent
  account can access (the agent is a fresh isolated Windows account; it has
  access to system-wide resources but not to the calling user's per-user
  data).

### Not supported

| Workload type | Why |
|---|---|
| Interactive shells / REPLs | The runner does not pipe stdin |
| GUI applications | No display server inside the session; only stdout/stderr captured |
| Long-running daemons | Process is expected to exit within `process.timeout` |
