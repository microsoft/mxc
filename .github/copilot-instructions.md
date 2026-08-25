# MXC (Microsoft eXecution Container) — Copilot Instructions

## Prerequisites

The Rust toolchain version is pinned in [`src/rust-toolchain.toml`](../src/rust-toolchain.toml) to match what CI uses (currently 1.93). The pin is honored automatically by `rustup` — running any `cargo` command from `src/` (or below) downloads and selects that channel on first use. To opt out for one-off testing on a different toolchain, use `cargo +<channel> ...` or set `RUSTUP_TOOLCHAIN`. When bumping the pinned version, bump the matching `version: 'ms-prod-1.<N>'` lines in the two `.azure-pipelines/templates/*.Build.Job.yml` files in the same commit.

LSP servers are configured in `.github/lsp.json` for Rust and TypeScript. Install them before use:

```
rustup component add rust-analyzer
npm install -g typescript-language-server typescript
```

Building the C# SDK (`sdk/dotnet/`) additionally requires the .NET SDK; the projects target `net8.0`. Running the tests with `dotnet test` requires .NET SDK 10 or newer.

## Build Commands

### Full build (Windows)

```
build.bat                  # Release build for current architecture
build.bat --debug          # Debug build
build.bat --all            # Release build for both x64 and ARM64
build.bat --with-microvm   # Include NanVix micro-VM binaries
```

### Full build (Linux)

```
./build.sh                 # Release build
./build.sh --debug         # Debug build
./build.sh --rust-only     # Only Rust binaries, skip SDK
```

### Full build (macOS)

```
./build-mac.sh             # Release build for native architecture (seatbelt backend)
./build-mac.sh --debug     # Debug build
./build-mac.sh --all       # Build for both aarch64 and x86_64
./build-mac.sh --rust-only # Only Rust binaries, skip SDK
```

Requires Xcode Command Line Tools and Rust. Produces an unsigned `mxc-exec-mac` binary (codesigning + notarization happen at release time). Schema `0.7.0-alpha` or later required for macOS/Seatbelt backend.

### GitHub Actions

`.github/workflows/Build.yml` is the PR/CI entry point. It fans out to the
workflow-call-only `Build.Windows.Job.yml`, `Build.Linux.Job.yml`, and
`Build.MacOS.Job.yml`, which build and upload the per-target artifacts in
parallel, then to the lint / versioning / SDK jobs.

**Validation (E2E) test infrastructure.** Fully documented in
[`docs/ci-validation-infrastructure.md`](../docs/ci-validation-infrastructure.md)
(matrix contents, job names, per-backend coverage and status, and the runbook
for adding/removing an OS, backend, or plan). Backend E2E tests run from those
same build artifacts — never from a fresh build — so artifact production and
consumption stay in one workflow run:

- `.github/workflows/Validation.Tests.Scheduled.yml` — scheduled entry point.
  The `nightly` plan runs Mon–Sat; Sunday runs `nightly` *and* `weekly`.
  `workflow_dispatch` takes a `plan` input to run one on demand.
- `.github/workflows/Validation.Tests.Matrix.Job.yml` — workflow-call-only,
  takes a `plan` input. Its `resolve` job expands the plan into per-family
  matrices, then the `windows` / `linux` / `macos` jobs each download the
  artifact, prepare the host, and run the backend suite.

An entry point must build the artifacts (call the three `Build.*.Job.yml`
workflows) before calling the matrix job.

**The matrix is declarative:**

- `scripts/ci/validation-test-matrix.json` is the catalog: `platforms` (each
  with per-architecture target/artifact/1ES pool and the backends that platform
  supports), `triggers` (which OS/backend pairs each plan runs), and the
  optional `backendDelayedStart` (per-backend job-start stagger, in seconds).
  The `triggers` keys *are* the plan list — the resolver reads them at run time,
  so adding a plan needs no script change.
- `scripts/ci/resolve-validation-test-matrix.mjs` validates that catalog and
  expands a plan (currently `pr`, `nightly`, `weekly`, `enabled`) into GitHub
  Actions matrices. It rejects an invalid catalog before any specialized test
  runner is allocated, so add a backend to a trigger only where the platform
  declares it.
- A non-macOS platform architecture with an empty `pool` is never scheduled,
  which is how a catalog entry stays declared but dormant. macOS entries use a
  GitHub-hosted `runner` instead of a 1ES `pool`.

**Host preparation** happens in the matrix job before the tests, keyed by the
matrix `backend` id: `scripts/ci/prepare-windows-host.ps1` and
`scripts/ci/prepare-linux-host.sh`. A backend with no prerequisites is an
explicit no-op, so the step runs unconditionally for every entry.

**Test dispatch** goes through `tests/scripts/run_ci_backend_tests.ps1`
(Windows) and `tests/scripts/run_ci_backend_tests.sh` (Linux/macOS), which map
the matrix `backend` id to the repository's existing backend suite. Ids that
share a suite get their own case (`process-t1` and `process-t3` both run
`WinProcessContainer-Tests.ps1`, which derives the tier it expects from the
host's own `--probe`). A backend with no wired suite fails loudly rather than
reporting a false success. The Windows dispatcher points `TEMP` at
`$RUNNER_TEMP` before running a suite, so anything a test writes to the temp
directory is picked up by the job's log upload without per-file CI wiring.

### Individual components

```
# Rust workspace (from src/)
cargo build --release --target x86_64-pc-windows-msvc
cargo build --release --target aarch64-pc-windows-msvc
cargo build --release -p lxc          # Linux only — builds lxc-exec
cargo build --release -p mxc_darwin --target aarch64-apple-darwin  # macOS only — builds mxc-exec-mac
cargo build --release -p mxc_ffi      # C ABI cdylib (mxc_ffi.dll/.so/.dylib) for the C# SDK

# TypeScript SDK (from sdk/node/)
npm install && npm run build

# C# SDK (from sdk/dotnet/)
dotnet build Microsoft.Mxc.Sdk.slnx
```

### Lint and format

```
# Rust (from src/)
cargo fmt --all -- --check
cargo clippy --workspace --all-targets -- -D warnings
```

### Tests

```
# Rust unit tests (from src/)
cargo test --workspace
cargo test -p wxc_common                    # Single crate
cargo test -p wxc_common -- config_parser   # Filter by test name

# SDK (from sdk/node/)
npm test
npm run test:integration

# C# SDK (from sdk/dotnet/)
dotnet test --solution Microsoft.Mxc.Sdk.slnx   # Debug only; builds mxc_ffi via cargo (Rust toolchain required)
                                                 # telemetry tests need the debug-only MXC_TEST_LOCALAPPDATA_OVERRIDE, so `-c Release` fails by design

# Local PowerShell helpers — run from repo root, require built binaries
tests\scripts\run_test_configs.ps1            # All test configs via wxc_test_driver
tests\scripts\run_basicprocess_test.ps1            # Single process container test
tests\scripts\run_isolation_session_tests.ps1                # IsolationSession one-shot E2E (requires host with the OS-side IsoSessionOps service)
tests\scripts\run_isolation_session_state_aware_tests.ps1    # IsolationSession state-aware lifecycle E2E (multi-invocation provision/start/exec/stop/deprovision, same host requirements)
tests\scripts\run_wslc_all_tests.ps1          # All WSLc one-shot config tests (Windows, requires a WSL2 host + wslcsdk.dll; skips if absent)
tests\scripts\run_wslc_state_aware_tests.ps1  # WSLc state-aware lifecycle E2E (multi-invocation provision/start/exec/stop/deprovision + warm-reuse + idle-teardown; requires a WSL2 host + staged wxc-wslc-daemon.exe; skips if absent)
tests\scripts\run_windows_sandbox_one_shot_tests.ps1       # Windows Sandbox one-shot E2E (fresh disposable VM per test; requires the Windows Sandbox optional feature)
tests\scripts\run_windows_sandbox_state_aware_tests.ps1     # Windows Sandbox state-aware lifecycle E2E (provision/start/exec*/stop/deprovision; requires the Windows Sandbox optional feature; skips if absent)
tests\scripts\run_lxc_all_tests.sh            # All LXC tests (Linux)
tests\scripts\run_bwrap_all_tests.sh          # All Bubblewrap tests (Linux, requires bwrap). Must NOT run as root — several tests assert the sandbox drops capabilities, which cannot hold under a root launcher; the script refuses root explicitly.
sudo tests\scripts\run_bwrap_inbound_deny_test.sh  # Bubblewrap inbound default-deny E2E (root-only: needs host CAP_NET_ADMIN to read the sandbox netns and inject a peer). Reported as skipped by the suite above; CI runs it separately from run_ci_backend_tests.sh.
tests\scripts\run_telemetry_consent_smoke_test.ps1  # Telemetry consent + policy CLI E2E (Windows; debug binary only)

# E2E test crate — Rust executor integration tests (from src/)
cargo test -p wxc_e2e_tests                 # Invokes MXC binaries directly
cargo test -p wxc_e2e_tests -- --ignored    # Include stress tests (run_on_repeat)

# WSLC has no cargo E2E suite — it is covered by tests\scripts\run_wslc_all_tests.ps1,
# which the validation matrix runs via tests\scripts\run_ci_backend_tests.ps1.

# CI validation entry points — run a backend suite against a downloaded artifact
# the way the validation matrix does. Take the matrix backend id exactly as it
# appears in scripts/ci/validation-test-matrix.json.
tests\scripts\run_ci_backend_tests.ps1 -Backend process-t1 -BinaryDirectory <dir> -Architecture x64
tests\scripts\run_ci_backend_tests.sh <bubblewrap|lxc|seatbelt> <binary-directory>

# Resolve a plan locally to see exactly what CI would schedule
node scripts/ci/resolve-validation-test-matrix.mjs --plan nightly
```

## Architecture

MXC is a **sandboxed code execution system** with a Rust core and TypeScript SDK layer.

### Containment backends

The Rust workspace (`src/`) implements multiple sandboxing backends behind the `ScriptRunner` trait (`core/wxc_common/src/script_runner.rs`):

| Backend | Binary | Platform | Module |
|---------|--------|----------|--------|
| AppContainer | `wxc-exec.exe` | Windows | `backends/appcontainer/common/src/appcontainer_runner.rs` |
| BaseContainer (OS sandbox API) | `wxc-exec.exe` | Windows | `backends/appcontainer/common/src/base_container_runner.rs` — prefers `CreateProcessSecurityEnvironment` with PSEC whenever its runtime probe succeeds and the requested policy is compatible, independent of schema version. PSEC is the only path that receives schema 0.8 egress filters, runtime proxy, proxy peer identity, and host-loopback configuration. When PSEC is unavailable or policy-incompatible, MXC tries `Experimental_CreateProcessInSandbox`; SBOX is selected only when its legacy FlatBuffer contract can represent the request without dropping those PSEC-only features, otherwise selection continues to the AppContainer tiers. SBOX keeps legacy proxy behavior but rejects schema 0.8 runtime proxy. `captureDenials` prefers the complete compatible PSEC + V2 Learning Mode path; when that path cannot fully honor a request, MXC retains the highest compatible legacy tier and pairs it with guarded WPR using exact handle-attested process scope. Both providers honor explicit `retainEtl` after a terminal wait; abandoned processes discard the trace. |
| Windows Sandbox | `wxc-exec.exe` | Windows | `backends/windows_sandbox/lifecycle/src/` (live transient one-shot `WindowsSandboxRunner` + state-aware `StatefulSandboxBackend`). Experimental — requires `--experimental`. Supports both **one-shot** (a fresh, disposable VM per invocation with guaranteed teardown, via `ScriptRunner`) and **state-aware** (multi-invocation provision/start/exec/stop/deprovision, via `StatefulSandboxBackend`) modes. State-aware holds a single live VM across separate `wxc-exec` phase processes behind a persistent detached host-side daemon (`backends/windows_sandbox/daemon/`); the OS enforces a single running Windows Sandbox VM per host, so the daemon owns it and reclaims an orphaned VM on restart only via positive process-identity proof. The shared boot sequence (write per-launch nonce, launch VM, capture ownership proof, wait rendezvous, connect) lives in `backends/windows_sandbox/lifecycle/src/vm.rs::launch_managed_vm`; each mode plugs in its own `LaunchObserver` for the per-caller ownership / proof bookkeeping. Honors `readwritePaths`/`readonlyPaths`/`deniedPaths` (HOST paths) at provision via `.wsb` `<MappedFolder>` entries (mapped at the same absolute host path inside the guest; rejects `deniedPaths` equal-to or nested-within a mapped share since `.wsb` has no Deny primitive); filesystem policy is immutable post-provision. Network isolation is enforced unconditionally by the in-guest agent; `network`/`ui` are not honored. ID prefix `wsb` (strict `wsb:<8-hex>` grammar). Per-launch handshake: 32-byte `Nonce` + 1-byte `ChannelRole` tag on every TCP connection (boot + reconnect); the guest pairs accepted sockets by declared role, not by accept order. The guest agent binary `wxc-windows-sandbox-guest.exe` (`backends/windows_sandbox/guest/`) is injected into the VM. |
| MicroVM (NanVix) | `wxc-exec.exe` | Windows | `backends/nanvix/runner/src/lib.rs` — feature-gated behind `microvm` |
| Hyperlight | `wxc-exec.exe` | Windows | `backends/hyperlight/common/src/lib.rs` — Hyperlight + Unikraft micro-VM backend |
| IsolationSession | `wxc-exec.exe` | Windows | `backends/isolation_session/common/src/` — feature-gated behind `isolation_session`, experimental, uses the in-proc `Windows.AI.IsolationSession.Preview` `IsoSessionOps` API. Supports both one-shot (single-invocation lifecycle, via `ScriptRunner`) and state-aware (multi-invocation provision/start/exec/stop/deprovision, via `StatefulSandboxBackend`) modes. Rejects all filesystem policy (`readwritePaths`/`readonlyPaths`/`deniedPaths`) at every phase with `policy_validation` — the backend has no host-folder-sharing primitive. Likewise rejects any supplied `ui` policy at every phase on both surfaces (as `policy_validation` on the state-aware surface; one-shot discards the typed variant and surfaces `backend_error` with the reason in the message): the isolation session isolates the *host's* UI from contained code but does not deny it UI capabilities (window creation, GDI and the session's own clipboard all work inside it), so no `ui` posture is truthful here — there is no value combination that could be accepted instead, which is why there is no acknowledgment-style gate as there is for `network`. The check is presence-based via `ContainerPolicy::ui_specified` (twin of `network_specified`) because `UiPolicy`'s defaults are full lockdown, making an explicit lockdown `ui` indistinguishable by value from an absent one. An omitted `ui` is accepted and applies no restriction — the schema's default-deny reading does not hold on this backend. One-shot additionally rejects `lifecycle.destroyOnExit=false` and `lifecycle.preservePolicy=true` — the in-proc API has no session-lifetime knob, and the default `destroyOnExit=true` matches actual behavior so it is accepted; the state-aware parser already rejects the whole `lifecycle` section. The full per-phase honor matrix for both surfaces is in `docs/isolation-session/state-aware-rust.md`. The container's network is unrestricted (outbound open; a process inside can listen on a localhost-reachable port) and MXC has no primitive to filter or deny it, so provision (and one-shot) accept ONLY the canonical unrestricted-network acknowledgment — `network.defaultPolicy=allow` + `network.allowLocalNetwork=true`, no host rules, no proxy, default enforcement — and refuse anything else (including an absent policy, which defaults to the unenforceable deny) with `policy_validation`; post-provision phases reject any supplied network policy (fixed at provision, tracked via `ExecutionRequest.network_specified`) and inherit an absent one. State-aware provision accepts an optional `appId` (a packaged app must pass its Package Family Name in the `PFN:<pfn>` format, e.g. `PFN:Contoso.App_8wekyb3d8bbwe`; an unpackaged app may pass any string), carried verbatim inside the returned `sandboxId`; the one-shot surface takes no backend configuration at all (a stray `experimental.isolation_session` payload is accepted and ignored). Streams stdout/stderr, forwards stdin, and switches to ConPTY mode when wxc-exec's stdout is a TTY for `spawnSandbox` parity. |
| WSLc | `wxc-exec.exe` | Windows | `backends/wslc/common/src/` — feature-gated behind `wslc`, experimental, uses the WSLc SDK (`wslcsdk.dll`, loaded at runtime) to run Linux containers in a WSL2 VM. Supports both one-shot (`WSLContainerRunner`, via `ScriptRunner` + streaming `SandboxBackend`) and state-aware (`state_aware.rs` `WslcStateAwareRunner`, via `StatefulSandboxBackend`) modes. Because the WSLc SDK has **no cross-process re-attach**, state-aware keeps the session (VM) + container warm across separate `wxc-exec` phase processes behind a persistent per-user daemon (`wxc-wslc-daemon.exe`, `backends/wslc/daemon/`) that owns the live `WslcSession`/`WslcContainer` handles; phase processes are thin named-pipe clients (`daemon_client.rs`). The daemon runs all SDK calls on one apartment-affine worker thread (so exec is currently serialized across sandboxes — see `docs/wsl/wslc-state-aware.md`). Honors `readwritePaths`/`readonlyPaths` at provision (→ container volumes) + `network.defaultPolicy` (`Block`→`None`, `Allow`→`Bridged`; networking is all-or-nothing — no per-host filtering, since the container lacks `CAP_NET_ADMIN`); rejects `deniedPaths` nested under a mount and rejects proxy/host-filtering at provision. exec honors `network.proxy` **url-form only** (injected as `HTTP_PROXY`/`HTTPS_PROXY`); start/stop/deprovision reject all policy. ID prefix `wslc` (`wslc:<32-hex>`). Idle-timeout is env-overridable via `MXC_WSLC_DAEMON_IDLE_TIMEOUT_SECS`/`MXC_WSLC_DAEMON_IDLE_POLL_SECS`. See `docs/wsl/wslc-state-aware.md`. |
| LXC | `lxc-exec` | Linux | `core/lxc/src/main.rs` + `backends/lxc/common/` |
| Seatbelt | `mxc-exec-mac` | macOS | `core/mxc_darwin/src/main.rs` + `backends/seatbelt/common/` — uses macOS App Sandbox (Seatbelt) profiles for process containment. Requires schema `0.7.0-alpha`+. Supports `network.proxy` via the same cooperative env-var model as Bubblewrap (injects `HTTP_PROXY`/`HTTPS_PROXY` into the sandbox, reusing `wxc_common::unix_proxy_coordinator`; `builtinTestServer` spawns the shared `unix-test-proxy`). Also declares the schema-0.8 directional `NetworkPolicySupport` capability flags (`EGRESS_DEFAULT \| INGRESS_DEFAULT \| HOST_LOOPBACK \| RUNTIME_PROXY`, no `EGRESS_RULES`/`PROXY_PEER_IDENTITY`): `network.egress.default`/`network.ingress.default`/`runtimeConfig.networkProxy` map onto the same profile rules as the legacy `defaultPolicy`/`allowLocalNetwork`/`network.proxy` fields (`profile_builder.rs` consults `network_egress`/`network_ingress` when populated, falling back to the legacy fields otherwise — see `docs/sandbox-policy/0.8.0/networking/networking.md`). Because Seatbelt has no independent host-loopback posture, `validate()` rejects `network.ingress.hostLoopback` values that diverge from `network.ingress.default`; for the legacy shape, `config_parser.rs` separately rejects `network.proxy` combined with `defaultPolicy='allow'` (a proxy adds no enforcement when outbound is already unrestricted). See `docs/seatbelt/seatbelt-backend.md`. |
| Bubblewrap | `lxc-exec` | Linux | `backends/bubblewrap/common/src/bwrap_runner.rs` — unprivileged sandboxing via Linux user namespaces and `bwrap`. Experimental — requires `--experimental`. Uses shared filesystem/network policy fields; per-host network filtering via `NetworkIptablesManager` from `backends/lxc/common`. For schema 0.8+, proxy mode uses a private network namespace with rootless `slirp4netns` routing and a default-DROP egress chain that permits only loopback and the translated proxy endpoint; `network.enforcementMode: "firewall"` with host lists takes the same private-namespace path and filters by IP/CIDR instead. Both also install a default-deny `MXC_INGRESS` chain on `INPUT` (accepting `-i lo` and `ESTABLISHED,RELATED`), whose posture comes from the directional `network.ingress` section at 0.8+ (`ingress.default`) or from `network.allowLocalNetwork` on the legacy shape; `ingress.default: "allow"` and `ingress.hostLoopback: "allow"` are both refused, as slirp offers no route in. `ingress.hostLoopback` is bidirectional, so its deny also drops egress to slirp's gateway `10.0.2.2` (the host's own loopback), lowered ahead of every caller rule so a broad allow cannot reopen it; proxy mode needs no such rule since it opens only the proxy endpoint. Rules are installed from a supervisor that holds the namespaces, via `nsenter` + `iptables-restore`/`ip6tables-restore` split into byte-budgeted numbered payloads (one restore is one bounded netlink transaction, so a large host list would otherwise exceed it and install nothing); both built-in hooks ride in the final transaction, so a hook is never live over a half-built chain. Both modes require `slirp4netns`, util-linux `unshare`/`nsenter`, `iptables`/`ip6tables`, `iptables-restore`/`ip6tables-restore` on PATH, and fail validation if any is unavailable. The `nf_conntrack` module must also be loaded for the ingress chain's connection-state match, but it is *not* probed at validation time: unprivileged bwrap cannot `modprobe`, and a missing module instead fails the `iptables-restore` transaction at launch, which rolls back and aborts the supervisor before the workload runs (fail-closed, not silently unenforced). `iptables`/`ip6tables` must also resolve to the `nf_tables` backend, unless `/run/xtables.lock` is writable by the calling user: the legacy backend opens that lock unconditionally, and the rules are installed by an unprivileged same-uid supervisor that cannot open a root-owned one — `validate` refuses such a host rather than letting the supervisor die at the first rule. The host proxy endpoint is rewritten to slirp's gateway `10.0.2.2`, so `127.0.0.1`/`0.0.0.0`/`::` are translated while `::1` is rejected (an IPv6-loopback listener cannot accept the gateway's IPv4 connection). Schema 0.6/0.7 and absent-version requests retain the legacy shared-network proxy behavior. See `docs/bwrap-support/bubblewrap-backend.md`. |

### Config flow

1. User provides JSON config (file or base64) → `config_deserialize.rs` performs path-aware typed deserialization into the wire model (`wxc_common::wire`) → `config_parser.rs` validates and maps it to `ExecutionRequest` (the internal execution model in `models.rs`)
2. `ExecutionRequest` includes the containment backend selection, process config, filesystem/network policies, and optional experimental features
3. The appropriate `ScriptRunner` implementation executes the process and returns `ScriptResponse`

### TypeScript layers

- **SDK** (`sdk/node/`, `@microsoft/mxc-sdk`) — the public API. The one-shot surface (`spawnSandbox` / `spawnSandboxFromConfig` / `spawnSandboxAsync`) builds a `ContainerConfig` from a `SandboxPolicy`, serialises to base64, and spawns the correct native binary (`wxc-exec.exe`, `lxc-exec`, or `mxc-exec-mac`) via `node-pty`. The state-aware surface (`provisionSandbox` / `startSandbox` / `execInSandbox` / `execInSandboxAsync` / `stopSandbox` / `deprovisionSandbox`, in `sdk/node/src/state-aware.ts`) drives a sandbox through a multi-call lifecycle against `StateAwareContainmentBackend` backends; per-(backend, phase) typed `*Config` interfaces and a branded `SandboxId<C>` live in `sdk/node/src/state-aware-types.ts`. Typed wire-format errors live in `sdk/node/src/errors.ts` (closed `ErrorCode` union plus a single `MxcError` class carrying `code: ErrorCode`, mirroring the Rust `MxcError` shape). Platform detection is in `platform.ts`.

The SDK auto-discovers native binaries by checking `sdk/node/bin/<target-triple>/` (npm-packaged) and `src/target/<target-triple>/{release,debug}/` (local dev). The `build.bat`/`build.sh`/`build-mac.sh` scripts copy binaries into the SDK bin directory.

### C# SDK

- **C# SDK** (`sdk/dotnet/`, `Microsoft.Mxc.Sdk`) — a managed binding that P/Invokes the native `mxc_ffi` library (which wraps the Rust `mxc-sdk` → `mxc_engine`), rather than spawning an executor. `MxcSandbox.Run(policy, command)` / `RunAsync` run a command to completion and return a `RunResult` (`ExitCode`, `TimedOut`, `Stdout`, `Stderr`); policy POCOs (`SandboxPolicy`, `FilesystemPolicy`, `NetworkPolicy`, `UiPolicy`) serialize to the same camelCase JSON the native layer expects. `MxcException` carries a typed `ErrorCode` that mirrors the native `MXC_STATUS_*` codes (parity-gated by `scripts/check-dotnet-errorcode-parity.js`). `Native/NativeMethods.g.cs` is **generated** by csbindgen from the Rust FFI and is **not committed** (gitignored) — the csproj's `GenerateNativeBindings` MSBuild target regenerates it at build time by invoking cargo, so a `dotnet build` needs the Rust toolchain on PATH; the build also stages the native unit beside the managed assembly — on Windows `mxc_ffi.dll` and the `plm.exe` sidecar `mxc_engine` resolves next to the loaded module. `NativeLibraryResolver` finds `mxc_ffi` via `MXC_FFI_DIR`, the assembly dir / `runtimes/<rid>/native`, or `src/target/{debug,release}`. Projects: `Microsoft.Mxc.Sdk` (library), `Microsoft.Mxc.Sdk.Sample` (console), `Microsoft.Mxc.Sdk.ConsoleDriver` (operator-run interactive-terminal driver), `Microsoft.Mxc.Sdk.Tests` (xUnit), in `Microsoft.Mxc.Sdk.slnx`. Beyond run-to-completion, it also exposes **streaming** (`MxcSandbox.Spawn` → `MxcSandboxProcess`: `Stream`-based stdio, `Wait`/`WaitAsync`/`Kill`) and the **state-aware lifecycle** (`MxcLifecycle.ProvisionSandbox`/`StartSandbox`/`ExecInSandbox`/`ExecInSandboxAsync`/`ExecInSandboxAttached`/`StopSandbox`/`DeprovisionSandbox`, with a typed `SandboxId`). `ProvisionSandbox` takes the backend as a required `StateAwareContainment`; `ExecInSandboxAttached` relays the workload onto the calling process's stdio so an interactive shell gets a real terminal.

### Schema system

- **Stable schemas**: released, immutable schemas live in [`schemas/stable/`](../schemas/stable) (one file per released version) — never edit them after release.
- **Dev schemas**: the in-progress schemas live in [`schemas/dev/`](../schemas/dev) and are generated by `mxc_schema_gen` — **do not hand-edit them**. The rolling `0.9.0-dev` artifact comes from `src/core/wxc_common/src/wire.rs`, which the current parser consumes; regenerate it with `cargo run --manifest-path src/Cargo.toml -p mxc_schema_gen -- schema --legacy-wire --out schemas/dev/mxc-config.schema.0.9.0-dev.json`. The exact `0.9.0-alpha` artifact comes from the closed contract in `src/core/mxc_config_contract/src/dev/`; regenerate it with `cargo run --manifest-path src/Cargo.toml -p mxc_schema_gen -- schema --version 0.9.0-alpha --out schemas/dev/mxc-config.schema.0.9.0-alpha.json`. Published schemas in `schemas/stable/` are immutable and are not regenerated. The rolling and exact development codegen gates fail when either committed artifact drifts. See [`docs/schema-codegen.md`](../docs/schema-codegen.md).
- **Generated SDK wire types**: `mxc_schema_support` provides the shared Rust TypeScript emitter. The rolling drift oracle is `sdk/node/src/generated/wire.ts`; regenerate it with `cargo run --manifest-path src/Cargo.toml -p mxc_schema_gen -- types --legacy-wire --out sdk/node/src/generated/wire.ts`. The exact development oracle is `sdk/node/src/generated/v0_9_0_alpha/wire.ts`; regenerate it with `cargo run --manifest-path src/Cargo.toml -p mxc_schema_gen -- types --version 0.9.0-alpha --out sdk/node/src/generated/v0_9_0_alpha/wire.ts`. Do not hand-edit either file. `scripts/versioning/check-sdk-types-codegen.js` gates the rolling oracle, `scripts/versioning/check-contract-codegen.js` gates the exact development artifacts, and the SDK wire-conformance tests compare the hand-written public types to the rolling oracle until exact dispatch becomes authoritative.
- **Canonical schema-version source**: `schemas/schema-version.json` — the single source of truth for the schema-version constants (min/maxSupported/state-aware/stable/dev). `scripts/versioning/check-schema-versions.js` enforces that the Rust parser, SDK, and schema filenames all agree with it; do not hand-edit a schema-version constant without updating the canonical file. See [`docs/versioning.md`](../docs/versioning.md) for the full design.
- Config files can reference schemas via `"$schema"` for editor validation. `scripts/versioning/validate-configs.js` validates the `tests/examples` + `tests/configs` corpus against the dev schema in CI.

### Key documentation (`docs/`)

Core references:

- `docs/schema.md` — full JSON configuration schema reference
- `docs/versioning.md` — schema versioning design, experimental feature lifecycle, and promotion process
- `docs/authoring-a-new-feature.md` — step-by-step guide for adding experimental features (which files to touch, in what order)
- `docs/examples.md` — annotated configuration examples (see also `tests/examples/` and `tests/configs/`)
- `docs/diagnostics.md` — diagnostic logging knobs (env vars, log file format)
- `docs/ci-validation-infrastructure.md` — validation (E2E) test matrix: workflows and job names, catalog format, per-backend coverage and status, and the runbook for adding/removing an OS, backend, or plan
- `docs/sandbox-policy/0.7.0/policy.md` — sandbox policy 0.7.0 specification
- `docs/sandbox-policy/v1/policy.md` — sandbox policy v1 specification
- `docs/telemetry/telemetry.md` — telemetry overview; `docs/telemetry/telemetry-consent-design.md` (Windows-only consent design and per-SDK surface) and `docs/telemetry/telemetry-administrative-policy.md` (the MDM / Group Policy ceiling)

Per-backend guides:

- `docs/process-container/guide.md` — process container (Windows AppContainer / BaseContainer)
- `docs/process-container/UIPolicy_Schema.md` — UI policy schema (JOB_OBJECT_UILIMIT_* mappings)
- `docs/process-container/os-version-support.md` — per-Windows-release policy-support matrix (filesystem / network / UI)
- `docs/lxc-support/lxc-backend.md` — LXC container backend (Linux)
- `docs/seatbelt/seatbelt-backend.md` — macOS Seatbelt backend
- `docs/windows-sandbox/windows-sandbox.md` / `docs/windows-sandbox/windows-sandbox-reference.md` — Windows Sandbox backend
- `docs/wsl/wsl-container-getting-started.md` / `docs/wsl/wsl-container-support-plan.md` — WSL Container (WSLC SDK)
- `docs/wsl/wslc-state-aware.md` — WSLc state-aware lifecycle (daemon-backed warm reuse, per-phase policy honor matrix, `wxc-wslc-daemon.exe`, idle-timeout env overrides)
- `docs/wsl/wslc-sdk-bindings.md` — WSLC SDK FFI bindings: `src/backends/wslc/common/src/wslcsdk_sys.rs` is **generated** by bindgen from `wslcsdk.h` (do NOT hand-edit); `wslc_bindings.rs` is a thin facade over it. On every WSLC SDK version bump, regenerate via `scripts/generate-wslc-bindings.ps1` (needs libclang + `bindgen-cli`, required only on the regen machine — normal/CI builds need neither) and commit the regenerated file with the `WSLC_SDK_VERSION` + hash change. See the doc for the full runbook.
- `docs/nanvix-microvm/nanvix.md` / `docs/nanvix-microvm/nanvix-integration-plan.md` — MicroVM via NanVix

State-aware lifecycle:

- `docs/state-aware-lifecycle/mxc-state-aware-sandbox-api.md` — state-aware sandbox lifecycle API (cross-backend wire format, Rust `StatefulSandboxBackend` trait, and dispatcher contract)
- `docs/state-aware-lifecycle/mxc-state-aware-sandbox-api-overview.md` — companion overview to the full state-aware design
- `docs/isolation-session/oneshot.md` — IsolationSession backend, one-shot bringup (experimental, isolated user account per execution via the OS-side service)
- `docs/isolation-session/state-aware-rust.md` — IsolationSession state-aware lifecycle, Rust-layer spec (per-phase config / metadata, policy matrix, idempotence, concurrency, error mapping)
- `docs/isolation-session/state-aware-typescript.md` — IsolationSession state-aware lifecycle, TypeScript SDK spec

## Key Conventions

### Experimental features

New features go under the `experimental` JSON section and are only active when `--experimental` is passed. See `docs/authoring-a-new-feature.md` for the full checklist. The pattern:

1. While the rolling parser and exact development contract coexist, add the field to both `src/core/wxc_common/src/wire.rs` and the matching closed request type under `src/core/mxc_config_contract/src/dev/`. Regenerate the rolling and exact schemas and TypeScript oracles with the `mxc_schema_gen schema|types --legacy-wire|--version ... --out ...` commands above — never hand-edit the generated artifacts.
2. Add the matching field to the wire model's `Experimental` struct (`src/core/wxc_common/src/wire.rs`) and the domain `ExperimentalConfig` in `models.rs`, then map wire→domain in `config_parser.rs` (use `From` impls beside the domain type for trivial enum/struct conversions)
3. Guard execution behind `if request.experimental_enabled` in the runner
4. Never modify files in `schemas/stable/` — those are immutable release artifacts

### Rust workspace structure

The workspace is organized into six top-level directories under `src/`:

| Directory | Purpose | Examples |
|-----------|---------|----------|
| `core/` | Cross-platform foundation + per-platform aggregator binaries | `wxc_common/`, `wxc/`, `lxc/`, `mxc_darwin/`, `mxc_engine/`, `mxc-sdk/`, `mxc_pty/`, `mxc_build_common/`, `learning_mode_core/`, `generated/` |
| `backends/` | Backend-specific code (one subfolder per containment backend or backend support component) | `appcontainer/common`, `windows_sandbox/{daemon,guest,common,lifecycle}`, `isolation_session/{bindings,common}`, `learning_mode/windows`, `hyperlight/common`, `nanvix/{common,build_common,binaries,runner}`, `lxc/common`, `bubblewrap/common`, `wslc/common`, `seatbelt/common` |
| `ffi/` | Foreign-function-interface crates (C ABI for language bindings) | `mxc_ffi/` |
| `host/` | Host-side utilities | `wxc_host_prep/`, `wxc_winhttp_proxy_shim/` |
| `testing/` | Test infrastructure crates | `wxc_e2e_tests/`, `wxc_test_driver/`, `wxc_test_proxy/`, `unix_test_proxy/`, `wxc_ui_probe/`, `fuzz/` |
| `tools/` | Developer/diagnostic tools | `mxc_diagnostic_console/` |

- `wxc_common` is the **cross-platform foundation**: config parsing, models, errors, logger, `ScriptRunner` / `StatefulSandboxBackend` traits, state-aware dispatch helpers, validators, ids, ui-policy, encoding. Plus a few thin Windows API helpers shared by host tools and backends (`process_util`, `string_util`, `filesystem_dacl`, `diagnostic`). It must not depend on any `backends/*` crate.
- Each Windows containment backend lives in its own `backends/*/common` crate (e.g. `appcontainer_common`, `windows_sandbox_common`, `isolation_session_common`, `hyperlight_common`, `nanvix_runner`). Backend crates depend on `wxc_common`; there are no cross-edges between backend crates. Windows Sandbox additionally has `windows_sandbox_lifecycle`, which owns the one-shot and state-aware runners and depends on `windows_sandbox_common` for the wire protocol, plus separate daemon and guest binaries.
- `learning_mode_core` is the cross-platform learning-mode denial model and output layer. It owns denial types, summaries, analyzer abstractions, plain-JSON document emission, and the serializable output-pointer type, and must not depend on any `backends/*` crate.
- `learning_mode_windows` (`backends/learning_mode/windows`) is a Windows-only backend support crate for the AppInfo-brokered Learning Mode APIs in `processmodel.dll`. It runtime-resolves the Learning Mode trace and process security-environment exports, owns their typed handle/lifecycle wrappers, decodes sealed ETL traces through `learning_mode_core`, and process-scopes guarded WPR retention with Windows Trace Relogger using exact job-attested PID/creation/exit `FILETIME` ranges. It depends on `wxc_common` plus `learning_mode_core`; runner integration consumes it from the AppContainer backend layer. The trace contract is `HRESULT Start` + retryable `HRESULT Stop` + infallible `Close`: `Stop` never consumes the trace handle, and every started trace must be closed exactly once (closing without stopping is the early-exit discard path). The process security-environment contract is `HRESULT Create` + infallible by-value `Close` and consumes a PSEC 1.0 FlatBuffer, not the legacy SBOX buffer; generated PSEC bindings live in `core/generated/process_security_environment_specification`.
- `plm` (`host/plm`) is the Windows-only legacy WPR Learning Mode helper. Public `plm.exe` is `asInvoker`: ETL analysis and every caller-selected file path stay under the caller token. It self-elevates only hidden fixed WPR operations; the retained elevated guardian accepts authenticated attach and stop/analyze/discard controls over unique local PID-checked named pipes and uses the compiled-in profile from protected fixed-volume ProgramData scratch. WPR's host-wide source ETL never crosses the privilege boundary: after terminal job tracking, the guardian relogs a separate ETL containing only supported Learning Mode events from exact handle-attested process generations, analyzes that filtered ETL, and returns its bytes only when explicitly retained. Relogging failure transfers no trace. Successful authenticated stop/discard disarms the child before releasing the PLM singleton. Owner death, pipe break, or another uncertain control failure preserves the recovery marker and deliberately leaves WPR untouched for administrator recovery.
- `wxc`, `lxc`, and `mxc_darwin` are thin binary crates (`wxc-exec` / `lxc-exec` / `mxc-exec-mac`) that wire up CLI args (`clap`), load/validate config, handle maintenance modes (`--probe`, `--delete`, `--setup-*`, `--audit`), and **delegate all backend dispatch to `mxc_engine`**. They contain no `match request.containment` of their own. `wxc-exec` additionally owns the Windows Ctrl-C / DACL-cleanup / telemetry orchestration around the engine call. Its `--audit` compatibility workflow synthesizes allow-mode `captureDenials` with ETL retention, then generates policy-authoring artifacts from the actionable denials document returned by the selected engine backend.
- `mxc_engine` is the **single execution engine** — the one home for "given an `ExecutionRequest`, run it". It owns: run-to-completion backend selection (`run` / `resolve_runner`, covering **all** backends, incl. the Windows ProcessContainer BaseContainer/AppContainer BFS/DACL fallback tiers via `appcontainer_common::dispatcher::dispatch_with_fallback`, and every experimental backend, feature-gated); streaming (`spawn` → `Box<dyn SandboxProcess>`); state-aware lifecycle dispatch (`run_state_aware`, including Windows Sandbox and IsolationSession); host probing (`platform_support` / `PlatformSupport`); and config building (`build_request` / `build_request_with_containment`, `SandboxPolicy` + sections, `available_tools_policy`/`user_profile_policy`/`temporary_files_policy`). It depends on the backend crates (cfg-split: appcontainer/windows_sandbox lifecycle/isolation_session/wslc/nanvix on Windows, bubblewrap/lxc/nanvix on Linux, seatbelt on macOS) so it can't live in `wxc_common`. Both the executor binaries and `mxc-sdk` call into it. `ResolvedRunner` carries the boxed runner plus (Windows only) the optional `DaclManager` guard, so `wxc-exec` can park the guard for its signal handler.
- `mxc-sdk` is the **public Rust SDK** — a thin facade over `mxc_engine`.
  Build a `SandboxRequest` with `build_request`, then either `run(request)`
  (run-to-completion; returns an `Output` with the `WaitOutcome`, captured
  `stdout`/`stderr`, warnings, and optional structured output metadata) or
  `spawn_sandbox(request)` (returns a `Sandbox` handle for live bidirectional
  stdio — `take_stdin`/`take_stdout`/`take_stderr`, `kill()`, `wait()` returning
  a `WaitOutcome` (`Exited(i32)` / `TimedOut`) as `io::Result`,
  `output_metadata()` after terminal completion, or `wait_with_output()`). It
  re-exports the engine's config-building surface (`build_request`,
  `build_request_with_containment` + `Containment`/`WslcSection`,
  `mxc_sdk::policy::{SandboxPolicy sections}`, discovery helpers) and
  `platform_support`; `mod sandbox` (wrapping the engine's `SandboxProcess` in
  `Sandbox`) is its only local module. `exec_attached` relays a state-aware exec
  onto the calling process's stdio and allocates a pty on IsolationSession; no
  other entry point allocates one. Streaming supports Seatbelt (macOS),
  Bubblewrap (Linux), Windows ProcessContainer (AppContainer + BaseContainer),
  and WSLC (Windows, experimental — needs the crate's `wslc` feature plus
  `SandboxRequest::set_experimental(true)`; no stdin and `id() == 0`, since the
  WSLC SDK exposes neither); other backends return
  `ErrorCode::UnsupportedContainment`.
- The lower-level execution surface lives in `wxc_common::sandbox_process`: the `SandboxBackend` trait (`validate` + `spawn(request, logger, StdioMode) -> Box<dyn SandboxProcess>` + a `diagnose_exit` hook) and the generic `Runner<B>` adapter that bridges any `SandboxBackend` to the run-to-completion `ScriptRunner` (via `spawn(StdioMode::Inherit)` then `wait()`). `SandboxProcess::output_metadata()` carries backend-produced structured outputs after terminal teardown without writing to process-global stdio. `StdioMode::Pipes` hands the caller live stdin/stdout/stderr (what the `mxc-sdk` streaming path uses); `StdioMode::Inherit` lets the child inherit the host's stdio (what the executor binaries use, preserving the TTY under a pty). `SandboxBackend` is implemented for Seatbelt, Bubblewrap, Windows ProcessContainer, and WSLC (on `wslc_common::WSLContainerRunner` itself, which shares one container lifecycle — `start_container` — between its streaming `SandboxBackend` and run-to-completion `ScriptRunner` impls, differing only in where the WSLC SDK's output callbacks write).
- `mxc_ffi` (`ffi/mxc_ffi`, `crate-type = ["cdylib", "staticlib", "lib"]`) is a flat, panic-safe **C ABI over `mxc-sdk`** for language bindings. `mxc_run(policyJson, command, out)` runs a sandbox to completion, filling a `#[repr(C)] MxcRunResult` (status + exit_code + timed_out, owned stdout/stderr/output-metadata C strings, and an `MxcErrorDetail` carrying the failure message plus the failing API call and its platform status); every entry point is `catch_unwind`-wrapped so a panic becomes a status code, never an unwind. Its `build.rs` runs **csbindgen** to generate the C# P/Invoke (`sdk/dotnet/Microsoft.Mxc.Sdk/Native/NativeMethods.g.cs`), gated behind the crate's **`dotnetsdk`** feature (off by default, so the whole-workspace backend build matrix doesn't compile csbindgen). The generated file is **not committed** (gitignored); the C# csproj regenerates it at build time and `scripts/check-dotnet-bindings-codegen.js` runs the codegen in CI and asserts the expected entry points are produced. The C ABI is **not a stable external contract** (native + binding are co-versioned and generated together; see the crate docs). It exposes three surfaces: **run-to-completion** (`mxc_run`), **streaming** (`mxc_spawn` → opaque `MxcSandbox` handle; `mxc_stream_read`/`write`/`flush`, `mxc_sandbox_take_stdin`/`stdout`/`stderr`, `mxc_sandbox_id`/`try_wait`/`wait`/`kill`/`output_metadata_json`/`free`, in `src/streaming.rs`), and the **state-aware lifecycle** (`mxc_state_aware` for the envelope phases, `mxc_state_aware_exec` returning a live streaming handle, and `mxc_state_aware_exec_attached` relaying onto this process's stdio and returning an outcome, in `src/state_aware.rs`). All four `.rs` files are csbindgen inputs in `build.rs` (the shared `MxcErrorDetail` lives in `src/error_detail.rs`); the `MXC_STATUS_*` space already reserves the state-aware phase codes.
- `mxc_pty` is the shared pty bridge used by the LXC backend (`lxc_common::lxc_bindings::attach_run`) so the inner shell sees a real TTY and host stdio is streamed live. (Seatbelt and Bubblewrap no longer use it: they spawn directly and let the child inherit the host's stdio — a TTY when the executor binary runs under a pty — via `SandboxBackend::spawn(StdioMode::Inherit)`.)
- `learning_mode_core` is the **cross-platform learning-mode / captureDenials model + output emitter**: `DeniedResource` (+ `ResourceType`/`AccessType`), `DenialSummary`, the `DenialAnalyzer` decode trait, actionable `DenialsDocument` emission, bounded sensitive-value-redacted `VerboseLoggingDocument` emission, and transactional paired-file write/relocation helpers. Every successful analysis writes the actionable artifact plus its deterministic `*.verbose.json` sibling; relocation reports destination commit separately from source-cleanup warnings so callers keep metadata truthful. The crate also defines the serializable `DenialsOutputPointer` and carries no OS-specific code (it must not depend on any `backends/*` crate). The Windows ETL decoder implementing `DenialAnalyzer` lives in `backends/learning_mode/windows`. When `processContainer.captureDenials` is set, native PSEC/V2 seals and decodes a managed ETL locally, while guarded WPR relogs its host-wide source into a process-scoped ETL before analysis; both routes write the same output pair through shared plumbing and return neutral `wxc_common` metadata. Explicit `retainEtl` preserves the native sealed trace or the guarded process-scoped relogged trace after a terminal wait; abandonment discards it. `wxc-exec` serializes the metadata as the one-line stderr pointer at the CLI boundary; Rust/C#/FFI callers receive it programmatically. Each actionable denial's `resource` field holds an authorable file path, UI category, or AppContainer capability name; registry writes and recognized Section, SymbolicLink, and Timer checks remain verbose-only because MXC has no corresponding config grants. Capability denials resolve their capability SID to a friendly name via `backends/learning_mode/windows`'s `capability_names` (well-known `S-1-15-3-…` SID → policy name; custom hashed SIDs fall back to the SID string).
- `mxc_build_common` is a build-time helper crate — all Windows binary crates use it in their `build.rs` to embed VersionInfo (ProductName, FileDescription, copyright, version+commit). When adding a new Windows binary crate, add `mxc_build_common` as a build-dependency and call `mxc_build_common::embed_version_info()` from `build.rs`
- `nanvix_build_common` is a **build-only** helper crate (never linked into the runtime): it stages NanVix binaries next to the executable and resolves the `NANVIX_BIN` prefetch directory. The `nanvix_binaries`, `wxc`, and `lxc` build scripts consume it as a `[build-dependencies]` entry. Runtime constants it needs (binary/snapshot filenames) stay in `nanvix_common`. Keep build-only file-staging logic here, not in `nanvix_common` (which is a runtime dependency of `nanvix_runner`).
- Platform-specific modules use `#[cfg(target_os = "windows")]` / `#[cfg(target_os = "linux")]`
- Workspace edition is 2021; shared dependencies are declared in the root `Cargo.toml` `[workspace.dependencies]`

### Config parser pattern

The parser deserializes JSON directly into the typed wire model (`wxc_common::wire`), the single source of truth for the config shape (it also generates the JSON schema). All typed config deserialization goes through `config_deserialize.rs`, which distinguishes syntax errors from typed policy errors and adds the complete JSON path plus source line/column when available; state-aware backend errors are prefixed with their full `experimental.<backend>.<phase>` location. `config_parser.rs` then maps the wire types to the validated domain structs in `models.rs`. The stable surface uses `deny_unknown_fields` (closed); the `experimental` block is permissive.

### TypeScript conventions

- Target ES2022, ESM modules (`module`/`moduleResolution: NodeNext`, `"type": "module"`), strict mode — relative imports use explicit `.js` extensions
- Tests use Node.js built-in test runner (`node --test`)

### Binary naming

- Windows: `wxc-exec.exe` (AppContainer / Windows Sandbox / MicroVM); `wxc-host-prep.exe` (host setup — see `docs/host-prep.md`)
- Linux: `lxc-exec` (LXC containers)
- macOS: `mxc-exec-mac` (Seatbelt)
- Target triples: `x86_64-pc-windows-msvc`, `aarch64-pc-windows-msvc`, `x86_64-unknown-linux-gnu`, `aarch64-unknown-linux-gnu`, `aarch64-apple-darwin`

### Telemetry consent

Telemetry is **Windows-only** and is never collected without explicit user consent. Three independent conditions must all hold before anything is emitted: the user has granted consent, the administrative (MDM / Group Policy) ceiling permits it, and the config kill-switch has not disabled it. `wxc_common::telemetry::is_enabled()` is the single place those three terms are combined — do not re-derive enablement anywhere else.

- **Everything fails closed.** Any error, unreadable value, corrupt file, missing native library, or ambiguity must resolve to "no telemetry" (`Undetermined` consent / `Blocked` policy), never to a permissive state.
- **Policy may restrict, but may never substitute for, consent.** The administrative policy is a deny-only ceiling: it can subtract from what a user permitted, never add to it. An administrator cannot opt a user in — a denied or never-asked user stays opted out even under `AllowTelemetry=3`. Keep the terms combined with `&&`; never add a policy value or config path that grants collection on its own.
- **MXC owns its own consent state.** It must never read or infer from the Windows system telemetry consent. The consent store is a per-user JSON file; the policy is `HKLM\SOFTWARE\Policies\Mxc` → `AllowTelemetry` (`REG_DWORD`).
- **One definition, distributed to the bindings.** The Rust `ConsentState` / `PolicyState` enums are the source of truth; the FFI, C#, and TypeScript layers marshal the same strings. Keep those spellings in sync anywhere this branch surfaces them.
- **Test isolation.** The consent store and the policy key are process-global, each behind its own mutex. Use `wxc_common::telemetry::test_support::TelemetryTestEnv` whenever a test needs both; constructing `PolicyKeyGuard` and `LocalAppDataGuard` directly in the same test risks a lock-order deadlock. The consent-store override is compiled into test binaries and into debug `test-support` builds only, so release binaries do not honor it. The `wxc_common` `test-support` feature re-exports the policy override for downstream crates' integration tests (`mxc_ffi` uses it) and must stay a dev-dependency-only feature.
- **Read-only queries must never be able to crash the host.** `NeedsConsentPrompt`/`needsTelemetryConsentPrompt` and `GetPolicy`/`getTelemetryPolicy` fail closed on *any* failure and never throw — including a non-`Success` FFI status, which covers a caught panic. The consent *read* and *write* still throw, because their callers must distinguish "not decided" from "could not read" and "did not persist"; when they do, they raise only the binding's documented exception type (`MxcException`), wrapping anything unexpected rather than letting a raw type escape.
- **Never swallow a failure silently.** Fail-closed return values are indistinguishable from legitimate ones, so a broken install would otherwise be invisible. Every swallowed failure is reported once per distinct failure per process (deduplicated — hosts poll these getters), and the reporter itself must never throw. At the FFI boundary, `catch_unwind` sites log the panic payload before returning `MXC_STATUS_PANIC`, which would otherwise be discarded.

### Package versioning

All Rust crates use `version.workspace = true` to inherit the version from `src/Cargo.toml` `[workspace.package]`. The npm SDK version in `sdk/node/package.json` and the C# SDK version (`<Version>` in `sdk/dotnet/Microsoft.Mxc.Sdk/Microsoft.Mxc.Sdk.csproj`) must match. Run `node scripts/check-version-sync.js` to validate they are in sync. When bumping the version, update `src/Cargo.toml` (workspace version), `sdk/node/package.json`, and the C# csproj in the same commit.

### Keeping docs up to date

When changing behavior covered by existing documentation, update the relevant docs in the same change:

- **Schema changes** (adding/removing/renaming config fields) → update `docs/schema.md` and the appropriate JSON schema in `schemas/dev/` or `schemas/stable/`
- **New experimental features** → follow `docs/authoring-a-new-feature.md`, which includes schema, Rust, and test config steps
- **SDK API changes** (new exports, changed signatures, new options) → update `sdk/node/README.md` and the JSDoc in `sdk/node/src/index.ts` (TypeScript SDK); the Rust `mxc-sdk` crate docs/`README.md`; and `sdk/dotnet/README.md` (C# SDK). If the `mxc_ffi` C ABI surface changes, the C# P/Invoke regenerates on the next C# build; keep the `ErrorCode` parity + bindings-codegen gates green.
- **New containment backends or major backend changes** → update the relevant doc in `docs/` (e.g., `lxc-support/lxc-backend.md`, `windows-sandbox/windows-sandbox.md`)
- **Versioning or promotion changes** → update `docs/versioning.md`
- **Telemetry consent or policy changes** → update `docs/telemetry/telemetry-consent-design.md` and/or `docs/telemetry/telemetry-administrative-policy.md`, and keep the Rust/C#/TypeScript spellings aligned in the files present on this branch

### Policy versioning

The `SandboxPolicy.version` in the SDK must match a JSON schema version in the supported range (`0.6.0-alpha` minimum, `0.9.0-alpha` maximum). The SDK validates this in `sandbox.ts` — if the policy version is older than `MIN_VERSION` or newer than `SUPPORTED_VERSION` it throws. State-aware lifecycle requests use `0.6.0-alpha`. These bounds are mirrored from the canonical `schemas/schema-version.json` and enforced by `scripts/versioning/check-schema-versions.js`. See `docs/versioning.md` for the full design.

## Creating Issues

When creating issues in this repository, follow the structure defined by the issue templates in `.github/ISSUE_TEMPLATE/`. Every issue **must** match one of the four categories below and include the corresponding labels, issue type, and required fields.

### Issue categories, types, and labels

| Category | GitHub Issue Type | Labels | Template |
|----------|------------------|--------|----------|
| 🐛 Bug Report | `Bug` | `Issue-Bug`, `Needs-Triage` | `Bug_Report.yml` |
| 🚀 Feature Request / Idea | `Feature` | `Issue-Feature`, `Needs-Triage` | `Feature_Request.yml` |
| 📚 Documentation Issue | `Task` | `Issue-Docs`, `Needs-Triage` | `Documentation_Issue.yml` |
| 📋 Task | `Task` | `Issue-Task`, `Needs-Triage` | `Task.yml` |

- Always apply `Needs-Triage` alongside the category-specific label.
- Apply exactly the labels listed above — do not invent new labels.
- When creating issues via the API, set labels and issue type explicitly — they are not applied automatically.

### Required body structure by category

Issues created via the API or by agents do not inherit the form layout from the YAML templates. Reproduce the structure in the issue body using the markdown skeletons below.

**🐛 Bug Report** — use when something is broken or behaving unexpectedly:

> ⚠️ **Security notice:** When reporting BSODs or security issues, **DO NOT** attach memory dumps, logs, or traces to GitHub issues. Instead, send them to secure@microsoft.com referencing the GitHub issue. For application crashes, include a Feedback Hub link if possible (open with Win+F, choose "Share My Feedback" after submission).

```markdown
### Relevant area(s)
<!-- One or more of: Linux, macOS, Windows -->

### Brief description of your issue

### Steps to reproduce
1.
2.
3.

### Expected behavior

### Actual behavior
```

All five sections are **required**.

**🚀 Feature Request / Idea** — use for new functionality or improvements:

```markdown
### Description of the new feature / enhancement
<!-- What problem does it solve? Why and how would a user use it? -->

### Proposed technical implementation details
<!-- Optional: how it could be built -->
```

"Description of the new feature / enhancement" is **required**. Omit "Proposed technical implementation details" if there is nothing meaningful to add.

**📚 Documentation Issue** — use when docs are incorrect, incomplete, or confusing:

```markdown
### Brief description of your issue
<!-- Which document needs correction and why -->
```

This section is **required**.

**📋 Task** — use for actionable work items:

```markdown
### Description of the task
<!-- Clear description of the task and expected outcome -->

### Additional context
<!-- Optional: links, references, or background information -->
```

"Description of the task" is **required**. Omit "Additional context" if there is nothing meaningful to add.

### Choosing the right category

- Something **used to work** or **doesn't work as documented** → Bug Report
- Proposing **new behavior or capabilities** → Feature Request / Idea
- **Incorrect, missing, or unclear documentation** → Documentation Issue
- A **discrete unit of work** that doesn't fit the above → Task

### Style guidelines

- Use the section headers exactly as shown in the skeletons above
- Be specific and concise — avoid vague descriptions like "it doesn't work"
- For bug reports, always include concrete reproduction steps
- For feature requests, explain the *why* (user problem) before the *how* (implementation)
- Reference relevant source files, config fields, or docs when applicable
- If any required field is unknown, **ask for the information rather than fabricating content**

## Creating Pull Requests

Pull requests must follow the template in `.github/PULL_REQUEST_TEMPLATE.md`. Complete all checklist items and add content below the separator (`-----`).

### Required structure

Every PR body should include:

1. **Template checklist** — check the boxes that apply (CLA, related issue, copilot-instructions update).
2. **Summary** — a brief description of what the PR does and why.
3. **Issue references** — if the PR is intended to close an issue, use GitHub closing keywords (`Closes #NNN`, `Fixes #NNN`, or `Resolves #NNN`). If the PR is related but does not close an issue, use an unordered list under a "Related Issues" heading (`- #NNN`).

### Example

```markdown
- [x] I have signed the [Contributor License Agreement](https://opensource.microsoft.com/cla/).
- [x] This pull request is related to an issue.
- [ ] If this PR changes build commands, project architecture, or key conventions, I have updated [`.github/copilot-instructions.md`](.github/copilot-instructions.md).

-----

## Summary

Brief description of the change.

Closes #42
```

### Guidelines

- One PR should address one issue or concern. Avoid bundling unrelated changes.
- If the PR updates build commands, project architecture, or key conventions, update `.github/copilot-instructions.md` in the same PR.
- Draft PRs are appropriate for work-in-progress that needs early feedback.
