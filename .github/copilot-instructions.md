# MXC (Microsoft eXecution Container) — Copilot Instructions

## Prerequisites

The Rust toolchain version is pinned in [`src/rust-toolchain.toml`](../src/rust-toolchain.toml) to match what CI uses (currently 1.93). The pin is honored automatically by `rustup` — running any `cargo` command from `src/` (or below) downloads and selects that channel on first use. To opt out for one-off testing on a different toolchain, use `cargo +<channel> ...` or set `RUSTUP_TOOLCHAIN`. When bumping the pinned version, bump the matching `version: 'ms-prod-1.<N>'` lines in the two `.azure-pipelines/templates/*.Build.Job.yml` files in the same commit.

LSP servers are configured in `.github/lsp.json` for Rust and TypeScript. Install them before use:

```
rustup component add rust-analyzer
npm install -g typescript-language-server typescript
```

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

### Individual components

```
# Rust workspace (from src/)
cargo build --release --target x86_64-pc-windows-msvc
cargo build --release --target aarch64-pc-windows-msvc
cargo build --release -p lxc          # Linux only — builds lxc-exec
cargo build --release -p mxc_darwin --target aarch64-apple-darwin  # macOS only — builds mxc-exec-mac

# SDK (from sdk/)
npm install && npm run build
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

# SDK (from sdk/)
npm test
npm run test:integration

# Local PowerShell helpers — run from repo root, require built binaries
tests\scripts\run_test_configs.ps1            # All test configs via wxc_test_driver
tests\scripts\run_basicprocess_test.ps1            # Single process container test
tests\scripts\run_isolation_session_tests.ps1                # IsolationSession one-shot E2E (requires host with the OS-side IsoSessionOps service)
tests\scripts\run_isolation_session_state_aware_tests.ps1    # IsolationSession state-aware lifecycle E2E (multi-invocation provision/start/exec/stop/deprovision, same host requirements)
tests\scripts\run_lxc_all_tests.sh            # All LXC tests (Linux)
tests\scripts\run_bwrap_all_tests.sh          # All Bubblewrap tests (Linux, requires bwrap)

# E2E test crate — Rust executor integration tests (from src/)
cargo test -p wxc_e2e_tests                 # Invokes MXC binaries directly
cargo test -p wxc_e2e_tests -- --ignored    # Include stress tests (run_on_repeat)
```

## Architecture

MXC is a **sandboxed code execution system** with a Rust core and TypeScript SDK layer.

### Containment backends

The Rust workspace (`src/`) implements multiple sandboxing backends behind the `ScriptRunner` trait (`core/wxc_common/src/script_runner.rs`):

| Backend | Binary | Platform | Module |
|---------|--------|----------|--------|
| AppContainer | `wxc-exec.exe` | Windows | `backends/appcontainer/common/src/appcontainer_runner.rs` |
| BaseContainer (OS sandbox API) | `wxc-exec.exe` | Windows | `backends/appcontainer/common/src/base_container_runner.rs` — calls `Experimental_CreateProcessInSandbox` via FlatBuffer |
| Windows Sandbox | `wxc-exec.exe` | Windows | `backends/windows_sandbox/common/src/windows_sandbox_runner.rs` |
| MicroVM (NanVix) | `wxc-exec.exe` | Windows | `backends/nanvix/runner/src/lib.rs` — feature-gated behind `microvm` |
| Hyperlight | `wxc-exec.exe` | Windows | `backends/hyperlight/common/src/lib.rs` — Hyperlight + Unikraft micro-VM backend |
| IsolationSession | `wxc-exec.exe` | Windows | `backends/isolation_session/common/src/` — feature-gated behind `isolation_session`, experimental, uses the in-proc `Windows.AI.IsolationSession` `IsoSessionOps` API (loaded from `IsoSessionApp.dll`). Supports both one-shot (single-invocation lifecycle, via `ScriptRunner`) and state-aware (multi-invocation provision/start/exec/stop/deprovision, via `StatefulSandboxBackend`) modes. Honors `readwritePaths` and `readonlyPaths` at provision via `ShareFolderBatchAsync` (rejects `deniedPaths` since the API has no Deny ACE primitive); filesystem policy is immutable post-provision and rejected at later phases. State-aware additionally accepts an optional `user` bundle (`upn`, `wamToken`) at provision and start to provision Entra cloud-agent sandboxes; one-shot rejects the bundle, and hosts that don't support Entra agents surface `backend_unavailable`. Streams stdout/stderr, forwards stdin, and switches to ConPTY mode when wxc-exec's stdout is a TTY for `spawnSandbox` parity. |
| LXC | `lxc-exec` | Linux | `core/lxc/src/main.rs` + `backends/lxc/common/` |
| Seatbelt | `mxc-exec-mac` | macOS | `core/mxc_darwin/src/main.rs` + `backends/seatbelt/common/` — uses macOS App Sandbox (Seatbelt) profiles for process containment. Requires schema `0.7.0-alpha`+. See `docs/macos-support/seatbelt-backend.md`. |
| Bubblewrap | `lxc-exec` | Linux | `backends/bubblewrap/common/src/bwrap_runner.rs` — unprivileged sandboxing via Linux user namespaces and `bwrap`. Experimental — requires `--experimental`. Uses shared filesystem/network policy fields; per-host network filtering via `NetworkIptablesManager` from `backends/lxc/common`. See `docs/bwrap-support/bubblewrap-backend.md`. |

### Config flow

1. User provides JSON config (file or base64) → `config_parser.rs` deserializes into the typed wire model (`wxc_common::wire`) → validates and maps to `ExecutionRequest` (the internal execution model in `models.rs`)
2. `ExecutionRequest` includes the containment backend selection, process config, filesystem/network policies, and optional experimental features
3. The appropriate `ScriptRunner` implementation executes the process and returns `ScriptResponse`

### TypeScript layers

- **SDK** (`sdk/`, `@microsoft/mxc-sdk`) — the public API. The one-shot surface (`spawnSandbox` / `spawnSandboxFromConfig` / `spawnSandboxAsync`) builds a `ContainerConfig` from a `SandboxPolicy`, serialises to base64, and spawns the correct native binary (`wxc-exec.exe`, `lxc-exec`, or `mxc-exec-mac`) via `node-pty`. The state-aware surface (`provisionSandbox` / `startSandbox` / `execInSandbox` / `execInSandboxAsync` / `stopSandbox` / `deprovisionSandbox`, in `sdk/src/state-aware.ts`) drives a sandbox through a multi-call lifecycle against `StateAwareContainmentBackend` backends; per-(backend, phase) typed `*Config` interfaces and a branded `SandboxId<C>` live in `sdk/src/state-aware-types.ts`. Typed wire-format errors live in `sdk/src/errors.ts` (closed `ErrorCode` union plus a single `MxcError` class carrying `code: ErrorCode`, mirroring the Rust `MxcError` shape). Platform detection is in `platform.ts`.

The SDK auto-discovers native binaries by checking `sdk/bin/<target-triple>/` (npm-packaged) and `src/target/<target-triple>/{release,debug}/` (local dev). The `build.bat`/`build.sh`/`build-mac.sh` scripts copy binaries into the SDK bin directory.

### Schema system

- **Stable schemas**: released, immutable schemas live in [`schemas/stable/`](../schemas/stable) (one file per released version) — never edit them after release.
- **Dev schema**: the in-progress schema lives in [`schemas/dev/`](../schemas/dev). It is **generated** from the Rust wire model (`src/core/wxc_common/src/wire.rs`) by the `mxc_schema_gen` tool — **do not hand-edit it**. To change the dev schema, edit the wire model and regenerate with `cargo run --manifest-path src/Cargo.toml -p mxc_schema_gen -- schemas/dev/mxc-config.schema.<dev>.json`. `scripts/versioning/check-schema-codegen.js` is a CI gate that regenerates and fails if the committed schema drifts. See [`docs/schema-codegen.md`](../docs/schema-codegen.md).
- **Generated SDK wire types**: `sdk/src/generated/wire.ts` is **generated** from the same wire model by the `mxc_schema_gen --ts` TypeScript emitter (`wxc_common::ts_emit`, no third-party generator) — **do not hand-edit it**. It is a drift oracle (not public API); the SDK unit test `sdk/tests/unit/wire-conformance.test.ts` asserts the hand-written public types in `sdk/src/types.ts` conform to it, and `scripts/versioning/check-sdk-types-codegen.js` is a CI gate that fails if the committed file drifts. Regenerate with `cargo run --manifest-path src/Cargo.toml -p mxc_schema_gen -- --ts sdk/src/generated/wire.ts`.
- **Canonical schema-version source**: `schemas/schema-version.json` — the single source of truth for the schema-version constants (min/maxSupported/state-aware/stable/dev). `scripts/versioning/check-schema-versions.js` enforces that the Rust parser, SDK, and schema filenames all agree with it; do not hand-edit a schema-version constant without updating the canonical file. See [`docs/versioning.md`](../docs/versioning.md) for the full design.
- Config files can reference schemas via `"$schema"` for editor validation. `scripts/versioning/validate-configs.js` validates the `tests/examples` + `tests/configs` corpus against the dev schema in CI.

### Key documentation (`docs/`)

Core references:

- `docs/schema.md` — full JSON configuration schema reference
- `docs/versioning.md` — schema versioning design, experimental feature lifecycle, and promotion process
- `docs/authoring-a-new-feature.md` — step-by-step guide for adding experimental features (which files to touch, in what order)
- `docs/examples.md` — annotated configuration examples (see also `tests/examples/` and `tests/configs/`)
- `docs/diagnostics.md` — diagnostic logging knobs (env vars, log file format)
- `docs/host-prep.md` — `wxc-host-prep.exe` host setup binary (`prepare-system-drive` / `unprepare-system-drive` for the AppContainer ACEs on the system-drive root, plus `prepare-null-device` / `verify-null-device` / `dump-null-device` for the `\Device\Null` security descriptor that AppContainer-based backends require). Owns elevation via embedded `requireAdministrator` manifest — `wxc-exec.exe` no longer self-elevates.
- `docs/sandbox-policy/v1/policy.md` — sandbox policy v1 specification

Per-backend guides:

- `docs/base-process-container/guide.md` — process container (Windows AppContainer / BaseContainer)
- `docs/base-process-container/UIPolicy_Schema.md` — UI policy schema (JOB_OBJECT_UILIMIT_* mappings)
- `docs/lxc-support/lxc-backend.md` — LXC container backend (Linux)
- `docs/macos-support/seatbelt-backend.md` — macOS Seatbelt backend
- `docs/windows-sandbox/windows-sandbox.md` / `docs/windows-sandbox/windows-sandbox-reference.md` — Windows Sandbox backend
- `docs/wsl/wsl-container-getting-started.md` / `docs/wsl/wsl-container-support-plan.md` — WSL Container (WSLC SDK)
- `docs/nanvix-microvm/nanvix.md` / `docs/nanvix-microvm/nanvix-integration-plan.md` — MicroVM via NanVix

State-aware lifecycle:

- `docs/state-aware-lifecycle/mxc-state-aware-sandbox-api.md` — state-aware sandbox lifecycle API (cross-backend wire format, Rust `StatefulSandboxBackend` trait, and dispatcher contract)
- `docs/state-aware-lifecycle/mxc-state-aware-sandbox-api-overview.md` — companion overview to the full state-aware design
- `docs/isolation-session/initial-bringup-plan.md` — IsolationSession backend, one-shot bringup (experimental, isolated user account per execution via the OS-side service)
- `docs/isolation-session/state-aware-rust-initial-plan.md` — IsolationSession state-aware lifecycle, Rust-layer plan (per-phase config / metadata, policy honor matrix, idempotence, concurrency, error mapping)
- `docs/isolation-session/state-aware-typescript-initial-plan.md` — IsolationSession state-aware lifecycle, TypeScript SDK plan

## Key Conventions

### Experimental features

New features go under the `experimental` JSON section and are only active when `--experimental` is passed. See `docs/authoring-a-new-feature.md` for the full checklist. The pattern:

1. Add the field to the Rust wire model (`src/core/wxc_common/src/wire.rs`) under the `Experimental` section, then regenerate the dev schema (`cargo run --manifest-path src/Cargo.toml -p mxc_schema_gen -- schemas/dev/mxc-config.schema.<dev>.json`) — do not hand-edit the generated schema
2. Add the matching field to the wire model's `Experimental` struct (`src/core/wxc_common/src/wire.rs`) and the domain `ExperimentalConfig` in `models.rs`, then map wire→domain in `config_parser.rs` (use `From` impls beside the domain type for trivial enum/struct conversions)
3. Guard execution behind `if request.experimental_enabled` in the runner
4. Never modify files in `schemas/stable/` — those are immutable release artifacts

### Rust workspace structure

The workspace is organized into five top-level directories under `src/`:

| Directory | Purpose | Examples |
|-----------|---------|----------|
| `core/` | Cross-platform foundation + per-platform aggregator binaries | `wxc_common/`, `wxc/`, `lxc/`, `mxc_darwin/`, `mxc-sdk/`, `mxc_pty/`, `mxc_build_common/`, `generated/` |
| `backends/` | Backend-specific code (one subfolder per containment backend) | `appcontainer/common`, `windows_sandbox/{daemon,guest,common}`, `isolation_session/{bindings,common}`, `hyperlight/common`, `nanvix/{common,build_common,binaries,runner}`, `lxc/common`, `bubblewrap/common`, `wslc/common`, `seatbelt/common` |
| `host/` | Host-side utilities | `wxc_host_prep/`, `wxc_winhttp_proxy_shim/` |
| `testing/` | Test infrastructure crates | `wxc_e2e_tests/`, `wxc_test_driver/`, `wxc_test_proxy/`, `linux_test_proxy/`, `wxc_ui_probe/`, `fuzz/` |
| `tools/` | Developer/diagnostic tools | `mxc_diagnostic_console/` |

- `wxc_common` is the **cross-platform foundation**: config parsing, models, errors, logger, `ScriptRunner` / `StatefulSandboxBackend` traits, state-aware dispatch helpers, validators, ids, ui-policy, encoding. Plus a few thin Windows API helpers shared by host tools and backends (`process_util`, `string_util`, `filesystem_dacl`, `diagnostic`). It must not depend on any `backends/*` crate.
- Each Windows containment backend lives in its own `backends/*/common` crate (e.g. `appcontainer_common`, `windows_sandbox_common`, `isolation_session_common`, `hyperlight_common`, `nanvix_runner`). Backend crates depend on `wxc_common`; there are no cross-edges between backend crates.
- `wxc` and `lxc` are thin binary crates that wire up CLI args (`clap`) and dispatch to `wxc_common` and the per-backend crates
- `mxc-sdk` is an **importable library** for starting sandboxes in-process without a pty: `spawn_sandbox` takes a `SandboxRequest` (from `build_request`), selects the host backend, and returns a `Sandbox` handle for persistent bidirectional stdio (`take_stdin`/`take_stdout`/`take_stderr`), `kill()`, and `wait()` (which drains and discards any untaken stdout/stderr and returns a `WaitOutcome` — `Exited(i32)` or `TimedOut` — as `io::Result`, reserving `Err` for an actual OS/wait failure), or `wait_with_output()` (consumes the handle, drains both streams concurrently, returns an `Output` with the `WaitOutcome` + captured `stdout`/`stderr`). It additionally ports the SDK's config-building surface so callers don't need the TypeScript module: `mxc_sdk::policy` (`SandboxPolicy` + `build_request` → `SandboxRequest` (opaque wrapper mapping to the internal `ExecutionRequest`), the port of `createConfigFromPolicy`; plus `available_tools_policy`/`user_profile_policy`/`temporary_files_policy` discovery helpers) and `mxc_sdk::platform_support` (port of `getPlatformSupport`, using the in-process probe on Windows). It depends on the backend crates (cfg-split: appcontainer on Windows, bubblewrap on Linux, seatbelt on macOS) — so it can't live in `wxc_common`. The public surface is deliberately minimal (streaming only): the `dispatch` and `platform` modules are private and only their used items are re-exported at the crate root (`platform_support`, `PlatformSupport`); `policy` is the one public submodule (callers name `mxc_sdk::policy::{SandboxPolicy sections}`). The execution surface lives in `wxc_common::sandbox_process`: the `SandboxBackend` trait (`validate` + `spawn(request, logger, StdioMode) -> Box<dyn SandboxProcess>` + a `diagnose_exit` hook for enriching launch-failure exits) and the generic `Runner<B>` adapter that bridges any `SandboxBackend` to the run-to-completion `ScriptRunner` (by calling `spawn(StdioMode::Inherit)` then `wait()`). `StdioMode::Pipes` hands the caller live stdin/stdout/stderr (what `mxc-sdk` uses); `StdioMode::Inherit` lets the child inherit the host process's own stdio (what the executor binaries use, preserving the TTY under a pty). `SandboxBackend` is implemented for every library backend — Seatbelt (macOS), Bubblewrap (Linux), and Windows ProcessContainer (AppContainer + BaseContainer). The `wxc`/`lxc`/`mxc_darwin` executor binaries do **not** depend on `mxc-sdk`; they keep their own backend dispatch (sharing only the lower-level `appcontainer_common::dispatcher::dispatch_with_fallback`). The `mxc-sdk` in-crate backend dispatch (`dispatch.rs`) and host probing (`platform.rs`) are **provisional** — a follow-up will move them into a dedicated `mxc` engine crate that both `mxc-sdk` and the executor binaries call into.
- `mxc_pty` is the shared pty bridge used by the LXC backend (`lxc_common::lxc_bindings::attach_run`) so the inner shell sees a real TTY and host stdio is streamed live. (Seatbelt and Bubblewrap no longer use it: they spawn directly and let the child inherit the host's stdio — a TTY when the executor binary runs under a pty — via `SandboxBackend::spawn(StdioMode::Inherit)`.)
- `mxc_build_common` is a build-time helper crate — all Windows binary crates use it in their `build.rs` to embed VersionInfo (ProductName, FileDescription, copyright, version+commit). When adding a new Windows binary crate, add `mxc_build_common` as a build-dependency and call `mxc_build_common::embed_version_info()` from `build.rs`
- `nanvix_build_common` is a **build-only** helper crate (never linked into the runtime): it stages NanVix binaries next to the executable and resolves the `NANVIX_BIN` prefetch directory. The `nanvix_binaries`, `wxc`, and `lxc` build scripts consume it as a `[build-dependencies]` entry. Runtime constants it needs (binary/snapshot filenames) stay in `nanvix_common`. Keep build-only file-staging logic here, not in `nanvix_common` (which is a runtime dependency of `nanvix_runner`).
- Platform-specific modules use `#[cfg(target_os = "windows")]` / `#[cfg(target_os = "linux")]`
- Workspace edition is 2021; shared dependencies are declared in the root `Cargo.toml` `[workspace.dependencies]`

### Config parser pattern

The parser deserializes JSON directly into the typed wire model (`wxc_common::wire`), the single source of truth for the config shape (it also generates the JSON schema). `config_parser.rs` then maps the wire types to the validated domain structs in `models.rs`. The stable surface uses `deny_unknown_fields` (closed); the `experimental` block is permissive.

### TypeScript conventions

- Target ES2022, ESM modules (`module`/`moduleResolution: NodeNext`, `"type": "module"`), strict mode — relative imports use explicit `.js` extensions
- Tests use Node.js built-in test runner (`node --test`)

### Binary naming

- Windows: `wxc-exec.exe` (AppContainer / Windows Sandbox / MicroVM); `wxc-host-prep.exe` (host setup — see `docs/host-prep.md`)
- Linux: `lxc-exec` (LXC containers)
- macOS: `mxc-exec-mac` (Seatbelt)
- Target triples: `x86_64-pc-windows-msvc`, `aarch64-pc-windows-msvc`, `x86_64-unknown-linux-gnu`, `aarch64-unknown-linux-gnu`, `aarch64-apple-darwin`

### Package versioning

All Rust crates use `version.workspace = true` to inherit the version from `src/Cargo.toml` `[workspace.package]`. The npm SDK version in `sdk/package.json` must match. Run `node scripts/check-version-sync.js` to validate they are in sync. When bumping the version, update both `src/Cargo.toml` (workspace version) and `sdk/package.json` in the same commit.

### Keeping docs up to date

When changing behavior covered by existing documentation, update the relevant docs in the same change:

- **Schema changes** (adding/removing/renaming config fields) → update `docs/schema.md` and the appropriate JSON schema in `schemas/dev/` or `schemas/stable/`
- **New experimental features** → follow `docs/authoring-a-new-feature.md`, which includes schema, Rust, and test config steps
- **SDK API changes** (new exports, changed signatures, new options) → update `sdk/README.md` and the JSDoc in `sdk/src/index.ts`
- **New containment backends or major backend changes** → update the relevant doc in `docs/` (e.g., `lxc-support/lxc-backend.md`, `windows-sandbox/windows-sandbox.md`)
- **Versioning or promotion changes** → update `docs/versioning.md`

### Policy versioning

The `SandboxPolicy.version` in the SDK must match a JSON schema version in the supported range (`0.4.0-alpha` minimum, `0.8.0-alpha` maximum). The SDK validates this in `sandbox.ts` — if the policy version is older than `MIN_VERSION` or newer than `SUPPORTED_VERSION` it throws. State-aware lifecycle requests use `0.6.0-alpha`. These bounds are mirrored from the canonical `schemas/schema-version.json` and enforced by `scripts/versioning/check-schema-versions.js`. See `docs/versioning.md` for the full design.

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
