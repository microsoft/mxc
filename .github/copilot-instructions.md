# MXC (Microsoft eXecution Container) — Copilot Instructions

## Prerequisites

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
./build.sh --rust-only     # Only Rust binaries, skip SDK/CLI
```

### Individual components

```
# Rust workspace (from src/)
cargo build --release --target x86_64-pc-windows-msvc
cargo build --release --target aarch64-pc-windows-msvc
cargo build --release -p lxc          # Linux only — builds lxc-exec

# SDK (from sdk/)
npm install && npm run build

# CLI (from cli/)
npm install && npm run build
```

### Lint and format

```
# Rust (from src/)
cargo fmt --all -- --check
cargo clippy --workspace --all-targets -- -D warnings

# CLI (from cli/)
npx eslint src --ext .ts
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

# CLI (from cli/) — requires build first
node --test dist/cli.test.js

# Local PowerShell helpers — run from repo root, require built binaries
test_scripts\run_test_configs.ps1           # All test configs via wxc_test_driver
test_scripts\run_basicac_test.ps1           # Single AppContainer test
test_scripts\run_lxc_all_tests.sh           # All LXC tests (Linux)

# E2E test crate — Rust executor integration tests (from src/)
cargo test -p wxc_e2e_tests                 # Invokes MXC binaries directly
cargo test -p wxc_e2e_tests -- --ignored    # Include stress tests (run_on_repeat)
```

## Architecture

MXC is a **sandboxed code execution system** with a Rust core and TypeScript SDK/CLI layer.

### Containment backends

The Rust workspace (`src/`) implements multiple sandboxing backends behind the `ScriptRunner` trait (`wxc_common/src/script_runner.rs`):

| Backend | Binary | Platform | Module |
|---------|--------|----------|--------|
| AppContainer | `wxc-exec.exe` | Windows | `appcontainer_runner.rs` |
| BaseContainer (OS sandbox API) | `wxc-exec.exe` | Windows | `base_container_runner.rs` — calls `Experimental_CreateProcessInSandbox` via FlatBuffer |
| Windows Sandbox | `wxc-exec.exe` | Windows | `windows_sandbox_runner.rs` |
| MicroVM (NanVix) | `wxc-exec.exe` | Windows | `nanvix_runner.rs` — feature-gated behind `microvm` |
| LXC | `lxc-exec` | Linux | `lxc/src/main.rs` + `lxc_common/` |

### Config flow

1. User provides JSON config (file or base64) → `config_parser.rs` deserializes into intermediate `Raw*` structs → validates and maps to `CodexRequest` (the internal execution model in `models.rs`)
2. `CodexRequest` includes the containment backend selection, process config, filesystem/network policies, and optional experimental features
3. The appropriate `ScriptRunner` implementation executes the process and returns `ScriptResponse`

### TypeScript layers

- **SDK** (`sdk/`, `@microsoft/mxc-sdk`) — the public API. `spawnSandbox()` builds a `ContainerConfig` from a `SandboxPolicy`, serializes to base64, and spawns the correct native binary (`wxc-exec.exe` or `lxc-exec`) via `node-pty`. Platform detection is in `platform.ts`.
- **CLI** (`cli/`, `mxc-cli`) — thin Commander.js wrapper around the SDK. Depends on `@microsoft/mxc-sdk` via `file:../sdk`.

The SDK auto-discovers native binaries by checking `sdk/bin/<target-triple>/` (npm-packaged) and `src/target/<target-triple>/{release,debug}/` (local dev). The `build.bat`/`build.sh` scripts copy binaries into the SDK bin directory.

### Schema system

- **Stable schema**: `schemas/stable/mxc-config.schema.0.4.0-alpha.json` — immutable after release
- **Dev schema**: `schemas/dev/mxc-config.schema.0.5.0-dev.json` — includes `experimental` section
- Current schema version: `0.4.0-alpha`
- Config files can reference schemas via `"$schema"` for editor validation

### Key documentation (`docs/`)

- `docs/schema.md` — full JSON configuration schema reference
- `docs/versioning.md` — schema versioning design, experimental feature lifecycle, and promotion process
- `docs/authoring-a-new-feature.md` — step-by-step guide for adding experimental features (which files to touch, in what order)
- `docs/lxc-backend.md` — LXC container backend details
- `docs/windows-sandbox.md` / `docs/windows-sandbox-reference.md` — Windows Sandbox backend
- `docs/examples.md` — annotated configuration examples (see also `examples/` and `test_configs/`)

## Key Conventions

### Experimental features

New features go under the `experimental` JSON section and are only active when `--experimental` is passed. See `docs/authoring-a-new-feature.md` for the full checklist. The pattern:

1. Add the property schema to `schemas/dev/` under `experimental`
2. Add Rust structs to `models.rs` (`ExperimentalConfig`) and `config_parser.rs` (`RawExperimental`)
3. Guard execution behind `if request.experimental_enabled` in the runner
4. Never modify files in `schemas/stable/` — those are immutable release artifacts

### Rust workspace structure

- `wxc_common` is the shared library — all config parsing, models, error types, and runner implementations live here
- `wxc` and `lxc` are thin binary crates that wire up CLI args (`clap`) and dispatch to `wxc_common`
- Platform-specific modules in `wxc_common` use `#[cfg(target_os = "windows")]` / `#[cfg(target_os = "linux")]`
- Workspace edition is 2021; shared dependencies are declared in the root `Cargo.toml` `[workspace.dependencies]`

### Config parser pattern

The parser uses two layers of structs: `Raw*` structs (matching JSON with `#[serde(rename)]`) that deserialize permissively, then map to validated domain structs in `models.rs`. This keeps serde attributes separate from the internal model.

### TypeScript conventions

- Target ES2020, CommonJS modules, strict mode
- SDK and CLI each have their own `tsconfig.json` with `declaration: true`
- Tests use Node.js built-in test runner (`node --test`)
- CLI uses flat ESLint config (`eslint.config.js`) with `typescript-eslint`

### Binary naming

- Windows: `wxc-exec.exe` (AppContainer / Windows Sandbox / MicroVM)
- Linux: `lxc-exec` (LXC containers)
- Target triples: `x86_64-pc-windows-msvc`, `aarch64-pc-windows-msvc`, `x86_64-unknown-linux-gnu`, `aarch64-unknown-linux-gnu`

### Keeping docs up to date

When changing behavior covered by existing documentation, update the relevant docs in the same change:

- **Schema changes** (adding/removing/renaming config fields) → update `docs/schema.md` and the appropriate JSON schema in `schemas/dev/` or `schemas/stable/`
- **New experimental features** → follow `docs/authoring-a-new-feature.md`, which includes schema, Rust, and test config steps
- **SDK API changes** (new exports, changed signatures, new options) → update `sdk/README.md` and the JSDoc in `sdk/src/index.ts`
- **CLI command changes** → update `cli/README.md` and `cli/ARCHITECTURE.md`
- **New containment backends or major backend changes** → update the relevant doc in `docs/` (e.g., `lxc-backend.md`, `windows-sandbox.md`)
- **Versioning or promotion changes** → update `docs/versioning.md`

### Policy versioning

The `SandboxPolicy.version` in the SDK must match the JSON schema version (currently `0.4.0-alpha`). The SDK validates this in `sandbox.ts` — if the policy version is newer than `SUPPORTED_VERSION`, it throws. See `docs/versioning.md` for the full design.

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
