# MXC Copilot Instructions

MXC (Microsoft eXecution Container) is a cross-platform sandboxed code execution system. Prefer precise, scoped changes and preserve existing platform behavior, feature gates, wire compatibility, and failure semantics.

## Before changing code

- Read the documentation for the affected subsystem. Start with the references below rather than inferring behavior from names.
- Follow any matching file-scoped instructions under `.github/instructions/`.
- Inspect nearby code and tests before editing. Reuse existing abstractions and error types.
- Do not hand-edit generated files or released schemas.
- Do not silently ignore unsupported policy. Reject it before creating a sandbox.

## Architecture invariants

- `wxc_common` is the cross-platform foundation. Do not move backend execution or enforcement into it, or add new backend implementation dependencies.
- Backend crates generally depend on `wxc_common`; avoid cross-dependencies between backend crates. The existing optional `nanvix_common` dependency supplies shared MicroVM data/constants rather than backend dispatch.
- `mxc_engine` is the single execution engine. Executor binaries and `mxc-sdk` delegate backend routing to it.
- Keep `wxc`, `lxc`, and `mxc_darwin` thin. Do not add backend-selection matches to the binaries.
- Keep build-time staging in `mxc_build_common` or `nanvix_build_common`, not runtime crates.
- Use `#[cfg(target_os = "...")]` and existing Cargo feature gates for platform-specific code.
- Preserve the distinction between run-to-completion, streaming, and state-aware lifecycle APIs.
- Unsupported policy must fail closed. Do not accept a field that the selected backend cannot enforce.

See:

- [`docs/schema.md`](../docs/schema.md)
- [`docs/versioning.md`](../docs/versioning.md)
- [`docs/state-aware-lifecycle/mxc-state-aware-sandbox-api.md`](../docs/state-aware-lifecycle/mxc-state-aware-sandbox-api.md)
- [`docs/ci-validation-infrastructure.md`](../docs/ci-validation-infrastructure.md)
- The relevant backend guide under `docs/`

## Build and validation

The Rust toolchain is pinned by `src/rust-toolchain.toml`. Run Rust commands from `src/` or pass `--manifest-path src/Cargo.toml`.

### Builds

```text
build.bat

./build.sh

./build-mac.sh
```

### Targeted validation

```text
# From src/
cargo fmt --all -- --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
cargo test -p wxc_common
cargo test -p wxc_common -- config_parser

# From sdk/node/
npm test
npm run test:integration

# From sdk/dotnet/ (requires .NET SDK 10+)
dotnet test --solution Microsoft.Mxc.Sdk.slnx
```

Prefer the smallest test command covering the change. Host-dependent backend suites live under `tests/scripts/`; use the applicable backend guide and `docs/ci-validation-infrastructure.md` before running or changing them.

## Schema and policy rules

- Production parsing dispatches through exact closed contracts and their
  version-specific adapters into private `CommonRequestIR` normalization input.
- Preserve optional-field presence through parsing and binding. Apply defaults and semantic validation in the backend.
- New features use their intended permanent JSON location in the exact
  development contract. JSON placement, publication eligibility, and runtime
  experimental authorization are separate. Update the matching closed request
  types, adapt them into `CommonRequestIR` or a phase-specific runtime config,
  and regenerate the registered exact schema and TypeScript artifacts.
- Never edit `schemas/stable/`; released schemas are immutable.
- Never hand-edit generated development schemas or generated TypeScript wire types.
- `schemas/schema-version.json` is the canonical source for compatibility constants.

See [`docs/schema-codegen.md`](../docs/schema-codegen.md) for regeneration commands.

## Error and security behavior

- Surface errors explicitly using repository error types and include actionable context.
- Preserve panic containment across `mxc_ffi`; no panic may unwind through the C ABI.
- Preserve exact resource ownership and cleanup contracts, especially for processes, jobs, traces, sessions, and native handles.
- Do not weaken validation or convert failures into success-shaped fallbacks.
- Telemetry is Windows-only, requires explicit user consent, and fails closed. Administrative policy may restrict consent but may never grant it. See [`docs/telemetry/`](../docs/telemetry/).

## Documentation

Update documentation in the same change when behavior changes:

- Schema or config fields: `docs/schema.md` and the applicable generated development artifacts.
- Experimental features: `docs/authoring-a-new-feature.md`.
- Versioning or promotion: `docs/versioning.md`.
- Backend behavior: the corresponding guide under `docs/`.
- SDK APIs: the affected SDK README/API documentation.
- Telemetry: `docs/telemetry/`.
- CI validation: `docs/ci-validation-infrastructure.md`.

Do not duplicate detailed backend behavior here. Keep the canonical explanation in the subsystem documentation.

## Issues and pull requests

Use the repository templates as the source of truth:

- Issues: `.github/ISSUE_TEMPLATE/`
- Pull requests: `.github/PULL_REQUEST_TEMPLATE.md`

When creating issues through an API, explicitly set the issue type and these exact labels:

| Category | Type | Labels |
|----------|------|--------|
| Bug report | `Bug` | `Issue-Bug`, `Needs-Triage` |
| Feature request | `Feature` | `Issue-Feature`, `Needs-Triage` |
| Documentation issue | `Task` | `Issue-Docs`, `Needs-Triage` |
| Task | `Task` | `Issue-Task`, `Needs-Triage` |

Do not fabricate missing required issue fields. For security issues or BSODs, do not attach dumps, logs, or traces to a public GitHub issue; direct sensitive material to `secure@microsoft.com` and reference the issue.
