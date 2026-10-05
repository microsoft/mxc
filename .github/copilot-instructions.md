# MXC Copilot Instructions

MXC (Microsoft eXecution Container) is a cross-platform sandboxed code execution system. Prefer precise, scoped changes and preserve existing platform behavior, feature gates, wire compatibility, and failure semantics.

## Before changing code

- Read the documentation for the affected subsystem. Start with the references below rather than inferring behavior from names.
- Follow any matching file-scoped instructions under `.github/instructions/`.
- Inspect nearby code and tests before editing. Reuse existing abstractions and error types.
- Do not hand-edit generated files or released schemas.
- Do not silently ignore unsupported policy. Reject it before creating a sandbox.

## Architecture invariants

- `mxc_sdk::mxc_common` is the cross-platform foundation. Do not move backend execution or enforcement into it, or add new backend implementation dependencies.
- Keep implementation dependencies internal to `mxc-sdk` as Rust modules in the `mxc-sdk` crate, not as separate workspace crates.
- Backend modules generally depend on `mxc_sdk::mxc_common`; avoid cross-dependencies between backend modules. The optional `nanvix_common` module supplies shared MicroVM data/constants rather than backend dispatch.
- `mxc_sdk::mxc_engine` is the single execution engine. Executor binaries and the public SDK facade delegate backend routing to it.
- Keep `wxc`, `lxc`, and `mxc_darwin` thin. Do not add backend-selection matches to the binaries.
- Keep build-time staging in the `mxc-sdk/build/` build modules, not runtime modules.
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

The sidecars declared as `[[bin]]` targets in `src/mxc-sdk/Cargo.toml` are
ordinary Cargo binary targets. Workspace builds compile the targets whose
`required-features` are enabled; do not invoke Cargo recursively from
`mxc-sdk/build.rs`. Build a sidecar directly with
`cargo build -p mxc-sdk --bin <target>`. The `wxc-wslc-daemon` target requires
`--features wslc`. Keep version-resource generation and dependency staging in
the package build script, and keep artifact copying/signing in the repository
build and CI entry points.

### Targeted validation

```text
# From src/
cargo fmt --all -- --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
cargo test -p mxc-sdk --lib
cargo test -p mxc-sdk --lib -- config_parser

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
- In the .NET SDK (`sdk/dotnet/`), every serialized or deserialized wire type
  must be registered as a `[JsonSerializable]` root in `MxcJsonContext`
  (`MxcJsonSerialization.cs`) and routed through the `MxcJson` helpers, so the
  source-generated resolver is used and no path falls back to reflection. When
  you add or change such a type or an options object, add a matching
  serialize/deserialize check to `Microsoft.Mxc.Sdk.AotSmokeTest`; its CI AOT
  publish gate fails on any reflection-dependent path.

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
- SDK APIs: the affected SDK README and versioned references under `docs/reference/{rust,dotnet,node}/v*/`.
- Telemetry: `docs/telemetry/`.
- CI validation: `docs/ci-validation-infrastructure.md`.

Do not duplicate detailed backend behavior here. Keep the canonical explanation in the subsystem documentation.

## SDK API consistency

- Publish every SDK operation, type, probe, discovery API, telemetry API, and helper only through a supported versioned (V*) namespace/module/entrypoint.
- Before adding or changing an API or type, compare the corresponding Rust, .NET, and Node references under `docs/reference/`. Align names, field meanings, defaults, optional-field presence, input order, and result/ownership semantics across SDKs.
- Use language-idiomatic spelling and construction: Rust snake_case and enums, .NET PascalCase and closed SDK-owned classes, and TypeScript camelCase and discriminated unions. Do not force identical syntax or add convenience abstractions merely to imitate another language.
- Keep authoring requests as typed data. Use consistent policy and backend configuration names; native adapters own wire mapping and the native engine owns semantic validation.
- Keep API-specific controls in the API-specific options type. Creation takes request then options; existing-container execution takes identity, request, then options; .NET cancellation tokens come last.
- Preserve existing behavior and ownership semantics. Do not broaden backend capabilities to manufacture parity.
- Document intentional language/runtime differences explicitly, and update the affected versioned (V*) signature/type references, examples, and tests in the same change.
- Breaking changes to a published SDK API require a new versioned (V*) API surface and matching signature/type references. Preserve the published version's references.

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
