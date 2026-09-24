# Request-Aware Probe API Parity

## Goal

Expose the existing Windows request-aware ProcessContainer probe through the
Rust, Node.js, and .NET SDKs while preserving the `wxc-exec --probe` command and
its JSON contract.

## Scope

The work covers three public surfaces:

1. The existing `wxc-exec --probe` CLI.
2. The public Rust SDK.
3. The Node.js and .NET language SDKs.

The probe remains Windows- and ProcessContainer-specific. SDK calls on other
platforms fail explicitly as unsupported. State-aware request envelopes remain
unsupported because the existing CLI accepts only one-shot requests.
One-shot requests whose resolved containment is not ProcessContainer also fail
with `UnsupportedContainment`; they must not be projected onto ProcessContainer
policy and reported with an irrelevant tier.

## Architecture

`mxc_engine` becomes the single owner of probe orchestration. It combines the
ProcessContainer fallback detector with engine-owned capability checks for
guarded capture, IsolationSession, and Hyperlight. The CLI delegates to this
engine API instead of applying those overrides itself.

The engine validates the resolved containment before invoking the backend
detector. This check belongs at the shared orchestration boundary rather than
in the CLI or individual SDK adapters, so every public surface has identical
behaviour and malformed-input parsing still takes precedence.

The Rust SDK re-exports the typed probe output and exposes:

```rust
pub fn probe(request: Option<&SandboxRequest>) -> Result<ProbeOutput, Error>;
```

`None` preserves the CLI's no-config behaviour by probing a default empty
request. `Some(request)` probes the supplied one-shot request without creating
a sandbox.

The .NET SDK calls the Rust API through a panic-safe `mxc_ffi` entry point. It
accepts an optional serialized binding request, returns the canonical probe JSON
through an owned C string, and reports malformed or unsupported requests through
the existing stable status and error-detail contracts.

The public .NET entry point is the static `MxcSandbox.Probe(...)` method. It is
not added to the existing `ISandboxRunner` dependency-injection contract.
`ISandboxRunner` is already documented for consumer-supplied fakes and custom
implementations, so adding a required member would break those implementations.
A separate probe interface is unnecessary while probing has a single static
entry point, and a default interface implementation has no useful native-free
fallback.

The Node.js SDK exposes a typed synchronous probe function. It invokes the
packaged `wxc-exec --probe` binary, adding `--config-base64` when a config is
supplied, and validates the returned JSON before returning it. Detection logic
is not duplicated in TypeScript.

## Public Models

The existing camelCase `ProbeOutput` JSON shape remains authoritative:

- `tier`
- `needsDaclAugmentation`
- `warnings`
- `probes`
- `error`

The nested machine facts and UI-capability fields retain their current names and
meanings. The Rust and .NET surfaces use typed models. Node.js defines matching
TypeScript interfaces and validates the required object, array, string, boolean,
and optional-field shapes at the process boundary.

Optional-backend facts are build-relative: `isolationSessionAvailable` and
`hyperlightAvailable` are `false` when the invoked CLI or SDK native library was
not compiled with that backend. Different packages may therefore report
different optional-backend facts while retaining the same contract and
ProcessContainer tier decision.

## Error Handling

- Detector failures remain successful probe calls with `ProbeOutput.error`,
  matching the CLI.
- Invalid request JSON, invalid binding requests, and unsupported platforms are
  API errors rather than success-shaped probe output.
- A valid one-shot request resolved to any backend other than
  ProcessContainer returns `UnsupportedContainment` before host capability
  probing.
- FFI entry points remain panic-contained and return owned strings that callers
  free through `mxc_string_free`.
- Node.js surfaces executable lookup, timeout, non-zero exit, and malformed
  output as exceptions with actionable context.

## Compatibility

- `wxc-exec --probe` output and exit behaviour remain unchanged.
- The CLI continues to accept no config, a path, `--config`, or
  `--config-base64`.
- State-aware requests continue to be rejected.
- No schema or generated wire type changes are required.

## Testing

- Engine tests pin default-request and request-aware orchestration, including
  ProcessContainer acceptance, non-ProcessContainer rejection, and
  IsolationSession and Hyperlight override seams where feature-gated.
- CLI tests or existing probe tests verify unchanged serialization.
- Rust SDK tests exercise both a supplied ProcessContainer request and exact
  `UnsupportedContainment` rejection for another backend.
- FFI tests verify null/default input, a serialized request, owned JSON, error
  status, non-ProcessContainer rejection, and panic containment conventions.
- .NET tests verify typed projection, supplied-request behaviour, and exact
  rejection of an incompatible containment backend. A compatibility test keeps
  a minimal consumer implementation of the pre-existing `ISandboxRunner`
  contract compiling without a probe member.
- Node.js unit tests inject the probe runner, verify argument construction for
  default and base64-config calls, validate the complete output shape, and
  reject malformed output. A production-boundary test verifies the CLI rejects
  a non-ProcessContainer config.
- Documentation for all three SDKs includes the new API and its Windows-only,
  advisory nature.
