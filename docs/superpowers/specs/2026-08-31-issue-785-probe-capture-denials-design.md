# Issue 785: Capture-Denials Probe Parity

## Context

`wxc-exec --probe` currently passes only `ContainerPolicy` to the fallback
detector. The runtime dispatcher instead evaluates the complete
`ExecutionRequest` and derives request-specific BaseContainer capabilities.
This can make the probe select a tier using less information than the real
execution path.

Issue #785 originally proposed rejecting `captureDenials` when the native V2
Learning Mode and process security-environment APIs are unavailable. That
recommendation predates PR #813, which added guarded WPR capture as a fallback.
The current runtime can therefore honor `captureDenials` on a non-native
BaseContainer or AppContainer tier when native V2 capture is unavailable.

## Goal

Make `wxc-exec --probe` use the same request-aware tier-selection inputs as the
current runtime while reporting whether the preferred native capture path is
available.

## Non-goals

- Requiring native V2 capture when guarded WPR can service the request.
- Refactoring runner construction or DACL application into a new shared
  dispatcher abstraction.
- Starting a sandbox or a guarded WPR session during the probe.
- Changing runtime fallback behavior.

## Design

### Probe input

Change `appcontainer_common::probe::run_probe` to accept an
`&ExecutionRequest`. The `wxc-exec --probe` path will retain the request returned
by `load_request` instead of discarding everything except its policy. With no
configuration, it will use `ExecutionRequest::default()`.

This preserves schema, networking, filesystem, and other request-level details
needed by the BaseContainer compatibility checks.

### Capability facts

Add an always-serialized `nativeCaptureAvailable: bool` field to `ProbeFacts`.
The value will be gathered from the same non-tracing PSEC and Learning Mode API
predicate used by native runtime selection. It describes whether the host has
the preferred native capture path; it does not describe overall
`captureDenials` support because guarded WPR may provide that support, nor does
it guarantee that a particular request is compatible with PSEC.

The implementation will gather host facts once and pass them to a small
side-effect-free internal decision helper. Unit tests can supply deterministic
facts without depending on the host OS API set.

### Tier selection

The public probe will derive the same request-specific inputs used by
`dispatcher::select_backend_with_fallback`:

- whether BaseContainer is usable for the request;
- whether the request can use native capture; and
- whether BaseContainer can enforce denied paths for the request.

It will then call
`fallback_detector::detect_with_base_container_capabilities` with those inputs.
The probe will not reject a `captureDenials` request merely because native
capture is unavailable or the selected tier is AppContainer. The real
`wxc-exec` runtime supplies the guarded-WPR factory for such requests, so that
selection remains launchable.

Existing fallback-detector errors remain unchanged and continue to omit `tier`
and `needsDaclAugmentation` from the JSON output.

## Error handling

The change introduces no new error category. Native capture unavailability is
reported as a capability fact rather than an error because guarded WPR can
service the request. Existing detector failures retain their current messages
and JSON shape.

## Testing

Targeted Rust unit tests will verify:

- `nativeCaptureAvailable` is always present and serializes in camel case;
- the pure decision helper uses request-aware BaseContainer capability inputs;
- a `captureDenials` request on a forced AppContainer fallback tier remains a
  successful probe when native capture is unavailable, matching the current
  executor fallback;
- existing tier strings and detector error serialization remain stable.

The implementation will be validated with the focused
`appcontainer_common` tests and Rust formatting/lint checks applicable to the
changed crate.

## Assumptions

1. The `wxc-exec` runtime continues to supply a guarded-WPR factory whenever
   `captureDenials` is requested.
2. `nativeCaptureAvailable` describes the preferred native V2 path, not total
   capture support.
3. Probe execution remains non-launching: it does not create a sandbox or start
   guarded WPR.
