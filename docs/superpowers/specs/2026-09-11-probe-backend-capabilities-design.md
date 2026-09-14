# Probe Backend Capabilities Design

## Problem

`available_backends()` tells a consumer that ProcessContainer is available and
names its highest reachable tier, but it does not tell the consumer whether that
tier can enforce selected policies whose support varies by OS capability.

GitHub Copilot CLI embeds `mxc-sdk`, calls `available_backends()` in-process,
and requires the reported ProcessContainer tier to be `base-container`. It
currently rejects every policy containing `filesystem.deniedPaths` and cannot
preflight `network.ingress.hostLoopback = "allow"` against the host's PSEC
ingress support.

The consumer should be able to distinguish these cases before execution:

- BaseContainer is available and can enforce native denied paths.
- BaseContainer is available but would need a lower-tier fallback for denied
  paths.
- BaseContainer is available and supports inbound host-loopback access.
- BaseContainer is available but supports only the default host-loopback deny
  posture.

## Decision

Extend the existing `BackendCapability` list returned by
`available_backends()` with a curated set of high-value, consumer-actionable
capabilities:

- `CaptureDenials` (existing)
- `FilesystemDeniedPaths`
- `IngressHostLoopbackAllow`

Do not turn `available_backends()` into a complete policy-support matrix.
Detailed diagnostics remain the responsibility of `wxc-exec --probe`.

## Capability Semantics

A capability means:

> The backend's reported tier can enforce this feature without falling back to
> a weaker tier.

For example:

```json
{
  "backend": "processcontainer",
  "tier": "base-container",
  "capabilities": [
    "captureDenials",
    "filesystemDeniedPaths",
    "ingressHostLoopbackAllow"
  ]
}
```

`FilesystemDeniedPaths` means the reported `base-container` tier can enforce
`filesystem.deniedPaths` natively. Its absence does not mean ProcessContainer
can never enforce denied paths: AppContainer+DACL may still enforce them after
a tier fallback. It means a consumer that requires the reported tier must not
assume denied paths are available there.

`IngressHostLoopbackAllow` means the reported tier can enforce exactly
`network.ingress.hostLoopback = "allow"`. The default deny posture is not
reported because consumers do not need to negotiate it.

`CaptureDenials` preserves its existing public meaning.

Capabilities are positive assertions. An absent capability means the consumer
must not safely request that feature while relying on the reported tier.

## Runtime Detection

The execution and discovery paths must use the same backend-owned runtime
detectors. Capability support must never be inferred from a Windows build
number.

### Native denied paths

`FilesystemDeniedPaths` reuses the selected BaseContainer contract's native
deny-path query. The capability is present only when the reported tier is
`base-container` and the applicable OS contract reports native deny support.

### Ingress host-loopback allow

`IngressHostLoopbackAllow` is present only when:

1. the reported tier is `base-container`;
2. Process Security Environment contract version 1.1 is supported; and
3. the OS reports the PSEC network-ingress support bit.

These are the same conditions the execution path applies before accepting
`network.ingress.hostLoopback = "allow"`.

### Fail-closed behavior

A missing API or export, an unset capability bit, or a query error omits the
capability. The lightweight `available_backends()` result does not distinguish
unsupported from unknown.

`wxc-exec --probe` exposes the same underlying facts for operators who need the
detailed reason. Both surfaces derive their answers from shared helpers so they
cannot drift.

## API and Binding Surfaces

The Rust API remains:

```rust
pub fn available_backends() -> Vec<AvailableBackend>;
```

The existing `AvailableBackend.capabilities` collection carries the new
`BackendCapability` variants. Serde emits camelCase values:

- `filesystemDeniedPaths`
- `ingressHostLoopbackAllow`

The C ABI's existing JSON discovery function inherits the values without a new
entry point.

The C# SDK adds corresponding typed enum values and parser mappings. Its
existing unknown-value behavior remains intact for forward compatibility.

The Rust SDK and C# documentation define the reported-tier semantics and show
how to gate a policy field on a capability.

## `wxc-exec --probe`

`wxc-exec --probe` remains the detailed Windows ProcessContainer diagnostic
surface. It exposes the raw native-denied-path and PSEC-ingress facts that feed
the curated capability list.

GitHub Copilot CLI must not depend on this executable path. It embeds `mxc-sdk`
and consumes `available_backends()` directly.

## GitHub Copilot CLI Follow-up

The CLI change belongs in its own repository and follows the MXC change.

The CLI will:

1. Continue calling `mxc_sdk::available_backends()` in-process.
2. Cache the ProcessContainer tier and capability set together.
3. Continue requiring `tier == "base-container"`.
4. Replace its blanket rejection of policies containing denied paths with a
   `FilesystemDeniedPaths` capability check.
5. Reject `allowLocalNetwork: true` before execution when
   `IngressHostLoopbackAllow` is absent.
6. Preserve the current default-deny behavior: `allowLocalNetwork: false`
   requires no new capability.

The CLI does not shell out to `wxc-exec --probe` and does not need a TypeScript
projection of MXC's Node SDK.

## Testing

MXC tests cover:

- supported, unsupported, missing-export, and query-error outcomes for each
  runtime detector;
- capability presence only when the reported tier can enforce the feature
  without fallback;
- capability absence on AppContainer BFS and AppContainer DACL tiers;
- stable camelCase serialization and omission of unavailable capabilities;
- preservation of existing `CaptureDenials` behavior;
- parity between `available_backends()` and detailed `wxc-exec --probe` facts;
- C ABI JSON serialization;
- C# enum parsing, including unknown-value forward compatibility.

The CLI follow-up tests cover:

- supported and unsupported denied-path policies;
- supported and unsupported local-network allow policies;
- default local-network deny without the allow capability;
- one cached ProcessContainer discovery result used consistently by host and
  policy checks.

## Scope

This design is limited to Windows ProcessContainer and the three curated
capabilities above. It does not:

- define a complete MXC policy capability matrix;
- add equivalent capability catalogs for Linux or macOS backends;
- change backend selection or tier fallback;
- infer capabilities from OS release names or build numbers;
- combine the MXC and GitHub Copilot CLI changes into one repository commit.
