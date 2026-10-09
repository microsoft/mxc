# Containment policy by schema version

> **Audience:** MXC consumers

These pages explain the filesystem, network, UI, and execution policies
available in each supported configuration contract. The exact contract
determines which fields a request can contain; the selected backend applies,
rejects, or ignores policy fields according to its documented behavior.
Check the [backend guides](../backends/) and [schema guide](../schema.md)
before relying on a restriction: a valid request alone does not establish
that the backend enforces it.

| Contract | Status | Documentation |
|---|---|---|
| `0.9.0-alpha` | Published; minimum supported | [Policy](0.9.0/policy.md) |
| `1.0.0` | Published; current stable | [Policy](1.0.0/policy.md) |
| `1.1.0-alpha` | Mutable V1 development contract | [Policy](v1-dev/policy.md) |

The current parser supports the three contracts above.
The `v1-dev/` directory follows the current V1 development contract; its
exact `version` is `1.1.0-alpha` today. A published `1.1.0` would have its
own versioned directory.

## Authoring a policy

For typed authoring, use the [Rust](../api-reference/rust/v1/README.md),
[.NET](../api-reference/dotnet/v1/README.md), or
[Node](../api-reference/node/v1/README.md) V1 SDK reference. These APIs select
the published `1.0.0` contract automatically. The
[stable policy guide](1.0.0/policy.md#typed-sdk-authoring)
shows a typed request; the [container lifecycle guide](../container-lifecycle.md)
covers persistent operations.

Raw JSON callers declare the exact `version` of a supported contract.
Raw configuration can select the mutable development `1.1.0-alpha` contract;
high-level V1 authoring selects published `1.0.0`. The
[versioning guide](../development/architecture/versioning.md) distinguishes
schema contracts, SDK versions, and host capabilities.
