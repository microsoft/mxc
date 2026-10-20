# SDK API reference

> **Audience:** MXC consumers

These references describe the supported versioned SDK APIs: operation
signatures, public types, fields, and containment choices. They complement the
SDK READMEs and backend guides; they do not replace native policy validation or
certify backend availability.

See the [consumer glossary](../glossary.md) for terminology.

| SDK | Reference | Public entrypoint |
|---|---|---|
| Rust | [V1](rust/v1/README.md) | `mxc_sdk::v1` |
| Rust creation options | [V1.1 revision](rust/v1_1/README.md) | `mxc_sdk::v1_1` |
| .NET | [V1](dotnet/v1/README.md) | `Microsoft.Mxc.Sdk.V1` |
| Node | [V1](node/v1/README.md) | `@microsoft/mxc-sdk/v1` |

V1.Dev JSON APIs are listed in [Rust](https://github.com/microsoft/mxc/blob/main/docs/api-reference/rust/v1/dev.md),
[.NET](https://github.com/microsoft/mxc/blob/main/docs/api-reference/dotnet/v1/dev.md),
and [Node](https://github.com/microsoft/mxc/blob/main/docs/api-reference/node/v1/dev.md). They accept complete
MXC request JSON with a caller-declared contract version registered in the
MXC build. Experimental backends require a separate invocation option.
Prefer typed V1 when it can express the request. Development-contract
fields and experimental backends are for development and testing, not
production dependencies.

## Choosing an operation

| Task | Input | Result |
|---|---|---|
| Create and run a container | `ContainerRequest`, operation options | Captured `ExecutionResult` or a live process |
| Provision a persistent container | `ProvisionRequest`, `ProvisionOptions` | `ProvisionResult` with `ContainerId` and optional metadata |
| Start, stop, or deprovision | `ContainerId`, operation options | `LifecycleResult` |
| Run in an existing container | `ContainerId`, `ExecutionRequest`, operation options | Captured `ExecutionResult` or a live process |
| Validate a lifecycle operation | The operation's typed inputs | `ValidationResult`, without performing the operation |

Choose captured output, live standard pipes, or an interactive terminal using
the launch tables for [Rust](rust/v1/api.md#choosing-a-launch-operation),
[.NET](dotnet/v1/api.md#choosing-a-launch-operation), and
[Node](node/v1/api.md#choosing-a-launch-operation). Requests describe the workload
and policy; operation options control invocation behavior. PTY options include
the initial size; resize is a method on the returned terminal process.

## Results and policy

Results and live handles expose warnings and optional execution metadata.
Provision metadata is backend-specific; each language's type reference lists
the supported fields.

`ContainerRequest` selects containment and carries shared restrictions;
backend-specific settings use `*Config` types listed in each language's type
reference. Omitted environment input
uses backend defaults, whereas an explicitly empty environment is preserved.
Filesystem discovery helpers follow the same distinction for their host
environment input. Native validation decides which policies the backend can
enforce.

Invocation telemetry belongs to operation options and is always subject to
persisted MXC consent and administrative restrictions.

Creation-policy mutation is also an invocation option, disabled by default.
Use `mutate_policy` in Rust V1.1 creation options, `MutatePolicy` in .NET V1,
or `mutatePolicy` in Node V1. The Rust revision preserves published V1 struct
literals; it uses the same V1 request and result types and the same `1.0.0`
request contract. The revision does not change SDK package versions.

## Language conventions

Rust execution is synchronous. .NET and Node also expose asynchronous
operations; their signature pages identify which have synchronous
counterparts. .NET cancellation tokens are trailing parameters. Casing,
constructors, enums, and discriminated unions follow each language's conventions.

## Contributor guidance: keeping references current

Update the affected signature and type pages whenever a public SDK API changes.
Review the corresponding APIs in all three SDKs, including options, defaults,
nullability, ownership, platform gates, and examples.

Breaking changes to a published SDK API require a new versioned (V*) API
surface and matching signature/type references under each affected SDK's
`docs/api-reference/<sdk>/v*/` directory. Preserve the published version's
references.
