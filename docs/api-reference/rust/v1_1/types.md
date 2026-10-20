# Rust V1.1 creation types

> **Audience:** MXC consumers

Public entrypoint: `mxc_sdk::v1_1`. [Operations](api.md) | [Overview](README.md)

## `mxc_sdk::v1_1::RunOptions`

Invocation controls for captured creation. Both fields default to the same
strict, telemetry-disabled behavior as ordinary V1 creation.

```rust
#[non_exhaustive]
pub struct RunOptions {
    pub telemetry: Option<TelemetryConfig>,
    pub mutate_policy: bool,
}
```

## `mxc_sdk::v1_1::SpawnOptions`

Invocation controls for live-pipe creation. `mutate_policy` defaults to `false`.

```rust
#[non_exhaustive]
pub struct SpawnOptions {
    pub telemetry: Option<TelemetryConfig>,
    pub mutate_policy: bool,
}
```

Both types implement `Debug`, `Clone`, `Copy`, `Default`, `PartialEq` and `Eq`.
Construct them with `Default` and assign the desired fields. Telemetry remains
subject to consent and policy; mutation authorization is never read from
request JSON and does not authorize experimental backends.

## Re-exported V1 types

`ContainerRequest`, `Error`, `ExecutionResult`, `MxcProcess` and `TelemetryConfig`
are re-exported unchanged from `mxc_sdk::v1`. Their fields, optional-value
semantics, error behavior and ownership remain defined by the
[V1 type reference](../v1/types.md).
