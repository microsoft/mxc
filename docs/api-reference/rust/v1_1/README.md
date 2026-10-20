# Rust V1.1 creation API revision

> **Audience:** MXC consumers

Public entrypoint: `mxc_sdk::v1_1`.

This scoped revision adds `mutate_policy` to captured and live-pipe creation
options. It preserves the published `mxc_sdk::v1` structs and strict operations,
and reuses V1 request, result and process types. It does not change SDK package
versions or the SDK-owned `1.0.0` request contract.

- [Operation signatures](api.md)
- [Types and fields](types.md)
- [Published V1 API](../v1/README.md)
- [Cross-SDK requirements](../../README.md)

```rust
use mxc_sdk::v1_1::{self, ContainerRequest, Error, ExecutionResult, RunOptions};

fn run_with_repairs(request: ContainerRequest) -> Result<ExecutionResult, Error> {
    let mut options = RunOptions::default();
    options.mutate_policy = true;
    let result = v1_1::run(request, options)?;
    for change in &result.warnings {
        eprintln!("{change}");
    }
    Ok(result)
}
```

Omission or `false` keeps creation strict. The revised option structs are
non-exhaustive: use `Default` and assign the desired fields so that future
invocation controls can be added without breaking callers.

Node and .NET expose the same authorization through their V1 options:
`mutatePolicy` and `MutatePolicy`. Rust uses a scoped revision because adding
a field to its published, exhaustively constructible V1 structs would break
existing struct literals.
