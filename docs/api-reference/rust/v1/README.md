# Rust V1 reference

> **Audience:** MXC consumers

The published V1 SDK operations and types are available through `mxc_sdk::v1`.
Filesystem discovery helpers and their result/options types use `v1::policy::filesystem`.
Discovery, probes, telemetry, and policy helpers use the same versioned boundary.

- [Operation signatures](api.md)
- [V1.Dev exact-JSON API](https://github.com/microsoft/mxc/blob/main/docs/api-reference/rust/v1/dev.md)
- [Types and fields](types.md)
- [Cross-SDK requirements](../../README.md)

Request data and operation controls are separate. Initial PTY size belongs to the corresponding PTY options; runtime resize remains a process-handle operation. Backend policy enforcement and support checks remain native.

For creation options with caller-authorized policy mutation, use the scoped
[V1.1 creation API revision](../v1_1/README.md). Published V1 option structs and
strict creation calls remain unchanged.
