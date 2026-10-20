# Rust V1 reference

> **Audience:** MXC consumers

All public SDK operations and types are available through `mxc_sdk::v1`.
Filesystem discovery helpers and their result/options types use `v1::policy::filesystem`.
Discovery, probes, telemetry, and policy helpers use the same versioned boundary.

Experimental backends use the same V1 typed requests and results through
`mxc_sdk::v1::experimental`. The `microvm` Cargo feature plus an experimental
operation is required for NVX MicroVM authoring; ordinary `v1::run`,
`v1::spawn`, and `v1::container::*` do not authorize it.

- [Operation signatures](api.md)
- [Types and fields](types.md)
- [Cross-SDK requirements](../../README.md)

Request data and operation controls are separate. Initial PTY size belongs to the corresponding PTY options; runtime resize remains a process-handle operation. Backend policy enforcement and support checks remain native.
