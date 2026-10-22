# Rust V1 reference

> **Audience:** MXC consumers

All public SDK operations and types are available through `mxc_sdk::v1`.
Filesystem discovery helpers and their result/options types use `v1::policy::filesystem`.
Discovery, probes, telemetry, and policy helpers use the same versioned boundary.

Experimental Windows x64 MicroVM captured execution uses
`v1::experimental::run` with `Containment::MicroVm { image }` and the `microvm`
build feature. This does not authorize MicroVM through stable launch operations
or change the published V1 contract target.

- [Operation signatures](api.md)
- [Types and fields](types.md)
- [Cross-SDK requirements](../../README.md)

Request data and operation controls are separate. Initial PTY size belongs to the corresponding PTY options; runtime resize remains a process-handle operation. Backend policy enforcement and support checks remain native.
