# Rust V1 reference

> **Audience:** MXC consumers

All public SDK operations and types are available through `mxc_sdk::v1`.
Filesystem discovery helpers and their result/options types use
`v1::policy::filesystem`. Shared request and policy types have one canonical
path at the `v1` root.

- [Operation signatures](api.md)
- [Types and fields](types.md)
- [Cross-SDK requirements](../../README.md)

`ContainerRequest` describes a workload that creates a new container.
`ExecutionRequest` describes a workload launched in a persistent container
created by `v1::container::provision_container`. Operation options control the
individual API call rather than the workload policy.

Initial PTY size belongs to the PTY operation options. Resize is available on
the returned `MxcPtyProcess`. Backend support and policy enforcement are
validated by the native engine.
