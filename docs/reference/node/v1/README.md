# Node V1 reference

> **Audience:** MXC consumers

All public SDK operations and types are available through `@microsoft/mxc-sdk/v1`.
Filesystem discovery helpers and their result/options types use `policy.filesystem`.
Discovery, probes, telemetry, and policy helpers use the same versioned boundary.

- [Operation signatures](api.md)
- [Types and fields](types.md)
- [Cross-SDK requirements](../../README.md)

Request data and operation controls are separate. Initial PTY size belongs to the corresponding PTY options; runtime resize remains a process-handle operation. Backend policy enforcement and support checks remain native.
