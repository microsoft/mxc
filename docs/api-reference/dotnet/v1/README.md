# .NET V1 reference

> **Audience:** MXC consumers

All public SDK operations and types are available under `Microsoft.Mxc.Sdk.V1`.
Filesystem discovery helpers use `Microsoft.Mxc.Sdk.V1.Policy.Filesystem`.
Discovery, probes, telemetry, and policy helpers use the same versioned boundary.

- [Operation signatures](api.md)
- [V1.Dev MXC request JSON API and policy preparation](https://github.com/microsoft/mxc/blob/main/docs/api-reference/dotnet/v1/dev.md)
- [Types and fields](types.md)
- [Cross-SDK requirements](../../README.md)

Request data and operation controls are separate. Initial PTY size belongs to the corresponding PTY options; runtime resize remains a process-handle operation. Backend policy enforcement and support checks remain native.

V1.Dev adds separate Windows ProcessContainer policy preparation.
[Preparation types and public JSON helpers](dev.md#policy-preparation-and-caller-owned-observations)
support typed extraction from `MxcException.Details` and lossless
application-owned storage, including Native AOT.
