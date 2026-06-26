# @microsoft/mxc-sdk-linux-arm64

Platform-specific native binaries for the [`@microsoft/mxc-sdk`](https://www.npmjs.com/package/@microsoft/mxc-sdk)
package, targeting **linux-arm64**.

This package is an implementation detail of `@microsoft/mxc-sdk`. It is listed
as one of that package's `optionalDependencies` and is installed automatically
by npm only on a matching host (via the `os` / `cpu` fields in its manifest).
Do not depend on it directly.

The native binaries are staged into this package at build time and published
from CI; they are not committed to the repository.
