# Troubleshooting MXC

> **Audience:** MXC consumers

## PowerShell startup

On Windows, PowerShell startup may fail when it requires drive-root
enumeration that the container's filesystem policy does not permit. The Rust
V1 `available_tools_policy` and Node V1 `getAvailableToolsPolicy` helpers do not
implicitly grant read access to a drive root when they discover `pwsh.exe`.

Use a PowerShell version that does not require root enumeration, or explicitly
configure the minimum permissions required by the workload and supported by
the selected backend. Avoid full-drive reads as a general startup workaround:
they can expose host files beyond the discovered tool directories.

For the compatibility policy, see the
[PowerShell security-servicing exception](development/architecture/versioning.md#security-servicing-exception-powershell-tool-discovery).
