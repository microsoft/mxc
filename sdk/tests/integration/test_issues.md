# Known Test Issues

## Store Python fails in AppContainer and BaseContainer

**Tests:** `should execute python in process container`, `should allow writing to brokered readwrite path`

Store Python's App Execution Alias reparse points can't be resolved inside sandboxes. Use MSI Python with `ALL APPLICATION PACKAGES:(RX)` ACL instead.

## Proxy tests timeout

**Tests:** `should route traffic through built-in proxy`, `should route traffic through external proxy`

Base process container proxy test stalls mid-round-trip. Tests should use PowerShell and WinHTTP COM instead of curl.
