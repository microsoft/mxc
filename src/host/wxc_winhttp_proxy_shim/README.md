# winhttp-proxy-shim

Temporary elevated helper that sets per-AppContainer WinHTTP proxy policy.

This binary will be removed once `CreateProcess` supports associating an
AppContainer with a localhost proxy at creation time. Until then, the
undocumented `WinHttpConnectionSetPolicyEntries` and
`WinHttpConnectionSetProxyInfo` APIs require elevation, so this shim is
launched with a UAC prompt to perform the binding.

Requires administrator privileges (UAC prompt) each time the proxy is started.
