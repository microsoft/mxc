# wxc_test_proxy

> **Audience:** MXC developers

**⚠️ Testing-only. NOT a production proxy.**

Minimal HTTP CONNECT proxy for `wxc` integration testing. Tunnels HTTPS via `CONNECT` — no caching, filtering, or auth.

## Usage

Launch this binary from an integration harness that owns a Windows cleanup
event and passes its PID. The proxy writes the selected loopback port to the
ready file; the harness can then supply its URL through
`runtimeConfig.networkProxy`. MXC does not start this binary from a request.

```text
wxc-test-proxy --ready-file <path> --cleanup-event <event-name> --parent-pid <pid>
```
