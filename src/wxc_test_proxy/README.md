# wxc_test_proxy

**⚠️ Testing-only. NOT a production proxy.**

Minimal HTTP CONNECT proxy for `wxc` integration testing. Tunnels HTTPS via `CONNECT` — no caching, filtering, or auth.

## Usage

Launched automatically by `wxc-exec` when the config specifies:

```json
{ "network": { "proxy": { "builtinTestServer": true } } }
```
