# wxc_test_proxy

**⚠️ Testing-only. NOT a production proxy.**

Minimal HTTP CONNECT proxy for `wxc` integration testing. Tunnels HTTPS via `CONNECT` — no caching, filtering, or auth.

## Usage

Launched automatically by `wxc-exec` when the config specifies:

```json
{ "network": { "proxy": { "builtinTestServer": true } } }
```

On Windows, the binary also provides test-only launcher subcommands used by
`tests/scripts/run_processcontainer_proxy_identity_tests.ps1`:

- `activate-package` starts an installed packaged copy of the proxy;
- `launch-appcontainer` starts the proxy in an unpackaged AppContainer;
- `derive-appcontainer-sid` prints the SID for an AppContainer profile;
- `delete-appcontainer` removes a test AppContainer profile.

Run `wxc-test-proxy.exe <subcommand> --help` for the required arguments.
