# wxc_test_proxy

**⚠️ Testing-only. NOT a production proxy.**

Minimal HTTP proxy for MXC integration testing. It tunnels HTTPS through
`CONNECT` and forwards ordinary HTTP requests. It provides no caching,
filtering, or authentication.

## Built-in proxy usage

Launched automatically by `wxc-exec` when the config specifies:

```json
{ "network": { "proxy": { "builtinTestServer": true } } }
```

## ProcessContainer proxy identity tests

On Windows,
[`run_processcontainer_proxy_identity_tests.ps1`](../../../tests/scripts/run_processcontainer_proxy_identity_tests.ps1)
uses this binary to verify that schema 0.8 `allowedProxyPeer` authorizes the
identity hosting a loopback proxy, rather than any process listening on the
configured port.

| Proxy deployment | Authorized identity | Expected result |
|---|---|---|
| Packaged AppContainer with a different package family authorized | Wrong package family | Failure |
| Packaged AppContainer | Its package family | Success |
| Packaged full trust | Its package family | Success |
| Unpackaged AppContainer | Its AppContainer profile name | Success |
| Unpackaged full trust | None; `hostLoopback` is allowed | Success |

The packaged negative case starts only the AppContainer proxy. It authorizes
the registered full-trust package family instead, proving that a valid but
different package identity cannot use the proxy endpoint.

Run only the packaged cases without elevation:

```powershell
tests\scripts\run_processcontainer_proxy_identity_tests.ps1 -PackagedOnly
```

Run all cases from an elevated PowerShell session:

```powershell
tests\scripts\run_processcontainer_proxy_identity_tests.ps1
```

The unpackaged cases require elevation because the harness creates machine
firewall rules. The packaged cases use loose development registration and
manifest-owned firewall rules, so they need neither elevation nor a trusted
test certificate.

## Windows launcher commands

The identity suite uses private test-launcher commands exposed by this binary:

- `activate-package` starts an installed packaged copy of the proxy;
- `launch-appcontainer` starts the proxy in an unpackaged AppContainer;
- `derive-appcontainer-sid` prints the SID for an AppContainer profile;
- `delete-appcontainer` removes a test AppContainer profile.

Keeping these commands with the proxy lets the unpackaged launcher execute its
own binary and keeps the package manifests, proxy arguments, and readiness
protocol together.

Run `wxc-test-proxy.exe <subcommand> --help` for the required arguments.
