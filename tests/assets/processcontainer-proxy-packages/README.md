# ProcessContainer proxy test packages

These test-only MSIX packages cover the two packaged proxy identities used by
the schema 0.8 ProcessContainer proxy tests:

- `appcontainer`: packaged classic app with AppContainer isolation;
- `fulltrust`: packaged classic app at medium integrity.

Both packages contain `wxc-test-proxy.exe`, declare an inbound TCP firewall
rule for loopback port 8080, and use a short-lived self-signed certificate.
Activate either package application with
`--port 8080 --standalone`; the E2E harness owns process termination.
Build them from an ordinary Windows PowerShell session with the Windows SDK
installed:

```powershell
.\build-proxy-test-packages.ps1 `
  -ProxyBinary ..\..\..\src\target\debug\wxc-test-proxy.exe `
  -OutputDirectory .\out
```

The script returns the two package paths and the exported public certificate.
The E2E harness installs the certificate into the current user's trusted store,
installs the packages, and removes both during cleanup. These assets are for
testing only and must not be distributed as product packages.
