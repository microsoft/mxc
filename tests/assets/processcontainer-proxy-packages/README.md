# ProcessContainer proxy test packages

These test-only MSIX packages cover the two packaged proxy identities used by
the schema 0.8 ProcessContainer proxy tests:

- `appcontainer`: packaged classic app with AppContainer isolation;
- `fulltrust`: packaged classic app at medium integrity.

Both packages contain `wxc-test-proxy.exe`, declare an inbound TCP firewall
rule for loopback port 8080, and are registered as loose development packages.
Activate either package application with
`--port 8080 --standalone`; the E2E harness owns process termination.
Stage them from an ordinary Windows PowerShell session:

```powershell
.\build-proxy-test-packages.ps1 `
  -ProxyBinary ..\..\..\src\target\debug\wxc-test-proxy.exe `
  -OutputDirectory .\out
```

The script returns the two staged manifest paths. The E2E harness registers
them with `Add-AppxPackage -Register`, which does not require package signing or
certificate trust, then unregisters the packages and removes the staged files
during cleanup. These loose packages are for testing only and must not be
distributed as product packages.
