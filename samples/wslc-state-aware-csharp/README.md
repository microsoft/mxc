# WSLC State-Aware C# Sample

This compact sample demonstrates:

```text
provision -> start -> exec attached -> stop -> deprovision
```

The image and command are hard-coded so the sample focuses on the
`MxcLifecycle` API. Cleanup runs after provisioning even when start or exec
fails.

## Run

Build MXC with WSLC support and prepare the image:

```powershell
.\build.bat --with-wslc
.\scripts\setup-wslc.ps1 -Image alpine:latest
```

Then run from a real console:

```powershell
dotnet run --project .\samples\wslc-state-aware-csharp
```

The attached exec API requires an interactive console. Do not redirect standard
input or output.
