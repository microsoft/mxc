# MXC UniFFI .NET prototype

`Generated/mxc_uniffi.cs` is generated from the same `mxc_uniffi` library metadata as the Node prototype:

```powershell
scripts\generate-uniffi-bindings.ps1
dotnet run --project sdk\dotnet\Microsoft.Mxc.Uniffi.Smoke
```

The generated project loads the Rust dynamic library directly through generated P/Invoke. Do not edit the generated
C# file.
