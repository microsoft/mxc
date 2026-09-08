# MXC UniFFI .NET prototype

`Generated/mxc_ffi.cs` is generated from the same `mxc_ffi` library metadata as the Node prototype:

```powershell
scripts\generate-uniffi-bindings.ps1
dotnet run --project sdk\dotnet\Microsoft.Mxc.Uniffi.Smoke
```

The generated project loads the Rust dynamic library directly through generated P/Invoke. Do not edit the generated
C# file. UniFFI replaces the legacy flat C projection rather than introducing another native library.
