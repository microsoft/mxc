# MXC Diplomat public prototype

`Microsoft.Mxc.Diplomat.Prototype` is a disposable evaluation layer over
Diplomat-generated bindings. Generate it with:

```powershell
.\scripts\generate-diplomat-bindings.ps1 -Build
```

## Live sandbox concurrency

`MxcDiplomatSandbox` wraps the current mutable `mxc_sdk::Sandbox` handle. Its
`wait`, `kill`, `try_wait`, and `take_*` operations all require exclusive
access to that SDK handle. The prototype never aliases that mutable handle
unsafely.

When one operation owns the handle, a concurrent operation fails immediately
with `MxcDiplomatException`, `MxcDiplomatErrorCode.BackendError`, and:

```text
sandbox handle is busy with another operation; wait for it to finish before retrying
```

Its `Inner.Operation()` is `Diplomat handle synchronization`. In particular,
`WaitAsync` does not make `KillAsync` interruptible: while its worker is in
`Sandbox.Wait`, `KillAsync`, `TryWait`, and `TakeStdin`/`TakeStdout`/`TakeStderr`
return the busy error rather than block or race the Rust handle.

A production API that needs cancellation must introduce an interruptible
wait/kill primitive in `mxc-sdk`, or an actor that owns the mutable sandbox and
serializes command messages while it waits. Do not work around this by issuing
concurrent mutable FFI calls.
