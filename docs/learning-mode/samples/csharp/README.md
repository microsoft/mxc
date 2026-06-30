# captureDenials — C# reference consumer

A standalone C# reference implementation of the `captureDenials` integration
contract, mirroring the Rust reference in
[`src/testing/wxc_e2e_tests/src/denial_consumer.rs`](../../../../src/testing/wxc_e2e_tests/src/denial_consumer.rs).
It drives `wxc-exec` directly (there is **no SDK wrapper** for this flow) and
receives the denial stream live over an anonymous pipe whose inheritable write
handle is passed to `wxc-exec` via the `--denials-fd` flag.

Read the full contract first:
[`../../consumer-guide.md`](../../consumer-guide.md).

## What it shows

- An **anonymous pipe** (`AnonymousPipeServerStream`, `PipeDirection.In`) whose
  inheritable write handle is handed to `wxc-exec` via `--denials-fd` —
  `wxc-exec` writes, the consumer reads.
- The `0x1E`-framed NDJSON wire format: incremental framing, the `denial` and
  `summary` records, lenient (forward-compatible) JSON parsing.
- The consumer-side default noise filters and NT-prefix stripping.
- **Live** per-denial delivery (react the moment a resource is blocked) plus the
  consolidated `deniedResources` carried on the terminating `summary`.

## Files

| File | Purpose |
|---|---|
| `DenialStream.cs` | Wire types (`Denial`, `Summary`), the `0x1E` NDJSON parser, and the default filters. |
| `DenialPipeConsumer.cs` | The reusable anonymous-pipe consumer with live `DenialReceived` / `SummaryReceived` events. |
| `Program.cs` | End-to-end demo: create the pipe, spawn `wxc-exec` with `--denials-fd`, consume live, finalize. |

## Build and run (Windows)

Requires the [.NET SDK](https://dotnet.microsoft.com/download) (8.0+). No NuGet
packages are needed — the sample uses only `System.IO.Pipes` and
`System.Text.Json`.

```pwsh
# 1) One-time host provisioning (elevated) — see consumer-guide.md §2
wxc-host-prep install-learning-mode-shim

# 2) Run the consumer against a config that sets "captureDenials": true
dotnet run --project MxcDenialConsumer -- C:\path\to\wxc-exec.exe C:\path\to\config.json
```

Minimal config (`captureDenials` is a top-level, first-class field):

```jsonc
{
  "version": "0.7.0-alpha",
  "containerId": "demo",
  "containment": "processcontainer",
  "captureDenials": true,
  "process": { "commandLine": "cmd /c type \"C:\\Users\\me\\secret.txt\"" },
  "filesystem": { "readonlyPaths": [], "readwritePaths": [] }
}
```

## Contract reminders

- **Pass the handle.** Pass `DenialPipeConsumer.ClientHandle` to `wxc-exec` as
  `--denials-fd <handle>`. The client (write) handle is created inheritable so the
  spawned child inherits it at the same numeric value.
- **Enable inheritance.** Spawn `wxc-exec` with handle inheritance on (the demo
  sets `RedirectStandardError = true`, which makes .NET start the child with
  `bInheritHandles=TRUE`).
- **Release after spawn.** Call `DisposeLocalCopyOfClientHandle()` right after
  starting `wxc-exec` so the read end observes EOF once the child exits.
- **Fallback to stderr.** If `wxc-exec` cannot adopt the handle it logs a warning
  and falls back to its stderr; no summary then arrives on the pipe. Cancel
  `RunAsync` once the child exits (the demo does this after a short grace period)
  and inspect `wxc-exec` stderr in that case.
- **`captureDenialsActive`.** `totalDenials: 0` is ambiguous — always check this
  flag to tell "clean run" from "capture never attached" (e.g. shim not installed).
- **PTY-independent.** This channel is the same regardless of how the workload's
  own stdio is wired; it exists precisely so a PTY/ConPTY terminal stays clean.

This is a reference, not a supported product surface; the Rust port remains the
authoritative reference for behavior.
