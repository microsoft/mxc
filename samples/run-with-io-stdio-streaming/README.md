# Run with streaming standard I/O

> **Audience:** MXC consumers

Spawns a live process in a transient container using the host's native
process-isolation backend. It forwards stdout and stderr as they arrive. Both
streams are drained concurrently before the process handle is released.
The Node sample demonstrates the `Readable.on('data', ...)` callback exposed by
`MxcProcess.standardOutput` and `standardError`.

## Run

From this sample's corresponding language directory:

```text
# Rust
cargo run

# .NET
dotnet run

# Node
npm --prefix ../../../sdk/node install
npm --prefix ../../../sdk/node run build
npm install
npm start
```

Expected output shows `first`, pauses briefly, then shows `second`.
