# Run with captured I/O

Runs a short command in a transient container using the host's native
process-isolation backend. The operation returns after the program finishes
with its complete captured stdout and stderr, warnings, and exit status.

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

Expected stdout contains `hello from MXC`.
