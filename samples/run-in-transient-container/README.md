# Run in a transient container

> **Audience:** MXC consumers

Demonstrates a complete run-to-completion container request using the host's native
process-isolation backend. The sample checks host support, supplies a bounded
command and an environment override, runs it in a newly created transient
container, reports warnings and output, and returns the workload's exit code.
The container is released automatically when the operation finishes.

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

Expected stdout contains `hello from transient-container`.
