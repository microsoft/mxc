# Run in a persisted container

> **Audience:** MXC consumers

Demonstrates a persisted IsolationSession container:

1. Provision a container.
2. Start it.
3. Run a command and capture its output.
4. Stop it.
5. Deprovision it.

Unlike a transient container, the provisioned container has an identity and
can execute multiple workloads before it is stopped and deprovisioned. This
sample runs one workload to keep the lifecycle and cleanup responsibilities
clear.

This sample is Windows-only and requires IsolationSession support. Cleanup is
attempted even when start or execution fails, and cleanup failures are reported.

## Run

From this sample's corresponding language directory:

```text
# Rust
cargo run

# .NET
dotnet run -p:MxcWithIsolationSession=true

# Node
npm --prefix ../../../sdk/node install
npm --prefix ../../../sdk/node run build
npm install
npm start
```
