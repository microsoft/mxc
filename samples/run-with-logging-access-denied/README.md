# Run with logging access denied

> **Audience:** MXC consumers

Runs a harmless Windows ProcessContainer workload that attempts to read a
checked-in file explicitly denied by policy. `captureDenials` keeps the access
blocked, records the denial, and returns structured metadata describing the
generated JSON report.

The sample prints the actionable report path and denial count and leaves the
generated actionable and verbose JSON reports available for inspection. It is
Windows-only and requires a host with ProcessContainer denial capture support.

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
