# Run with network containment

> **Audience:** MXC consumers

Starts a temporary loopback HTTP endpoint in the host process, then runs a
transient container with outbound, inbound, and host-loopback networking
explicitly denied. The contained `curl` request must fail; a successful request
causes the sample to fail.

The host's native process-isolation backend must support this deny-all posture.
Unsupported policy fails before creating the container.

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

Expected stdout contains `network access blocked by policy`.
