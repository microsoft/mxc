# Run with telemetry

> **Audience:** MXC consumers

Requests telemetry consent when the current user still needs to make a
decision, then opts one small transient-container run into telemetry.

The SDK supplies the complete, versioned consent resource. The sample renders
its user-facing title, body, labels, and privacy link, and persists only the
user's explicit decision. Telemetry remains off when consent is denied or
dismissed, administrative policy blocks it, or consent state cannot be read.

The per-run telemetry option authorizes optional diagnostic data for this run
only. In a Microsoft telemetry-routed build, authorized diagnostics may be sent
to Microsoft. MXC does not send commands, container output, complete file
paths, credentials, or other customer content. Public and normal development
builds emit local-only ETW instead of routing events to Microsoft.

Telemetry consent and collection are Windows-only. On Linux and macOS the
consent APIs report that telemetry is not applicable and the transient
container still runs without telemetry.

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
