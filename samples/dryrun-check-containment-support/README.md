# Dry-run check for containment support

> **Audience:** MXC consumers

Discovers which containment backends the current host can run without creating
a container or starting a process. It prints platform support, each
host-available backend, optional capabilities, and warnings.

On Windows, the check also probes a typed ProcessContainer request.
Availability is advisory: the host can change between probing and a later
launch.

## Run

From the corresponding language directory:

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
