# Dry-run check for containment support

Discovers which containment backends the current host can run without creating
a container or starting a process. It prints platform support, each
host-available backend, effective isolation tiers, optional capabilities, and
warnings.

On Windows, the check also probes a typed ProcessContainer request to show
which isolation tier would serve that request. Availability is advisory: the
host can change between probing and a later launch.

## Run

From the corresponding language directory:

```text
# Rust
cargo run

# .NET
dotnet run

# Node
npm install
npm start
```
