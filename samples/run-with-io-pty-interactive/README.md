# Run with interactive PTY I/O

> **Audience:** MXC consumers

Runs an interactive shell in a transient container and connects the calling
console to an MXC-owned pseudo-terminal. Terminal output is merged, input is
forwarded until the contained shell exits, and the workload exit code is
returned.

The sample uses IsolationSession on Windows, Bubblewrap through the native
process intent on Linux, and Seatbelt through the native process intent on
macOS. Windows requires IsolationSession support; Linux requires Bubblewrap.
Type `exit` to leave the contained shell.

## Run

From this sample's corresponding language directory:

```text
# Rust
cargo run

# .NET, Linux or macOS
dotnet run

# .NET, Windows
dotnet run -p:MxcWithIsolationSession=true

# Node
npm --prefix ../../../sdk/node install
npm --prefix ../../../sdk/node run build
npm install
npm start
```
