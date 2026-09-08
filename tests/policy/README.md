# Cross-language policy fixtures

Hand-authored JSON request fixtures asserted against by **both** language
bindings. They pin the co-versioned binding request contract — the
`RequestSpec` / `SandboxRequest` wire shape — so the Rust and C# models cannot
drift apart silently.

| Fixture | Contract |
|---------|----------|
| `request-process-container.json` | One-shot process-container request |
| `request-directional-network.json` | One-shot request using the schema 0.8 directional network shape |
| `request-wslc.json` | One-shot WSLC request |
| `state-aware-wslc-provision.json` | State-aware WSLC `provision` envelope |
| `state-aware-wslc-exec.json` | State-aware WSLC `exec` envelope |

## Consumers

- **Rust** — `src/ffi/mxc_ffi/src/request.rs` and `src/ffi/mxc_ffi/src/state_aware.rs`
  pull each file in with `include_str!` and assert the native contract accepts it.
- **C#** — `sdk/dotnet/Microsoft.Mxc.Sdk.Tests` embeds `*.json` from this
  directory (see its `.csproj`) and compares serializer output via
  `JsonAssert.MatchesGolden`.

They live here rather than under either SDK because neither owns them: a Rust
crate reaching into `sdk/dotnet/` for test data inverts the dependency, and
reorganizing one SDK would break the other's tests.

## These are written by hand, on purpose

Do **not** generate them from the Rust structs or the C# POCOs. Their value is
that they are an *independent* statement of the expected wire shape. Deriving
them from either model under test would make the assertion tautological — a
field renamed in the model would silently rename itself in the fixture and the
test would still pass.

When the request contract changes intentionally, edit these files by hand and
let both test suites confirm the change is what you meant.

## Not config files

These are **binding request** documents (`{ policy, command, containment, … }`),
not `MxcConfig` documents. They are deliberately outside `tests/configs/` and
`tests/examples/`, which `scripts/versioning/validate-configs.js` validates
against the `MxcConfig` dev schema; these would fail that schema because they
describe a different contract.
