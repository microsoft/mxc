# API proposal: Seatbelt learning mode

> **Audience:** MXC developers

- **Issue:** [#1591](https://github.com/microsoft/mxc/issues/1591)
- **Feature design spec:** [README.md](README.md)

The v1 SDKs already expose `captureDenials` for ProcessContainer. This
proposal adds the same setting to the Seatbelt configuration in Rust, .NET,
and Node. It reuses the existing capture types and results. FFI needs no
change: `mxc_run_json` and `mxc_spawn_json` already accept a `1.1.0-alpha`
request with `seatbelt.captureDenials`.

**Availability:** the v1 SDKs send `1.0.0` requests, which have no
`seatbelt.captureDenials` field. The SDKs map the field once contract `1.1.0`
is published and `sdkMajorTargets["1"]` becomes `1.1.0`. Until then, setting
it fails before any request is sent (see
[Inputs, results, and SDK differences](#inputs-results-and-sdk-differences)).
Under the [SDK versioning policy](../../../../repository-management.md#sdk-and-schema-versioning),
this is a minor change.

## Caller scenario

This covers [example 1](README.md#problem-and-scope), `block` mode. `allow` mode
uses the same API with a different mode value, so there is one scenario.

**Rust**

```rust
use mxc_sdk::v1::{self, configs::{CaptureDenials, CaptureDenialsMode, SeatbeltConfig}, Containment, ContainerRequest};

let mut capture = CaptureDenials::default();
capture.mode = CaptureDenialsMode::Block;
capture.output_path = Some("/Users/me/mxc/denials.json".into());
let mut seatbelt = SeatbeltConfig::default();
seatbelt.capture_denials = Some(capture);

let output = v1::run(
    ContainerRequest { containment: Containment::Seatbelt(seatbelt), ..ContainerRequest::new("npm install") },
    Default::default(),
)?;
if let Some(report) = output.output_metadata.as_ref().and_then(|m| m.capture_denials.as_ref()) {
    println!("{} denials in {}", report.total_denials, report.output_path);
    // Caller deletes report.output_path and its .verbose.json sibling.
}
```

**.NET**

```csharp
var request = new ContainerRequest("npm install")
{
    Containment = new Containment.Seatbelt
    {
        CaptureDenials = new CaptureDenialsPolicy
        {
            Mode = CaptureDenialsMode.Block,
            OutputPath = "/Users/me/mxc/denials.json",
        },
    },
};
ExecutionResult output = await MxcContainer.RunAsync(request);
if (output.OutputMetadata?.CaptureDenials is { } report)
{
    Console.WriteLine($"{report.TotalDenials} denials in {report.OutputPath}");
}
```

**Node**

```typescript
import { run } from '@microsoft/mxc-sdk/v1';

const output = await run({
  command: 'npm install',
  containment: {
    type: 'seatbelt',
    config: { captureDenials: { mode: 'block', outputPath: '/Users/me/mxc/denials.json' } },
  },
});
const report = output.outputMetadata?.captureDenials;
if (report) console.log(`${report.totalDenials} denials in ${report.outputPath}`);
```

Streaming (Rust `spawn`, .NET `SpawnAsync`, Node `spawn`) reports the same
metadata on the process after `wait`.

## Proposed signatures and types

The existing v1 API version fits: Yes. Every change adds an optional member.
No new functions.

**Rust**: `mxc_sdk::v1::configs`

```rust
#[non_exhaustive]
pub struct SeatbeltConfig {
    // existing fields unchanged
    pub capture_denials: Option<CaptureDenials>, // new
}
```

`CaptureDenials`, `CaptureDenialsMode`, and `ExecutionMetadata::capture_denials`
are reused. Their docs change from "ProcessContainer" to "ProcessContainer and
Seatbelt". The `retain_etl` / `etl_path` docs (and their .NET and Node
equivalents) also say that on macOS the file is a `.seatbelt.log`.

**.NET**: `Microsoft.Mxc.Sdk.V1`

```csharp
public abstract class Containment
{
    public sealed class Seatbelt : Containment
    {
        // existing properties unchanged
        [JsonPropertyName("captureDenials")]
        public CaptureDenialsPolicy? CaptureDenials { get; set; } // new
    }
}
```

**Node**: `@microsoft/mxc-sdk/v1`

```typescript
/** Named so ProcessContainer and Seatbelt share it; same shape as today. */
export interface CaptureDenialsConfig {
  mode?: 'block' | 'allow';
  outputPath?: string;
  retainEtl?: boolean; // Windows .etl or macOS .seatbelt.log
}

export interface ProcessContainerConfig {
  captureDenials?: CaptureDenialsConfig; // was an inline type with this shape
}

export interface SeatbeltConfig {
  // existing fields unchanged
  captureDenials?: CaptureDenialsConfig; // new
}
```

Calls are synchronous or asynchronous as they are today. Cancellation is
unchanged.

## Inputs, results, and SDK differences

- **`mode`, `outputPath`:** see the
  [field table](README.md#proposed-behavior). Omitting `captureDenials`
  (`None` / `null` / `undefined`) disables capture.
- **`retainEtl`:** for Seatbelt, keeps the run's `.seatbelt.log`. Default
  `false`.
- **SDK target still `1.0.0`:** a Seatbelt `captureDenials` value is rejected
  with the same errors. Errors:
  - Rust: `MxcError` with `ErrorCode::MalformedRequest`.
  - .NET: `ArgumentException`.
  - Node: `MxcError` with code `malformed_request`.
- **Results:** use the existing `CaptureDenialsResult`. For Seatbelt,
  `etlPath` holds the `.seatbelt.log` path when retained, and
  `captureDenialsError` is never set. Capture failures come back as run or
  wait errors. When the run also times out, the capture failure is in the
  process warnings.
- **Caller cleanup:** yes. Delete `outputPath`, its `.verbose.json` sibling,
  and any `etlPath` file when done.
- **Discovery:** `v1::available_backends()` / `MxcPlatform.GetAvailableBackends` /
  `getAvailableBackends()` list `captureDenials` for `seatbelt`. The type and
  value already exist. See
  [backend availability](README.md#backend-applicability-and-availability)
  for what discovery can't detect.
- **SDK differences:** No.

### Trace naming

v1 keeps the existing `retainEtl` / `etlPath` names for both backends, even
though the Seatbelt file is a log, not an ETL. Renaming them, or adding
`trace_path` to Rust's `CaptureDenialsResult`, would break callers; the struct
isn't `#[non_exhaustive]`.

The rename to `retainTrace` / `tracePath` is a required V2 change. #1580
records it in the
[SDK major-version notes](../../versioning.md#sdk-major-version-namespaces)
and opens a tracking issue tagged for V2.

## Compatibility and request mapping

- **Existing callers compile and behave the same?** Yes.
  - Rust `SeatbeltConfig` is `#[non_exhaustive]`, so the new field doesn't
    break callers.
  - Adding a .NET property is source- and binary-compatible.
  - The Node change is a new optional field and a named alias for an existing
    inline type.
- **Discovery behavior change:** `seatbelt` gains a capability entry. Callers
  that compare the capability list exactly will see a new value.

| SDK input | Request field | Version |
|---|---|---|
| Seatbelt `capture_denials` / `CaptureDenials` / `captureDenials` | `seatbelt.captureDenials` | `1.1.0` |
| `.mode` | `seatbelt.captureDenials.mode` | `1.1.0` |
| `.output_path` / `OutputPath` / `outputPath` | `seatbelt.captureDenials.outputPath` | `1.1.0` |
| `.retain_etl` / `RetainEtl` / `retainEtl` | `seatbelt.captureDenials.retainEtl` | `1.1.0` |

- **Omitted values:** an omitted `outputPath` is omitted from the request, so
  MXC uses a temp file. Rust and .NET default `mode` to `block` and can't
  distinguish an omitted `mode` from `block`. This matches ProcessContainer
  today.
- **Unsupported combinations:** for example, with `profileOverride`. The engine
  rejects these as described in [README](README.md#proposed-behavior), and
  they surface as each SDK's existing engine validation error.

## Validation and documentation

- Shared scenarios: see the [validation plan](README.md#acceptance-criteria-and-validation-plan).
- SDK tests:
  - Request mapping per SDK: the Seatbelt capture serializes under
    `seatbelt.captureDenials` in a `1.1.0` request.
  - `retainEtl: true` on Seatbelt is sent as `retainEtl: true`, and `etlPath`
    names the `.seatbelt.log`.
  - With the target at `1.0.0`, the field is rejected.
  - .NET: add a Seatbelt capture serialize/deserialize check to
    `Microsoft.Mxc.Sdk.AotSmokeTest`.
  - Functional: a Seatbelt `block` run through `cargo test -p mxc-sdk --test streaming`
    in macOS CI. It asserts the result metadata and the report on disk.
- Docs:
  - `docs/api-reference/{rust,dotnet,node}/v1/types.md` for `SeatbeltConfig`,
    `Containment.Seatbelt`, and `CaptureDenialsConfig`.
  - Each SDK README's capture section.
  - Remove the "v1 SDKs can't enable this" note in `seatbelt-backend.md`.

## Review checklist

- [ ] Examples demonstrate a useful caller task and correct ownership.
- [ ] Concrete versioned entry points are named; any new API version is justified.
- [ ] Defaults, optional values, errors, and cancellation are explicit.
- [ ] Rust, .NET, and Node offer equivalent feature support through idiomatic APIs.
- [ ] SDK behavior differences are intentional and documented; naming and syntax follow each language's conventions.
- [ ] Backend and execution-mode support decisions are linked; SDK discovery results and errors reflect them.
- [ ] Compatibility and request mapping are addressed; breaking changes are prominent.
- [ ] Public API validation and consumer documentation updates are planned.
- [ ] Answers and examples are concise; shared design details are linked, not repeated.
