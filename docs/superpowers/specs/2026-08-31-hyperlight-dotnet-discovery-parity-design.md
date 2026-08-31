# Hyperlight .NET Discovery Parity Design

## Context

PR #1059 changed native host discovery to report Hyperlight when Windows
Hypervisor Platform is available. The native result uses
`ContainmentBackend::Hyperlight.wire_name()`, whose wire value is
`"hyperlight"`.

The C# discovery surface predates that addition. Its `ContainmentBackend` enum
has no `Hyperlight` member, and `MxcSandbox.ParseBackend` consequently maps the
new native value to `Unknown`. The static parity gate on current `main`
identifies both parts of the drift:

```text
discovery backend enum: managed [...] Rust [..., Hyperlight, ...]
discovery backend Hyperlight: managed wire "undefined", Rust wire "hyperlight"
```

This is a managed discovery-contract regression, not a Hyperlight runtime
implementation problem.

## Assumptions

- The implementation branch starts from current `main`, including PR #1059.
- PR #1070 remains unchanged.
- Existing workflows, package sources, and dependency versions remain
  unchanged.

## Goals

- Represent native Hyperlight discovery as
  `ContainmentBackend.Hyperlight` in the C# SDK.
- Map the exact native wire name `"hyperlight"` to that enum member.
- Extend the existing table-driven parser test with the Hyperlight mapping.
- Demonstrate that the existing static parity gate fails before the production
  change and passes after it.
- Run the focused .NET discovery mapping test after implementation.

## Non-goals

- Do not change native Hyperlight probing, launch behavior, or feature gates.
- Do not add a new C# containment request type or claim that this discovery
  result changes which backends the managed SDK can launch.
- Do not modify PR #1070 or its behavior.
- Do not weaken CI, alter workflows, or change dependencies.
- Do not add code to bypass Azure Artifacts authentication. An HTTP 403 from
  the package feed is an external Azure `ReadPackages` authorization failure
  and must remain an environment/setup issue.

## Considered Approaches

### 1. Add explicit managed parity (selected)

Add the enum member, parser case, and one row to the existing mapping theory.
This mirrors the native discovery contract and satisfies both parity-gate
failures with the smallest complete change.

### 2. Preserve Hyperlight as `Unknown`

The forward-compatible `Unknown` fallback is appropriate for an unrecognized
backend from a newer native library, but not for a backend deliberately shipped
by the same repository and checked by the static parity gate. This would leave
the public managed discovery API behind native behavior.

### 3. Exclude Hyperlight from the parity gate

Filtering Hyperlight out of `scripts/check-dotnet-api-parity.js` would conceal
the mismatch rather than fix it. It would also weaken the guard that is meant
to catch future native/managed discovery drift.

## Design

### Managed API

Add `Hyperlight` to `ContainmentBackend` in
`sdk/dotnet/Microsoft.Mxc.Sdk/PlatformDiscovery.cs`, with XML documentation
identifying it as the Hyperlight micro-VM backend.

This is an additive enum change. `Unknown` remains the fallback for genuinely
unrecognized future wire values.

### Wire mapping

Add the exact case below to `MxcSandbox.ParseBackend` in
`sdk/dotnet/Microsoft.Mxc.Sdk/MxcSandbox.cs`:

```csharp
"hyperlight" => ContainmentBackend.Hyperlight,
```

Both `GetAvailableBackends` and `GetPlatformSupport` already flow native wire
names through `ParseBackend`, so no additional discovery path or JSON model
change is required.

### Test coverage

Add this row to the existing `Discovery_MapsEveryNativeBackend` theory in
`sdk/dotnet/Microsoft.Mxc.Sdk.Tests/MxcSandboxTests.cs`:

```csharp
[InlineData("hyperlight", ContainmentBackend.Hyperlight)]
```

The existing `Discovery_PreservesUnknownNativeBackend` test remains unchanged
and continues to verify the forward-compatible fallback.

## Data Flow

1. Native discovery emits `"hyperlight"` when its existing WHP availability
   probe succeeds.
2. The C# FFI wrapper deserializes that string into the existing native
   discovery DTO.
3. `ParseBackend` maps it to `ContainmentBackend.Hyperlight`.
4. The typed value appears in `AvailableBackend.Backend` or
   `PlatformSupport.AvailableMethods`, depending on the discovery API called.

No new serialization format, native ABI, or runtime launch path is introduced.

## Error Handling and Compatibility

The change does not introduce a new failure mode. Exact known wire names map to
their typed enum members; all other values continue to map to `Unknown`.
Hyperlight remains subject to the native availability probe and is not
synthesized by the managed SDK.

Because this is additive, existing callers that do not inspect Hyperlight are
unaffected. Callers that exhaustively switch over `ContainmentBackend` may
choose to handle the new member explicitly, which is the intended signal of an
expanded discovery contract.

## Verification

Implementation must preserve the red/green evidence:

1. On current `main`, run `node scripts/check-dotnet-api-parity.js` and retain
   the failure showing the missing managed enum member and parser wire case.
2. Apply the three managed changes described above.
3. Re-run `node scripts/check-dotnet-api-parity.js`; it must report C# API
   parity success.
4. From `sdk/dotnet`, run:
   `dotnet test Microsoft.Mxc.Sdk.Tests/Microsoft.Mxc.Sdk.Tests.csproj --filter FullyQualifiedName~Discovery_MapsEveryNativeBackend`.

If .NET restore or test execution receives an Azure Artifacts HTTP 403, report
the external `ReadPackages` authorization block. Do not alter package sources,
credentials, dependencies, or CI configuration to bypass it.

## Scope and Deliverables

The implementation is limited to:

- `sdk/dotnet/Microsoft.Mxc.Sdk/PlatformDiscovery.cs`
- `sdk/dotnet/Microsoft.Mxc.Sdk/MxcSandbox.cs`
- `sdk/dotnet/Microsoft.Mxc.Sdk.Tests/MxcSandboxTests.cs`

No other production, test, workflow, or dependency files are required.
