# Process Container: Adding OS Features

This guide covers adding new OS-level features that flow
through MXC's process container pipeline. It is specific
to the Windows process container backend.

For which policy aspects this backend can enforce on each Windows 11 release
(23H2 / 24H2 / 25H2 / 25H2+), see
[Windows OS-version policy support](./os-version-support.md).

## Prerequisites

1. Read the
[Sandbox Policy spec](../sandbox-policy/v1/policy.md) to
understand how SandboxPolicy maps to ContainerConfig.
2. Read
[authoring-a-new-feature.md](../authoring-a-new-feature.md),
especially Step 1 (feature spec) and Step 2 (OS changes).
3. We recommend submitting a feature spec via the MXC repo so
reviewers understand the end-to-end flow.

## Architecture recap

For the BaseProcessContainer backend, the flow is:

```
SandboxPolicy
  → SDK: createConfigFromPolicy() → ContainerConfig JSON
    → wxc-exec: parses ContainerConfig
      → BaseContainerRunner: builds FlatBuffer SandboxSpec
        → CreateProcessInSandbox (processmodel.dll)
          → OS applies restrictions (Job Objects, mitigations, etc.)
```

Your OS change lives at the bottom of this stack. The
FlatBuffer `SandboxSpec` is the contract between MXC and the
OS. If you add a new field to `SandboxSpec`, you must also
update MXC so the data flows down from the ContainerConfig
into the FlatBuffer blob passed to
`CreateProcessInSandbox`.

## Step-by-step

### 1. Update the OS FlatBuffer schema

> **Note:** Steps 1–3 below modify the internal Microsoft Windows OS source
> tree and the `processmodel` component, and are only actionable for
> contributors with access to that source. External contributors typically
> consume the OS-side schema via `external/windows-sdk/BaseContainerSpecification.fbs`
> (see Step 4) once a new field has shipped in the public Windows SDK.

The source-of-truth schema lives inside the Microsoft Windows OS source tree
(path not publicly disclosed). It defines the `SandboxSpec` table:

```flatbuffers
table SandboxSpec {
    // ... existing fields ...

    // Your new field (example):
    your_new_restriction:bool = false;
}
```

### 2. Build processmodel

Build the `processmodel` component in the Microsoft Windows OS source tree to
pick up the schema change.

This regenerates the OS-side FlatBuffer bindings and makes
the new field available to `CreateProcessInSandbox`.

### 3. Implement OS enforcement

In the processmodel code, update `ParseSandboxTechSpec` (or
equivalent) to read your new field from the FlatBuffer and
apply the OS enforcement (e.g., set a Job Object restriction,
apply a process mitigation, configure a firewall rule).

### 4. Update MXC's FlatBuffer copy

Once your OS change has shipped (or is available on your dev
build), copy the updated `.fbs` file to MXC:

```
external/windows-sdk/BaseContainerSpecification.fbs
```

Then regenerate the Rust bindings. See
[src/core/generated/base_container_specification/README.md](
../../src/core/generated/base_container_specification/README.md)
for the exact steps.

If the OS change hasn't shipped yet and the `.fbs` is not in
the Windows SDK, copy it directly from the Microsoft Windows OS source tree
into `external/windows-sdk/BaseContainerSpecification.fbs`.

### 5. Update BaseContainerRunner in MXC

In `src/backends/appcontainer/common/src/base_container_runner.rs`, update
`build_sandbox_spec` to include your new data:

```rust
fn build_sandbox_spec(request: &ExecutionRequest) -> Vec<u8> {
    // ... existing code ...

    let spec = SandboxSpec::create(
        &mut builder,
        &SandboxSpecArgs {
            // ... existing fields ...
            your_new_restriction: request.policy.your_field,
        },
    );

    // ...
}
```

The `request.policy` fields come from the Config JSON, which
comes from the SDK's `createConfigFromPolicy()`. Make sure the
Config schema and SDK mapping are also updated (see [authoring-a-new-feature.md](../authoring-a-new-feature.md)).

### 6. Test end-to-end

You need a build of Windows with your processmodel changes.

1. **Config-level test:** Create a test config JSON with your
new field set. Run `wxc-exec config.json` directly. Verify
the OS enforcement works.

2. **SDK-level test:** Set the corresponding SandboxPolicy
policy field and call `spawnSandbox()`. Verify
the full pipeline: policy → Config → FlatBuffer → OS.

3. **Verify default-deny:** Omit the field from Config.
Verify the most-restrictive default is applied.

## Summary of files to touch

| Layer | Repo | File |
|-------|------|------|
| OS schema | Microsoft Windows OS source (internal) | `SandboxSpec.fbs` |
| OS enforcement | Microsoft Windows OS source (internal) | `processmodel` component |
| MXC FlatBuffer copy | mxc | `external/windows-sdk/BaseContainerSpecification.fbs` |
| MXC generated bindings | mxc | `src/core/generated/base_container_specification/` (regenerated) |
| MXC executor | mxc | `src/backends/appcontainer/common/src/base_container_runner.rs` |
| MXC Config schema | mxc | `schemas/dev/mxc-config.schema.*.json` |
| MXC SDK mapping | mxc | `sdk/src/sandbox.ts` |
| MXC SDK types | mxc | `sdk/src/types.ts` |
