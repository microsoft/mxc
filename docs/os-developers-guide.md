# OS Developer Guide

This guide is for developers adding new OS-level features that
flow through MXC's BaseProcessContainer pipeline. It covers
the end-to-end process from OS API to MXC executor.

## Prerequisites

1. Read the
[SandboxRequest spec](sandbox-policy/v1/policy.md) to
understand how policy and environment map to Config.
2. Read
[authoring-a-new-feature.md](authoring-a-new-feature.md),
especially Step 1 (feature spec) and Step 2 (OS changes).
3. **Write and get approval on a feature spec before starting
OS work.** The spec ensures your OS API can be plumbed
end-to-end through Config into SandboxRequest.

## Architecture recap

```
SandboxRequest (policy + environment)
  → SDK: buildSandboxConfig() → Config JSON
    → wxc-exec: parses Config
      → BaseContainerRunner: builds FlatBuffer SandboxSpec
        → Experimental_CreateProcessInSandbox (processmodel.dll)
          → OS enforces policies from the FlatBuffer
```

Your OS change lives at the bottom of this stack. The
FlatBuffer `SandboxSpec` is the contract between MXC and the
OS. If you add a new field to `SandboxSpec`, it must be
reachable from the top (SandboxRequest).

## Step-by-step

### 1. Update the OS FlatBuffer schema

The source-of-truth schema is in the OS repo:

```
/onecore/base/appmodel/execmodel/processmodel/lib/schema/SandboxSpec.fbs
```

Add your new field to the `SandboxSpec` table:

```flatbuffers
table SandboxSpec {
    // ... existing fields ...

    // Your new field (example):
    your_new_restriction:bool = false;
}
```

### 2. Build processmodel

Build the processmodel project in the OS repo to pick up the
schema change:

```
/onecore/base/appmodel/execmodel/processmodel
```

This regenerates the internal FlatBuffer bindings and makes
the new field available to `Experimental_CreateProcessInSandbox`.

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
[src/generated/base_container_specification/README.md](
../src/generated/base_container_specification/README.md)
for the exact steps.

If the OS change hasn't shipped yet and the `.fbs` is not in
the Windows SDK, you can copy it directly from the OS repo:

```
/onecore/base/appmodel/execmodel/processmodel/lib/schema/SandboxSpec.fbs
→ external/windows-sdk/BaseContainerSpecification.fbs
```

### 5. Update BaseContainerRunner in MXC

In `src/wxc_common/src/base_container_runner.rs`, update
`build_sandbox_spec` to include your new data:

```rust
fn build_sandbox_spec(request: &CodexRequest) -> Vec<u8> {
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
comes from the SDK's `buildSandboxConfig()`. Make sure the
Config schema and SDK mapping are also updated (see Step 3+
in authoring-a-new-feature.md).

### 6. Test end-to-end

You need a build of Windows with your processmodel changes.

1. **Config-level test:** Create a test config JSON with your
new field set. Run `wxc-exec config.json` directly. Verify
the OS enforcement works.

2. **SDK-level test:** Set the corresponding SandboxRequest
policy or environment field and call `spawnSandbox()`. Verify
the full pipeline: request → Config → FlatBuffer → OS.

3. **Verify default-deny:** Omit the field from Config.
Verify the most-restrictive default is applied.

## Summary of files to touch

| Layer | Repo | File |
|-------|------|------|
| OS schema | os.2020 | `/onecore/.../schema/SandboxSpec.fbs` |
| OS enforcement | os.2020 | processmodel implementation |
| MXC FlatBuffer copy | mxc | `external/windows-sdk/BaseContainerSpecification.fbs` |
| MXC generated bindings | mxc | `src/generated/base_container_specification/` (regenerated) |
| MXC executor | mxc | `src/wxc_common/src/base_container_runner.rs` |
| MXC Config schema | mxc | `schemas/dev/mxc-config.schema.*.json` |
| MXC SDK mapping | mxc | `sdk/src/sandbox.ts` |
| MXC SDK types | mxc | `sdk/src/types.ts` |
