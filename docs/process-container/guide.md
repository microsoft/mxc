# Process Container: Adding OS Features

This guide covers adding new OS-level features that flow through MXC's Windows
process container pipeline.

Exact v0.9 networking uses directional egress/ingress,
`runtimeConfig.networkProxy`, and ProcessContainer proxy-peer identity. Legacy
networking fields remain available under their published contracts. Backend
selection depends on host capability and requested policy, not schema version.

For which policy aspects this backend can enforce on each Windows 11 release,
see [Windows OS-version policy support](./os-version-support.md).

## Prerequisites

1. Read the [Sandbox Policy spec](../sandbox-policy/0.7.0/policy.md) to
   understand how `SandboxPolicy` maps to `ContainerConfig`.
2. Read [authoring-a-new-feature.md](../authoring-a-new-feature.md), especially
   Step 1 (feature spec) and Step 2 (OS changes).
3. Submit a feature spec so reviewers understand the end-to-end flow.

## Architecture recap

For the BaseContainer tier, the flow is:

```text
SandboxPolicy
  -> SDK: createConfigFromPolicy() -> ContainerConfig JSON
    -> wxc-exec: parses ContainerConfig
      -> BaseContainerRunner: builds a PSEC FlatBuffer
        -> CreateProcessSecurityEnvironment (processmodel.dll)
          -> CreateProcessW with PROC_THREAD_ATTRIBUTE_SECURITY_ENVIRONMENT
            -> OS applies restrictions
```

The PSEC FlatBuffer is the contract between MXC and the OS process security
environment. New features must flow from the versioned config contract into the
runtime model and then into that FlatBuffer.

## Step-by-step

### 1. Update the OS PSEC schema and implementation

The source-of-truth schema and processmodel implementation live in the internal
Windows OS source tree. Add the new contract field, regenerate the OS bindings,
and implement the corresponding enforcement.

### 2. Update MXC's PSEC schema copy

Once the OS change is available on the target build, update:

```text
external/windows-sdk/ProcessSecurityEnvironment.fbs
```

Then regenerate the Rust bindings in:

```text
src/core/generated/process_security_environment_specification/
```

### 3. Flow the policy through MXC

Update the exact development config contract, normalized wire model, runtime
model, and parser mapping. Follow
[authoring-a-new-feature.md](../authoring-a-new-feature.md) and regenerate the
development schemas and generated SDK wire types rather than editing generated
artifacts by hand.

### 4. Build the PSEC specification

Update the helpers under
`src/backends/process_container/common/src/base_container_helpers.rs` to encode
the runtime policy into the PSEC FlatBuffer. Update
`BaseContainerRunner::is_usable_for_request()` so the BaseContainer tier is
selected only when the runtime OS probe reports every capability required to
enforce the request.

If PSEC cannot represent the request, selection must continue to an
AppContainer tier that can fully enforce it. Never silently omit a requested
restriction.

### 5. Test end-to-end

Use a Windows build containing the processmodel change.

1. Add focused parsing and PSEC-construction tests.
2. Run `wxc-exec` with a config that enables the new field and verify the OS
   enforcement.
3. Exercise the corresponding SDK policy and verify the complete
   policy-to-OS flow.
4. Verify omission applies the intended secure default.
5. Verify an unsupported host selects a compatible AppContainer tier or returns
   an actionable error without weakening policy.

## Summary of files to touch

| Layer | Repo | File |
|-------|------|------|
| OS schema and enforcement | Microsoft Windows OS source (internal) | processmodel PSEC contract and implementation |
| MXC FlatBuffer copy | mxc | `external/windows-sdk/ProcessSecurityEnvironment.fbs` |
| MXC generated bindings | mxc | `src/core/generated/process_security_environment_specification/` |
| MXC specification builder | mxc | `src/backends/process_container/common/src/base_container_helpers.rs` |
| MXC executor and capability selection | mxc | `src/backends/process_container/common/src/base_container_runner.rs` |
| MXC Config schema | mxc | `schemas/dev/mxc-config.schema.*.json` |
| MXC SDK mapping | mxc | `sdk/node/src/sandbox.ts` |
| MXC SDK types | mxc | `sdk/node/src/types.ts` |
