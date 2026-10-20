# Rust V1.1 creation operation signatures

> **Audience:** MXC consumers

Public entrypoint: `mxc_sdk::v1_1`. [Types](types.md) | [Overview](README.md)

## Choosing a creation operation

| Output | Operation | Options | Result |
|---|---|---|---|
| Captured stdout and stderr | `run` | `RunOptions` | V1 `ExecutionResult` |
| Live standard pipes | `spawn` | `SpawnOptions` | V1 `MxcProcess` |

Both operations are strict by default. Set `mutate_policy = true` in the
operation options to authorize restrictive corrections before native Windows
ProcessContainer creation. The caller's request is not edited, and the workload
is launched once. Unsupported backends and unsafe or unknown corrections remain
errors; MXC never selects a weaker tier or backend to evade a refusal.
There is no mutation option for PTY or container lifecycle operations. See
[supported corrections and limits](../../../development/guides/process-container-adding-os-features.md#opt-in-creation-policy-mutation).

The native retry loop revalidates remembered narrowing edits against the current
request for the same creator identity. Unrelated grants or proxy endpoints do
not invalidate an applicable edit and are never copied from an old request.
Windows validates every creation again. No cache object or additional option
is required. Strict creation does not use the cache. A cache hit emits no
mutation warning unless Windows requires another correction. New corrections
use warning text beginning `Sandbox configuration updated due to IT policy`;
successful negotiation updates the cache.

## `mxc_sdk::v1_1::run`

Run a V1 `ContainerRequest` to completion and capture its output. Creation
corrections are described in `ExecutionResult.warnings`, not stdout or stderr.
Creation and operating-system wait failures return `Error`; workload exit and
timeout outcomes retain their ordinary V1 result semantics.

```rust
pub fn run(request: ContainerRequest, options: RunOptions) -> Result<ExecutionResult, Error>;
```

## `mxc_sdk::v1_1::spawn`

Create a container and return its V1 live process. Read correction descriptions
through `MxcProcess::warnings()`. Standard-stream, termination, wait and cleanup
ownership are unchanged.
Warnings are diagnostic text for a person or agent, not a stable parsing
contract. No structured creation-change accessor is exposed.

```rust
pub fn spawn(request: ContainerRequest, options: SpawnOptions) -> Result<MxcProcess, Error>;
```
