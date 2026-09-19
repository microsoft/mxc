# Working Directory Validation Placement Analysis

Status: architecture analysis and implementation recommendation.

Date: September 19, 2026.

## 1. Scope

This analysis considers the working-directory changes in #1147 against the
exact-contract stack:

| PR | Purpose |
| --- | --- |
| #1184 | Publish the exact v0.9 contract and open v0.10 |
| #1185 | Remove the rolling configuration architecture |
| #1186 | Harden the exact-contract infrastructure |

The relevant stack is linear:

```text
#1184
  -> #1185
    -> #1186
```

The goal is to enforce the schema-v0.9 rule that an explicit `process.cwd`
must be absolute as early as practical, preferably before constructing
`ExecutionRequest`, without losing:

- backend-specific Windows versus Unix path semantics;
- the one-shot versus state-aware WSLC distinction;
- the `policy_validation` error classification;
- protection for Rust SDK callers that mutate a request after construction;
- the separate WSLC requirement that a host path be translatable into the
  container.

## 2. Conclusion

On the final #1186 architecture, the canonical early check belongs in
`wxc_common::config_parser::convert_config_input`:

1. exact contracts deserialize the request;
2. version-specific adapters produce the private `ConfigInput`;
3. state-aware normalization supplies containment from the operation or
   `sandboxId`;
4. `convert_config_input` resolves abstract containment to the concrete
   platform backend;
5. working-directory validation runs;
6. only then is `ExecutionRequest` constructed.

The check should be driven by typed compatibility carried in `ConfigInput`,
not by parsing a contract-version string or comparing `ContractVersion` in
shared runtime code.

The existing late validation should remain as defense-in-depth until every
programmatic mutation path, especially
`SandboxRequest::set_working_directory`, performs equivalent validation.

The WSLC path-translation check should remain backend-local. It enforces a
different invariant from absoluteness.

## 3. Current #1147 Placement

#1147 adds two distinct categories of checks.

### 3.1 Absolute-path policy

`wxc_common::validator::validate_working_directory` accepts a completed
`ExecutionRequest` and is called from:

- `validate_common` for one-shot execution;
- `validate_exec_common` for state-aware `exec`.

It obtains the expected path style from
`ContainmentBackend::working_directory_style`:

| Backend or surface | Required style |
| --- | --- |
| Windows ProcessContainer | Windows |
| Windows Sandbox | Windows |
| IsolationSession | Windows |
| WSLC one-shot | Windows host path |
| WSLC state-aware exec | Unix in-container path |
| LXC, Bubblewrap, Seatbelt, MicroVM, Hyperlight, VM | Unix |

This placement correctly catches `ExecutionRequest` values changed after
parsing, but it is later than necessary for normal exact-contract requests.
The parser has already allocated and populated the complete execution-domain
model.

### 3.2 WSLC path translation

`wslc_common::wsl_container_runner::container_working_directory` converts a
one-shot Windows host path to its in-container path. It is called from both:

- the WSLC validation path, so dry-run rejects the request;
- `start_container`, before COM, session, image, or SDK work.

This closes the prior silent-drop behavior. A non-empty `cwd` that cannot be
translated is now rejected rather than ignored.

This check is not equivalent to the shared absolute-path rule. For example, a
UNC path can be Windows-absolute but still have no WSLC `/mnt/<drive>/...`
translation. The conversion must therefore remain in the WSLC backend.

## 4. Architecture at #1184

#1184 makes exact contracts authoritative:

```text
JSON
  -> exact v0.6-v0.10 contract
  -> contract cross-field validation
  -> version-specific adapter
  -> common normalization input
  -> ExecutionRequest
```

At this point, placing the check in an exact-contract validator would be
tempting, but incorrect:

- Windows versus Unix absoluteness depends on the concrete host/backend;
- abstract `process` containment is resolved per host;
- state-aware exec derives its backend from `sandboxId`;
- the contract crate should remain platform-independent;
- published v0.9 contract types should not own runtime backend policy.

The exact contract can document that `cwd` is absolute, but runtime enforcement
belongs after backend resolution.

## 5. Architecture Added by #1185

#1185 removes rolling whole-request deserialization and introduces the private
`ConfigInput` normalization DTO:

```text
exact contract
  -> version-specific adapter
  -> ConfigInput
  -> convert_config_input
  -> ExecutionRequest
```

`ConfigInput` is the important new seam. It contains:

- typed source-contract attribution;
- typed network-enforcement compatibility;
- optional containment;
- the adapted process, including `cwd`;
- the remaining common and backend-specific normalization inputs.

This is a better location than the exact adapters themselves. Putting the
check in every adapter would duplicate policy between v0.9 and v0.10 and make
each future contract repeat host-dependent logic.

#1185 also establishes a design rule relevant to this change: runtime behavior
should use typed compatibility rather than parsing version strings.

## 6. Hardening Added by #1186

#1186 reinforces `ConfigInput` as an internal implementation boundary:

- normalization DTOs are not deserialization contracts;
- exact contracts remain authoritative for JSON shape, aliases, schemas, and
  generated contract types;
- adapters assemble private inputs for shared runtime normalization;
- registry metadata owns exact artifact and request-root behavior.

On the #1186 shape, `convert_config_input`:

1. extracts `process.commandLine`, `process.cwd`, timeout, and environment;
2. resolves `cfg.containment` through `map_wire_containment`;
3. normalizes policy and backend configuration;
4. constructs `ExecutionRequest` only at the end.

For state-aware requests, `normalize_state_aware_common` first sets
`common.containment`:

- provision uses the typed provision operation;
- later phases derive containment from `sandboxId`.

It then calls `convert_config_input`. Consequently, the conversion function
has both the adapted `cwd` and the concrete runtime backend before it constructs
`ExecutionRequest`.

## 7. Recommended Design

### 7.1 Add typed working-directory compatibility

Add a compatibility type alongside `NetworkEnforcementCompatibility`:

```rust
pub enum WorkingDirectoryCompatibility {
    LegacyRelativeAllowed,
    AbsoluteRequired,
}
```

Add it to `ConfigInput`:

```rust
pub(crate) working_directory_compatibility:
    WorkingDirectoryCompatibility,
```

Every exact adapter must assign it explicitly:

| Contract | Value |
| --- | --- |
| v0.6 | `LegacyRelativeAllowed` |
| v0.7 | `LegacyRelativeAllowed` |
| v0.8 | `LegacyRelativeAllowed` |
| published v0.9 | `AbsoluteRequired` |
| development v0.10 | `AbsoluteRequired` |

This is preferable to:

- parsing a schema-version string;
- ordering `ContractVersion` values in shared runtime code;
- testing for a list of current version variants in `convert_config_input`.

Typed compatibility makes the behavioral choice explicit when a new exact
contract is added.

### 7.2 Pass an explicit process scope

The conversion path must know whether the process is a one-shot process or a
state-aware exec process. This controls WSLC path style.

Use an explicit value such as:

```rust
pub enum WorkingDirectoryScope {
    OneShot,
    Exec,
}
```

and pass:

```rust
Option<WorkingDirectoryScope>
```

to `convert_config_input`:

| Request | Scope |
| --- | --- |
| One-shot | `Some(OneShot)` |
| State-aware exec | `Some(Exec)` |
| Provision, start, stop, deprovision | `None` |

This is clearer than deriving cwd semantics from `require_process` or
`state_aware_wslc_exec`. The latter is a network-normalization exception and
should not become a general execution-surface discriminator.

### 7.3 Validate after containment resolution

Refactor the checker so it no longer accepts `ExecutionRequest`:

```rust
fn validate_working_directory(
    compatibility: WorkingDirectoryCompatibility,
    cwd: &str,
    containment: ContainmentBackend,
    scope: WorkingDirectoryScope,
) -> Result<(), WorkingDirectoryError>
```

Call it in `convert_config_input` after:

```rust
let containment = map_wire_containment(cfg.containment.as_ref());
```

and before policy normalization and the final:

```rust
Ok(ExecutionRequest { ... })
```

Conceptually:

```rust
let working_directory = extract_process_cwd(&cfg)?;
let containment = map_wire_containment(cfg.containment.as_ref());

if let Some(scope) = working_directory_scope {
    validate_working_directory(
        cfg.working_directory_compatibility,
        &working_directory,
        containment.clone(),
        scope,
    )?;
}

// Continue normalization and eventually construct ExecutionRequest.
```

This is the earliest shared point that knows:

- whether the source contract requires an absolute path;
- the exact supplied cwd string;
- the concrete host backend;
- whether WSLC interprets the value as a host or container path.

### 7.4 Preserve typed error classification

#1147 intentionally reports this refusal as `policy_validation`:

- one-shot uses `FailurePhase::Rejected`;
- state-aware exec uses `MxcError::policy_validation`.

Moving the check into `convert_config_input` must not turn the failure into:

- `ConfigParse`;
- `malformed_request`;
- a generic normalization failure.

The conversion layer currently returns `WxcError`, while the state-aware
surface requires a typed `MxcError`. Introduce a conversion error that
distinguishes malformed input from a policy refusal, for example:

```rust
enum ConfigConversionError {
    Malformed(WxcError),
    PolicyValidation(String),
}
```

The callers then map `PolicyValidation` according to their surface:

| Surface | Mapping |
| --- | --- |
| One-shot | Rejected `ScriptResponse` / `policy_validation` envelope |
| State-aware exec | `MxcError::policy_validation` |
| Internal exact builder | corresponding typed builder error |

The specific type can differ, but the error category must survive the earlier
validation placement.

## 8. Programmatic Mutation

Early normalization does not cover every request.

The Rust SDK currently permits:

```rust
request.set_working_directory(value);
```

after the `ExecutionRequest` inside `SandboxRequest` has already been
constructed. Direct internal construction can do the same.

Therefore, removing the checks from `validate_common` and
`validate_exec_common` would reopen the post-parse mutation path described by
#873.

The recommended transition is:

1. validate normal exact-contract inputs in `convert_config_input`;
2. retain the late common check as defense-in-depth;
3. add a fallible SDK API if early failure is desired for Rust callers:

   ```rust
   pub fn try_set_working_directory(
       &mut self,
       cwd: impl Into<String>,
   ) -> Result<&mut Self, MxcError>;
   ```

4. remove or reduce the late check only after every public and internal
   mutation path enforces the invariant.

Keeping both checks initially is intentional. The early check improves parser
and builder behavior; the late check protects mutable domain objects.

## 9. WSLC Responsibilities

The shared and backend checks should remain separate:

| Check | Owner | Question answered |
| --- | --- | --- |
| Absolute path | Shared normalization | Can this path resolve against ambient launcher cwd? |
| WSLC translation | WSLC backend | Can this Windows host path map into the container? |

For one-shot WSLC:

```text
C:\workspace
  -> absolute Windows path
  -> translatable
  -> /mnt/c/workspace
```

A path such as `\\server\share` may pass the first check and fail the second.
That is correct.

`container_working_directory` should continue to be called from:

- WSLC runner validation, including dry-run;
- `start_container`, before any SDK or host-side setup.

The second call protects direct callers that bypass the normal runner
validation path.

## 10. Contract and Stack Integration

The contract documentation and runtime implementation should be integrated at
different stack points.

### 10.1 Contract description

The v0.9 exact contract should describe the absolute-cwd rule before #1184
publishes it. The v0.10 development contract should carry the same description.

Because #1184 establishes the published v0.9 artifact and the stack protects
published history from later mutation, the schema/documentation portion should
be folded into #1184 or otherwise ordered before publication.

It should not be introduced by modifying the published v0.9 artifact after
#1184 has merged.

### 10.2 Runtime implementation

The runtime implementation should be based on the #1186 architecture:

- `ConfigInput` carries typed cwd compatibility;
- `convert_config_input` performs the early check;
- state-aware normalization supplies backend identity before conversion;
- the late validators remain as mutation-path protection;
- WSLC retains its translation check.

This avoids implementing the feature against the intermediate
`wire::MxcConfig` architecture that #1185 removes.

## 11. Suggested Test Coverage

### 11.1 Adapter compatibility attribution

For every exact adapter, assert the expected
`WorkingDirectoryCompatibility`:

- v0.6-v0.8 are legacy-compatible;
- v0.9-v0.10 require absolute paths.

### 11.2 Pre-construction normalization

Cover:

- omitted cwd;
- empty cwd;
- valid Windows drive path;
- Windows UNC/device paths;
- drive-relative `C:work`;
- root-relative `\work`;
- valid Unix `/work`;
- relative Unix `work`;
- `~` paths;
- whitespace-prefixed values such as ` /work`;
- abstract `process` containment on each host;
- every concrete backend;
- one-shot versus state-aware WSLC.

### 11.3 Error classification

Assert that:

- one-shot reports `policy_validation`;
- state-aware exec reports `policy_validation`;
- malformed command or envelope errors remain `malformed_request`;
- the cwd message is emitted once.

### 11.4 Programmatic mutation

Construct a valid request, then assign a relative cwd through:

- `SandboxRequest::set_working_directory`;
- any direct internal request mutation supported by tests.

Assert that the late safety check still rejects it.

### 11.5 WSLC translation

Retain backend tests proving:

- drive-rooted paths translate correctly;
- UNC, Unix, relative, and drive-relative paths are rejected;
- rejection occurs before SDK initialization;
- direct `start_container` callers cannot bypass the check.

## 12. Final Recommendation

Implement the absolute-cwd policy at the private normalization boundary created
by #1185 and hardened by #1186:

```text
exact contract
  -> exact adapter
  -> ConfigInput
  -> resolve concrete containment
  -> validate cwd compatibility and target path style
  -> construct ExecutionRequest
```

Use typed compatibility rather than version parsing, pass an explicit
one-shot/exec scope, preserve `policy_validation`, and retain the late validator
until mutable SDK paths are made fallible.

Keep WSLC host-to-container translation in the backend because it is a
backend-capability check rather than an exact-contract or common path-shape
rule.
