# Rust V1.Dev MXC request JSON API and policy preparation

> **Audience:** MXC consumers

Public entrypoint: `mxc_sdk::v1::dev`. Execution methods pass complete MXC
request JSON unchanged to the in-process engine. The JSON supplies the
contract `version`, `phase`, and container ID where applicable. MXC rejects
unregistered versions, unknown fields, and malformed JSON.

`JsonOptions` contains only `experimental: bool`, which authorizes experimental
backends independently of the JSON version. It supports struct literals such
as `JsonOptions { experimental: false }` and lifetime-free `Vec<JsonOptions>`
storage. `PtyJsonOptions` carries
`size: MxcPtySize` (24 rows by 80 columns by default).
Result and process types belong to `mxc_sdk::v1`.

## Separate policy preparation

On native Windows ProcessContainer, a creation refusal can carry structured
policy failures when the OS supports reporting them. `Error.message`,
`Display`, and warnings do not contain the specific policy failures. Use
`PolicyFailures::from_error(&error)` to copy the data from `Error.details`.
The original native operation and status remain authoritative.
Policy refusals retain high-level IT-managed-policy guidance.

Strict creation returns observations from that attempt only. Use
`prior.merged_with(&current)` to create an owned, bounded history
without changing either input. It preserves order and deduplicates identical
whole batches, including duplicates within each input; it does not combine or
rewrite individual details. A merge exceeding the storage limits fails without
truncating data. These observations do not enumerate the complete
administrative policy.

`prepare_policy_json` proposes supported restrictive edits against a freshly
supplied request. It never calls `CreateProcessSecurityEnvironment`, starts a
trace, or executes a workload. It may query host support and use bounded
filesystem probes in the current creator's context. Unsupported actions and
unsafe changes fail explicitly.

Preparation accepts create-and-run requests for every backend and OS. With
empty observations it returns the request unchanged with no changes.
Observations are specific to the backend that reported them; native Windows
ProcessContainer is currently the only backend that reports and applies them.
Non-empty observations for any other backend fail with
`UnsupportedContainment` rather than being ignored.

```rust
pub fn prepare_policy_json(
    json: &str,
    failures: &PolicyFailures,
    options: PolicyPreparationOptions,
) -> Result<PreparedPolicyRequest, Error>;
```

These types are non-exhaustive:

```rust
pub struct PolicyPreparationOptions {
    pub experimental: bool,
}
pub struct PreparedPolicyRequest {
    pub request_json: String,
    pub changes: Vec<PolicyChange>,
}
pub struct PolicyChange {
    pub operation: PolicyChangeOperation,
    pub path: String,
    pub before: serde_json::Value,
    pub after: serde_json::Value,
}
pub enum PolicyChangeOperation { Add, Remove, Replace }
```

Construct `PolicyPreparationOptions` with `Default` and set `experimental`
when needed. It authorizes a backend independently of the JSON contract;
it cannot change the declared `version` or authorize unsupported policy.

The candidate preserves the original contract version, container metadata,
unrelated settings and optional-field presence. Formatting and property order
can change. Only required authoring edits are projected; arrays may be reported
as a single replacement. If restrictions would change the inferred working
directory, preparation adds `process.cwd` to retain the original directory.
Capture restrictions use `learningMode` and `captureDenials`, not reserved
entries in `processContainer.capabilities`. MXC reparses the candidate and
checks that it reproduces the prospective PSEC and effective policy.

Preparation returns this JSON shape through `PreparedPolicyRequest::to_json`:

```json
{
  "requestJson": "{\"version\":\"1.0.0\",\"process\":{\"commandLine\":\"cmd.exe /c exit 0\"},\"processContainer\":{\"capabilities\":[]}}",
  "changes": [
    { "operation": "replace", "path": "/processContainer/capabilities", "before": ["registryRead"], "after": [] }
  ]
}
```

Every change requires both `before` and `after`. `path` is a JSON Pointer:
`~0` escapes `~`, `~1` escapes `/`, and the empty pointer identifies the root.
`Add.before = null` means the original location was absent;
`Remove.after = null` means the candidate location is absent. For `Replace`,
null is an actual JSON null value, not an omitted field.

`PreparedPolicyRequest::to_json` and `from_json` validate bounded storage data;
restoring a result does not establish approval or validate creation.
Inspect, accept, edit or reject the proposed JSON, then submit the chosen
request through ordinary strict `run_json` or `spawn_json`. Each creation call
makes one native creation attempt and executes only the supplied request. MXC
keeps no observations between calls. Preparation
and caller acceptance are not OS approval: Windows evaluates the current
creator's policy on every creation.

Observations may be reused with changed requests or creators. Preparation
derives each candidate from that call's original request, including current
proxy endpoints, certificate grants and capture settings. Unknown or incomplete
observations never authorize guessed edits. Ordinary preparation errors do not
echo the request or specific observation values; inspect structured details
when supplied.

`PolicyFailures`, `PolicyFailureResult` and `PolicyFailureDetail` are
non-exhaustive, so struct literals are unavailable outside the crate; use
`from_json` or `from_error` to obtain values. `PolicyFailures` provides:

```rust
impl PolicyFailures {
    pub fn from_error(error: &Error) -> Result<Option<Self>, Error>;
    pub fn merged_with(&self, newer: &Self) -> Result<Self, Error>;
    pub fn to_json(&self) -> Result<String, Error>;
    pub fn from_json(json: &str) -> Result<Self, Error>;
}
```

Its `format_version` identifies observation JSON, independently of each native
result's `version` and `minimum_reader_version` and the MXC request JSON's
`version`. The supported values are `PolicyFailures::FORMAT_VERSION`,
`PolicyFailureResult::VERSION` and `PolicyFailureResult::MINIMUM_READER_VERSION`.
`results` contains `PolicyFailureResult` values with
numeric `outcome` and `details: Vec<PolicyFailureDetail>`. Native numeric
discriminators and flags retain unknown values. `requested_value` and
`required_value` are `u64`, stored as decimal strings in JSON. Optional
`resource: Option<String>` contains the native resource text without a
terminator; an empty string remains distinct from absence. When a native
resource is not valid UTF-16, such as one containing an unpaired surrogate,
the text is omitted, `FLAG_RESOURCE_UNAVAILABLE` is set and
`FLAG_RESOURCE_COMPLETE` is cleared. That detail never authorizes a repair.
JSON readers reject unpaired surrogates, treat `null` as absent and omit absent fields when
serializing.

Use associated constants for known values, for example
`result.outcome == PolicyFailureResult::OUTCOME_BLOCKED` or
`detail.failure_reason == PolicyFailureDetail::REASON_CAPABILITY_NOT_ALLOWED`.
The fields remain `u32` or `u64`, not closed enums; unknown values survive
inspection and storage. These names do not establish that replay is safe.

`PolicyFailures::NATIVE_CODE_POLICY_BLOCKED` is the `&str` `"0x800704EC"` for
comparison with `Error.native_code.as_deref()`. It represents
`HRESULT_FROM_WIN32(ERROR_ACCESS_DISABLED_BY_POLICY)`. The caller example
also checks the native operation, structured outcome, progress, and stop limits;
this status alone does not establish that another creation call is safe.

| Type and constant prefix | Known suffixes and values |
|---|---|
| `PolicyFailures::` (`u32`) | `FORMAT_VERSION = 1` |
| `PolicyFailureResult::` (`u32`) | `VERSION = 1`, `MINIMUM_READER_VERSION = 1` |
| `PolicyFailureResult::OUTCOME_` (`u32`) | `UNKNOWN = 0`, `BLOCKED = 1`, `EVALUATION_FAILED = 2` |
| `PolicyFailureDetail::CLASS_` (`u32`) | `NONE = 0`, `NETWORK = 1`, `FILESYSTEM = 2`, `ENFORCEMENT_MODE = 3` |
| `PolicyFailureDetail::REASON_` (`u32`) | `NONE = 0`, `CAPABILITY_NOT_ALLOWED = 1`, `ACCESS_EXCEEDS_CEILING = 2`, `DENY_REQUIRED = 3`, `REQUEST_PATH_LIMIT = 4` |
| `PolicyFailureDetail::ACTION_` (`u32`) | `NONE = 0`, `REMOVE_CAPABILITY = 1`, `RESTRICT_FILESYSTEM_ACCESS = 2`, `REDUCE_PATH_COUNT = 3` |
| `PolicyFailureDetail::RESOURCE_KIND_` (`u32`) | `NONE = 0`, `PATH = 1`, `CAPABILITY = 2` |
| `PolicyFailureDetail::VALUE_KIND_` (`u32`) | `NONE = 0`, `ACCESS = 1`, `PATH_COUNT = 2` |
| `PolicyFailureDetail::ACCESS_` (`u64`) | `NONE = 0`, `READ_ONLY = 1`, `READ_WRITE = 2`; for requested/required values when `value_kind` is `VALUE_KIND_ACCESS` |
| `PolicyFailureDetail::FLAG_` (`u32`) | `NONE = 0`, `HAS_ACTIONABLE_DETAILS = 1`, `RESOURCE_COMPLETE = 2`, `RESOURCE_UNAVAILABLE = 4`; combine or inspect as a bitmask |

Store and prepare only the extracted observations, not the whole error
extension:

```text
Error.details: { policyFailures: F, companion diagnostics... }
Observations file: F = { formatVersion: FORMAT_VERSION, results: [...] }
prepare_policy_json(&request_json, &F, options)
```

Storage helpers do not retain companion diagnostics or application retry
budgets. Persist stopping decisions separately when they must survive a restart.
Successfully parsing stored observations does not establish that preparation
can safely use them.

Preparation request input is bounded to 8 MiB of UTF-8. Its complete result is
bounded to 32 MiB and 4,096 changes. A stored candidate request can exceed
8 MiB when the complete result fits the result limit. A result contains every
change or none; no partial candidate or truncated report is returned.

Observation input is bounded to 4 MiB, 64 batches, 1,024 details and 262,144
resource accounting units, with 64 details and 32,768 units per native batch.
Each resource counts its length plus one. `PolicyFailures::to_json`,
`from_json`, and `merged_with` allow one final native batch beyond the
preparation input limits:

| Observation limit | Preparation input | `to_json`, `from_json`, `merged_with` |
|---|---:|---:|
| UTF-8 bytes | 4 MiB | 4.5 MiB |
| Results | 64 | 65 |
| Total details | 1,024 | 1,088 |
| Total resource accounting units | 262,144 | 294,912 |

A stored result that uses the extra batch cannot be prepared unchanged.
`Error.details.policyFeedbackError` is an object with string `code`
and `reason` fields. Current codes are `unsafeReplay` and
`feedbackLimitExceeded`. Stop automatic retries on its presence, including
unknown codes; do not match diagnostic text.
If fresh diagnostics are unavailable, the error can carry
`policyResultUnavailable`. Retain earlier observations in caller storage;
strict creation does not receive or return that history. Repeated observations
or an unchanged candidate are not progress.

The [Rust caller example](../../../../src/mxc-sdk/examples/policy_feedback.rs)
uses an application-owned eight-creation-call budget, merges owned observations,
preserves the original request JSON, and stores observations even on terminal
failure. It writes a prepared candidate separately from the input and requires
an exact caller-reviewed candidate snapshot before accepting changes. Keep
stopping decisions and budgets separately when they must survive application
restarts. Run it from `src` with:

```powershell
cargo run -p mxc-sdk --example policy_feedback -- config.json policy-failures.json candidate.json
# Inspect candidate.json, then save an approved snapshot as approved-candidate.json.
cargo run -p mxc-sdk --example policy_feedback -- config.json policy-failures.json candidate.json approved-candidate.json
```

```rust
use mxc_sdk::v1::{
    dev::{self, JsonOptions, PolicyFailures, PreparedPolicyRequest},
    Error, ExecutionResult,
};

fn execute_approved(
    request_json: &str,
    failures: &PolicyFailures,
    accept: impl FnOnce(&PreparedPolicyRequest) -> bool,
) -> Result<Option<ExecutionResult>, Error> {
    let prepared = dev::prepare_policy_json(request_json, failures, Default::default())?;
    if !accept(&prepared) {
        return Ok(None);
    }
    dev::run_json(&prepared.request_json, JsonOptions { experimental: false }).map(Some)
}
```

`run_json` and `run_in_container_json` return byte-preserving
`ExecutionResult` values; a nonzero workload exit or timeout is an outcome,
not an API error. Pipe and PTY spawns return owned `MxcProcess` and
`MxcPtyProcess` handles. Existing-container execution does not deprovision
the caller-owned container. The phase-specific lifecycle and validation
methods require the matching `phase` in the JSON before dispatch; validation
uses native dry-run behavior. They return the complete native response
envelope as a `String`, including backend-specific metadata.

```rust
pub fn run_json(json: &str, options: JsonOptions) -> Result<ExecutionResult, Error>;
pub fn spawn_json(json: &str, options: JsonOptions) -> Result<MxcProcess, Error>;
pub fn spawn_with_pty_json(json: &str, options: PtyJsonOptions)
    -> Result<MxcPtyProcess, Error>;

pub fn run_in_container_json(json: &str, options: JsonOptions)
    -> Result<ExecutionResult, Error>;
pub fn spawn_in_container_json(json: &str, options: JsonOptions) -> Result<MxcProcess, Error>;
pub fn spawn_in_container_with_pty_json(json: &str, options: PtyJsonOptions)
    -> Result<MxcPtyProcess, Error>;

pub fn provision_container_json(json: &str, options: JsonOptions) -> Result<String, Error>;
pub fn start_container_json(json: &str, options: JsonOptions) -> Result<String, Error>;
pub fn stop_container_json(json: &str, options: JsonOptions) -> Result<String, Error>;
pub fn deprovision_container_json(json: &str, options: JsonOptions) -> Result<String, Error>;
pub fn validate_provision_json(json: &str, options: JsonOptions) -> Result<String, Error>;
pub fn validate_start_json(json: &str, options: JsonOptions) -> Result<String, Error>;
pub fn validate_stop_json(json: &str, options: JsonOptions) -> Result<String, Error>;
pub fn validate_deprovision_json(json: &str, options: JsonOptions) -> Result<String, Error>;
pub fn validate_process_json(json: &str, options: JsonOptions) -> Result<String, Error>;
```

`run_json` uses pipe-backed execution or backend-owned capture. MicroVM supports
captured and live stdout/stderr and the JSON lifecycle functions above, but
not writable stdin or PTY. It requires Windows x64, the `microvm` Cargo feature,
experimental authorization, and the signed NVX bundle. Without platform/build
support, `run_json` returns `BackendUnavailable`, `spawn_json` returns
`UnsupportedContainment`, and lifecycle functions return `UnsupportedPhase`.
Missing runtime prerequisites on a supported build return `BackendUnavailable`.
See the [MicroVM guide](https://github.com/microsoft/mxc/blob/main/docs/backends/nvx/nvx.md)
for the 64 MiB capture limit, caller-owned streams, and sensitive
`Error.details.nvxRecovery` information when provision succeeds but cleanup fails.

Pipe and PTY spawns and existing-container capture require the selected
backend's corresponding I/O and lifecycle support. Unsupported modes fail
rather than switching to another I/O mode.
