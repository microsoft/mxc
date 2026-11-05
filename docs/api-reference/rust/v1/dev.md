# Rust V1.Dev exact-JSON API

> **Audience:** MXC consumers

Public entrypoint: `mxc_sdk::v1::dev`. Methods pass complete MXC request JSON
unchanged to the in-process engine. The JSON supplies the contract `version`,
`phase`, and container ID where applicable. MXC rejects unregistered versions,
unknown fields, and malformed JSON.

`JsonOptions<'a>` is non-exhaustive. Construct it with `Default` and set
`experimental` to authorize experimental backends independently of the JSON
version. Its optional `policy_failures: Option<&'a PolicyFailures>` applies
only to `run_json` and `spawn_json` creation. Other operations reject supplied
creation feedback. `PtyJsonOptions` carries
`size: MxcPtySize` (24 rows by 80 columns by default).
Result and process types belong to `mxc_sdk::v1`.

## Caller-owned creation-policy feedback

On native Windows ProcessContainer, a creation refusal can carry structured
policy failures when the OS supports reporting them. `Error.message`,
`Display`, and warnings do not contain the specific policy failures. Use
`PolicyFailures::from_error(&error)` to copy the data from `Error.details`.
The original native operation and status remain authoritative.
Policy refusals retain high-level IT-managed-policy guidance.

Pass the value through `JsonOptions.policy_failures` on a later call. MXC
applies only supported restrictive changes to a private request copy and makes
one native creation attempt. The caller owns retry limits, storage, and
stopping on repeated feedback or non-policy errors. Further refusals return
all known input observations plus the new native batch, deduplicating
identical batches. This does not enumerate the complete administrative policy.

Feedback may be reused with changed requests or creators. It is not approval:
edits are validated against the current request and Windows reevaluates
creation. Unsupported actions, unsafe edits and unsupported backends fail
explicitly. Successful calls return the ordinary result or process handle
without correction warnings or a change report.

`PolicyFailures` provides `to_json`, `from_json`, and `from_error`.
Its `format_version` identifies feedback JSON, independently of each native
result's `version` and `minimum_reader_version` and the MXC request JSON's
`version`. `results` contains `PolicyFailureResult` values with
numeric `outcome` and `details: Vec<PolicyFailureDetail>`. Native numeric
discriminators and flags retain unknown values. `requested_value` and
`required_value` are `u64`, stored as decimal strings in JSON. Optional
`resource` contains UTF-16 units without a terminator; `resource_text()`
decodes strictly without treating invalid text as a repair instruction.
JSON readers treat `resource: null` as absent and omit it when serializing;
an empty array remains distinct.

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
| `PolicyFailureResult::OUTCOME_` (`u32`) | `UNKNOWN = 0`, `BLOCKED = 1`, `EVALUATION_FAILED = 2` |
| `PolicyFailureDetail::CLASS_` (`u32`) | `NONE = 0`, `NETWORK = 1`, `FILESYSTEM = 2`, `ENFORCEMENT_MODE = 3` |
| `PolicyFailureDetail::REASON_` (`u32`) | `NONE = 0`, `CAPABILITY_NOT_ALLOWED = 1`, `ACCESS_EXCEEDS_CEILING = 2`, `DENY_REQUIRED = 3`, `REQUEST_PATH_LIMIT = 4` |
| `PolicyFailureDetail::ACTION_` (`u32`) | `NONE = 0`, `REMOVE_CAPABILITY = 1`, `RESTRICT_FILESYSTEM_ACCESS = 2`, `REDUCE_PATH_COUNT = 3` |
| `PolicyFailureDetail::RESOURCE_KIND_` (`u32`) | `NONE = 0`, `PATH = 1`, `CAPABILITY = 2` |
| `PolicyFailureDetail::VALUE_KIND_` (`u32`) | `NONE = 0`, `ACCESS = 1`, `PATH_COUNT = 2` |
| `PolicyFailureDetail::ACCESS_` (`u64`) | `NONE = 0`, `READ_ONLY = 1`, `READ_WRITE = 2`; for requested/required values when `value_kind` is `VALUE_KIND_ACCESS` |
| `PolicyFailureDetail::FLAG_` (`u32`) | `NONE = 0`, `HAS_ACTIONABLE_DETAILS = 1`, `RESOURCE_COMPLETE = 2`, `RESOURCE_UNAVAILABLE = 4`; combine or inspect as a bitmask |

Store and pass only the extracted feedback, not the whole error extension:

```text
Error.details: { policyFailures: F, companion diagnostics... }
Feedback file: F = { formatVersion: 1, results: [...] }
JsonOptions.policy_failures: the restored F
```

Storage helpers do not retain companion diagnostics or application retry
budgets. Persist stopping decisions separately when they must survive a restart.
Successfully parsing stored feedback does not establish that it can be replayed.

Input is bounded to 4 MiB, 64 batches, 1,024 details and 262,144 resource
accounting units, with 64 details and 32,768 units per native batch. Each
resource counts its length plus one. A terminal result can contain one
additional native batch and remains serializable, but cannot be reapplied
unchanged. `Error.details.policyFeedbackError` is an object with string `code`
and `reason` fields. Current codes are `unsafeReplay` and
`feedbackLimitExceeded`. Stop automatic retries on its presence, including
unknown codes; do not match diagnostic text.
If fresh diagnostics are unavailable, known input observations remain available
with `policyResultUnavailable`; unchanged feedback is not progress.

The [Rust caller example](../../../../src/mxc-sdk/examples/policy_feedback.rs)
uses an application-owned eight-call budget, replaces cumulative feedback,
preserves the original request JSON, and stores the value even on terminal
failure. Run it from `src` with:

```powershell
cargo run -p mxc-sdk --example policy_feedback -- config.json feedback.json
```

```rust
use mxc_sdk::v1::dev::{self, JsonOptions, PolicyFailures};

let stored: Option<PolicyFailures> = None;
let mut options = JsonOptions::default();
options.policy_failures = stored.as_ref();
let result = dev::run_json(&request_json, options);
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

`run_json` uses pipe-backed execution or backend-owned capture. MicroVM
provides captured output without live pipes; it requires Windows x64, a build
with the `microvm` Cargo feature, experimental authorization, and the signed
NVX bundle and host prerequisites described in the
[MicroVM guide](https://github.com/microsoft/mxc/blob/main/docs/backends/nvx/nvx.md). Missing platform or build
support returns `BackendUnavailable`.

Pipe and PTY spawns and existing-container capture require the selected
backend's corresponding I/O and lifecycle support. MicroVM does not support
these operations. Unsupported modes fail rather than switching to another
I/O mode.
