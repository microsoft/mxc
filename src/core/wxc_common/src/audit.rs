// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Structured **local** diagnostic audit records.
//!
//! These are *not* ETW events. Each record is serialised to a single JSON line
//! and written through [`Logger::log_audit_event`](crate::logger::Logger::log_audit_event),
//! which forwards it to the auxiliary diagnostic sinks only — the `--log-file`
//! sink and the `MXC_DIAG_CONSOLE` named pipe. It deliberately never reaches the
//! primary console/buffer sink, which is the SDK caller's captured output.
//!
//! # Format
//!
//! One record = one line = one JSON object:
//!
//! ```text
//! {"event":"mxc.ProcessExited","backend":"processcontainer","identity":"sandbox-a3f1c8e40029bd17","pid":1234,"exit_code":0}
//! ```
//!
//! Invariants, all enforced by this module:
//!
//! 1. `"event"` is always the first key, so a consumer can classify a line with a
//!    prefix match before parsing it.
//! 2. Field order is the builder's call order — deterministic per call site.
//! 3. Values are strings, integers, or booleans only. No nested objects, no
//!    arrays: a set-valued field is emitted as a comma-joined bounded string plus
//!    an explicit `_count` companion.
//! 4. String values are escaped by `serde_json`, so an embedded quote, backslash,
//!    or newline can never break the one-record-per-line invariant.
//! 5. Event names come from the closed [`AuditEventName`] enum — a typo is a
//!    compile error, not a silently unmatched record.
//!
//! # Content rules
//!
//! No free-form text. Reasons, statuses, and methods are bounded enums; error
//! detail is reduced to a numeric code. **No config values, no filesystem paths,
//! no command lines, and no raw UPNs** — a diagnostic log file is routinely
//! attached to a bug report. Config field *paths* are permitted (they are bounded
//! and already public in the schema); field *values* are not.
//!
//! Caller-supplied identifiers (e.g. `containerId`, which becomes the
//! AppContainer profile name and therefore the sandbox identity) are *config
//! values*. Pass them through [`sanitize_identity`] before they reach a record.

/// Closed set of audit record names. The `mxc.` prefix namespaces the record/// against unrelated lines sharing the same sink.
///
/// The name is the stability anchor for a record's field set: if a record has to
/// change incompatibly, mint a new variant rather than redefining an existing
/// one.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuditEventName {
    /// A `process_container` sandboxed process exited on its own.
    ProcessExited,
    /// A sandboxed process exceeded `scriptTimeout` and was force-terminated.
    ProcessTimedOut,
    /// A kill/terminate call failed. Emitted only on failure, so a healthy run
    /// produces none.
    ProcessKillFailed,
    /// The preferred isolation tier was not selected.
    EnforcementDegraded,
    /// The canonical hash of the effective policy at launch.
    PolicyHash,
    /// Network policy was installed (or failed to install) for a sandbox.
    NetworkPolicyApplied,
    /// Per-run sandbox resources were released.
    SandboxTornDown,
    /// A request was rejected before (or during) validation.
    ConfigRejected,
    /// The sandbox identity join key, emitted once per lifecycle.
    SandboxIdentity,
}

impl AuditEventName {
    /// Wire name written into the `event` field.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::ProcessExited => "mxc.ProcessExited",
            Self::ProcessTimedOut => "mxc.ProcessTimedOut",
            Self::ProcessKillFailed => "mxc.ProcessKillFailed",
            Self::EnforcementDegraded => "mxc.EnforcementDegraded",
            Self::PolicyHash => "mxc.PolicyHash",
            Self::NetworkPolicyApplied => "mxc.NetworkPolicyApplied",
            Self::SandboxTornDown => "mxc.SandboxTornDown",
            Self::ConfigRejected => "mxc.ConfigRejected",
            Self::SandboxIdentity => "mxc.SandboxIdentity",
        }
    }

    /// Fields the OpenShell requirements mandate for this record.
    ///
    /// This table *is* the M-ETW requirement set, encoded so it can be checked
    /// rather than trusted:
    ///
    /// * M-ETW-1 — `ProcessExited (identity, processId, exitCode)`,
    ///   `ProcessTimedOut (identity, processId, timeoutMs)`,
    ///   `ProcessKillFailed (identity, processId, error)`.
    /// * M-ETW-2 — `identity, tier, needsDaclAugmentation, degradationReasons[],
    ///   effectiveEnforcementLevel`.
    /// * M-ETW-3 — a stable `policyHash` on the policy event.
    /// * M-ETW-4 — `identity, enforcementMode, defaultPolicy, proxyPort`.
    /// * M-ETW-5 — `identity, status`, and what was released.
    /// * M-ETW-7 — correlation id (identity is not available on a rejection),
    ///   `rejectedReason`, and the offending field.
    ///
    /// Names here are the MXC-native `lower_snake_case` spellings of those
    /// fields. Only *required* fields are listed; a record may carry more.
    ///
    /// [`AuditEvent::missing_required_fields`] checks a built record against
    /// this list, and [`crate::logger::Logger::log_audit_event`] asserts it in
    /// debug builds, so dropping a mandated field from any emission site fails
    /// that site's own tests.
    pub fn required_fields(self) -> &'static [&'static str] {
        match self {
            // `error` (M-ETW-1) is carried as a bounded numeric `error_code`;
            // the record must never hold free-form error prose.
            Self::ProcessKillFailed => &["identity", "pid", "error_code"],
            Self::ProcessExited => &["identity", "pid", "exit_code"],
            Self::ProcessTimedOut => &["identity", "pid", "timeout_ms"],
            Self::EnforcementDegraded => &[
                "identity",
                "tier",
                "needs_dacl_augmentation",
                "degradation_reasons",
                "effective_enforcement_level",
            ],
            Self::PolicyHash => &["policy_hash"],
            Self::NetworkPolicyApplied => &[
                "identity",
                "enforcement_mode",
                "default_policy",
                "proxy_port",
            ],
            Self::SandboxTornDown => &["identity", "status"],
            // A rejected config never named a sandbox, so M-ETW-7's
            // "identity if assigned" degrades to the correlation id.
            // `offending_field` is deliberately absent: the requirement asks
            // for "the offending field(s)", but a payload that is not JSON at
            // all has no field to name, and inventing one would be worse than
            // omitting it.
            Self::ConfigRejected => &["correlation_id", "reason"],
            Self::SandboxIdentity => &["identity"],
        }
    }
}

impl std::fmt::Display for AuditEventName {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Which OS primitive was used for a kill attempt. Determined by the call site,
/// never inferred from an error.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KillMethod {
    /// `TerminateJobObject` — tree-kill via the job the child was assigned to.
    TerminateJobObject,
    /// `TerminateProcess` — root-only fallback when no job is available.
    TerminateProcess,
}

impl KillMethod {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::TerminateJobObject => "terminate_job_object",
            Self::TerminateProcess => "terminate_process",
        }
    }
}

/// Outcome of a teardown pass.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TeardownStatus {
    /// Everything that was supposed to be released was released.
    Success,
    /// At least one release step reported a failure.
    Failure,
    /// Release was deliberately not attempted (e.g. `preserve_policy`, or a
    /// cleanup path that is not implemented yet).
    Skipped,
}

impl TeardownStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Success => "success",
            Self::Failure => "failure",
            Self::Skipped => "skipped",
        }
    }
}

/// Why a teardown reported [`TeardownStatus::Skipped`]. Bounded so the record
/// never carries prose.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TeardownSkipReason {
    /// `lifecycle.preservePolicy` asked for the policy to outlive the run.
    PreservePolicy,
    /// The BaseContainer per-sandbox cleanup path is a documented no-op stub
    /// (child-process tracking is not implemented). Reporting this honestly is
    /// preferable to a green record that claims a cleanup that did not happen.
    CleanupNotImplemented,
}

impl TeardownSkipReason {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::PreservePolicy => "preserve_policy",
            Self::CleanupNotImplemented => "cleanup_not_implemented",
        }
    }
}

/// Generic success/failure status for a single operation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OperationStatus {
    Success,
    Failure,
}

impl OperationStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Success => "success",
            Self::Failure => "failure",
        }
    }
}

/// Closed vocabulary for the effective process-container enforcement level.
///
/// This is derived from the selected isolation tier and whether host-DACL
/// augmentation was required. It describes the enforcement mechanism MXC
/// selected; it does not claim any additional OS telemetry state.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EffectiveEnforcementLevel {
    BaseContainer,
    BaseContainerDaclAugmented,
    AppContainerBfs,
    AppContainerBfsDaclAugmented,
    AppContainerDacl,
}

impl EffectiveEnforcementLevel {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::BaseContainer => "base-container",
            Self::BaseContainerDaclAugmented => "base-container-dacl-augmented",
            Self::AppContainerBfs => "appcontainer-bfs",
            Self::AppContainerBfsDaclAugmented => "appcontainer-bfs-dacl-augmented",
            Self::AppContainerDacl => "appcontainer-dacl",
        }
    }
}

/// Closed set of reasons a request was rejected. Each variant corresponds to a
/// distinct existing rejection path — none is invented, and none is derived by
/// pattern-matching an error message.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RejectionReason {
    /// The input was not valid JSON (or not valid base64-wrapped JSON).
    MalformedJson,
    /// The input parsed as JSON but violated the config schema.
    SchemaViolation,
    /// Neither the policy nor the CLI supplied a command line.
    MissingCommand,
    /// A field is valid in the schema but unsupported by the resolved backend.
    UnsupportedFieldForBackend,
    /// The CLI command override could not be applied.
    InvalidCommandOverride,
    /// A sandbox id or other identifier had the wrong shape.
    IdentityShapeInvalid,
    /// The requested containment backend is not supported here.
    UnsupportedContainment,
    /// The requested state-aware phase is not supported by the backend.
    UnsupportedPhase,
    /// A runner could not be resolved for the request on this host.
    RunnerUnavailable,
}

impl RejectionReason {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::MalformedJson => "malformed_json",
            Self::SchemaViolation => "schema_violation",
            Self::MissingCommand => "missing_command",
            Self::UnsupportedFieldForBackend => "unsupported_field_for_backend",
            Self::InvalidCommandOverride => "invalid_command_override",
            Self::IdentityShapeInvalid => "identity_shape_invalid",
            Self::UnsupportedContainment => "unsupported_containment",
            Self::UnsupportedPhase => "unsupported_phase",
            Self::RunnerUnavailable => "runner_unavailable",
        }
    }
}

/// A single audit record under construction.
///
/// Build with [`AuditEvent::new`] and the typed `str`/`u64`/`i64`/`bool`
/// setters, then hand it to
/// [`Logger::log_audit_event`](crate::logger::Logger::log_audit_event).
///
/// ```
/// use wxc_common::audit::{AuditEvent, AuditEventName};
///
/// let line = AuditEvent::new(AuditEventName::ProcessExited)
///     .str("backend", "processcontainer")
///     .u64("pid", 1234)
///     .i64("exit_code", 0)
///     .to_json_line();
/// assert!(line.starts_with(r#"{"event":"mxc.ProcessExited","backend":"processcontainer""#));
/// ```
#[derive(Debug, Clone)]
pub struct AuditEvent {
    name: AuditEventName,
    /// Pre-rendered `"key":value` fragments in declaration order. Rendering
    /// eagerly keeps the struct free of an enum-per-value and makes the escaping
    /// rule impossible to bypass.
    fields: Vec<String>,
}

impl AuditEvent {
    /// Start a record with the given closed event name.
    pub fn new(name: AuditEventName) -> Self {
        Self {
            name,
            fields: Vec::new(),
        }
    }

    /// Append a string field. The value is JSON-escaped, so it can never break
    /// the one-record-per-line invariant.
    ///
    /// Callers are responsible for the *content* rule: bounded vocabularies,
    /// identifiers, and config field paths only — never a config value, a
    /// filesystem path, a command line, or a raw UPN.
    pub fn str(mut self, key: &str, value: &str) -> Self {
        self.push_field(key, &escape_json_string(value));
        self
    }

    /// Append a string field only when `value` is non-empty. Keeps records
    /// narrow when a field is genuinely inapplicable (e.g. `phase` for a
    /// one-shot run) instead of emitting a meaningless empty string.
    pub fn str_opt(self, key: &str, value: &str) -> Self {
        if value.is_empty() {
            self
        } else {
            self.str(key, value)
        }
    }

    /// Append an unsigned integer field.
    pub fn u64(mut self, key: &str, value: u64) -> Self {
        self.push_field(key, &value.to_string());
        self
    }

    /// Append a signed integer field.
    pub fn i64(mut self, key: &str, value: i64) -> Self {
        self.push_field(key, &value.to_string());
        self
    }

    /// Append a boolean field.
    pub fn bool(mut self, key: &str, value: bool) -> Self {
        self.push_field(key, if value { "true" } else { "false" });
        self
    }

    /// Render the record as one JSON object on a single line (no trailing
    /// newline — the sink adds it).
    pub fn to_json_line(&self) -> String {
        // 32 bytes covers `{"event":"…"}` for every current name; the fields add
        // the rest. One allocation for the common case.
        let mut out =
            String::with_capacity(32 + self.fields.iter().map(|f| f.len() + 1).sum::<usize>());
        out.push_str("{\"event\":\"");
        // Every `AuditEventName` is a compile-time `mxc.<PascalCase>` literal
        // with nothing to escape, asserted by `event_names_need_no_escaping`.
        out.push_str(self.name.as_str());
        out.push('"');
        for field in &self.fields {
            out.push(',');
            out.push_str(field);
        }
        out.push('}');
        out
    }

    /// The record's event name.
    pub fn name(&self) -> AuditEventName {
        self.name
    }

    /// Mandated fields (see [`AuditEventName::required_fields`]) that this
    /// record does not carry.
    ///
    /// Returns an empty vector for a conformant record. Used by the debug-build
    /// assertion in [`crate::logger::Logger::log_audit_event`], so every
    /// emission site is checked by whatever test already exercises it.
    pub fn missing_required_fields(&self) -> Vec<&'static str> {
        self.name
            .required_fields()
            .iter()
            .copied()
            .filter(|key| !self.has_field(key))
            .collect()
    }

    /// Whether a field with this exact key was appended.
    ///
    /// Fields are stored pre-rendered as `"key":value`, so the key is matched
    /// against that prefix rather than re-parsing the JSON.
    fn has_field(&self, key: &str) -> bool {
        let prefix = format!("\"{key}\":");
        self.fields.iter().any(|f| f.starts_with(&prefix))
    }

    fn push_field(&mut self, key: &str, rendered_value: &str) {
        debug_assert!(
            is_bare_json_key(key),
            "audit field keys must be lower_snake_case ASCII so they need no escaping: {key:?}"
        );
        let mut field = String::with_capacity(key.len() + rendered_value.len() + 4);
        field.push('"');
        field.push_str(key);
        field.push_str("\":");
        field.push_str(rendered_value);
        self.fields.push(field);
    }
}

/// Whether `key` is a bare `lower_snake_case` ASCII identifier, i.e. contains
/// nothing JSON would need to escape.
///
/// Every key in this codebase is a call-site literal, so this holds by
/// construction; the check exists so a future non-literal key fails loudly in a
/// debug build instead of silently producing malformed JSON.
fn is_bare_json_key(key: &str) -> bool {
    !key.is_empty()
        && key
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_')
}

/// Maximum length of a sanitized identity. Long enough for the MXC-minted
/// shapes (`sandbox-<16 hex>` = 24 chars, `iso:`/`wsb:` state-aware ids),
/// short enough that a caller cannot smuggle a payload through the field.
const MAX_IDENTITY_LEN: usize = 64;

/// Placeholder written when a caller-supplied identity is not an opaque token.
pub const REDACTED_IDENTITY: &str = "redacted";

/// Literal identity written by `AppContainerRunner`/`BaseContainerRunner` when
/// the caller left `containerId` empty. Not caller-controlled, so it is always
/// safe to log.
const DEFAULT_CLI_IDENTITY: &str = "CLI";

/// Length of the hex portion of a `sandbox-<hex>` identity minted by
/// `sandbox_tracking::generate_sandbox_identity` (8 bytes of CSPRNG
/// randomness rendered as lowercase hex).
const SANDBOX_ID_HEX_LEN: usize = 16;

/// The current process's correlation id, minted on first use.
///
/// `mxc.ConfigRejected` is the one record that cannot carry a sandbox identity:
/// the config was refused, so no sandbox was ever named. M-ETW-7 therefore asks
/// for a *correlation id* instead, and this supplies it — a value that is
/// constant for one executor invocation and distinct across invocations.
///
/// That matters because the diagnostic sinks are shared: several concurrent
/// sandboxes can write to the same `--log-file` or diagnostic-console pipe, so
/// without it a consumer cannot tell which rejections belong to which
/// invocation.
///
/// Deliberately *not* stamped on the other records — those already carry a
/// sandbox `identity`, which is the stronger join key.
pub fn process_correlation_id() -> &'static str {
    static CORRELATION_ID: std::sync::OnceLock<String> = std::sync::OnceLock::new();
    CORRELATION_ID.get_or_init(crate::id::mint_random_token)
}

/// Render a sandbox identity so it is safe to write to a diagnostic log file.
///
/// **Sandbox identities are not always MXC-minted.** On the Windows
/// ProcessContainer path with `destroy_on_exit = false`, the identity is the
/// AppContainer profile name, which is the caller-supplied `containerId`
/// straight out of the config. That makes it a *config value*, and config values
/// must never reach a record (see the module-level content rules) — a caller can
/// otherwise put a UPN, a path, a ticket number, or any other arbitrary string
/// into the audit stream. Character and length checks alone cannot distinguish
/// a caller-chosen opaque-looking string (e.g. `alice`, `ticket-1234`) from a
/// value MXC actually minted, so this function does not attempt to recognise
/// "opaque-looking" input at all.
///
/// Instead it allows through only the closed set of shapes MXC itself
/// produces, unconditionally redacting every caller-supplied `containerId`:
///
/// * [`DEFAULT_CLI_IDENTITY`] — the literal default used when `containerId`
///   is empty;
/// * `sandbox-<16 lowercase hex>` — minted by
///   `sandbox_tracking::generate_sandbox_identity` for the BaseContainer
///   backend;
/// * `iso:<token>` / `wsb:<token>` — state-aware sandbox ids minted by the
///   IsolationSession / Windows Sandbox backends, bounded by
///   [`MAX_IDENTITY_LEN`] and restricted to opaque token characters.
///
/// Anything else becomes [`REDACTED_IDENTITY`]. That loses the join key for
/// callers who chose their own `containerId`, which is the correct trade: a
/// record with no join key is recoverable, a leaked identifier is not.
pub fn sanitize_identity(identity: &str) -> &str {
    if identity.is_empty() {
        return identity;
    }
    if identity == DEFAULT_CLI_IDENTITY {
        return identity;
    }
    if let Some(hex) = identity.strip_prefix("sandbox-") {
        if hex.len() == SANDBOX_ID_HEX_LEN
            && hex
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
        {
            return identity;
        }
        return REDACTED_IDENTITY;
    }
    // Length cap applies before shape-checking the `iso:`/`wsb:` prefix. Without
    // this bound a caller who chose an overlong `containerId` could still
    // smuggle a payload through the record by tagging it with a recognised
    // prefix.
    if identity.len() > MAX_IDENTITY_LEN {
        return REDACTED_IDENTITY;
    }
    let mxc_opaque = identity
        .split_once(':')
        .map(|(prefix, token)| {
            matches!(prefix, "iso" | "wsb")
                && !token.is_empty()
                && token
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_' || b == b'.')
        })
        .unwrap_or(false);
    if mxc_opaque {
        identity
    } else {
        REDACTED_IDENTITY
    }
}

/// Render `value` as a quoted, escaped JSON string.
///
/// `serde_json::to_string` on a `&str` is infallible (a `&str` is always valid
/// UTF-8 and the only failure mode of the `String` serializer is an I/O error,
/// which cannot occur for an in-memory buffer).
fn escape_json_string(value: &str) -> String {
    serde_json::to_string(value).expect("serializing a &str to JSON is infallible")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn event_key_is_always_first() {
        let line = AuditEvent::new(AuditEventName::SandboxIdentity)
            .str("backend", "processcontainer")
            .to_json_line();
        assert!(
            line.starts_with(r#"{"event":"mxc.SandboxIdentity","#),
            "got: {line}"
        );
    }

    #[test]
    fn fields_keep_declaration_order() {
        let line = AuditEvent::new(AuditEventName::ProcessExited)
            .str("backend", "processcontainer")
            .str("identity", "sandbox-0123456789abcdef")
            .u64("pid", 4242)
            .i64("exit_code", -1)
            .to_json_line();
        assert_eq!(
            line,
            r#"{"event":"mxc.ProcessExited","backend":"processcontainer","identity":"sandbox-0123456789abcdef","pid":4242,"exit_code":-1}"#
        );
    }

    #[test]
    fn string_values_are_escaped_so_one_record_stays_one_line() {
        let line = AuditEvent::new(AuditEventName::ConfigRejected)
            .str("offending_field", "weird\"key\nwith\\breaks")
            .to_json_line();
        assert!(!line.contains('\n'), "record spans lines: {line}");
        assert!(
            line.contains(r#""weird\"key\nwith\\breaks""#),
            "got: {line}"
        );
    }

    #[test]
    fn every_record_parses_as_json() {
        let line = AuditEvent::new(AuditEventName::SandboxTornDown)
            .str("backend", "processcontainer")
            .str("status", TeardownStatus::Failure.as_str())
            .bool("firewall_removal_ok", false)
            .u64("firewall_rules_removed", 3)
            .to_json_line();
        let parsed: serde_json::Value = serde_json::from_str(&line).expect("valid JSON");
        assert_eq!(parsed["event"], "mxc.SandboxTornDown");
        assert_eq!(parsed["status"], "failure");
        assert_eq!(parsed["firewall_removal_ok"], false);
        assert_eq!(parsed["firewall_rules_removed"], 3);
    }

    #[test]
    fn str_opt_omits_empty_values() {
        let line = AuditEvent::new(AuditEventName::ConfigRejected)
            .str_opt("phase", "")
            .str_opt("backend", "lxc")
            .to_json_line();
        assert!(!line.contains("phase"), "got: {line}");
        assert!(line.contains(r#""backend":"lxc""#), "got: {line}");
    }

    #[test]
    fn bounded_vocabularies_are_snake_case_and_distinct() {
        let names = [
            KillMethod::TerminateJobObject.as_str(),
            KillMethod::TerminateProcess.as_str(),
            TeardownStatus::Success.as_str(),
            TeardownStatus::Failure.as_str(),
            TeardownStatus::Skipped.as_str(),
            TeardownSkipReason::PreservePolicy.as_str(),
            TeardownSkipReason::CleanupNotImplemented.as_str(),
            RejectionReason::MalformedJson.as_str(),
            RejectionReason::SchemaViolation.as_str(),
            RejectionReason::MissingCommand.as_str(),
            RejectionReason::UnsupportedFieldForBackend.as_str(),
            RejectionReason::InvalidCommandOverride.as_str(),
            RejectionReason::IdentityShapeInvalid.as_str(),
            RejectionReason::UnsupportedContainment.as_str(),
            RejectionReason::UnsupportedPhase.as_str(),
            RejectionReason::RunnerUnavailable.as_str(),
        ];
        for name in names {
            assert!(
                name.chars()
                    .all(|c| c.is_ascii_lowercase() || c == '_' || c.is_ascii_digit()),
                "not snake_case: {name}"
            );
        }
    }

    #[test]
    fn effective_enforcement_levels_are_stable() {
        assert_eq!(
            EffectiveEnforcementLevel::BaseContainer.as_str(),
            "base-container"
        );
        assert_eq!(
            EffectiveEnforcementLevel::BaseContainerDaclAugmented.as_str(),
            "base-container-dacl-augmented"
        );
        assert_eq!(
            EffectiveEnforcementLevel::AppContainerBfs.as_str(),
            "appcontainer-bfs"
        );
        assert_eq!(
            EffectiveEnforcementLevel::AppContainerBfsDaclAugmented.as_str(),
            "appcontainer-bfs-dacl-augmented"
        );
        assert_eq!(
            EffectiveEnforcementLevel::AppContainerDacl.as_str(),
            "appcontainer-dacl"
        );
    }

    #[test]
    fn event_names_are_unique_and_prefixed() {
        let names = [
            AuditEventName::ProcessExited,
            AuditEventName::ProcessTimedOut,
            AuditEventName::ProcessKillFailed,
            AuditEventName::EnforcementDegraded,
            AuditEventName::PolicyHash,
            AuditEventName::NetworkPolicyApplied,
            AuditEventName::SandboxTornDown,
            AuditEventName::ConfigRejected,
            AuditEventName::SandboxIdentity,
        ];
        let mut seen = std::collections::HashSet::new();
        for name in names {
            assert!(name.as_str().starts_with("mxc."), "got: {name}");
            assert!(seen.insert(name.as_str()), "duplicate: {name}");
        }
    }

    /// `to_json_line` writes the event name without escaping it, which is only
    /// sound because every name is an ASCII `mxc.<PascalCase>` literal.
    #[test]
    fn event_names_need_no_escaping() {
        let names = [
            AuditEventName::ProcessExited,
            AuditEventName::ProcessTimedOut,
            AuditEventName::ProcessKillFailed,
            AuditEventName::EnforcementDegraded,
            AuditEventName::PolicyHash,
            AuditEventName::NetworkPolicyApplied,
            AuditEventName::SandboxTornDown,
            AuditEventName::ConfigRejected,
            AuditEventName::SandboxIdentity,
        ];
        for name in names {
            let raw = name.as_str();
            assert_eq!(
                serde_json::to_string(raw).expect("infallible"),
                format!("\"{raw}\""),
                "event name would need escaping: {raw}"
            );
        }
    }

    /// Field keys are written without escaping too, so they must all be bare
    /// snake_case. Exercised through the debug assertion in `push_field`.
    #[test]
    fn field_keys_must_be_bare_snake_case() {
        assert!(is_bare_json_key("exit_code"));
        assert!(is_bare_json_key("pid"));
        assert!(is_bare_json_key("degradation_reason_count"));
        assert!(!is_bare_json_key(""));
        assert!(!is_bare_json_key("Exit-Code"));
        assert!(!is_bare_json_key("quote\"key"));
    }

    #[test]
    fn mxc_minted_identities_pass_sanitization_unchanged() {
        for id in [
            "sandbox-a3f1c8e40029bd17",
            "iso:wxc-abcd1234",
            "wsb:deadbeef",
            "CLI",
            "",
        ] {
            assert_eq!(sanitize_identity(id), id);
        }
    }

    /// A caller-supplied `containerId` becomes the AppContainer profile name and
    /// therefore the sandbox identity. It is a config value, so it must always be
    /// redacted regardless of shape — character/length checks cannot prove a
    /// value is opaque rather than caller-chosen (e.g. `alice`, `ticket-1234`,
    /// or a standalone `wxc-`-looking token that did not come through the
    /// `iso:`/`wsb:` minting path).
    #[test]
    fn caller_supplied_identities_are_always_redacted() {
        for id in [
            "alice",
            "secret",
            "ticket-1234",
            "my.container_id-7",
            "wxc-abcd1234",
            "alice@contoso.com",
            "C:\\Users\\alice\\secret",
            "/home/alice/secret",
            "has space",
            "has\"quote",
            "has\nnewline",
            &"x".repeat(MAX_IDENTITY_LEN + 1),
        ] {
            assert_eq!(
                sanitize_identity(id),
                REDACTED_IDENTITY,
                "should have been redacted: {id:?}"
            );
        }
    }

    /// A `sandbox-` prefix alone does not grant a pass: the hex portion must be
    /// exactly [`SANDBOX_ID_HEX_LEN`] lowercase hex characters, matching
    /// `sandbox_tracking::generate_sandbox_identity`'s output shape.
    #[test]
    fn malformed_sandbox_prefixed_identities_are_redacted() {
        for id in [
            "sandbox-",
            "sandbox-abc",
            "sandbox-A3F1C8E40029BD17",
            "sandbox-a3f1c8e40029bd17extra",
            "sandbox-not-hex-at-all!!",
        ] {
            assert_eq!(
                sanitize_identity(id),
                REDACTED_IDENTITY,
                "should have been redacted: {id:?}"
            );
        }
    }

    /// The length cap applies to both accepted identity shapes, including the
    /// prefixed `iso:` / `wsb:` shape. Without the bound on the prefixed shape
    /// a caller could still smuggle a payload of arbitrary length through the
    /// record by tagging it with a recognised prefix.
    #[test]
    fn overlong_prefixed_identities_are_redacted() {
        for prefix in ["iso", "wsb"] {
            let token = "a".repeat(MAX_IDENTITY_LEN);
            let overlong = format!("{}:{}", prefix, token);
            assert!(overlong.len() > MAX_IDENTITY_LEN);
            assert_eq!(
                sanitize_identity(&overlong),
                REDACTED_IDENTITY,
                "prefixed identity beyond MAX_IDENTITY_LEN should have been redacted: {overlong:?}"
            );
        }
    }

    /// The length cap is inclusive — a prefixed identity that just fits the
    /// cap still passes through unredacted, so the tighter bound does not
    /// accidentally reject well-formed short ids.
    #[test]
    fn prefixed_identities_within_len_pass_through() {
        for prefix in ["iso", "wsb"] {
            let colon_and_prefix = prefix.len() + 1;
            let token = "a".repeat(MAX_IDENTITY_LEN - colon_and_prefix);
            let id = format!("{}:{}", prefix, token);
            assert_eq!(id.len(), MAX_IDENTITY_LEN);
            assert_eq!(sanitize_identity(&id), id);
        }
    }
}

/// Per-requirement conformance tests for the OpenShell M-ETW asks.
///
/// These live in `wxc_common` — which builds on Windows, Linux and macOS —
/// rather than in the Windows-only backend crates, so the requirement contract
/// is verified on every host the project targets. The *emission sites* are
/// checked separately by the debug assertion in
/// [`crate::logger::Logger::log_audit_event`], which runs inside whatever test
/// already drives each site.
#[cfg(test)]
mod requirement_conformance {
    use super::*;

    /// Build the record exactly as a compliant emission site would, then assert
    /// the requirement's mandated fields are all present.
    fn assert_conformant(event: &AuditEvent) {
        assert!(
            event.missing_required_fields().is_empty(),
            "{} is missing {:?}",
            event.name(),
            event.missing_required_fields(),
        );
        // A record is worthless if a consumer cannot parse it.
        let line = event.to_json_line();
        serde_json::from_str::<serde_json::Value>(&line).expect("record must be valid JSON");
    }

    /// Process outcome (M-ETW-1): "ProcessExited (identity, processId, exitCode), ProcessTimedOut
    /// (identity, processId, timeoutMs), ProcessKillFailed (identity,
    /// processId, error)".
    #[test]
    fn process_outcome_records_carry_identity_pid_and_outcome() {
        assert_conformant(
            &AuditEvent::new(AuditEventName::ProcessExited)
                .str("identity", "sandbox-0123456789abcdef")
                .u64("pid", 1234)
                .i64("exit_code", 3),
        );
        assert_conformant(
            &AuditEvent::new(AuditEventName::ProcessTimedOut)
                .str("identity", "sandbox-0123456789abcdef")
                .u64("pid", 1234)
                .u64("timeout_ms", 5000),
        );
        assert_conformant(
            &AuditEvent::new(AuditEventName::ProcessKillFailed)
                .str("identity", "sandbox-0123456789abcdef")
                .u64("pid", 1234)
                .str("kill_method", KillMethod::TerminateProcess.as_str())
                .i64("error_code", -2147024891),
        );
    }

    /// Process outcome acceptance (M-ETW-1): "a workload exiting non-zero produces ProcessExited
    /// with matching exitCode". The exit code must survive as a signed number,
    /// not a string, and must not be clamped.
    #[test]
    fn process_outcome_exit_code_round_trips_including_negative_values() {
        for code in [0i64, 3, -1, i64::from(i32::MIN)] {
            let line = AuditEvent::new(AuditEventName::ProcessExited)
                .str("identity", "CLI")
                .u64("pid", 1)
                .i64("exit_code", code)
                .to_json_line();
            let parsed: serde_json::Value = serde_json::from_str(&line).unwrap();
            assert_eq!(
                parsed["exit_code"], code,
                "exit_code {code} did not survive"
            );
        }
    }

    /// Enforcement degradation (M-ETW-2): "identity, tier, needsDaclAugmentation, degradationReasons[],
    /// effectiveEnforcementLevel".
    #[test]
    fn enforcement_degradation_carries_tier_and_reasons() {
        assert_conformant(
            &AuditEvent::new(AuditEventName::EnforcementDegraded)
                .str("identity", "CLI")
                .str("tier", "appcontainer-dacl")
                .str(
                    "effective_enforcement_level",
                    EffectiveEnforcementLevel::AppContainerDacl.as_str(),
                )
                .bool("needs_dacl_augmentation", true)
                .str("degradation_reasons", "base_container_unavailable")
                .u64("degradation_reason_count", 1),
        );
    }

    /// Enforcement degradation regression guard (M-ETW-2): `identity` was absent from the first
    /// implementation, which is the field the requirement lists first.
    #[test]
    fn enforcement_degradation_without_identity_is_non_conformant() {
        let event = AuditEvent::new(AuditEventName::EnforcementDegraded)
            .str("tier", "appcontainer-dacl")
            .str("effective_enforcement_level", "appcontainer-dacl")
            .bool("needs_dacl_augmentation", true)
            .str("degradation_reasons", "base_container_unavailable");
        assert_eq!(event.missing_required_fields(), vec!["identity"]);
    }

    /// Network policy (M-ETW-4): "identity, enforcementMode (capabilities|firewall|both),
    /// defaultPolicy (allow|block), proxyPort".
    #[test]
    fn network_policy_applied_carries_mode_policy_and_port() {
        assert_conformant(
            &AuditEvent::new(AuditEventName::NetworkPolicyApplied)
                .str("identity", "CLI")
                .str("enforcement_mode", "capabilities")
                .str("default_policy", "block")
                .u64("proxy_port", 8080)
                .str("status", OperationStatus::Success.as_str()),
        );
    }

    /// Network policy (M-ETW-4) names the accepted `enforcementMode` values explicitly, and
    /// `capabilities` is the OS-enforced (BaseContainer) case.
    #[test]
    fn network_policy_enforcement_mode_vocabulary_matches_the_requirement() {
        use crate::models::NetworkEnforcementMode;
        assert_eq!(
            NetworkEnforcementMode::Capabilities.as_str(),
            "capabilities"
        );
        assert_eq!(NetworkEnforcementMode::Firewall.as_str(), "firewall");
        assert_eq!(NetworkEnforcementMode::Both.as_str(), "both");
    }

    /// Sandbox teardown (M-ETW-5): "identity, status (success/failure), and what was released".
    /// Acceptance: "a cleanup failure is distinguishable from success".
    #[test]
    fn sandbox_teardown_distinguishes_failure_from_success() {
        assert_conformant(
            &AuditEvent::new(AuditEventName::SandboxTornDown)
                .str("identity", "CLI")
                .str("status", TeardownStatus::Success.as_str())
                .u64("firewall_rules_removed", 2)
                .bool("container_released", true),
        );
        let success = AuditEvent::new(AuditEventName::SandboxTornDown)
            .str("identity", "CLI")
            .str("status", TeardownStatus::Success.as_str())
            .to_json_line();
        let failure = AuditEvent::new(AuditEventName::SandboxTornDown)
            .str("identity", "CLI")
            .str("status", TeardownStatus::Failure.as_str())
            .to_json_line();
        assert_ne!(success, failure);
        assert_ne!(
            TeardownStatus::Success.as_str(),
            TeardownStatus::Skipped.as_str()
        );
    }

    /// Configuration rejection (M-ETW-7): "correlation id (or identity if assigned), rejectedReason /
    /// errorCode, and the offending field(s)".
    #[test]
    fn configuration_rejection_carries_correlation_id_and_reason() {
        assert_conformant(
            &AuditEvent::new(AuditEventName::ConfigRejected)
                .str("correlation_id", process_correlation_id())
                .str("backend", "processcontainer")
                .str("reason", RejectionReason::SchemaViolation.as_str())
                .str_opt("offending_field", "process.commandLine"),
        );
    }

    /// The correlation id must be stable within one invocation, or records from
    /// the same rejection could not be grouped.
    #[test]
    fn configuration_rejection_correlation_id_is_stable_within_a_process() {
        let first = process_correlation_id();
        assert_eq!(first, process_correlation_id());
        assert!(!first.is_empty());
        assert!(
            first.bytes().all(|b| b.is_ascii_hexdigit()),
            "correlation id must be an opaque hex token, got {first:?}"
        );
    }

    /// Every record name declares a requirement contract, and every field it
    /// names must be a legal JSON key (the builder debug-asserts key shape, so
    /// a contract naming an illegal key would be unsatisfiable).
    #[test]
    fn every_event_name_declares_satisfiable_required_fields() {
        for name in [
            AuditEventName::ProcessExited,
            AuditEventName::ProcessTimedOut,
            AuditEventName::ProcessKillFailed,
            AuditEventName::EnforcementDegraded,
            AuditEventName::PolicyHash,
            AuditEventName::NetworkPolicyApplied,
            AuditEventName::SandboxTornDown,
            AuditEventName::ConfigRejected,
            AuditEventName::SandboxIdentity,
        ] {
            let required = name.required_fields();
            assert!(!required.is_empty(), "{name} declares no required fields");
            for key in required {
                assert!(is_bare_json_key(key), "{name} requires illegal key {key:?}");
            }
            // Building a record with exactly the required fields must satisfy
            // the contract, i.e. the contract is self-consistent.
            let mut event = AuditEvent::new(name);
            for key in required {
                event = event.str(key, "x");
            }
            assert!(event.missing_required_fields().is_empty(), "{name}");
        }
    }
}
