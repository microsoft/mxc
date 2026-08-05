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
