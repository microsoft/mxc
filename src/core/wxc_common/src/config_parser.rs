// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use std::{borrow::Cow, fs};

use crate::config_deserialize;
use crate::encoding::base64_decode;
use crate::error::WxcError;
use crate::logger::Logger;
use crate::models::{
    CaptureDenialsConfig, CaptureDenialsMode, ContainerPolicy, ContainmentBackend,
    ExecutionRequest, ExperimentalConfig, LifecycleConfig, LxcConfig, NetworkEnforcementMode,
    NetworkPolicy, PortMapping, SeatbeltConfig, TelemetryConfig, TestFeatureConfig, UiPolicy,
    WindowsSandboxConfig, WslcConfig,
};
use crate::mxc_error::MxcError;
use crate::network_parser::{
    directional_network_version_error, host_is_loopback, parse_network_policy,
    supports_directional_network, NetworkSections,
};
use crate::state_aware_request::{MxcRequest, ParsedStateAwareRequest, Phase};
use crate::wire;
use serde::{Deserialize, Deserializer};
use serde_json::value::RawValue;

/// Categorised error from `load_mxc_request`. The `wxc-exec` driver uses the
/// variant to choose the failure-output convention: state-aware failures
/// emit a JSON `{"error": ...}` envelope on stdout, while one-shot and
/// pre-discrimination failures keep the existing diagnostic-on-stderr path.
#[derive(Debug)]
pub enum ParseError {
    /// I/O, base64-decode, or top-level JSON parse failure — the input could
    /// not be discriminated as state-aware vs one-shot.
    Decode(WxcError),
    /// Discriminated as one-shot; conversion to `ExecutionRequest` failed.
    OneShot(WxcError),
    /// Discriminated as state-aware; conversion to `ParsedStateAwareRequest`
    /// failed. Carries an `MxcError` so the driver can emit a typed envelope.
    StateAware(MxcError),
}

#[derive(Debug, Clone, Copy)]
enum ErrorOutput {
    Primary,
    DiagnosticOnly,
}

impl ParseError {
    fn output(&self) -> ErrorOutput {
        match self {
            Self::Decode(_) | Self::OneShot(_) => ErrorOutput::Primary,
            Self::StateAware(_) => ErrorOutput::DiagnosticOnly,
        }
    }

    fn message(&self) -> String {
        match self {
            Self::Decode(error) | Self::OneShot(error) => error.to_string(),
            Self::StateAware(error) => error.to_string(),
        }
    }
}

#[derive(Deserialize)]
#[serde(expecting = "a configuration object")]
struct RequestDiscriminator<'a> {
    #[serde(borrow, default, deserialize_with = "deserialize_present_raw")]
    phase: Option<&'a RawValue>,
    #[serde(borrow, default, deserialize_with = "deserialize_present_raw")]
    experimental: Option<&'a RawValue>,
}

fn deserialize_present_raw<'de, D>(deserializer: D) -> Result<Option<&'de RawValue>, D::Error>
where
    D: Deserializer<'de>,
{
    <&RawValue>::deserialize(deserializer).map(Some)
}

// ---------- Public API ----------

/// Options for [`load_mxc_request_with_options`].
///
/// Kept as a struct (rather than additional positional arguments) so future
/// loader-tuning knobs can be threaded through without re-spinning every
/// caller.
#[derive(Debug, Clone, Copy, Default)]
pub struct LoadOptions {
    /// Treat `input` as a base64-encoded JSON blob rather than a file path.
    pub is_base64: bool,
    /// Allow `process.commandLine` to be absent or empty in the policy.
    ///
    /// The driver sets this when it has a CLI-provided command-line
    /// override to splice into `script_code` after parsing. Without it,
    /// missing/empty `commandLine` is a hard parse error in one-shot
    /// and state-aware exec requests (matching the legacy contract).
    pub allow_missing_command: bool,
}

/// A parsed request together with its validated JSON command line.
///
/// The contained request deliberately has an empty `script_code`; callers can
/// choose the effective command and apply it through [`ExecutionRequest::set_script`].
#[derive(Debug)]
pub struct ParsedRequestParts<T> {
    /// The parsed request without a command applied.
    pub request: T,
    /// The non-empty `process.commandLine` supplied by the JSON request.
    pub command_line: Option<String>,
}

impl<T> ParsedRequestParts<T> {
    fn map<U>(self, map_request: impl FnOnce(T) -> U) -> ParsedRequestParts<U> {
        ParsedRequestParts {
            request: map_request(self.request),
            command_line: self.command_line,
        }
    }
}

impl ParsedRequestParts<MxcRequest> {
    fn into_request(mut self) -> MxcRequest {
        if let Some(command) = self.command_line {
            let execution_request = match &mut self.request {
                MxcRequest::OneShot(request) => request,
                MxcRequest::StateAware(parsed) => &mut parsed.request,
            };
            execution_request.set_script(command);
        }

        self.request
    }
}

/// Loads and parses a JSON-based code execution request.
///
/// If `is_base64` is true, `input` is treated as a base64-encoded JSON string.
/// Otherwise `input` is treated as a file path.
pub fn load_request(
    input: &str,
    logger: &mut Logger,
    is_base64: bool,
) -> Result<ExecutionRequest, WxcError> {
    load_request_with_options(
        input,
        logger,
        LoadOptions {
            is_base64,
            allow_missing_command: false,
        },
    )
}

/// Options-aware variant of [`load_request`] used by drivers that may
/// override `process.commandLine` from the CLI. See [`LoadOptions`].
pub fn load_request_with_options(
    input: &str,
    logger: &mut Logger,
    opts: LoadOptions,
) -> Result<ExecutionRequest, WxcError> {
    let result = (|| {
        let json_str = decode_request_input_without_logging(input, opts.is_base64)?;

        let cfg: wire::MxcConfig = config_deserialize::from_str(&json_str)
            .map_err(|error| WxcError::ConfigParse(error.to_string()))?;
        let raw: serde_json::Value = config_deserialize::from_str(&json_str)
            .map_err(|error| WxcError::ConfigParse(error.to_string()))?;
        validate_directional_network_field_versions(&raw)?;

        let ParsedRequestParts {
            mut request,
            command_line,
        } = convert_wire_config(cfg, logger, true, opts.allow_missing_command)?;

        if let Some(command) = command_line {
            request.set_script(command);
        }

        Ok(request)
    })();
    log_one_shot_error(logger, &result);
    result
}

/// Build a request from an already-parsed wire-format config [`Value`], running
/// the same validation and wire→model mapping as [`load_request_with_options`]
/// but without a base64 (or file) round-trip. For in-process callers (e.g. the
/// `mxc` crate) that already hold the config as JSON and would otherwise pay to
/// serialise → base64 → decode → re-parse it.
///
/// [`Value`]: serde_json::Value
pub fn load_request_from_value(
    config: serde_json::Value,
    logger: &mut Logger,
    allow_missing_command: bool,
) -> Result<ExecutionRequest, WxcError> {
    let result = (|| {
        let raw = config.clone();
        let cfg: wire::MxcConfig = config_deserialize::from_value(config)
            .map_err(|error| WxcError::ConfigParse(error.to_string()))?;
        validate_directional_network_field_versions(&raw)?;

        let ParsedRequestParts {
            mut request,
            command_line,
        } = convert_wire_config(cfg, logger, true, allow_missing_command)?;

        if let Some(command) = command_line {
            request.set_script(command);
        }
        Ok(request)
    })();
    log_one_shot_error(logger, &result);
    result
}
/// driver can pick the right output convention per path (envelope on stdout
/// for state-aware, diagnostic on stderr for one-shot and pre-discrimination
/// failures).
pub fn load_mxc_request(
    input: &str,
    logger: &mut Logger,
    is_base64: bool,
) -> Result<MxcRequest, ParseError> {
    load_mxc_request_with_options(
        input,
        logger,
        LoadOptions {
            is_base64,
            allow_missing_command: false,
        },
    )
}

/// Options-aware variant of [`load_mxc_request`]. When
/// `LoadOptions::allow_missing_command` is set, a missing or empty
/// `process.commandLine` in the policy is tolerated and `script_code`
/// is left empty for the driver to fill in from a CLI override.
pub fn load_mxc_request_with_options(
    input: &str,
    logger: &mut Logger,
    opts: LoadOptions,
) -> Result<MxcRequest, ParseError> {
    load_mxc_request_parts_with_options(input, logger, opts).map(ParsedRequestParts::into_request)
}

/// Loads an MXC request while keeping its JSON command line separate.
///
/// Unlike [`load_mxc_request_with_options`], this function leaves the contained
/// [`ExecutionRequest::script_code`] empty and returns the validated
/// `process.commandLine` through [`ParsedRequestParts::command_line`].
pub fn load_mxc_request_parts_with_options(
    input: &str,
    logger: &mut Logger,
    opts: LoadOptions,
) -> Result<ParsedRequestParts<MxcRequest>, ParseError> {
    let result = (|| {
        let json_str = decode_request_input_without_logging(input, opts.is_base64)
            .map_err(ParseError::Decode)?;
        parse_mxc_request_json(&json_str, logger, opts.allow_missing_command)
    })();

    if let Err(error) = &result {
        log_error(logger, &error.message(), error.output());
    }

    result
}

/// Parse an MXC request from a **raw JSON string** (already decoded — not a file
/// path or base64). Discriminates one-shot vs state-aware by the `phase` key,
/// the same as [`load_mxc_request`], but skips the file/base64 decode step so an
/// in-memory JSON string can be parsed directly.
pub fn load_mxc_request_from_json(
    json_str: &str,
    logger: &mut Logger,
) -> Result<MxcRequest, ParseError> {
    let result = parse_mxc_request_json(json_str, logger, /*allow_missing_command=*/ false);
    if let Err(error) = &result {
        log_error(logger, &error.message(), error.output());
    }
    result.map(ParsedRequestParts::into_request)
}

/// Shared parse core over an already-decoded JSON string.
///
/// Borrows only the discriminator and the raw state-aware backend block, then
/// deserialises the typed model directly from source text so policy errors
/// retain line and column information (`serde_json::Value` would discard it).
fn parse_mxc_request_json(
    json_str: &str,
    logger: &mut Logger,
    allow_missing_command: bool,
) -> Result<ParsedRequestParts<MxcRequest>, ParseError> {
    let discriminator: RequestDiscriminator<'_> = config_deserialize::from_str(json_str)
        .map_err(|error| ParseError::Decode(WxcError::ConfigParse(error.to_string())))?;

    if discriminator.phase.is_some() {
        let raw: serde_json::Value = config_deserialize::from_str(json_str)
            .map_err(|error| ParseError::Decode(WxcError::ConfigParse(error.to_string())))?;
        validate_directional_network_field_versions(&raw).map_err(|error| {
            ParseError::StateAware(MxcError::malformed_request(error.to_string()))
        })?;
        convert_wire_state_aware(
            json_str,
            discriminator.experimental,
            logger,
            allow_missing_command,
        )
        .map(|parts| parts.map(MxcRequest::StateAware))
        .map_err(|e| ParseError::StateAware(MxcError::malformed_request(e.to_string())))
    } else {
        let cfg: wire::MxcConfig = config_deserialize::from_str(json_str)
            .map_err(|error| ParseError::OneShot(WxcError::ConfigParse(error.to_string())))?;
        let raw: serde_json::Value = config_deserialize::from_str(json_str)
            .map_err(|error| ParseError::OneShot(WxcError::ConfigParse(error.to_string())))?;
        validate_directional_network_field_versions(&raw).map_err(ParseError::OneShot)?;

        convert_wire_config(cfg, logger, true, allow_missing_command)
            .map(|parts| parts.map(MxcRequest::OneShot))
            .map_err(ParseError::OneShot)
    }
}

fn validate_directional_network_field_versions(config: &serde_json::Value) -> Result<(), WxcError> {
    let Some(config) = config.as_object() else {
        return Ok(());
    };
    if let Some(version) = config.get("version").and_then(serde_json::Value::as_str) {
        if semver::Version::parse(version).is_err() || supports_directional_network(version) {
            return Ok(());
        }
    }

    let has_directional_network = config
        .get("network")
        .and_then(serde_json::Value::as_object)
        .is_some_and(|network| network.contains_key("egress") || network.contains_key("ingress"));
    let has_runtime_config = config.contains_key("runtimeConfig");
    let has_process_container_network = ["processContainer", "appContainer"]
        .into_iter()
        .filter_map(|key| config.get(key))
        .filter_map(serde_json::Value::as_object)
        .any(|process_container| process_container.contains_key("network"));

    if has_directional_network || has_runtime_config || has_process_container_network {
        return Err(directional_network_version_error());
    }
    Ok(())
}

fn log_one_shot_error<T>(logger: &mut Logger, result: &Result<T, WxcError>) {
    if let Err(error) = result {
        log_error(logger, &error.to_string(), ErrorOutput::Primary);
    }
}

fn log_error(logger: &mut Logger, message: &str, output: ErrorOutput) {
    match output {
        ErrorOutput::Primary => logger.log_line(message),
        ErrorOutput::DiagnosticOnly => logger.log_diagnostic_line(message),
    }
}

/// Reads a request from disk or decodes it from base64.
fn decode_request_input_without_logging(input: &str, is_base64: bool) -> Result<String, WxcError> {
    if is_base64 {
        let bytes = base64_decode(input).map_err(|_| {
            WxcError::ConfigParse("Failed to decode base64 configuration".to_string())
        })?;
        String::from_utf8(bytes).map_err(|_| {
            WxcError::ConfigParse("Base64 decoded content is not valid UTF-8".to_string())
        })
    } else {
        // The file path is untrusted input; on Linux/macOS it may contain
        // newlines or terminal control characters. Escape it before embedding
        // in diagnostics so a missing/unreadable file cannot inject forged
        // multi-line log output.
        let safe_input = config_deserialize::escape_diagnostic_text(input);
        if !std::path::Path::new(input).exists() {
            return Err(WxcError::ConfigParse(format!(
                "Configuration file not found: {safe_input}"
            )));
        }
        fs::read_to_string(input).map_err(|e| {
            WxcError::ConfigParse(format!(
                "Failed to read configuration file '{safe_input}': {e}"
            ))
        })
    }
}

// ---------- Cross-field validation ----------

/// Maximum supported schema version (major.minor). Configs with a higher major.minor are rejected.
const SUPPORTED_VERSION: &str = ">=0.6, <=0.9";

/// Canonical "latest" schema version string used in samples and tests. Bump
/// alongside `SUPPORTED_VERSION`'s upper bound when a new dev schema lands.
#[cfg(test)]
const CURRENT_SCHEMA_VERSION: &str = "0.9.0-alpha";

/// Known `experimental.<backend>` keys. Used by validation code to flag
/// experimental backend sections that don't match the selected
/// `containment`. Add a new entry when promoting a backend to a top-level
/// section or graduating one from experimental.
const KNOWN_EXPERIMENTAL_BACKENDS: &[&str] = &["windows_sandbox", "wslc", "isolation_session"];

/// Validate that the schema version (semver) is supported by this binary.
/// Compares major.minor only — patch and pre-release labels are ignored.
fn validate_schema_version(version: &str) -> Result<(), WxcError> {
    if version.is_empty() {
        return Ok(());
    }

    // Parse the version, stripping pre-release suffix for comparison
    // (e.g., "0.4.0-alpha" is treated as "0.4.0")
    let parsed = semver::Version::parse(version).map_err(|_| {
        WxcError::ConfigParse(format!(
            "Invalid schema version '{}': must be semver (e.g., 'X.Y.Z' or 'X.Y.Z-alpha')",
            config_deserialize::escape_diagnostic_text(version)
        ))
    })?;

    let req = semver::VersionReq::parse(SUPPORTED_VERSION).unwrap();

    // semver crate treats pre-release as lower precedence, so we compare
    // against a version without the pre-release label for major.minor check.
    let comparable = semver::Version::new(parsed.major, parsed.minor, parsed.patch);
    if !req.matches(&comparable) {
        let min = semver::VersionReq::parse(">=0.6").unwrap();
        let safe_version = config_deserialize::escape_diagnostic_text(version);
        let msg = if !min.matches(&comparable) {
            format!(
                "Config schema version '{}' is older than supported (supported: {}). Update your config.",
                safe_version, SUPPORTED_VERSION
            )
        } else {
            format!(
                "Config schema version '{}' is newer than supported (supported: {}). Upgrade wxc-exec.",
                safe_version, SUPPORTED_VERSION
            )
        };
        return Err(WxcError::ConfigParse(msg));
    }
    Ok(())
}

fn validate_filesystem_paths(policy: &ContainerPolicy) -> Result<(), WxcError> {
    validate_paths(&policy.readonly_paths)?;
    validate_paths(&policy.readwrite_paths)?;
    validate_paths(&policy.denied_paths)?;
    Ok(())
}

fn validate_paths(paths: &[String]) -> Result<(), WxcError> {
    for path in paths {
        // A blank entry names nothing: backends would either grant nothing or,
        // worse, treat it as "unset" (e.g. a NULL working directory).
        if path.trim().is_empty() {
            return Err(WxcError::ConfigParse(
                "Filesystem path is empty".to_string(),
            ));
        }
        // An interior NUL silently truncates the path once it is converted to a
        // C/UTF-16 string, so the enforced grant would not be the one requested.
        if path.contains('\0') {
            let msg = format!(
                "Filesystem path '{}' contains an embedded NUL character",
                config_deserialize::escape_diagnostic_text(path)
            );
            return Err(WxcError::ConfigParse(msg));
        }
        if path.contains('"') {
            let msg = format!(
                "Filesystem path '{}' contains invalid character '\"'",
                config_deserialize::escape_diagnostic_text(path)
            );
            return Err(WxcError::ConfigParse(msg));
        }
    }
    Ok(())
}

/// Normalizes cross-list filesystem path constraints by applying
/// **most-restrictive-wins** precedence (`deny` > `readonly` > `readwrite`):
///
/// 1. Same-path conflict: if a path string appears in multiple lists, it is kept
///    only in the most restrictive list (e.g. a path in both `readwritePaths` and
///    `deniedPaths` is normalized to denied).
/// 2. Paths should exist: logs a WARNING for paths that don't exist on the host
///    (advisory — some backends create mount targets dynamically; not a hard error).
///
/// This never rejects the config — conflicting intents are resolved deterministically
/// rather than erroring, matching the roadmap's most-restrictive-wins decision.
fn normalize_filesystem_paths(policy: &mut ContainerPolicy, logger: &mut Logger) {
    if policy.readwrite_paths.is_empty()
        && policy.readonly_paths.is_empty()
        && policy.denied_paths.is_empty()
    {
        return;
    }

    // 1. Same-path (string) conflict: drop a path from a list if it also appears
    //    in a more restrictive list.
    let denied: std::collections::HashSet<String> = policy.denied_paths.iter().cloned().collect();
    let readonly: std::collections::HashSet<String> =
        policy.readonly_paths.iter().cloned().collect();

    policy.readwrite_paths.retain(|p| {
        if denied.contains(p) {
            logger.log_line(&format!(
                "Filesystem path '{}' appears in 'readwritePaths' and 'deniedPaths'; \
                 applying most-restrictive intent (denied)",
                config_deserialize::escape_diagnostic_text(p)
            ));
            false
        } else if readonly.contains(p) {
            logger.log_line(&format!(
                "Filesystem path '{}' appears in 'readwritePaths' and 'readonlyPaths'; \
                 applying most-restrictive intent (readonly)",
                config_deserialize::escape_diagnostic_text(p)
            ));
            false
        } else {
            true
        }
    });
    policy.readonly_paths.retain(|p| {
        if denied.contains(p) {
            logger.log_line(&format!(
                "Filesystem path '{}' appears in 'readonlyPaths' and 'deniedPaths'; \
                 applying most-restrictive intent (denied)",
                config_deserialize::escape_diagnostic_text(p)
            ));
            false
        } else {
            true
        }
    });

    // 2. Existence warning (advisory; not a hard gate).
    for (paths, list_name) in [
        (&policy.readwrite_paths, "readwritePaths"),
        (&policy.readonly_paths, "readonlyPaths"),
        (&policy.denied_paths, "deniedPaths"),
    ] {
        for path in paths {
            if fs::metadata(path).is_err() {
                logger.log_line(&format!(
                    "WARNING: filesystem path '{}' (in '{}') does not exist on the host; \
                     the backend may fail at mount time",
                    config_deserialize::escape_diagnostic_text(path),
                    list_name
                ));
            }
        }
    }
}

// ---------- Conversion from wire model to domain model ----------

fn present_backend_sections(cfg: &wire::MxcConfig) -> Vec<&'static str> {
    let mut sections: Vec<&'static str> = Vec::new();
    let mut push = |backend: ContainmentBackend| {
        if let Some(path) = backend.section_path() {
            sections.push(path);
        }
    };
    if cfg.process_container.is_some() {
        push(ContainmentBackend::ProcessContainer);
    }
    if cfg.lxc.is_some() {
        push(ContainmentBackend::Lxc);
    }
    if cfg.seatbelt.is_some() {
        push(ContainmentBackend::Seatbelt);
    }
    if let Some(experimental) = cfg.experimental.as_ref() {
        if experimental.windows_sandbox.is_some() {
            push(ContainmentBackend::WindowsSandbox);
        }
        if experimental.wslc.is_some() {
            push(ContainmentBackend::Wslc);
        }
        if experimental.isolation_session.is_some() {
            push(ContainmentBackend::IsolationSession);
        }
    }
    sections
}

fn validate_single_backend_section(
    containment: ContainmentBackend,
    present_sections: &[&'static str],
) -> Result<(), WxcError> {
    let allowed_section = containment.section_path();
    let extras: Vec<&'static str> = present_sections
        .iter()
        .copied()
        .filter(|section| Some(*section) != allowed_section)
        .collect();
    if extras.is_empty() {
        return Ok(());
    }

    let containment_wire = containment.wire_name();
    let msg = match allowed_section {
        Some(name) => format!(
            "Multiple containment backends configured: 'containment' is '{containment_wire}' \
             (allows the '{name}' section), but the config also includes unrelated \
             backend section(s): {}. Only one backend section is allowed; remove the unused \
             section(s).",
            extras.join(", "),
        ),
        None => format!(
            "Multiple containment backends configured: 'containment' is '{containment_wire}' \
             (no per-backend section is defined for this backend), but the config includes \
             backend section(s): {}. Only one backend section is allowed; remove the unused \
             section(s).",
            extras.join(", "),
        ),
    };
    Err(WxcError::ConfigParse(msg))
}

/// Rejects `experimental.<backend>` keys that don't match the resolved
/// `containment`. When `containment` is `None` (state-aware non-provision
/// phases can resolve the backend from `sandboxId`), a single key is
/// allowed; two or more is unambiguously wrong.
fn validate_experimental_backend_keys(
    containment: Option<&ContainmentBackend>,
    experimental_raw: Option<&serde_json::Value>,
) -> Result<(), WxcError> {
    let Some(serde_json::Value::Object(map)) = experimental_raw else {
        return Ok(());
    };

    let matching_key = containment
        .and_then(|c| c.section_path())
        .and_then(|path| path.strip_prefix("experimental."));

    let present: Vec<&'static str> = KNOWN_EXPERIMENTAL_BACKENDS
        .iter()
        .copied()
        .filter(|key| map.contains_key(*key))
        .collect();

    let rejected: Vec<&'static str> = match matching_key {
        Some(allowed) => present.into_iter().filter(|k| *k != allowed).collect(),
        None if present.len() > 1 => present,
        None => return Ok(()),
    };

    if rejected.is_empty() {
        return Ok(());
    }

    let qualified: Vec<String> = rejected
        .iter()
        .map(|k| format!("experimental.{k}"))
        .collect();
    let msg = format!(
        "Multiple containment backends configured: request includes \
         experimental backend section(s) {}. Only one backend section is allowed; \
         remove the unused section(s).",
        qualified.join(", "),
    );
    Err(WxcError::ConfigParse(msg))
}

/// Convert a typed `wire::Seatbelt` block into the validated domain struct.
fn make_seatbelt_config(sb: wire::Seatbelt) -> SeatbeltConfig {
    // Destructure (no `..`) so adding a wire field without mapping it is a
    // compile error rather than a silent runtime drop.
    let wire::Seatbelt {
        profile_override,
        gui_access,
        launch_method,
        nested_pty,
        keychain_access,
        extra_mach_lookups,
    } = sb;
    SeatbeltConfig {
        profile_override,
        gui_access: gui_access.unwrap_or(false),
        launch_method: launch_method.map(Into::into).unwrap_or_default(),
        nested_pty: nested_pty.unwrap_or(true),
        keychain_access: keychain_access.unwrap_or(false),
        extra_mach_lookups: extra_mach_lookups.unwrap_or_default(),
    }
}

/// Resolve the optional `containment` wire enum to a concrete domain backend.
///
/// An omitted `containment` (`None`) resolves identically to the abstract
/// `process` intent: the OS-native process sandbox. Concrete and abstract
/// variants are mapped by `From<wire::Containment>`.
fn map_wire_containment(c: Option<&wire::Containment>) -> ContainmentBackend {
    match c {
        Some(c) => c.clone().into(),
        None => wire::Containment::Process.into(),
    }
}

fn state_aware_containment_from_id(sandbox_id: &str) -> Option<wire::Containment> {
    match sandbox_id.split_once(':')?.0 {
        "wslc" => Some(wire::Containment::Wslc),
        "wsb" => Some(wire::Containment::WindowsSandbox),
        "iso" => Some(wire::Containment::IsolationSession),
        _ => None,
    }
}

/// Validates a caller-specified `processContainer.captureDenials.outputPath`: it
/// must be an absolute path whose parent directory already exists (the runner
/// writes the JSON denials output file there after the workload exits). The
/// path itself must not be an existing directory. A relative path, directory
/// path, or missing parent yields an actionable error.
fn validate_capture_denials_output_path(path: &str, logger: &mut Logger) -> Result<(), WxcError> {
    let candidate = std::path::Path::new(path);
    if !candidate.is_absolute() {
        let msg = format!(
            "processContainer.captureDenials.outputPath must be an absolute path: '{path}'"
        );
        logger.log_line(&msg);
        return Err(WxcError::ConfigParse(msg));
    }
    match candidate.parent() {
        // A filesystem root ("/", "C:\\") has either no parent (`None`) or an
        // empty parent, and cannot name a trace file.
        None => {
            let msg = format!(
                "processContainer.captureDenials.outputPath must name a file, not a \
                 directory root: '{path}'"
            );
            logger.log_line(&msg);
            Err(WxcError::ConfigParse(msg))
        }
        Some(parent) if parent.as_os_str().is_empty() => {
            let msg = format!(
                "processContainer.captureDenials.outputPath must name a file, not a \
                 directory root: '{path}'"
            );
            logger.log_line(&msg);
            Err(WxcError::ConfigParse(msg))
        }
        Some(parent) if !parent.is_dir() => {
            let msg = format!(
                "processContainer.captureDenials.outputPath parent directory does not \
                 exist: '{}'",
                parent.display()
            );
            logger.log_line(&msg);
            Err(WxcError::ConfigParse(msg))
        }
        Some(_) if candidate.is_dir() => {
            let msg = format!(
                "processContainer.captureDenials.outputPath must name a file, not an \
                 existing directory: '{path}'"
            );
            logger.log_line(&msg);
            Err(WxcError::ConfigParse(msg))
        }
        _ => Ok(()),
    }
}

// `allow_missing_command` relaxes the `require_process == true` arms so that a
// CLI command-line override (provided by the driver after parsing) can stand in
// for `process.commandLine`. When set, a missing or empty `commandLine` is
// silently accepted and `script_code` is left empty.
fn convert_wire_config(
    cfg: wire::MxcConfig,
    logger: &mut Logger,
    require_process: bool,
    allow_missing_command: bool,
) -> Result<ParsedRequestParts<ExecutionRequest>, WxcError> {
    // `phase` / `sandboxId` are state-aware-only fields. The state-aware path
    // consumes them before delegating here, so if either is still present the
    // input is a state-aware-shaped payload sent to a one-shot entry point;
    // reject it loudly rather than silently executing it as a one-shot.
    if cfg.phase.is_some() {
        return Err(WxcError::ConfigParse(
            "'phase' is only valid on state-aware lifecycle requests".to_string(),
        ));
    }
    if cfg.sandbox_id.is_some() {
        return Err(WxcError::ConfigParse(
            "'sandboxId' is only valid on state-aware lifecycle requests".to_string(),
        ));
    }
    if cfg.correlation_vector.is_some() {
        let msg = "'correlationVector' is only valid on state-aware lifecycle requests".to_string();
        logger.log_line(&msg);
        return Err(WxcError::ConfigParse(msg));
    }

    // Backend sections present in the config (captured before fields move out).
    let present_backend_sections = present_backend_sections(&cfg);

    let schema_version = cfg.version.unwrap_or_default();

    // Validate the schema version up front so an unsupported version fails fast.
    validate_schema_version(&schema_version)?;
    let container_id = cfg.container_id.unwrap_or_default();

    // Process section: required for one-shot and state-aware exec; optional for
    // non-exec state-aware phases (require_process == false) or when the driver
    // signalled a CLI command-line override (allow_missing_command).
    let command_required = require_process && !allow_missing_command;
    let (command_line, working_directory, script_timeout, env) = match cfg.process {
        Some(process) => {
            let command_line = match process.command_line {
                Some(command) if !command.is_empty() => Some(command),
                Some(_) if command_required => {
                    return Err(WxcError::ConfigParse(
                        "process.commandLine cannot be empty".to_string(),
                    ));
                }
                None if command_required => {
                    return Err(WxcError::ConfigParse(
                        "Missing required field: process.commandLine".to_string(),
                    ));
                }
                _ => None,
            };

            // Null bytes can hide malicious payloads from audit logs.
            if command_line
                .as_deref()
                .is_some_and(|command| command.contains('\0'))
            {
                return Err(WxcError::ConfigParse(
                    "process.commandLine must not contain null bytes".to_string(),
                ));
            }

            (
                command_line,
                process.cwd.unwrap_or_default(),
                process.timeout.unwrap_or(0),
                process.env.unwrap_or_default(),
            )
        }
        None if command_required => {
            return Err(WxcError::ConfigParse(
                "'process' section is required".into(),
            ));
        }
        None => (None, String::new(), 0, Vec::new()),
    };

    // Containment backend selection. The wire enum has already constrained the
    // value to a known variant (invalid strings fail at deserialize); abstract
    // intents and the omitted case resolve to the OS-native backend here.
    let containment = map_wire_containment(cfg.containment.as_ref());

    validate_single_backend_section(containment.clone(), &present_backend_sections)?;

    // LXC configuration
    let lxc_config = match cfg.lxc {
        Some(l) => LxcConfig {
            distribution: l.distribution.unwrap_or_default(),
            release: l.release.unwrap_or_default(),
        },
        None => LxcConfig::default(),
    };

    let mut policy = ContainerPolicy::default();

    // ProcessContainer section. Holds settings that apply to the Windows
    // process-level backend regardless of whether the runner picks the legacy
    // AppContainer implementation (capabilities/learningMode/leastPrivilege) or
    // the newer BaseContainer implementation (ui).
    let mut process_container_network = None;
    if let Some(ac) = cfg.process_container {
        if let Some(lp) = ac.least_privilege {
            policy.least_privilege_mode = lp;
        }

        // The learningMode boolean maps to the deny-and-record learning-mode
        // capability (`learningModeLogging`). AppContainer restrictions remain
        // enforced; access denials are recorded for diagnostics. This is
        // available in every build.
        if ac.learning_mode.unwrap_or(false) {
            policy.capabilities.push("learningModeLogging".to_string());
        }

        // Learning-mode capability names are reserved for the dedicated entry
        // points (`learningMode`, `--audit`, and future captureDenials wiring).
        // Reject direct capability-array use case-insensitively because Windows
        // derives capability SIDs case-insensitively.
        if let Some(caps) = ac.capabilities {
            if let Some(invalid) = caps.iter().find(|capability| capability.contains(',')) {
                let msg = format!(
                    "processContainer.capabilities entry '{invalid}' must not contain a comma; \
                     provide multiple capabilities as separate JSON array entries"
                );
                logger.log_line(&msg);
                return Err(WxcError::ConfigParse(msg));
            }
            if let Some(reserved) = caps.iter().find(|capability| {
                capability.eq_ignore_ascii_case("learningModeLogging")
                    || capability.eq_ignore_ascii_case("permissiveLearningMode")
            }) {
                let msg = format!(
                    "processContainer.capabilities must not include reserved learning-mode \
                     capability '{reserved}'; use processContainer.learningMode for \
                     deny-and-record mode or --audit for permissive mode"
                );
                logger.log_line(&msg);
                return Err(WxcError::ConfigParse(msg));
            }
            policy.capabilities.extend(caps);
        }

        // captureDenials (Windows denial capture). Presence enables capture: the
        // runner records the process's ungranted access attempts to a
        // learning-mode ETL trace. `mode` decides whether each recorded access is
        // blocked (`block`, the default) or allowed (`allow`).
        // The optional outputPath names where the trace is sealed; validate it
        // eagerly so a bad path fails at parse time rather than deep in the runner.
        if let Some(cd) = ac.capture_denials {
            if let Some(path) = cd.output_path.as_deref() {
                validate_capture_denials_output_path(path, logger)?;
            }
            let mode = match cd.mode {
                Some(wire::CaptureDenialsMode::Allow) => CaptureDenialsMode::Allow,
                Some(wire::CaptureDenialsMode::Block) | None => CaptureDenialsMode::Block,
            };

            // captureDenials drives the learning-mode ETL capture in the runner,
            // which requires the corresponding learning-mode capability on the
            // child token so the OS emits the access-check records the capture
            // path collects. Inject it additively (preserving the workload's real
            // capabilities). `block` keeps deny-by-default via
            // `learningModeLogging`; `allow` replaces deny-and-record with
            // `permissiveLearningMode` (the runner surfaces the security warning).
            let capture_capability = match mode {
                CaptureDenialsMode::Block => {
                    // Capability entries are exact names. Comma-packed entries
                    // were rejected above, so substring matching here would
                    // incorrectly remove unrelated custom capabilities.
                    policy.capabilities.retain(|capability| {
                        !capability.eq_ignore_ascii_case("permissiveLearningMode")
                    });
                    "learningModeLogging"
                }
                CaptureDenialsMode::Allow => {
                    policy.capabilities.retain(|capability| {
                        !capability.eq_ignore_ascii_case("learningModeLogging")
                    });
                    "permissiveLearningMode"
                }
            };
            if !policy
                .capabilities
                .iter()
                .any(|capability| capability.eq_ignore_ascii_case(capture_capability))
            {
                policy.capabilities.push(capture_capability.to_string());
            }

            policy.capture_denials = Some(CaptureDenialsConfig {
                mode,
                output_path: cd.output_path,
                retain_etl: cd.retain_etl.unwrap_or(false),
            });
        }

        // BaseProcessContainer-specific UI config.
        if let Some(raw_ui) = ac.ui {
            policy.base_process_ui.isolation = raw_ui
                .isolation
                .as_ref()
                .map(wire::UiIsolation::as_str)
                .unwrap_or("container")
                .to_string();
            policy.base_process_ui.desktop_system_control =
                raw_ui.desktop_system_control.unwrap_or(false);
            policy.base_process_ui.system_settings =
                raw_ui.system_settings.unwrap_or_else(|| "none".to_string());
            policy.base_process_ui.ime = raw_ui.ime.unwrap_or(false);
        }

        process_container_network = ac.network;
    }

    // Filesystem section
    if let Some(fscfg) = cfg.filesystem {
        if let Some(v) = fscfg.denied_paths {
            policy.denied_paths = v;
        }
        if let Some(v) = fscfg.readwrite_paths {
            policy.readwrite_paths = v;
        }
        if let Some(v) = fscfg.readonly_paths {
            policy.readonly_paths = v;
        }
    }
    validate_filesystem_paths(&policy)?;
    normalize_filesystem_paths(&mut policy, logger);

    // Fallback section
    if let Some(fbcfg) = cfg.fallback {
        if let Some(v) = fbcfg.allow_dacl_mutation {
            policy.fallback.allow_dacl_mutation = v;
        }
    }

    let parsed_network = parse_network_policy(
        &mut policy,
        &schema_version,
        NetworkSections {
            network: cfg.network,
            runtime: cfg.runtime_config,
            process_container: process_container_network,
        },
        &containment,
    )?;

    if let Some(legacy) = parsed_network {
        if policy.network_proxy.is_enabled() {
            let proxy_used_localhost = legacy.proxy_used_localhost;
            let proxy_config = &policy.network_proxy;
            if proxy_config.is_enabled()
                && containment != ContainmentBackend::ProcessContainer
                && containment != ContainmentBackend::Bubblewrap
                && containment != ContainmentBackend::Lxc
                && containment != ContainmentBackend::Seatbelt
                && containment != ContainmentBackend::Wslc
            {
                let msg = "Network proxy is only supported with the 'processcontainer', \
                           'bubblewrap', 'lxc', 'seatbelt', or 'wslc' containment backends";
                logger.log_line(msg);
                return Err(WxcError::ConfigParse(msg.to_string()));
            }

            if containment == ContainmentBackend::Lxc && proxy_config.builtin_test_server {
                let msg = "LXC: network.proxy.builtinTestServer is not supported; \
                           use network.proxy.url";
                logger.log_line(msg);
                return Err(WxcError::ConfigParse(msg.to_string()));
            }

            // `network.proxy.localhost` maps to 127.0.0.1, which inside an LXC
            // network namespace is the container's own loopback rather than the
            // host. The injected HTTP(S)_PROXY would be unreachable and the
            // iptables proxy-allow rule would never match, so require a routable
            // host via `network.proxy.url` instead.
            if containment == ContainmentBackend::Lxc && proxy_used_localhost {
                let msg = "LXC: network.proxy.localhost is not reachable from the \
                           container network namespace (127.0.0.1 is the container \
                           loopback); use network.proxy.url with a host routable from \
                           inside the container";
                logger.log_line(msg);
                return Err(WxcError::ConfigParse(msg.to_string()));
            }

            // WSLc containers run in their own network namespace, so an
            // MXC-run host-loopback proxy is unreachable. Accept only the
            // caller-supplied `url` form (which carries `original_url`); reject
            // the `localhost` / `builtinTestServer` forms.
            if containment == ContainmentBackend::Wslc && proxy_config.is_enabled() {
                let is_url_form = proxy_config
                    .address
                    .as_ref()
                    .is_some_and(|addr| addr.original_url.is_some());
                if !is_url_form {
                    let msg = "WSLc: network.proxy must use the 'url' form pointing at a \
                               routable proxy (e.g. \"url\": \"http://proxy.example:8080\"). \
                               The 'localhost' and 'builtinTestServer' forms are not supported \
                               because a WSLc container runs in its own network namespace and \
                               cannot reach a host-loopback proxy.";
                    logger.log_line(msg);
                    return Err(WxcError::ConfigParse(msg.to_string()));
                }
            }

            // Under LXC a loopback-literal proxy host names the container's own
            // network-namespace loopback rather than the host, so it can never
            // be the proxy: the chain opens egress to the proxy endpoint across
            // the veth and the address is pinned into the container's
            // /etc/hosts, both of which assume a routable host.
            //
            // WSLc is deliberately excluded. Its supported topology puts the
            // proxy *inside* the container -- `tests/configs/wslc_network_proxy.json`
            // runs one on 127.0.0.1:8888 -- because loopback is the only address
            // both the client and a self-hosted proxy can reach. The forms that
            // name a host-run proxy, `localhost` and `builtinTestServer`, are
            // already rejected for WSLc just above; that check is the one doing
            // the work there, and this one would only break the case WSLc
            // supports.
            if containment == ContainmentBackend::Lxc {
                if let Some(host) = proxy_config.address.as_ref().map(|addr| addr.host()) {
                    if host_is_loopback(host) {
                        let msg = "network.proxy.url host is a loopback address \
                                   (127.0.0.0/8, ::1, or localhost), which names the \
                                   container's own network-namespace loopback rather than \
                                   the host; use a proxy host routable from inside the \
                                   container";
                        logger.log_line(msg);
                        return Err(WxcError::ConfigParse(msg.to_string()));
                    }
                }
            }
        }

        // WSLc routes egress through the cooperative proxy but does not forward
        // host lists to it, and a 'block' default (the WSLc default) yields no
        // outbound networking / a drop-floor that can't even reach the proxy.
        // Require an 'allow' default with no host lists so the proxy is reachable.
        if containment == ContainmentBackend::Wslc
            && policy.network_proxy.is_enabled()
            && (policy.default_network_policy == NetworkPolicy::Block
                || !policy.allowed_hosts.is_empty()
                || !policy.blocked_hosts.is_empty())
        {
            let msg = "WSLc: network.proxy requires network.defaultPolicy='allow' and no \
                       allowedHosts/blockedHosts. A WSLc container reaches the proxy only \
                       with outbound networking enabled, and host lists are enforced by the \
                       proxy, not forwarded to it.";
            logger.log_line(msg);
            return Err(WxcError::ConfigParse(msg.to_string()));
        }

        // WSLc cannot enforce per-host egress filtering: containers lack
        // CAP_NET_ADMIN (so in-container iptables aborts at exec), and WSLc
        // cannot expose VM-level enforcement without breaking other security
        // guarantees (e.g. MDE). Reject up front; the backend's validate_runner
        // enforces the same for requests that bypass this parser. Bare defaults
        // with no host lists (full cutoff / full NAT) are enforceable, left as-is.
        if containment == ContainmentBackend::Wslc {
            if policy.needs_host_filtering() {
                let msg = "WSLc: per-host egress filtering (allowedHosts with \
                           defaultPolicy='block', or blockedHosts with \
                           defaultPolicy='allow') is not supported. A WSLc container has \
                           no CAP_NET_ADMIN for in-container iptables, and VM-level \
                           enforcement is not available without breaking other security \
                           guarantees (e.g. MDE). Use network.proxy (defaultPolicy='allow') \
                           for cooperative host filtering, or remove the host lists.";
                logger.log_line(msg);
                return Err(WxcError::ConfigParse(msg.to_string()));
            }

            // WSLc cannot honor a blanket inbound-listen grant. The runner only
            // wires explicit host->container port forwards (experimental.wslc
            // portMappings) into the WSL2 VM's NAT; it never consults
            // allowLocalNetwork. Reject `true` and point at portMappings.
            // (`false` is the default and a no-op.)
            if policy.allow_local_network {
                let msg = "WSLc: network.allowLocalNetwork=true is not supported. A WSLc \
                           container runs in the NAT'd WSL2 VM and MXC does not honor a \
                           blanket inbound-listen grant; expose specific ports with \
                           experimental.wslc.portMappings instead.";
                logger.log_line(msg);
                return Err(WxcError::ConfigParse(msg.to_string()));
            }
        }

        // Bubblewrap is unprivileged by design; iptables-based enforcement
        // (firewall / both) requires CAP_NET_ADMIN, which defeats the backend's
        // privilege story. Reject the combination explicitly.
        if containment == ContainmentBackend::Bubblewrap
            && policy.network_proxy.is_enabled()
            && matches!(
                policy.network_enforcement_mode,
                NetworkEnforcementMode::Firewall | NetworkEnforcementMode::Both
            )
        {
            let msg = "Bubblewrap: network.proxy cannot be combined with \
                       network.enforcementMode='firewall' or 'both'. The cooperative \
                       env-var proxy enforces hosts at the proxy layer; iptables-based \
                       enforcement requires privilege and is mutually exclusive.";
            return Err(WxcError::ConfigParse(msg.to_string()));
        }

        // Seatbelt has no privileged packet-filter layer on macOS: it enforces
        // network policy through the sandbox profile (capabilities-style) and
        // ignores enforcementMode. Combining network.proxy with a firewall mode
        // would silently drop the firewall expectation, so reject it explicitly,
        // mirroring the Bubblewrap guard above.
        if containment == ContainmentBackend::Seatbelt
            && policy.network_proxy.is_enabled()
            && matches!(
                policy.network_enforcement_mode,
                NetworkEnforcementMode::Firewall | NetworkEnforcementMode::Both
            )
        {
            let msg = "Seatbelt: network.proxy cannot be combined with \
                       network.enforcementMode='firewall' or 'both'. macOS Seatbelt \
                       enforces network policy through the sandbox profile and has no \
                       packet-filter layer, so a firewall mode cannot be honored.";
            logger.log_line(msg);
            return Err(WxcError::ConfigParse(msg.to_string()));
        }

        // Seatbelt scopes a *loopback* proxy's reachability to its exact port
        // even under default-deny (profile_builder::write_proxy_reachability_rules),
        // but it cannot filter a *remote* proxy by host: a remote proxy under
        // defaultPolicy='block' degrades to allow-all outbound, silently turning
        // the kernel-enforced deny into allow-all for raw-socket clients that
        // ignore HTTP_PROXY. Reject that combination. Loopback proxies (including
        // builtinTestServer, whose loopback address is resolved at runtime and is
        // therefore absent here) stay port-scoped and are allowed.
        if containment == ContainmentBackend::Seatbelt
            && policy.default_network_policy == NetworkPolicy::Block
            && policy
                .network_proxy
                .address
                .as_ref()
                .is_some_and(|addr| !matches!(addr.host(), "127.0.0.1" | "::1" | "localhost"))
        {
            let msg = "Seatbelt: a remote network.proxy (non-loopback host) cannot be \
                       combined with defaultPolicy='block'. Seatbelt cannot filter a remote \
                       proxy by host, so outbound reachability degrades to allow-all, \
                       silently weakening the deny for raw-socket clients that ignore \
                       HTTP_PROXY. Use a loopback proxy (127.0.0.1/::1/localhost) or \
                       'network.proxy.builtinTestServer: true' for port-scoped reachability \
                       under deny.";
            logger.log_line(msg);
            return Err(WxcError::ConfigParse(msg.to_string()));
        }

        // LXC is the inverse of the two guards above: it *does* have a
        // privileged packet-filter layer, and that layer is the only thing that
        // makes the proxy an exception rather than a suggestion. Under the
        // default `Capabilities` mode `apply_firewall_rules` installs nothing,
        // so the runner would inject HTTP(S)_PROXY while leaving direct egress
        // wide open -- a config that reads as deny-all-except-proxy and
        // enforces neither half. Reject it rather than auto-promoting, so the
        // user's stated enforcement is never silently rewritten.
        if containment == ContainmentBackend::Lxc
            && policy.network_proxy.is_enabled()
            && !matches!(
                policy.network_enforcement_mode,
                NetworkEnforcementMode::Firewall | NetworkEnforcementMode::Both
            )
        {
            let msg = "LXC: network.proxy requires network.enforcementMode='firewall' \
                       or 'both'. Under the default 'capabilities' mode no iptables \
                       rules are installed, so the proxy environment variables would be \
                       injected while direct egress stayed unrestricted -- any client \
                       that ignores HTTP_PROXY would bypass the proxy entirely.";
            logger.log_line(msg);
            return Err(WxcError::ConfigParse(msg.to_string()));
        }

        // A proxy URL may carry `user:pass@` userinfo, and neither LXC nor
        // Bubblewrap keeps that value out of process argv: LXC turns each env
        // entry into an `lxc-attach --set-var=KEY=VALUE` argument, and
        // Bubblewrap serializes it into a `bwrap --setenv KEY VALUE` argument
        // (bwrap_command.rs). argv is world-readable through /proc/<pid>/cmdline
        // for the command's lifetime, and neither helper offers an argv-free way
        // to pass a variable, so refuse the credential rather than leak it.
        if matches!(
            containment,
            ContainmentBackend::Lxc | ContainmentBackend::Bubblewrap
        ) && policy
            .network_proxy
            .address
            .as_ref()
            .map(|address| address.to_url())
            .is_some_and(|url| crate::proxy_env::proxy_url_has_credentials(&url))
        {
            // Built from the redacted form so the rejection cannot become the
            // leak it is rejecting.
            let msg = format!(
                "network.proxy.url must not carry credentials ('{}'). LXC and Bubblewrap \
                 pass the proxy URL to the sandbox helper as a command-line argument \
                 (lxc-attach --set-var, bwrap --setenv), and process arguments are \
                 world-readable through /proc/<pid>/cmdline, so the password would be \
                 visible to every local user while the command runs. Use a proxy that does \
                 not require inline credentials, or supply them to the proxy itself rather \
                 than through the URL.",
                policy
                    .network_proxy
                    .address
                    .as_ref()
                    .map(|address| crate::proxy_env::redact_proxy_url(&address.to_url()))
                    .unwrap_or_default()
            );
            logger.log_line(&msg);
            return Err(WxcError::ConfigParse(msg));
        }

        // External proxy (`url` / `localhost`) enforces its own policy — the
        // runner does NOT forward host lists to it. Reject configs that combine
        // an external proxy with host lists or a restrictive default, otherwise
        // users get silently weaker enforcement.
        if containment == ContainmentBackend::Bubblewrap
            && policy.network_proxy.is_enabled()
            && !policy.network_proxy.builtin_test_server
            && (!policy.allowed_hosts.is_empty()
                || !policy.blocked_hosts.is_empty()
                || policy.default_network_policy == NetworkPolicy::Block)
        {
            let msg = "Bubblewrap: an external network.proxy (url/localhost) cannot be \
                       combined with allowedHosts, blockedHosts, or defaultPolicy='block'. \
                       The external proxy is expected to enforce its own host policy; \
                       MXC does not forward host lists to it. Use \
                       'network.proxy.builtinTestServer: true' (testing only) for \
                       MXC-enforced host filtering, or remove the host policy.";
            return Err(WxcError::ConfigParse(msg.to_string()));
        }

        // Cooperative-model warning: builtin test proxy + defaultPolicy 'block'
        // with no allowlist denies well-behaved HTTP clients at the proxy, but
        // raw-socket clients still reach the host network.
        if containment == ContainmentBackend::Bubblewrap
            && policy.network_proxy.is_enabled()
            && policy.default_network_policy == NetworkPolicy::Block
            && policy.allowed_hosts.is_empty()
            && policy.blocked_hosts.is_empty()
        {
            logger.log_line(
                "WARNING: Bubblewrap network.proxy with defaultPolicy='block' is \
                 cooperative. HTTP_PROXY-aware clients (curl, requests, etc.) are \
                 denied at the proxy, but raw-socket clients that ignore HTTP_PROXY \
                 bypass the proxy and reach the host network. For strict isolation \
                 of all clients, remove network.proxy so --unshare-net applies; for \
                 host-list enforcement, add allowedHosts (cooperative tools only).",
            );
        }
    }

    // Lifecycle section
    let lifecycle = match cfg.lifecycle {
        Some(lc) => LifecycleConfig {
            destroy_on_exit: lc.destroy_on_exit.unwrap_or(true),
            preserve_policy: lc.preserve_policy.unwrap_or(false),
        },
        None => LifecycleConfig {
            destroy_on_exit: true,
            preserve_policy: false,
        },
    };

    // Experimental section (parsed but only applied when --experimental is set).
    let experimental = if let Some(raw_exp) = cfg.experimental {
        let test = raw_exp.test.map(|t| TestFeatureConfig::from_raw(t.message));
        let windows_sandbox = raw_exp.windows_sandbox.map(|sb| {
            let mut config = WindowsSandboxConfig::default();
            if let Some(t) = sb.idle_timeout_ms.or(sb.idle_timeout) {
                config.idle_timeout_ms = t;
            }
            if let Some(name) = sb.daemon_pipe_name {
                config.daemon_pipe_name = name;
            }
            config
        });
        let wslc = if let Some(cc) = raw_exp.wslc {
            let mut config = WslcConfig::default();
            if let Some(os) = cc.target_os {
                config.target_os = os;
            }
            if let Some(img) = cc.image {
                config.image = img;
            }
            config.image_tar_path = cc.image_tar_path;
            config.cpu_count = cc.cpu_count;
            config.memory_mb = cc.memory_mb;
            if let Some(gpu) = cc.gpu {
                config.gpu = gpu;
            }
            config.storage_path = cc.storage_path;
            if let Some(mappings) = cc.port_mappings {
                let mut converted = Vec::with_capacity(mappings.len());
                for (idx, m) in mappings.into_iter().enumerate() {
                    if m.windows_port == 0 {
                        let msg = format!(
                            "experimental.wslc.portMappings[{idx}]: 'windowsPort' must be > 0"
                        );
                        return Err(WxcError::ConfigParse(msg));
                    }
                    if m.container_port == 0 {
                        let msg = format!(
                            "experimental.wslc.portMappings[{idx}]: 'containerPort' must be > 0"
                        );
                        return Err(WxcError::ConfigParse(msg));
                    }
                    // Only TCP is representable in the wire model
                    // (TransportProtocol is tcp-only); a `udp` value is rejected
                    // at deserialize. The WSLC SDK runtime returns E_NOTIMPL for
                    // UDP, so only TCP is currently supported.
                    let protocol = "tcp".to_string();
                    converted.push(PortMapping {
                        windows_port: m.windows_port,
                        container_port: m.container_port,
                        protocol,
                    });
                }
                // Reject duplicate (windowsPort, protocol) entries. Same host
                // port on TCP+UDP would in principle be legal, but UDP is
                // rejected at deserialize (the wire model is tcp-only); the
                // second protocol dimension is retained in the dedupe key in
                // case UDP support is enabled later.
                let mut seen: std::collections::HashSet<(u16, &str)> =
                    std::collections::HashSet::new();
                for pm in &converted {
                    if !seen.insert((pm.windows_port, pm.protocol.as_str())) {
                        let msg = format!(
                            "experimental.wslc.portMappings: duplicate windowsPort {} \
                             for protocol '{}'",
                            pm.windows_port, pm.protocol
                        );
                        return Err(WxcError::ConfigParse(msg));
                    }
                }
                config.port_mappings = converted;
            }
            Some(config)
        } else {
            None
        };
        if raw_exp.seatbelt.is_some() {
            let msg = "'experimental.seatbelt' has moved to the stable section; \
                       use top-level 'seatbelt' instead."
                .to_string();
            return Err(WxcError::ConfigParse(msg));
        }
        let telemetry = raw_exp.telemetry.map(|raw_t| TelemetryConfig {
            enabled: raw_t.enabled,
        });
        ExperimentalConfig {
            test,
            windows_sandbox,
            wslc,
            telemetry,
        }
    } else {
        ExperimentalConfig::default()
    };

    // Top-level `seatbelt` config. Configs using `experimental.seatbelt` are
    // rejected above.
    let seatbelt = cfg.seatbelt.map(make_seatbelt_config);

    // UI section. Capture presence before the typed mapping consumes `ui`:
    // `UiPolicy::default()` is full lockdown, so an explicit lockdown `ui` is
    // otherwise indistinguishable from an absent one, and a backend that cannot
    // honor UI restrictions has no way to tell "caller asked for lockdown" from
    // "caller said nothing". Twin of `network_specified`.
    policy.ui_specified = cfg.ui.is_some();
    if let Some(raw_ui) = cfg.ui {
        let clipboard = raw_ui.clipboard.map(Into::into).unwrap_or_default();
        policy.ui = UiPolicy {
            disable: raw_ui.disable.unwrap_or(true),
            clipboard,
            injection: raw_ui.injection.unwrap_or(false),
        };
    }

    let request = ExecutionRequest {
        schema_version,
        container_id,
        env,
        script_code: String::new(),
        working_directory,
        script_timeout,
        containment,
        lifecycle,
        policy,
        lxc_config,
        seatbelt,
        experimental_enabled: false,
        testing_features_enabled: false,
        experimental,
        dry_run: false,
    };
    Ok(ParsedRequestParts {
        request,
        command_line,
    })
}

fn convert_wire_state_aware(
    json: &str,
    experimental: Option<&RawValue>,
    logger: &mut Logger,
    allow_missing_command: bool,
) -> Result<ParsedRequestParts<ParsedStateAwareRequest>, WxcError> {
    let experimental_raw = experimental
        .map(|raw| {
            config_deserialize::from_str::<serde_json::Value>(raw.get())
                .map_err(|error| WxcError::ConfigParse(error.to_string()))
        })
        .transpose()?;

    // Peeling `experimental` off above also removes it from the typed
    // deserialize, so a non-object value (e.g. `"experimental": 42`) would slip
    // through unchecked here and be silently ignored — unlike the one-shot path,
    // where `experimental` is a typed `Option<Experimental>` and a non-object is
    // a hard parse error. Reject a present, non-null, non-object value up front
    // so both paths fail malformed configs consistently. (`null` maps to "absent"
    // on both paths and is accepted.)
    if let Some(exp) = experimental_raw.as_ref() {
        if !exp.is_null() && !exp.is_object() {
            return Err(WxcError::ConfigParse(
                "Invalid configuration at `experimental`: expected an object".to_string(),
            ));
        }
    }

    let base_json = mask_state_aware_experimental(json, experimental)?;
    let mut cfg: wire::MxcConfig = config_deserialize::from_str(&base_json)
        .map_err(|error| WxcError::ConfigParse(error.to_string()))?;

    // `phase` is the state-aware discriminator and is constrained by the wire
    // enum; absence here would be a logic error in the caller's discrimination.
    let phase = match cfg.phase.take() {
        Some(p) => p.into(),
        None => {
            return Err(WxcError::ConfigParse(
                "Missing required field: phase".to_string(),
            ));
        }
    };

    // Resolved backend, present only when the request carried `containment`.
    let containment = cfg
        .containment
        .as_ref()
        .map(|c| map_wire_containment(Some(c)));

    // `containment` is a provision-only field: the backend is selected once at
    // provision, and every later phase routes by `sandboxId`. A stray
    // `containment` on a non-provision phase would otherwise leak into the
    // shared converter's per-backend network guards and produce contradictory
    // policy behavior (e.g. an exec `containment:"wslc"` + proxy is rejected
    // either as "proxy requires allow" or as an immutable post-provision mode
    // change). Reject it once, clearly, as a malformed envelope.
    if phase != Phase::Provision && cfg.containment.is_some() {
        return Err(WxcError::ConfigParse(format!(
            "State-aware '{phase}' requests must not carry 'containment'; the backend is fixed \
             at provision and later phases route by 'sandboxId'."
        )));
    }

    // Mirror the one-shot rejection of moved-to-stable experimental sections.
    // The one-shot path errors on `experimental.seatbelt` in `convert_wire_config`,
    // but the state-aware path peels `experimental` into `experimental_raw`
    // before that runs, so without this check the block would be silently
    // discarded (the same silent-policy-drop class as the moved-to-stable
    // sections).
    if let Some(serde_json::Value::Object(exp)) = experimental_raw.as_ref() {
        for key in ["seatbelt", "macos_sandbox"] {
            if exp.contains_key(key) {
                let msg = format!(
                    "'experimental.{key}' has moved to the stable section; \
                     use top-level 'seatbelt' instead."
                );
                return Err(WxcError::ConfigParse(msg));
            }
        }
    }

    validate_experimental_backend_keys(containment.as_ref(), experimental_raw.as_ref())?;

    let sandbox_id = cfg.sandbox_id.clone();
    let correlation_vector = cfg.correlation_vector.clone();
    let network_supplied = cfg.network.is_some();

    // State-aware requests carry only cross-cutting fields (process /
    // filesystem / network / ui) plus the experimental backend block. One-shot-
    // only stable sections and lifecycle are not valid here; reject them
    // explicitly rather than silently discarding a policy the caller believes
    // is in effect.
    let mut stray: Vec<&'static str> = Vec::new();
    if cfg.seatbelt.is_some() {
        stray.push("seatbelt");
    }
    if cfg.process_container.is_some() {
        stray.push("processContainer");
    }
    if cfg.lxc.is_some() {
        stray.push("lxc");
    }
    if cfg.lifecycle.is_some() {
        stray.push("lifecycle");
    }
    if !stray.is_empty() {
        let msg = format!(
            "State-aware lifecycle requests do not accept one-shot section(s): {}. \
             Remove them; per-backend policy and lifecycle are fixed at provision time.",
            stray.join(", ")
        );
        return Err(WxcError::ConfigParse(msg));
    }

    // Populate the inner ExecutionRequest from cross-cutting fields only. Clear
    // the state-aware-only fields (already consumed above) and the
    // now-validated-absent stable sections so the shared one-shot converter
    // sees a clean surrogate and its `phase`/`sandboxId` guard passes.
    cfg.sandbox_id = None;
    cfg.correlation_vector = None;
    cfg.experimental = None;
    cfg.seatbelt = None;
    cfg.process_container = None;
    cfg.lxc = None;
    cfg.lifecycle = None;
    if phase != Phase::Provision {
        cfg.containment = sandbox_id
            .as_deref()
            .and_then(state_aware_containment_from_id);
    }

    let require_process = phase == Phase::Exec;
    let ParsedRequestParts {
        mut request,
        command_line,
    } = convert_wire_config(cfg, logger, require_process, allow_missing_command)?;
    if phase != Phase::Provision && !network_supplied {
        request.policy.network_egress = None;
        request.policy.network_ingress = None;
    }

    // Populate the typed `experimental.telemetry` field from the raw block that
    // was peeled off above. The rest of `experimental` is typed per-backend at
    // dispatch time (from `experimental_raw`), but telemetry is a cross-cutting,
    // backend-independent setting consumed the same way as the one-shot path —
    // so it belongs on the typed request, not in a parallel raw-JSON reader. A
    // present-but-malformed `telemetry` object is a client error (rejected here,
    // exactly like the one-shot parser), not a silent disable.
    if let Some(telemetry_val) = experimental_raw
        .as_ref()
        .and_then(|exp| exp.get("telemetry"))
    {
        let telemetry: TelemetryConfig =
            serde_json::from_value(telemetry_val.clone()).map_err(|e| {
                // Do not log here: state-aware parse errors are routed centrally
                // and exactly once by the outer `load_mxc_request*` wrapper via
                // `log_error(..., ErrorOutput::DiagnosticOnly)`. Logging here as
                // well would produce a duplicate auxiliary diagnostic.
                // Returning the error keeps stdout clean (envelope-owned) and
                // yields a single auxiliary-sink line.
                WxcError::ConfigParse(format!("invalid experimental.telemetry: {e}"))
            })?;
        request.experimental.telemetry = Some(telemetry);
    }

    Ok(ParsedRequestParts {
        request: ParsedStateAwareRequest {
            request,
            phase,
            containment,
            sandbox_id,
            correlation_vector,
            experimental_raw,
            // Retain the decoded request text so the dispatcher can deserialize each
            // `experimental.<backend>.<phase>` sub-slice positionally and report
            // typed errors with whole-file line/column (parity with base config).
            source_text: Some(json.to_owned().into_boxed_str()),
        },
        command_line,
    })
}

/// Byte range `[start, end)` of the borrowed `experimental` value within the
/// original request text.
///
/// `raw` is `serde_json`'s borrowed `RawValue` for the `experimental` field,
/// which — for `&str` input — is a sub-slice of `json`; its pointer therefore
/// lies within `json`'s allocation and its length stays within bounds. The
/// checks below make that invariant explicit and fail closed if a future caller
/// ever passes a `raw` not borrowed from `json` (unreachable on the normal
/// parser path).
fn experimental_source_span(json: &str, raw: &str) -> Result<(usize, usize), WxcError> {
    let locate_err = || {
        WxcError::ConfigParse("Unable to locate the experimental configuration block".to_string())
    };
    let start = (raw.as_ptr() as usize)
        .checked_sub(json.as_ptr() as usize)
        .filter(|start| *start <= json.len())
        .ok_or_else(locate_err)?;
    let end = start
        .checked_add(raw.len())
        .filter(|end| *end <= json.len())
        .ok_or_else(locate_err)?;
    Ok((start, end))
}

fn mask_state_aware_experimental<'a>(
    json: &'a str,
    experimental: Option<&RawValue>,
) -> Result<Cow<'a, str>, WxcError> {
    let Some(experimental) = experimental else {
        return Ok(Cow::Borrowed(json));
    };

    let raw = experimental.get();
    let (start, end) = experimental_source_span(json, raw)?;
    let (prefix, suffix) = match (json.get(..start), json.get(end..)) {
        (Some(prefix), Some(suffix)) => (prefix, suffix),
        _ => {
            return Err(WxcError::ConfigParse(
                "Unable to locate the experimental configuration block".to_string(),
            ))
        }
    };

    // State-aware backend config is retained separately and typed at dispatch.
    // Replace it with an empty object of identical byte/line length so the base
    // wire model validates cross-cutting fields without shifting source
    // coordinates. ASCII spaces preserve byte offsets; retained CR/LF preserve
    // lines. The caller already verified that `raw` is an object.
    let mut masked = String::with_capacity(json.len());
    masked.push_str(prefix);
    let mut braces = ['{', '}'].into_iter();
    for byte in raw.bytes() {
        match byte {
            b'\r' => masked.push('\r'),
            b'\n' => masked.push('\n'),
            _ => masked.push(braces.next().unwrap_or(' ')),
        }
    }
    debug_assert!(braces.next().is_none());
    masked.push_str(suffix);
    debug_assert_eq!(masked.len(), json.len());

    Ok(Cow::Owned(masked))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::encoding::base64_encode;
    use crate::logger::Mode;
    use crate::models::{ClipboardPolicy, NetworkAction, ProxyAddress};

    fn test_logger() -> Logger {
        Logger::new(Mode::Buffer)
    }

    fn load_mxc(json: &str) -> Result<MxcRequest, ParseError> {
        let encoded = base64_encode(json.as_bytes());
        let mut logger = test_logger();
        load_mxc_request(&encoded, &mut logger, true)
    }

    fn load_mxc_with_opts(json: &str, opts: LoadOptions) -> Result<MxcRequest, ParseError> {
        let encoded = base64_encode(json.as_bytes());
        let mut logger = test_logger();
        load_mxc_request_with_options(
            &encoded,
            &mut logger,
            LoadOptions {
                is_base64: true,
                ..opts
            },
        )
    }

    fn load_mxc_parts_with_opts(
        json: &str,
        opts: LoadOptions,
    ) -> Result<ParsedRequestParts<MxcRequest>, ParseError> {
        let encoded = base64_encode(json.as_bytes());
        let mut logger = test_logger();
        load_mxc_request_parts_with_options(
            &encoded,
            &mut logger,
            LoadOptions {
                is_base64: true,
                ..opts
            },
        )
    }

    #[test]
    fn parts_loader_surfaces_one_shot_command_line() {
        let json = r#"{
            "process": {
                "commandLine": "echo from policy",
                "cwd": "C:\\workspace"
            }
        }"#;

        let parts = load_mxc_parts_with_opts(json, LoadOptions::default()).unwrap();

        assert_eq!(parts.command_line.as_deref(), Some("echo from policy"));
        match parts.request {
            MxcRequest::OneShot(request) => {
                assert!(request.script_code.is_empty());
                assert_eq!(request.working_directory, "C:\\workspace");
            }
            MxcRequest::StateAware(_) => panic!("expected one-shot"),
        }
    }

    #[test]
    fn parts_loader_surfaces_state_aware_exec_command_line() {
        let json = r#"{
            "phase": "exec",
            "sandboxId": "iso:abcd1234",
            "process": {"commandLine": "echo from lifecycle"}
        }"#;

        let parts = load_mxc_parts_with_opts(json, LoadOptions::default()).unwrap();

        assert_eq!(parts.command_line.as_deref(), Some("echo from lifecycle"));
        match parts.request {
            MxcRequest::StateAware(parsed) => {
                assert_eq!(parsed.phase, Phase::Exec);
                assert!(parsed.request.script_code.is_empty());
            }
            MxcRequest::OneShot(_) => panic!("expected state-aware"),
        }
    }

    #[test]
    fn compatibility_loader_reapplies_surfaced_command_line() {
        let json = r#"{"process": {"commandLine": "echo compatibility"}}"#;

        match load_mxc_with_opts(json, LoadOptions::default()).unwrap() {
            MxcRequest::OneShot(request) => {
                assert_eq!(request.script_code, "echo compatibility");
            }
            MxcRequest::StateAware(_) => panic!("expected one-shot"),
        }
    }

    #[test]
    fn allow_missing_command_lets_one_shot_skip_command_line() {
        // No process.commandLine in the policy — without the flag this would
        // be a parse error; with allow_missing_command set the parser yields
        // an empty script_code for the driver to fill in.
        let json = r#"{"process": {"cwd": "C:\\tmp"}}"#;
        let opts = LoadOptions {
            is_base64: true,
            allow_missing_command: true,
        };
        match load_mxc_with_opts(json, opts).unwrap() {
            MxcRequest::OneShot(req) => {
                assert!(req.script_code.is_empty());
                assert_eq!(req.working_directory, "C:\\tmp");
            }
            MxcRequest::StateAware(_) => panic!("expected one-shot"),
        }
    }

    #[test]
    fn allow_missing_command_lets_one_shot_skip_process_block_entirely() {
        let json = r#"{"containment": "processcontainer"}"#;
        let opts = LoadOptions {
            is_base64: true,
            allow_missing_command: true,
        };
        match load_mxc_with_opts(json, opts).unwrap() {
            MxcRequest::OneShot(req) => assert!(req.script_code.is_empty()),
            MxcRequest::StateAware(_) => panic!("expected one-shot"),
        }
    }

    #[test]
    fn allow_missing_command_lets_state_aware_exec_skip_command_line() {
        let json = r#"{
            "phase": "exec",
            "sandboxId": "iso:abcd1234",
            "process": {"cwd": "C:\\tmp"}
        }"#;
        let opts = LoadOptions {
            is_base64: true,
            allow_missing_command: true,
        };
        match load_mxc_with_opts(json, opts).unwrap() {
            MxcRequest::StateAware(p) => {
                assert_eq!(p.phase, Phase::Exec);
                assert!(p.request.script_code.is_empty());
            }
            MxcRequest::OneShot(_) => panic!("expected state-aware"),
        }
    }

    #[test]
    fn default_options_still_reject_missing_command_line() {
        // Sanity: without the flag, the legacy contract holds — missing
        // commandLine is a hard parse error.
        let json = r#"{"process": {"cwd": "C:\\tmp"}}"#;
        let opts = LoadOptions {
            is_base64: true,
            allow_missing_command: false,
        };
        assert!(load_mxc_with_opts(json, opts).is_err());
    }

    #[test]
    fn one_shot_routes_via_load_mxc_request() {
        let json = r#"{"process": {"commandLine": "echo hello"}}"#;
        match load_mxc(json).unwrap() {
            MxcRequest::OneShot(req) => assert_eq!(req.script_code, "echo hello"),
            MxcRequest::StateAware(_) => panic!("expected one-shot"),
        }
    }

    #[test]
    fn state_aware_provision_request_routes_to_state_aware_arm() {
        let json = r#"{
            "phase": "provision",
            "containment": "isolation_session",
            "filesystem": {"readwritePaths": ["C:\\workspace"]}
        }"#;
        match load_mxc(json).unwrap() {
            MxcRequest::StateAware(p) => {
                assert_eq!(p.phase, Phase::Provision);
                assert_eq!(p.containment, Some(ContainmentBackend::IsolationSession));
                assert!(p.sandbox_id.is_none());
                assert!(p.experimental_raw.is_none());
                assert_eq!(p.request.policy.readwrite_paths, vec!["C:\\workspace"]);
                // Non-exec phase: process-related fields stay default.
                assert!(p.request.script_code.is_empty());
            }
            MxcRequest::OneShot(_) => panic!("expected state-aware"),
        }
    }

    #[test]
    fn state_aware_start_request_carries_sandbox_id_and_experimental() {
        let json = r#"{
            "phase": "start",
            "sandboxId": "iso:abcd1234",
            "experimental": {
                "isolation_session": {"start": {"opaqueFutureField": true}}
            }
        }"#;
        match load_mxc(json).unwrap() {
            MxcRequest::StateAware(p) => {
                assert_eq!(p.phase, Phase::Start);
                assert_eq!(p.sandbox_id.as_deref(), Some("iso:abcd1234"));
                // Assert the nested experimental payload survives extraction
                // unchanged (not merely that the block is present), since the
                // dispatcher types it per-backend from this raw value.
                let exp = p.experimental_raw.expect("experimental block present");
                assert_eq!(
                    exp,
                    serde_json::json!({
                        "isolation_session": {"start": {"opaqueFutureField": true}}
                    })
                );
            }
            MxcRequest::OneShot(_) => panic!("expected state-aware"),
        }
    }

    #[test]
    fn state_aware_telemetry_populates_typed_field() {
        // Telemetry is a cross-cutting setting: the state-aware parser must
        // populate the typed `experimental.telemetry` field (consumed the same
        // way as one-shot) while leaving the per-backend `experimental_raw`
        // block intact for dispatch.
        let json = r#"{
            "phase": "provision",
            "containment": "isolation_session",
            "experimental": {"telemetry": {"enabled": true}}
        }"#;
        match load_mxc(json).unwrap() {
            MxcRequest::StateAware(p) => {
                let telem = p
                    .request
                    .experimental
                    .telemetry
                    .expect("telemetry should be populated");
                assert_eq!(telem.enabled, Some(true));
                // The raw block is still available for per-backend dispatch.
                assert!(p.experimental_raw.is_some());
            }
            MxcRequest::OneShot(_) => panic!("expected state-aware"),
        }
    }

    #[test]
    fn state_aware_without_telemetry_leaves_typed_field_unset() {
        let json = r#"{
            "phase": "start",
            "sandboxId": "iso:abcd1234",
            "experimental": {"isolation_session": {"start": {"opaqueFutureField": true}}}
        }"#;
        match load_mxc(json).unwrap() {
            MxcRequest::StateAware(p) => assert!(p.request.experimental.telemetry.is_none()),
            MxcRequest::OneShot(_) => panic!("expected state-aware"),
        }
    }

    #[test]
    fn state_aware_malformed_telemetry_is_rejected() {
        // A present-but-malformed telemetry block is a client error rejected at
        // parse time (surfaced as a state-aware envelope), not a silent disable.
        let json = r#"{
            "phase": "provision",
            "containment": "isolation_session",
            "experimental": {"telemetry": 42}
        }"#;
        let r = load_mxc(json);
        assert!(matches!(r, Err(ParseError::StateAware(_))), "got {:?}", r);
    }

    #[test]
    fn state_aware_rejects_containment_on_non_provision_phase() {
        // `containment` is provision-only; later phases route by `sandboxId`.
        // A stray `containment` on start/exec/stop/deprovision is a malformed
        // envelope, rejected once rather than leaking into per-backend guards.
        for phase in ["start", "exec", "stop", "deprovision"] {
            let json = format!(
                r#"{{
                    "phase": "{phase}",
                    "sandboxId": "iso:abcd1234",
                    "containment": "wslc"
                }}"#
            );
            let opts = LoadOptions {
                is_base64: true,
                allow_missing_command: true,
            };
            let r = load_mxc_with_opts(&json, opts);
            assert!(
                matches!(r, Err(ParseError::StateAware(_))),
                "phase {phase}: expected state-aware rejection, got {:?}",
                r
            );
        }
    }

    #[test]
    fn state_aware_pre_v08_rejects_null_directional_sections() {
        for extra in [
            r#""network": {"egress": null}"#,
            r#""runtimeConfig": null"#,
            r#""processContainer": {"network": null}"#,
        ] {
            let json = format!(
                r#"{{
                    "version": "0.7.0-alpha",
                    "phase": "start",
                    "sandboxId": "wslc:0123456789abcdef0123456789abcdef",
                    {extra}
                }}"#
            );
            assert!(matches!(load_mxc(&json), Err(ParseError::StateAware(_))));
        }
    }

    #[test]
    fn state_aware_v08_omitted_network_remains_absent_after_parsing() {
        let json = r#"{
            "version": "0.8.0-alpha",
            "phase": "start",
            "sandboxId": "wslc:0123456789abcdef0123456789abcdef"
        }"#;
        let parsed = match load_mxc(json).unwrap() {
            MxcRequest::StateAware(parsed) => parsed,
            MxcRequest::OneShot(_) => panic!("expected state-aware request"),
        };

        assert!(parsed.request.policy.network_egress.is_none());
        assert!(parsed.request.policy.network_ingress.is_none());
        assert!(!parsed.request.policy.network_specified);
        assert!(!parsed.request.policy.network_mode_specified);
    }

    #[test]
    fn state_aware_v08_runtime_proxy_uses_sandbox_backend_context() {
        let json = r#"{
            "version": "0.8.0-alpha",
            "phase": "exec",
            "sandboxId": "wslc:0123456789abcdef0123456789abcdef",
            "runtimeConfig": {"networkProxy": "http://127.0.0.1:8888"},
            "process": {"commandLine": "echo hi"}
        }"#;
        let parsed = match load_mxc(json).unwrap() {
            MxcRequest::StateAware(parsed) => parsed,
            MxcRequest::OneShot(_) => panic!("expected state-aware request"),
        };

        assert_eq!(parsed.request.containment, ContainmentBackend::Wslc);
        assert!(parsed.request.policy.runtime_network_proxy_specified);
        assert!(parsed.request.policy.network_proxy.is_enabled());
    }

    /// Parse a provision request and return the resolved cross-cutting policy.
    fn provision_policy(network_json: &str) -> ContainerPolicy {
        let json = format!(
            r#"{{
                "phase": "provision",
                "containment": "processcontainer",
                "network": {network_json}
            }}"#
        );
        match load_mxc(&json).unwrap() {
            MxcRequest::StateAware(p) => p.request.policy,
            MxcRequest::OneShot(_) => panic!("expected state-aware"),
        }
    }

    #[test]
    fn state_aware_network_mode_specified_true_for_each_mode_field() {
        // Every network *mode* field (everything except `proxy`) must flip the
        // presence bit so post-provision phases can reject an immutable-posture
        // change by presence.
        for net in [
            r#"{"defaultPolicy": "allow"}"#,
            r#"{"enforcementMode": "firewall"}"#,
            r#"{"allowLocalNetwork": true}"#,
            r#"{"allowedHosts": ["example.com"]}"#,
            r#"{"blockedHosts": ["example.com"]}"#,
        ] {
            let policy = provision_policy(net);
            assert!(
                policy.network_mode_specified,
                "network {net} should set network_mode_specified"
            );
            assert!(policy.network_specified);
        }
    }

    #[test]
    fn state_aware_proxy_only_block_leaves_network_mode_unspecified() {
        // A proxy-only block sets `network_specified` (the block is present) but
        // NOT `network_mode_specified`, so the cooperative proxy stays honourable
        // at exec while no immutable mode change is falsely detected.
        let policy = provision_policy(r#"{"proxy": {"url": "http://proxy.example:8080"}}"#);
        assert!(policy.network_specified);
        assert!(
            !policy.network_mode_specified,
            "proxy-only block must not set network_mode_specified"
        );
        assert!(policy.network_proxy.is_enabled());
    }

    #[test]
    fn state_aware_malformed_telemetry_logs_once_and_keeps_primary_clean() {
        // The malformed-telemetry error must reach the auxiliary
        // diagnostic sink exactly once (routed centrally by the outer
        // `load_mxc_request` wrapper), never duplicated, and must never touch the
        // primary buffer/stdout that the state-aware JSON envelope owns.
        let json = r#"{
            "phase": "provision",
            "containment": "isolation_session",
            "experimental": {"telemetry": 42}
        }"#;
        let encoded = base64_encode(json.as_bytes());

        let dir = tempfile::tempdir().unwrap();
        let log_path = dir.path().join("diag.log");
        let mut logger = Logger::new(Mode::Buffer);
        logger.enable_file_sink(&log_path).unwrap();

        let result = load_mxc_request(&encoded, &mut logger, true);
        assert!(
            matches!(result, Err(ParseError::StateAware(_))),
            "got {result:?}"
        );
        assert!(
            logger.get_buffer().is_empty(),
            "state-aware error must not touch the primary buffer: {:?}",
            logger.get_buffer()
        );
        drop(logger);

        let logged = std::fs::read_to_string(&log_path).unwrap();
        assert_eq!(
            logged.matches("invalid experimental.telemetry").count(),
            1,
            "expected exactly one auxiliary diagnostic, got: {logged:?}"
        );
    }

    #[test]
    fn state_aware_non_object_experimental_is_rejected() {
        // A non-object `experimental` (here a bare number) is a hard parse error
        // on the one-shot path (typed `Option<Experimental>`); the state-aware
        // path peels `experimental` off before typed deserialize, so it must
        // reject a non-object value explicitly to stay consistent rather than
        // silently ignoring it.
        let json = r#"{
            "phase": "start",
            "sandboxId": "iso:abcd1234",
            "experimental": 42
        }"#;
        let r = load_mxc(json);
        assert!(matches!(r, Err(ParseError::StateAware(_))), "got {:?}", r);
    }

    #[test]
    fn state_aware_null_experimental_is_accepted() {
        // `null` maps to "absent" on both the one-shot and state-aware paths, so
        // it is accepted (leaving telemetry unset), unlike a non-object value.
        let json = r#"{
            "phase": "start",
            "sandboxId": "iso:abcd1234",
            "experimental": null
        }"#;
        match load_mxc(json).unwrap() {
            MxcRequest::StateAware(p) => assert!(p.request.experimental.telemetry.is_none()),
            MxcRequest::OneShot(_) => panic!("expected state-aware"),
        }
    }

    #[test]
    fn state_aware_exec_request_requires_command_line() {
        let json = r#"{
            "phase": "exec",
            "sandboxId": "iso:abcd1234",
            "process": {"commandLine": "echo hello"}
        }"#;
        match load_mxc(json).unwrap() {
            MxcRequest::StateAware(p) => {
                assert_eq!(p.phase, Phase::Exec);
                assert_eq!(p.request.script_code, "echo hello");
            }
            MxcRequest::OneShot(_) => panic!("expected state-aware"),
        }
    }

    #[test]
    fn state_aware_exec_without_process_is_rejected() {
        // Exec phase still requires the process.commandLine wire field.
        let json = r#"{ "phase": "exec", "sandboxId": "iso:abcd1234" }"#;
        let r = load_mxc(json);
        assert!(matches!(r, Err(ParseError::StateAware(_))), "got {:?}", r);
    }

    #[test]
    fn state_aware_unknown_phase_is_rejected() {
        let json = r#"{"phase": "teleport"}"#;
        let error = match load_mxc(json) {
            Err(ParseError::StateAware(error)) => error,
            other => panic!("expected state-aware error, got {other:?}"),
        };
        assert!(error.message.contains("Invalid configuration at `phase`"));
        assert!(error.message.contains("unknown variant `teleport`"));
    }

    #[test]
    fn present_null_phase_is_still_discriminated_as_state_aware() {
        let error = match load_mxc(r#"{"phase": null}"#) {
            Err(ParseError::StateAware(error)) => error,
            other => panic!("expected state-aware error, got {other:?}"),
        };

        assert!(error.message.contains("Missing required field: phase"));
    }

    #[test]
    fn state_aware_unknown_containment_is_rejected() {
        let json = r#"{
            "phase": "provision",
            "containment": "totally_made_up"
        }"#;
        let error = match load_mxc(json) {
            Err(ParseError::StateAware(error)) => error,
            other => panic!("expected state-aware error, got {other:?}"),
        };
        assert!(
            error
                .message
                .contains("Invalid configuration at `containment`"),
            "got: {}",
            error.message
        );
        assert!(error.message.contains("unknown variant `totally_made_up`"));
        assert!(error.message.contains("line 3"));
    }

    #[test]
    fn state_aware_mask_preserves_locations_after_multiline_experimental() {
        let json = r#"{
            "phase": "provision",
            "experimental": {
                "future_backend": {
                    "nested": true
                }
            },
            "process": {"timeout": "soon"}
        }"#;
        let error = match load_mxc(json) {
            Err(ParseError::StateAware(error)) => error,
            other => panic!("expected state-aware error, got {other:?}"),
        };

        assert!(
            error
                .message
                .contains("Invalid configuration at `process.timeout`"),
            "got: {}",
            error.message
        );
        assert!(error.message.contains("line 8"), "got: {}", error.message);
    }

    #[test]
    fn state_aware_mask_handles_empty_object_at_root_boundaries() {
        for json in [
            r#"{"experimental":{},"phase":"provision"}"#,
            r#"{"phase":"provision","experimental":{}}"#,
        ] {
            let discriminator: RequestDiscriminator<'_> =
                config_deserialize::from_str(json).unwrap();
            let masked = mask_state_aware_experimental(json, discriminator.experimental).unwrap();

            assert_eq!(masked.len(), json.len());
            let config: wire::MxcConfig = config_deserialize::from_str(&masked).unwrap();
            assert!(matches!(config.phase, Some(wire::Phase::Provision)));
        }
    }

    #[test]
    fn state_aware_mask_handles_whitespace_only_multiline_object() {
        let json = "{\n  \"phase\": \"provision\",\n  \"experimental\": {\r\n    \r\n  }\n}";
        let discriminator: RequestDiscriminator<'_> = config_deserialize::from_str(json).unwrap();
        let masked = mask_state_aware_experimental(json, discriminator.experimental).unwrap();

        assert_eq!(masked.len(), json.len());
        assert_eq!(
            masked.bytes().filter(|byte| *byte == b'\n').count(),
            json.bytes().filter(|byte| *byte == b'\n').count()
        );
        let config: wire::MxcConfig = config_deserialize::from_str(&masked).unwrap();
        assert!(matches!(config.phase, Some(wire::Phase::Provision)));
    }

    #[test]
    fn experimental_source_span_locates_the_borrowed_block() {
        let json = r#"{"phase":"provision","experimental":{"a":{"b":1}}}"#;
        let discriminator: RequestDiscriminator<'_> = config_deserialize::from_str(json).unwrap();
        let raw = discriminator.experimental.unwrap().get();

        let (start, end) = experimental_source_span(json, raw).unwrap();
        assert_eq!(&json[start..end], raw);
        assert_eq!(&json[start..start + 1], "{");
        assert_eq!(&json[end - 1..end], "}");
    }

    #[test]
    fn experimental_source_span_rejects_a_foreign_slice() {
        // A `raw` not borrowed from `json` must fail closed rather than compute
        // an out-of-range offset — the invariant guard the masking relies on.
        let json = r#"{"experimental":{}}"#;
        let foreign = String::from("{}");
        let error = experimental_source_span(json, foreign.as_str()).unwrap_err();
        assert!(matches!(error, WxcError::ConfigParse(_)));
    }

    #[test]
    fn state_aware_mask_span_contains_only_braces_spaces_and_newlines() {
        let json = "{\n  \"experimental\": {\n    \"wslc\": { \"image\": \"py\" }\n  },\n  \"phase\": \"provision\"\n}";
        let discriminator: RequestDiscriminator<'_> = config_deserialize::from_str(json).unwrap();
        let raw = discriminator.experimental.unwrap().get();
        let (start, end) = experimental_source_span(json, raw).unwrap();
        let masked = mask_state_aware_experimental(json, discriminator.experimental).unwrap();

        // The masked span replaces content with exactly one `{`, one `}`,
        // spaces, and preserved newlines; everything outside is byte-identical.
        assert_eq!(masked[..start], json[..start]);
        assert_eq!(masked[end..], json[end..]);
        let span = &masked[start..end];
        assert!(span
            .bytes()
            .all(|b| matches!(b, b'{' | b'}' | b' ' | b'\r' | b'\n')));
        assert_eq!(span.bytes().filter(|b| *b == b'{').count(), 1);
        assert_eq!(span.bytes().filter(|b| *b == b'}').count(), 1);
    }

    #[test]
    fn state_aware_rejects_non_object_experimental_block() {
        // `null` maps to "absent" and is accepted (see
        // `state_aware_null_experimental_is_accepted`); only non-null,
        // non-object values are rejected.
        for value in [r#""oops""#, "42", "[]"] {
            let json = format!(r#"{{"phase":"provision","experimental":{value}}}"#);
            let error = match load_mxc(&json) {
                Err(ParseError::StateAware(error)) => error,
                other => panic!("expected state-aware error for {value}, got {other:?}"),
            };
            assert!(
                error
                    .message
                    .ends_with("Invalid configuration at `experimental`: expected an object"),
                "got: {}",
                error.message
            );
        }
    }

    #[test]
    fn state_aware_provision_works_with_no_containment() {
        // Containment is optional at parse time; the dispatcher enforces it
        // (provision needs containment, non-provision uses sandbox_id prefix).
        let json = r#"{"phase": "provision"}"#;
        match load_mxc(json).unwrap() {
            MxcRequest::StateAware(p) => {
                assert_eq!(p.phase, Phase::Provision);
                assert!(p.containment.is_none());
            }
            MxcRequest::OneShot(_) => panic!("expected state-aware"),
        }
    }

    #[test]
    fn minimal_config() {
        let json = r#"{"process": {"commandLine": "echo hello"}}"#;
        let encoded = base64_encode(json.as_bytes());
        let mut logger = test_logger();

        let req = load_request(&encoded, &mut logger, true).unwrap();
        assert_eq!(req.script_code, "echo hello");
        assert_eq!(req.script_timeout, 0);
        assert!(req.working_directory.is_empty());
    }

    #[test]
    fn load_request_from_value_reports_and_logs_typed_error_path() {
        let config = serde_json::json!({
            "process": {
                "commandLine": "echo hello",
                "timeout": "soon"
            }
        });
        let mut logger = test_logger();

        let error = load_request_from_value(config, &mut logger, false).unwrap_err();
        let message = error.to_string();
        assert!(message.contains("Invalid configuration at `process.timeout`"));
        assert!(message.contains("expected u32"));
        assert_eq!(
            logger
                .get_buffer()
                .matches("Invalid configuration at `process.timeout`")
                .count(),
            1
        );
    }

    #[test]
    fn load_request_from_value_preserves_null_sensitive_version_gating() {
        for config in [
            serde_json::json!({
                "version": "0.7.0-alpha",
                "process": {"commandLine": "echo hi"},
                "network": {"egress": null}
            }),
            serde_json::json!({
                "version": "0.7.0-alpha",
                "process": {"commandLine": "echo hi"},
                "runtimeConfig": null
            }),
            serde_json::json!({
                "version": "0.7.0-alpha",
                "process": {"commandLine": "echo hi"},
                "processContainer": {"network": null}
            }),
        ] {
            let mut logger = test_logger();
            assert!(load_request_from_value(config, &mut logger, false).is_err());
        }
    }

    #[test]
    fn missing_process_section() {
        let json = r#"{"containment": "processcontainer"}"#;
        let encoded = base64_encode(json.as_bytes());
        let mut logger = test_logger();

        let result = load_request(&encoded, &mut logger, true);
        assert!(result.is_err());
    }

    #[test]
    fn missing_command_line() {
        let json = r#"{"process": {"cwd": "/tmp"}}"#;
        let encoded = base64_encode(json.as_bytes());
        let mut logger = test_logger();

        let result = load_request(&encoded, &mut logger, true);
        assert!(result.is_err());
    }

    #[test]
    fn empty_command_line() {
        let json = r#"{"process": {"commandLine": ""}}"#;
        let encoded = base64_encode(json.as_bytes());
        let mut logger = test_logger();

        let result = load_request(&encoded, &mut logger, true);
        assert!(result.is_err());
    }

    #[test]
    fn malicious_command_line() {
        let json = r#"{"process": {"commandLine": "echo hello\0world"}}"#;
        let encoded = base64_encode(json.as_bytes());
        let mut logger = test_logger();

        let result = load_request(&encoded, &mut logger, true);
        assert!(result.is_err());
    }

    #[test]
    fn full_config() {
        let json = r#"{
            "containerId": "TestProfile",
            "containment": "processcontainer",
            "process": {
                "commandLine": "dir",
                "cwd": "C:\\temp",
                "timeout": 3000
            },
            "processContainer": {
                "leastPrivilege": true,
                "capabilities": ["internetClient"]
            },
            "filesystem": {
                "readwritePaths": ["C:\\rw"],
                "readonlyPaths": ["C:\\ro"],
                "deniedPaths": ["C:\\denied"]
            },
            "network": {
                "defaultPolicy": "block",
                "enforcementMode": "firewall",
                "allowedHosts": ["example.com"],
                "blockedHosts": ["evil.com"]
            }
        }"#;
        let encoded = base64_encode(json.as_bytes());
        let mut logger = test_logger();

        let req = load_request(&encoded, &mut logger, true).unwrap();
        assert_eq!(req.script_code, "dir");
        assert_eq!(req.working_directory, "C:\\temp");
        assert_eq!(req.script_timeout, 3000);
        assert_eq!(req.container_id, "TestProfile");
        assert!(req.policy.least_privilege_mode);
        assert!(req
            .policy
            .capabilities
            .contains(&"internetClient".to_string()));
        assert_eq!(req.policy.readwrite_paths, vec!["C:\\rw"]);
        assert_eq!(req.policy.readonly_paths, vec!["C:\\ro"]);
        assert_eq!(req.policy.denied_paths, vec!["C:\\denied"]);
        assert_eq!(req.policy.default_network_policy, NetworkPolicy::Block);
        assert_eq!(
            req.policy.network_enforcement_mode,
            NetworkEnforcementMode::Firewall
        );
        assert_eq!(req.policy.allowed_hosts, vec!["example.com"]);
        assert_eq!(req.policy.blocked_hosts, vec!["evil.com"]);
    }

    #[test]
    fn invalid_network_policy() {
        let json =
            r#"{"process": {"commandLine": "echo x"}, "network": {"defaultPolicy": "invalid"}}"#;
        let encoded = base64_encode(json.as_bytes());
        let mut logger = test_logger();

        let err = load_request(&encoded, &mut logger, true).unwrap_err();
        let msg = format!("{err}");
        assert!(
            msg.contains("unknown variant") && msg.contains("invalid"),
            "expected serde unknown-variant rejection, got: {msg}"
        );
        assert!(
            msg.contains("Invalid configuration at `network.defaultPolicy`"),
            "expected the policy path, got: {msg}"
        );
    }

    #[test]
    fn wrong_value_type_reports_path_and_source_location() {
        let json = r#"{
            "process": {
                "commandLine": "echo x",
                "timeout": "soon"
            }
        }"#;
        let encoded = base64_encode(json.as_bytes());
        let mut logger = test_logger();

        let error = load_request(&encoded, &mut logger, true).unwrap_err();
        let message = error.to_string();
        assert!(
            message.contains("Invalid configuration at `process.timeout`"),
            "expected the field path, got: {message}"
        );
        assert!(
            message.contains("invalid type") && message.contains("expected u32"),
            "expected the type mismatch, got: {message}"
        );
        assert!(
            message.contains("line 4"),
            "expected the source line, got: {message}"
        );
        assert_eq!(
            logger
                .get_buffer()
                .lines()
                .filter(|line| line.contains("process.timeout"))
                .count(),
            1,
            "the path-aware diagnostic should be logged once"
        );
    }

    #[test]
    fn state_aware_parse_errors_reach_diagnostic_file_without_stderr_duplication() {
        let directory = tempfile::tempdir().unwrap();
        let log_path = directory.path().join("mxc.log");
        let mut logger = test_logger();
        logger.enable_file_sink(&log_path).unwrap();
        let encoded = base64_encode(br#"{"phase":"teleport"}"#);

        let result = load_mxc_request(&encoded, &mut logger, true);
        assert!(matches!(result, Err(ParseError::StateAware(_))));
        assert!(
            logger.get_buffer().is_empty(),
            "the JSON error envelope owns the primary state-aware output"
        );

        drop(logger);
        let log = std::fs::read_to_string(log_path).unwrap();
        assert!(log.contains("Invalid configuration at `phase`"));
        assert!(log.contains("unknown variant `teleport`"));
    }

    #[test]
    fn out_of_range_value_reports_path() {
        let json =
            r#"{"process":{"commandLine":"echo x"},"network":{"proxy":{"localhost":70000}}}"#;
        let encoded = base64_encode(json.as_bytes());
        let mut logger = test_logger();

        let error = load_request(&encoded, &mut logger, true).unwrap_err();
        let message = error.to_string();
        assert!(
            message.contains("Invalid configuration at `network.proxy.localhost`"),
            "expected the field path, got: {message}"
        );
        assert!(
            message.contains("70000") && message.contains("expected u16"),
            "expected the range mismatch, got: {message}"
        );
    }

    #[test]
    fn malformed_json_is_reported_as_syntax_not_policy_data() {
        let json = r#"{"process":{"commandLine":"echo x"}"#;
        let encoded = base64_encode(json.as_bytes());
        let mut logger = test_logger();

        let error = load_request(&encoded, &mut logger, true).unwrap_err();
        let message = error.to_string();
        assert!(
            message.contains("Invalid JSON syntax:"),
            "expected a syntax error, got: {message}"
        );
        assert!(
            !message.contains("Invalid configuration at"),
            "syntax errors should not claim a policy path: {message}"
        );
    }

    #[test]
    fn invalid_enforcement_mode() {
        let json =
            r#"{"process": {"commandLine": "echo x"}, "network": {"enforcementMode": "invalid"}}"#;
        let encoded = base64_encode(json.as_bytes());
        let mut logger = test_logger();

        let err = load_request(&encoded, &mut logger, true).unwrap_err();
        let msg = format!("{err}");
        assert!(
            msg.contains("unknown variant") && msg.contains("invalid"),
            "expected serde unknown-variant rejection, got: {msg}"
        );
    }

    #[test]
    fn load_from_file() {
        let dir = tempfile::tempdir().unwrap();
        let file_path = dir.path().join("config.json");
        std::fs::write(&file_path, r#"{"process": {"commandLine": "whoami"}}"#).unwrap();

        let mut logger = test_logger();
        let req = load_request(file_path.to_str().unwrap(), &mut logger, false).unwrap();
        assert_eq!(req.script_code, "whoami");
    }

    #[test]
    fn file_not_found() {
        let mut logger = test_logger();
        let result = load_request("nonexistent.json", &mut logger, false);
        assert!(result.is_err());
        assert_eq!(
            logger
                .get_buffer()
                .matches("Configuration file not found: nonexistent.json")
                .count(),
            1
        );
    }

    #[test]
    fn file_not_found_path_with_newline_is_escaped() {
        // A file path is untrusted input and may contain a newline on
        // Linux/macOS; the diagnostic must escape it so it cannot inject a
        // forged multi-line log entry.
        let mut logger = test_logger();
        let result = load_request("missing\nfile.json", &mut logger, false);
        assert!(result.is_err());

        let message = match result.unwrap_err() {
            WxcError::ConfigParse(message) => message,
            other => panic!("expected ConfigParse error, got: {other:?}"),
        };
        assert!(!message.contains('\n'), "raw newline leaked: {message}");
        assert!(message.contains("missing\\nfile.json"), "got: {message}");
    }

    #[test]
    fn empty_file_path_error_is_logged_once() {
        let mut logger = test_logger();
        let result = load_request("", &mut logger, false);
        assert!(result.is_err());
        assert_eq!(
            logger
                .get_buffer()
                .matches("Configuration file not found:")
                .count(),
            1
        );
    }

    #[test]
    fn file_read_error_is_logged_once() {
        let directory = tempfile::tempdir().unwrap();
        let mut logger = test_logger();
        let result = load_request(directory.path().to_str().unwrap(), &mut logger, false);
        assert!(result.is_err());
        assert_eq!(
            logger
                .get_buffer()
                .matches("Failed to read configuration file")
                .count(),
            1
        );
    }

    #[test]
    fn invalid_base64() {
        let mut logger = test_logger();
        let result = load_request("not-valid-base64!!!", &mut logger, true);
        assert!(result.is_err());
        assert_eq!(
            logger
                .get_buffer()
                .lines()
                .filter(|line| line.contains("Failed to decode base64 configuration"))
                .count(),
            1,
            "the fatal diagnostic should be logged once"
        );
    }

    #[test]
    fn console_mode_logs_decode_errors_once() {
        let directory = tempfile::tempdir().unwrap();
        let log_path = directory.path().join("mxc.log");
        let mut logger = Logger::new(Mode::Console);
        logger.enable_file_sink(&log_path).unwrap();

        let result = load_request("not-valid-base64!!!", &mut logger, true);
        assert!(result.is_err());

        drop(logger);
        let log = std::fs::read_to_string(log_path).unwrap();
        assert_eq!(
            log.matches("Failed to decode base64 configuration").count(),
            1,
            "console mode should emit one decode diagnostic"
        );
    }

    #[test]
    fn state_aware_semantic_errors_stay_off_primary_output() {
        let directory = tempfile::tempdir().unwrap();
        let log_path = directory.path().join("mxc.log");
        let mut logger = test_logger();
        logger.enable_file_sink(&log_path).unwrap();
        let encoded = base64_encode(br#"{"phase":"provision","experimental":{"seatbelt":{}}}"#);

        let result = load_mxc_request(&encoded, &mut logger, true);
        assert!(matches!(result, Err(ParseError::StateAware(_))));
        assert!(
            logger.get_buffer().is_empty(),
            "the JSON envelope owns primary state-aware error output"
        );

        drop(logger);
        let log = std::fs::read_to_string(log_path).unwrap();
        assert_eq!(
            log.matches("'experimental.seatbelt' has moved").count(),
            1,
            "state-aware diagnostics should reach auxiliary sinks exactly once"
        );
    }

    #[test]
    fn invalid_json() {
        let encoded = base64_encode(b"{ not json }");
        let mut logger = test_logger();
        let result = load_request(&encoded, &mut logger, true);
        assert!(result.is_err());
        assert!(logger.get_buffer().contains("Invalid JSON syntax:"));
    }

    #[test]
    fn learning_mode_boolean_maps_to_deny_and_record_capability() {
        let json = r#"{"process": {"commandLine": "echo x"}, "containment": "processcontainer", "processContainer": {"learningMode": true}}"#;
        let encoded = base64_encode(json.as_bytes());
        let mut logger = test_logger();

        let req = load_request(&encoded, &mut logger, true).unwrap();
        assert!(req
            .policy
            .capabilities
            .contains(&"learningModeLogging".to_string()));
        // The boolean must NOT inject the allow-all permissive capability.
        assert!(!req
            .policy
            .capabilities
            .contains(&"permissiveLearningMode".to_string()));
    }

    #[test]
    fn explicit_learning_mode_capabilities_are_rejected_case_insensitively() {
        for capability in [
            "learningModeLogging",
            "LearningModeLogging",
            "permissiveLearningMode",
            "PERMISSIVELEARNINGMODE",
        ] {
            let json = format!(
                r#"{{"process": {{"commandLine": "echo x"}}, "containment": "processcontainer", "processContainer": {{"capabilities": ["{capability}"]}}}}"#
            );
            let encoded = base64_encode(json.as_bytes());
            let mut logger = test_logger();

            let error = load_request(&encoded, &mut logger, true)
                .expect_err("reserved learning-mode capability must be rejected");
            let message = error.to_string();
            assert!(message.contains("reserved learning-mode capability"));
            assert!(message.contains(capability));
        }
    }

    #[test]
    fn comma_delimited_capability_entries_are_rejected() {
        for capability in [
            "internetClient,permissiveLearningMode",
            "learningModeLogging,internetClient",
            "internetClient,privateNetworkClientServer",
        ] {
            let json = format!(
                r#"{{"process": {{"commandLine": "echo x"}}, "containment": "processcontainer", "processContainer": {{"capabilities": ["{capability}"]}}}}"#
            );
            let encoded = base64_encode(json.as_bytes());
            let mut logger = test_logger();

            let error = load_request(&encoded, &mut logger, true)
                .expect_err("comma-delimited capability entry must be rejected");
            let message = error.to_string();
            assert!(message.contains("must not contain a comma"));
            assert!(message.contains("separate JSON array entries"));
            assert!(message.contains(capability));
        }
    }

    // ====== Tests ported from C++ ConfigurationParserTests.cpp ======

    #[test]
    fn script_with_timeout() {
        let json =
            r#"{"process": {"commandLine": "import sys\nprint(sys.version)", "timeout": 60000}}"#;
        let encoded = base64_encode(json.as_bytes());
        let mut logger = test_logger();

        let req = load_request(&encoded, &mut logger, true).unwrap();
        assert_eq!(req.script_timeout, 60000);
    }

    #[test]
    fn process_container_capabilities() {
        let json = r#"{
            "process": {"commandLine": "print('test')"},
            "containment": "processcontainer",
            "processContainer": {
                "capabilities": ["internetClient", "privateNetworkClientServer", "documentsLibrary"]
            }
        }"#;
        let encoded = base64_encode(json.as_bytes());
        let mut logger = test_logger();

        let req = load_request(&encoded, &mut logger, true).unwrap();
        assert_eq!(req.policy.capabilities.len(), 3);
        assert_eq!(req.policy.capabilities[0], "internetClient");
        assert_eq!(req.policy.capabilities[1], "privateNetworkClientServer");
        assert_eq!(req.policy.capabilities[2], "documentsLibrary");
    }

    #[test]
    fn capture_denials_absent_leaves_policy_none() {
        let json = r#"{
            "process": {"commandLine": "print('test')"},
            "containment": "processcontainer",
            "processContainer": {}
        }"#;
        let encoded = base64_encode(json.as_bytes());
        let mut logger = test_logger();
        let req = load_request(&encoded, &mut logger, true).unwrap();
        assert!(req.policy.capture_denials.is_none());
    }

    #[test]
    fn capture_denials_presence_enables_capture_without_path() {
        let json = r#"{
            "process": {"commandLine": "print('test')"},
            "containment": "processcontainer",
            "processContainer": {"captureDenials": {}}
        }"#;
        let encoded = base64_encode(json.as_bytes());
        let mut logger = test_logger();
        let req = load_request(&encoded, &mut logger, true).unwrap();
        let cd = req
            .policy
            .capture_denials
            .expect("captureDenials presence should enable capture");
        assert!(cd.output_path.is_none());
        assert!(!cd.retain_etl);
        // Omitting `mode` defaults to the safe block behavior.
        assert_eq!(cd.mode, CaptureDenialsMode::Block);
    }

    #[test]
    fn capture_denials_retain_etl_is_parsed() {
        let json = r#"{
            "process": {"commandLine": "print('test')"},
            "containment": "processcontainer",
            "processContainer": {"captureDenials": {"retainEtl": true}}
        }"#;
        let encoded = base64_encode(json.as_bytes());
        let mut logger = test_logger();
        let req = load_request(&encoded, &mut logger, true).unwrap();
        let cd = req.policy.capture_denials.expect("captureDenials present");
        assert!(cd.retain_etl);
    }

    #[test]
    fn capture_denials_mode_block_is_parsed() {
        let json = r#"{
            "process": {"commandLine": "print('test')"},
            "containment": "processcontainer",
            "processContainer": {"captureDenials": {"mode": "block"}}
        }"#;
        let encoded = base64_encode(json.as_bytes());
        let mut logger = test_logger();
        let req = load_request(&encoded, &mut logger, true).unwrap();
        let cd = req.policy.capture_denials.expect("captureDenials present");
        assert_eq!(cd.mode, CaptureDenialsMode::Block);
    }

    #[test]
    fn capture_denials_mode_allow_is_parsed() {
        let json = r#"{
            "process": {"commandLine": "print('test')"},
            "containment": "processcontainer",
            "processContainer": {"captureDenials": {"mode": "allow"}}
        }"#;
        let encoded = base64_encode(json.as_bytes());
        let mut logger = test_logger();
        let req = load_request(&encoded, &mut logger, true).unwrap();
        let cd = req.policy.capture_denials.expect("captureDenials present");
        assert_eq!(cd.mode, CaptureDenialsMode::Allow);
    }

    #[test]
    fn capture_denials_block_injects_learning_mode_logging_capability() {
        let json = r#"{
            "process": {"commandLine": "print('test')"},
            "containment": "processcontainer",
            "processContainer": {"captureDenials": {"mode": "block"}}
        }"#;
        let encoded = base64_encode(json.as_bytes());
        let mut logger = test_logger();
        let req = load_request(&encoded, &mut logger, true).unwrap();
        assert!(
            req.policy
                .capabilities
                .contains(&"learningModeLogging".to_string()),
            "block capture must additively inject learningModeLogging: {:?}",
            req.policy.capabilities
        );
        assert!(
            !req.policy
                .capabilities
                .contains(&"permissiveLearningMode".to_string()),
            "block must not inject permissiveLearningMode"
        );
    }

    #[test]
    fn capture_denials_allow_injects_permissive_learning_mode_capability() {
        let json = r#"{
            "process": {"commandLine": "print('test')"},
            "containment": "processcontainer",
            "processContainer": {"captureDenials": {"mode": "allow"}}
        }"#;
        let encoded = base64_encode(json.as_bytes());
        let mut logger = test_logger();
        let req = load_request(&encoded, &mut logger, true).unwrap();
        assert!(
            req.policy
                .capabilities
                .contains(&"permissiveLearningMode".to_string()),
            "allow capture must inject permissiveLearningMode: {:?}",
            req.policy.capabilities
        );
    }

    #[test]
    fn capture_denials_default_injects_learning_mode_logging_capability() {
        let json = r#"{
            "process": {"commandLine": "print('test')"},
            "containment": "processcontainer",
            "processContainer": {"captureDenials": {}}
        }"#;
        let encoded = base64_encode(json.as_bytes());
        let mut logger = test_logger();
        let req = load_request(&encoded, &mut logger, true).unwrap();
        assert!(
            req.policy
                .capabilities
                .contains(&"learningModeLogging".to_string()),
            "default (block) capture must inject learningModeLogging: {:?}",
            req.policy.capabilities
        );
    }

    #[test]
    fn capture_denials_allow_overrides_learning_mode_boolean() {
        let json = r#"{
            "process": {"commandLine": "print('test')"},
            "containment": "processcontainer",
            "processContainer": {
                "learningMode": true,
                "capabilities": ["internetClient"],
                "captureDenials": {"mode": "allow"}
            }
        }"#;
        let encoded = base64_encode(json.as_bytes());
        let mut logger = test_logger();
        let req = load_request(&encoded, &mut logger, true).unwrap();
        assert!(
            req.policy
                .capabilities
                .contains(&"internetClient".to_string()),
            "the workload's own capabilities must be preserved"
        );
        assert!(
            req.policy
                .capabilities
                .contains(&"permissiveLearningMode".to_string()),
            "allow capture must inject permissiveLearningMode"
        );
        assert!(
            !req.policy
                .capabilities
                .contains(&"learningModeLogging".to_string()),
            "allow capture must remove deny-and-record mode"
        );
        assert!(
            !logger.get_buffer().contains("restrictions remain enforced"),
            "parser must not log the superseded deny-and-record mode"
        );
    }

    #[test]
    fn capture_denials_unknown_mode_rejected() {
        let json = r#"{
            "process": {"commandLine": "print('test')"},
            "containment": "processcontainer",
            "processContainer": {"captureDenials": {"mode": "audit"}}
        }"#;
        let encoded = base64_encode(json.as_bytes());
        let mut logger = test_logger();
        let err = load_request(&encoded, &mut logger, true)
            .expect_err("an unknown captureDenials mode must be rejected");
        // serde surfaces the accepted variants; the message must name both so
        // the error is actionable.
        let msg = format!("{err:?}");
        assert!(
            msg.contains("block") && msg.contains("allow"),
            "error should list the valid modes: {msg}"
        );
    }

    #[test]
    fn capture_denials_accepts_valid_absolute_output_path() {
        let dir = tempfile::tempdir().expect("temp dir");
        let path = dir.path().join("denials.json");
        let path_json = serde_json::to_string(&path.to_string_lossy()).unwrap();
        let json = format!(
            r#"{{
                "process": {{"commandLine": "print('test')"}},
                "containment": "processcontainer",
                "processContainer": {{"captureDenials": {{"outputPath": {path_json}}}}}
            }}"#
        );
        let encoded = base64_encode(json.as_bytes());
        let mut logger = test_logger();
        let req = load_request(&encoded, &mut logger, true).unwrap();
        let cd = req.policy.capture_denials.expect("captureDenials present");
        assert_eq!(
            cd.output_path.as_deref(),
            Some(path.to_string_lossy().as_ref())
        );
    }

    #[test]
    fn capture_denials_relative_output_path_rejected() {
        let json = r#"{
            "process": {"commandLine": "print('test')"},
            "containment": "processcontainer",
            "processContainer": {"captureDenials": {"outputPath": "relative/denials.json"}}
        }"#;
        let encoded = base64_encode(json.as_bytes());
        let mut logger = test_logger();
        let err = load_request(&encoded, &mut logger, true)
            .expect_err("a relative outputPath must be rejected");
        assert!(
            format!("{err:?}").contains("absolute"),
            "error should mention the absolute-path requirement: {err:?}"
        );
    }

    #[test]
    fn capture_denials_missing_parent_dir_rejected() {
        let dir = tempfile::tempdir().expect("temp dir");
        // Parent directory `nonexistent` is never created.
        let path = dir.path().join("nonexistent").join("denials.json");
        let path_json = serde_json::to_string(&path.to_string_lossy()).unwrap();
        let json = format!(
            r#"{{
                "process": {{"commandLine": "print('test')"}},
                "containment": "processcontainer",
                "processContainer": {{"captureDenials": {{"outputPath": {path_json}}}}}
            }}"#
        );
        let encoded = base64_encode(json.as_bytes());
        let mut logger = test_logger();
        let err = load_request(&encoded, &mut logger, true)
            .expect_err("an outputPath whose parent is missing must be rejected");
        assert!(
            format!("{err:?}").contains("parent directory does not"),
            "error should mention the missing parent directory: {err:?}"
        );
    }

    #[test]
    fn capture_denials_filesystem_root_output_path_rejected() {
        // A bare filesystem root has no parent (`Path::parent()` == None) and
        // cannot name a trace file. Use a platform-appropriate root.
        let root = if cfg!(windows) { "C:\\" } else { "/" };
        let root_json = serde_json::to_string(root).unwrap();
        let json = format!(
            r#"{{
                "process": {{"commandLine": "print('test')"}},
                "containment": "processcontainer",
                "processContainer": {{"captureDenials": {{"outputPath": {root_json}}}}}
            }}"#
        );
        let encoded = base64_encode(json.as_bytes());
        let mut logger = test_logger();
        let err = load_request(&encoded, &mut logger, true)
            .expect_err("a filesystem-root outputPath must be rejected");
        assert!(
            format!("{err:?}").contains("directory root"),
            "error should mention the directory-root rejection: {err:?}"
        );
    }

    #[test]
    fn capture_denials_existing_directory_output_path_rejected() {
        let dir = tempfile::tempdir().expect("temp dir");
        let path_json = serde_json::to_string(&dir.path().to_string_lossy()).unwrap();
        let json = format!(
            r#"{{
                "process": {{"commandLine": "print('test')"}},
                "containment": "processcontainer",
                "processContainer": {{"captureDenials": {{"outputPath": {path_json}}}}}
            }}"#
        );
        let encoded = base64_encode(json.as_bytes());
        let mut logger = test_logger();

        let err = load_request(&encoded, &mut logger, true)
            .expect_err("an existing directory outputPath must be rejected");
        assert!(
            format!("{err:?}").contains("existing directory"),
            "error should identify the directory path: {err:?}"
        );
    }

    #[test]
    fn least_privilege_mode() {
        let json = r#"{"process": {"commandLine": "print('test')"}, "containment": "processcontainer", "processContainer": {"leastPrivilege": true}}"#;
        let encoded = base64_encode(json.as_bytes());
        let mut logger = test_logger();

        let req = load_request(&encoded, &mut logger, true).unwrap();
        assert!(req.policy.least_privilege_mode);
    }

    #[test]
    fn network_default_policy_allow() {
        let json = r#"{"process": {"commandLine": "print('test')"}, "network": {"defaultPolicy": "allow"}}"#;
        let encoded = base64_encode(json.as_bytes());
        let mut logger = test_logger();

        let req = load_request(&encoded, &mut logger, true).unwrap();
        assert_eq!(req.policy.default_network_policy, NetworkPolicy::Allow);
    }

    #[test]
    fn network_default_policy_block() {
        let json = r#"{"process": {"commandLine": "print('test')"}, "network": {"defaultPolicy": "block"}}"#;
        let encoded = base64_encode(json.as_bytes());
        let mut logger = test_logger();

        let req = load_request(&encoded, &mut logger, true).unwrap();
        assert_eq!(req.policy.default_network_policy, NetworkPolicy::Block);
    }

    #[test]
    fn network_default_policy_absent_defaults_to_block_on_any_version() {
        // wxc-exec is the trust boundary -- absent `defaultPolicy`
        // resolves to `Block` regardless of declared schema version.
        for version in ["0.6.0-alpha", "0.7.0-alpha", "0.8.0-alpha", "0.9.0-alpha"] {
            let json = format!(
                r#"{{"version": "{}", "process": {{"commandLine": "echo x"}}}}"#,
                version
            );
            let encoded = base64_encode(json.as_bytes());
            let mut logger = test_logger();
            let req = load_request(&encoded, &mut logger, true).unwrap();
            assert_eq!(
                req.policy.default_network_policy,
                NetworkPolicy::Block,
                "version {} should default to Block",
                version
            );
        }
    }

    #[test]
    fn network_enforcement_mode_capabilities() {
        let json = r#"{"process": {"commandLine": "print('test')"}, "network": {"enforcementMode": "capabilities"}}"#;
        let encoded = base64_encode(json.as_bytes());
        let mut logger = test_logger();

        let req = load_request(&encoded, &mut logger, true).unwrap();
        assert_eq!(
            req.policy.network_enforcement_mode,
            NetworkEnforcementMode::Capabilities
        );
    }

    #[test]
    fn network_enforcement_mode_firewall() {
        let json = r#"{"process": {"commandLine": "print('test')"}, "network": {"enforcementMode": "firewall"}}"#;
        let encoded = base64_encode(json.as_bytes());
        let mut logger = test_logger();

        let req = load_request(&encoded, &mut logger, true).unwrap();
        assert_eq!(
            req.policy.network_enforcement_mode,
            NetworkEnforcementMode::Firewall
        );
    }

    #[test]
    fn network_enforcement_mode_both() {
        let json = r#"{"process": {"commandLine": "print('test')"}, "network": {"enforcementMode": "both"}}"#;
        let encoded = base64_encode(json.as_bytes());
        let mut logger = test_logger();

        let req = load_request(&encoded, &mut logger, true).unwrap();
        assert_eq!(
            req.policy.network_enforcement_mode,
            NetworkEnforcementMode::Both
        );
    }

    #[test]
    fn network_hosts() {
        let json = r#"{
            "process": {"commandLine": "print('test')"},
            "network": {
                "allowedHosts": ["example.com", "api.trusted.com"],
                "blockedHosts": ["malicious.com", "tracker.net"]
            }
        }"#;
        let encoded = base64_encode(json.as_bytes());
        let mut logger = test_logger();

        let req = load_request(&encoded, &mut logger, true).unwrap();
        assert_eq!(req.policy.allowed_hosts.len(), 2);
        assert_eq!(req.policy.allowed_hosts[0], "example.com");
        assert_eq!(req.policy.allowed_hosts[1], "api.trusted.com");
        assert_eq!(req.policy.blocked_hosts.len(), 2);
        assert_eq!(req.policy.blocked_hosts[0], "malicious.com");
        assert_eq!(req.policy.blocked_hosts[1], "tracker.net");
    }

    #[test]
    fn network_allow_local_network() {
        let json = r#"{
            "process": {"commandLine": "print('test')"},
            "network": {"allowLocalNetwork": true}
        }"#;
        let encoded = base64_encode(json.as_bytes());
        let mut logger = test_logger();

        let req = load_request(&encoded, &mut logger, true).unwrap();
        assert!(req.policy.allow_local_network);
    }

    #[test]
    fn network_allow_local_network_defaults_false() {
        let json = r#"{
            "process": {"commandLine": "print('test')"},
            "network": {}
        }"#;
        let encoded = base64_encode(json.as_bytes());
        let mut logger = test_logger();

        let req = load_request(&encoded, &mut logger, true).unwrap();
        assert!(!req.policy.allow_local_network);
    }

    #[test]
    fn network_specified_true_when_network_present() {
        // An empty `network: {}` object still counts as "supplied".
        let json = r#"{
            "process": {"commandLine": "echo x"},
            "network": {}
        }"#;
        let encoded = base64_encode(json.as_bytes());
        let mut logger = test_logger();

        let req = load_request(&encoded, &mut logger, true).unwrap();
        assert!(req.policy.network_specified);
    }

    #[test]
    fn network_specified_false_when_network_absent() {
        let json = r#"{"process": {"commandLine": "echo x"}}"#;
        let encoded = base64_encode(json.as_bytes());
        let mut logger = test_logger();

        let req = load_request(&encoded, &mut logger, true).unwrap();
        assert!(!req.policy.network_specified);
    }

    #[test]
    fn ui_specified_true_when_ui_present() {
        // An empty `ui: {}` still counts as "supplied" — the twin of
        // `network_specified`. Backends with no UI primitive refuse on
        // presence, because `UiPolicy::default()` is full lockdown and so an
        // explicit lockdown `ui` is indistinguishable from an absent one.
        let json = r#"{"process": {"commandLine": "echo x"}, "ui": {}}"#;
        let encoded = base64_encode(json.as_bytes());
        let mut logger = test_logger();

        let req = load_request(&encoded, &mut logger, true).unwrap();
        assert!(req.policy.ui_specified);
    }

    #[test]
    fn ui_specified_false_when_ui_absent() {
        let json = r#"{"process": {"commandLine": "echo x"}}"#;
        let encoded = base64_encode(json.as_bytes());
        let mut logger = test_logger();

        let req = load_request(&encoded, &mut logger, true).unwrap();
        assert!(!req.policy.ui_specified);
    }

    #[test]
    fn ui_specified_true_on_state_aware_requests() {
        let json = r#"{
            "phase": "provision",
            "containment": "isolation_session",
            "ui": {"disable": true}
        }"#;
        match load_mxc(json).unwrap() {
            MxcRequest::StateAware(p) => assert!(p.request.policy.ui_specified),
            other => panic!("expected state-aware request, got {other:?}"),
        }
    }

    #[test]
    fn filesystem_paths() {
        let json = r#"{
            "process": {"commandLine": "print('test')"},
            "filesystem": {
                "readwritePaths": ["C:\\Users\\Public", "C:\\Temp\\Data"],
                "deniedPaths": ["C:\\Windows\\System32", "C:\\Program Files"]
            }
        }"#;
        let encoded = base64_encode(json.as_bytes());
        let mut logger = test_logger();

        let req = load_request(&encoded, &mut logger, true).unwrap();
        assert_eq!(req.policy.readwrite_paths.len(), 2);
        assert_eq!(req.policy.readwrite_paths[0], "C:\\Users\\Public");
        assert_eq!(req.policy.readwrite_paths[1], "C:\\Temp\\Data");
        assert_eq!(req.policy.denied_paths.len(), 2);
        assert_eq!(req.policy.denied_paths[0], "C:\\Windows\\System32");
        assert_eq!(req.policy.denied_paths[1], "C:\\Program Files");
    }

    #[test]
    fn block_evil_filesystem_paths() {
        let json = r#"{
            "process": {"commandLine": "print('test')"},
            "filesystem": {
                "readwritePaths": ["C:\\My \"Evil\\Path"]
            }
        }"#;
        let encoded = base64_encode(json.as_bytes());
        let mut logger = test_logger();

        let result = load_request(&encoded, &mut logger, true);
        assert!(result.is_err());
    }

    /// A blank grant names nothing, and previously flowed through to backends
    /// that treat an empty path as "unset" (e.g. a NULL working directory).
    #[test]
    fn block_blank_filesystem_paths() {
        for blank in ["", "   "] {
            let json = format!(
                r#"{{
                "process": {{"commandLine": "print('test')"}},
                "filesystem": {{ "readwritePaths": ["{blank}", "C:\\workspace"] }}
            }}"#
            );
            let encoded = base64_encode(json.as_bytes());
            let mut logger = test_logger();

            let result = load_request(&encoded, &mut logger, true);
            let err = result.expect_err("blank path should be rejected");
            assert!(
                format!("{err}").contains("empty"),
                "unexpected error for {blank:?}: {err}"
            );
        }
    }

    /// An interior NUL truncates the path once converted to a C/UTF-16 string,
    /// so the grant enforced would not be the one requested.
    #[test]
    fn block_filesystem_paths_with_embedded_nul() {
        let json = r#"{
            "process": {"commandLine": "print('test')"},
            "filesystem": {
                "readonlyPaths": ["C:\\workspace\u0000\\..\\secrets"]
            }
        }"#;
        let encoded = base64_encode(json.as_bytes());
        let mut logger = test_logger();

        let result = load_request(&encoded, &mut logger, true);
        let err = result.expect_err("embedded NUL should be rejected");
        assert!(format!("{err}").contains("NUL"), "unexpected error: {err}");
    }

    #[test]
    fn base64_complex_config() {
        let json = r#"{
            "containerId": "TestContainer",
            "containment": "processcontainer",
            "process": {
                "commandLine": "import sys\nprint(sys.version)",
                "timeout": 10000
            },
            "processContainer": {
                "capabilities": ["internetClient", "privateNetworkClientServer"]
            }
        }"#;
        let encoded = base64_encode(json.as_bytes());
        let mut logger = test_logger();

        let req = load_request(&encoded, &mut logger, true).unwrap();
        assert_eq!(req.script_code, "import sys\nprint(sys.version)");
        assert_eq!(req.script_timeout, 10000);
        assert_eq!(req.container_id, "TestContainer");
        assert_eq!(req.policy.capabilities.len(), 2);
    }

    #[test]
    fn invalid_json_syntax() {
        let json = r#"{"process": {"commandLine": "print('test')"}, INVALID_JSON}"#;
        let encoded = base64_encode(json.as_bytes());
        let mut logger = test_logger();

        let result = load_request(&encoded, &mut logger, true);
        assert!(result.is_err());
    }

    #[test]
    fn default_timeout_is_zero() {
        let json = r#"{"process": {"commandLine": "echo hello"}}"#;
        let encoded = base64_encode(json.as_bytes());
        let mut logger = test_logger();

        let req = load_request(&encoded, &mut logger, true).unwrap();
        assert_eq!(req.script_timeout, 0);
    }

    #[test]
    fn allow_dacl_mutation_default_true() {
        let json = r#"{"process": {"commandLine": "echo hi"}}"#;
        let encoded = base64_encode(json.as_bytes());
        let mut logger = test_logger();
        let req = load_request(&encoded, &mut logger, true).unwrap();
        assert!(req.policy.fallback.allow_dacl_mutation);
    }

    #[test]
    fn allow_dacl_mutation_explicit_false() {
        let json = r#"{
            "process": {"commandLine": "echo hi"},
            "fallback": {"allowDaclMutation": false}
        }"#;
        let encoded = base64_encode(json.as_bytes());
        let mut logger = test_logger();
        let req = load_request(&encoded, &mut logger, true).unwrap();
        assert!(!req.policy.fallback.allow_dacl_mutation);
    }

    #[test]
    fn allow_dacl_mutation_explicit_true() {
        let json = r#"{
            "process": {"commandLine": "echo hi"},
            "fallback": {"allowDaclMutation": true}
        }"#;
        let encoded = base64_encode(json.as_bytes());
        let mut logger = test_logger();
        let req = load_request(&encoded, &mut logger, true).unwrap();
        assert!(req.policy.fallback.allow_dacl_mutation);
    }

    // ====== Containment backend selection tests ======

    #[test]
    fn default_containment_resolves_per_target() {
        // Omitted `containment` resolves to the OS-native process sandbox:
        // ProcessContainer on Windows, Bubblewrap on Linux, Seatbelt on macOS.
        let json = r#"{"process": {"commandLine": "echo hello"}}"#;
        let encoded = base64_encode(json.as_bytes());
        let mut logger = test_logger();

        let req = load_request(&encoded, &mut logger, true).unwrap();

        #[cfg(target_os = "linux")]
        assert_eq!(req.containment, ContainmentBackend::Bubblewrap);
        #[cfg(target_os = "macos")]
        assert_eq!(req.containment, ContainmentBackend::Seatbelt);
        #[cfg(not(any(target_os = "linux", target_os = "macos")))]
        assert_eq!(req.containment, ContainmentBackend::ProcessContainer);
    }

    #[test]
    fn explicit_processcontainer_containment() {
        let json =
            r#"{"process": {"commandLine": "echo hello"}, "containment": "processcontainer"}"#;
        let encoded = base64_encode(json.as_bytes());
        let mut logger = test_logger();

        let req = load_request(&encoded, &mut logger, true).unwrap();
        assert_eq!(req.containment, ContainmentBackend::ProcessContainer);
    }

    #[test]
    fn process_containment_resolves_per_target() {
        // Abstract intent "process" resolves to the OS-native process sandbox:
        // ProcessContainer on Windows, Bubblewrap on Linux, Seatbelt on macOS.
        // Callers who want LXC (a full container) must request it explicitly
        // via `"containment": "lxc"`.
        let json = r#"{"process": {"commandLine": "echo hello"}, "containment": "process"}"#;
        let encoded = base64_encode(json.as_bytes());
        let mut logger = test_logger();

        let req = load_request(&encoded, &mut logger, true).unwrap();

        #[cfg(target_os = "linux")]
        assert_eq!(req.containment, ContainmentBackend::Bubblewrap);
        #[cfg(target_os = "macos")]
        assert_eq!(req.containment, ContainmentBackend::Seatbelt);
        #[cfg(not(any(target_os = "linux", target_os = "macos")))]
        assert_eq!(req.containment, ContainmentBackend::ProcessContainer);
    }

    #[test]
    fn explicit_lxc_containment_unaffected_by_default_shift() {
        // Regression guard: making bubblewrap the Linux default for the
        // abstract `"process"` intent must NOT change how explicit `"lxc"`
        // resolves. LXC remains available to any caller that asks for it.
        let json = r#"{"process": {"commandLine": "echo hello"}, "containment": "lxc"}"#;
        let encoded = base64_encode(json.as_bytes());
        let mut logger = test_logger();

        let req = load_request(&encoded, &mut logger, true).unwrap();
        assert_eq!(req.containment, ContainmentBackend::Lxc);
    }

    #[test]
    fn explicit_bubblewrap_containment_parses_cleanly() {
        // Bubblewrap no longer requires gating in the parser/SDK; explicit
        // `"bubblewrap"` should parse to the concrete backend on every
        // target without error. (Host availability is checked at runtime by
        // the runner, not here.)
        let json = r#"{"process": {"commandLine": "echo hello"}, "containment": "bubblewrap"}"#;
        let encoded = base64_encode(json.as_bytes());
        let mut logger = test_logger();

        let req = load_request(&encoded, &mut logger, true).unwrap();
        assert_eq!(req.containment, ContainmentBackend::Bubblewrap);
    }

    #[test]
    fn hyperlight_containment_value_parses() {
        // Lock in that `"hyperlight"` is accepted by the parser (the
        // `map_wire_containment` arm handles both one-shot and state-aware).
        let json = r#"{"process": {"commandLine": "echo hello"}, "containment": "hyperlight"}"#;
        let encoded = base64_encode(json.as_bytes());
        let mut logger = test_logger();

        let req = load_request(&encoded, &mut logger, true).unwrap();
        assert_eq!(req.containment, ContainmentBackend::Hyperlight);
    }

    #[test]
    fn vm_containment_resolves_per_target() {
        // Abstract intent "vm" resolves to Windows Sandbox on Windows. On
        // other targets there is no concrete VM backend yet, so the parser
        // returns the historical `Vm` placeholder variant which the host
        // binaries surface as a "not implemented" error.
        let json = r#"{"process": {"commandLine": "echo hello"}, "containment": "vm"}"#;
        let encoded = base64_encode(json.as_bytes());
        let mut logger = test_logger();

        let req = load_request(&encoded, &mut logger, true).unwrap();

        #[cfg(target_os = "windows")]
        assert_eq!(req.containment, ContainmentBackend::WindowsSandbox);
        #[cfg(not(target_os = "windows"))]
        assert_eq!(req.containment, ContainmentBackend::Vm);
    }

    #[test]
    fn sandbox_containment() {
        let json =
            r#"{"process": {"commandLine": "echo hello"}, "containment": "windows_sandbox"}"#;
        let encoded = base64_encode(json.as_bytes());
        let mut logger = test_logger();

        let req = load_request(&encoded, &mut logger, true).unwrap();
        assert_eq!(req.containment, ContainmentBackend::WindowsSandbox);
    }

    #[test]
    fn invalid_containment_value() {
        let json = r#"{"process": {"commandLine": "echo hello"}, "containment": "docker"}"#;
        let encoded = base64_encode(json.as_bytes());
        let mut logger = test_logger();

        let err = load_request(&encoded, &mut logger, true).unwrap_err();
        let msg = format!("{err}");
        assert!(
            msg.contains("unknown variant") && msg.contains("docker"),
            "expected serde unknown-variant rejection, got: {msg}"
        );
    }

    #[test]
    fn sandbox_config_defaults() {
        let json = r#"{"process": {"commandLine": "echo hello"}, "containment": "windows_sandbox", "experimental": {"windows_sandbox": {}}}"#;
        let encoded = base64_encode(json.as_bytes());
        let mut logger = test_logger();

        let req = load_request(&encoded, &mut logger, true).unwrap();
        let sandbox = req.experimental.windows_sandbox.unwrap();
        assert_eq!(sandbox.idle_timeout_ms, 300_000);
        assert_eq!(sandbox.daemon_pipe_name, "wxc-windows-sandbox");
    }

    #[test]
    fn sandbox_config_custom_values() {
        let json = r#"{
            "process": {"commandLine": "echo hello"},
            "containment": "windows_sandbox",
            "experimental": {
                "windows_sandbox": {
                    "idleTimeoutMs": 60000,
                    "daemonPipeName": "my-custom-pipe"
                }
            }
        }"#;
        let encoded = base64_encode(json.as_bytes());
        let mut logger = test_logger();

        let req = load_request(&encoded, &mut logger, true).unwrap();
        let sandbox = req.experimental.windows_sandbox.unwrap();
        assert_eq!(sandbox.idle_timeout_ms, 60000);
        assert_eq!(sandbox.daemon_pipe_name, "my-custom-pipe");
    }

    // ====== Network proxy configuration tests ======

    #[test]
    fn no_proxy_leaves_default() {
        let json =
            r#"{"process": {"commandLine": "echo test"}, "network": {"defaultPolicy": "block"}}"#;
        let encoded = base64_encode(json.as_bytes());
        let mut logger = test_logger();

        let req = load_request(&encoded, &mut logger, true).unwrap();
        assert!(!req.policy.network_proxy.is_enabled());
    }

    #[test]
    fn proxy_localhost_port() {
        let json = r#"{
            "process": {"commandLine": "echo test"},
            "containment": "processcontainer",
            "network": {
                "proxy": { "localhost": 8080 }
            }
        }"#;
        let encoded = base64_encode(json.as_bytes());
        let mut logger = test_logger();

        let req = load_request(&encoded, &mut logger, true).unwrap();
        assert!(req.policy.network_proxy.is_enabled());
        assert_eq!(
            req.policy.network_proxy.address.as_ref().unwrap().port(),
            8080
        );
    }

    #[test]
    fn proxy_url_parsed() {
        let json = r#"{
            "process": {"commandLine": "echo test"},
            "containment": "processcontainer",
            "network": {
                "proxy": { "url": "http://localhost:3128" }
            }
        }"#;
        let encoded = base64_encode(json.as_bytes());
        let mut logger = test_logger();

        let req = load_request(&encoded, &mut logger, true).unwrap();
        assert!(req.policy.network_proxy.is_enabled());
        let addr = req.policy.network_proxy.address.as_ref().unwrap();
        assert_eq!(addr.port(), 3128);
        assert_eq!(addr.host(), "localhost");
    }

    #[test]
    fn proxy_url_non_localhost() {
        let json = r#"{
            "process": {"commandLine": "echo test"},
            "containment": "processcontainer",
            "network": {
                "proxy": { "url": "http://proxy.example.com:8080" }
            }
        }"#;
        let encoded = base64_encode(json.as_bytes());
        let mut logger = test_logger();

        let req = load_request(&encoded, &mut logger, true).unwrap();
        let addr = req.policy.network_proxy.address.as_ref().unwrap();
        assert_eq!(addr.port(), 8080);
        assert_eq!(addr.host(), "proxy.example.com");
    }

    #[test]
    fn proxy_url_missing_port() {
        let json =
            r#"{"process":{"commandLine":"x"},"network":{"proxy":{"url":"http://localhost"}}}"#;
        let encoded = base64_encode(json.as_bytes());
        let mut logger = test_logger();

        let result = load_request(&encoded, &mut logger, true);
        assert!(result.is_err());
    }

    #[test]
    fn proxy_url_ipv6_loopback() {
        let json = r#"{
            "process": {"commandLine": "echo test"},
            "containment": "processcontainer",
            "network": {
                "proxy": { "url": "http://[::1]:8080" }
            }
        }"#;
        let encoded = base64_encode(json.as_bytes());
        let mut logger = test_logger();

        let req = load_request(&encoded, &mut logger, true).unwrap();
        let addr = req.policy.network_proxy.address.as_ref().unwrap();
        assert_eq!(addr.port(), 8080);
        assert_eq!(addr.host(), "[::1]");
    }

    #[test]
    fn proxy_with_firewall_fields() {
        let json = r#"{
            "process": {"commandLine": "echo test"},
            "containment": "processcontainer",
            "network": {
                "defaultPolicy": "block",
                "allowedHosts": ["api.github.com"],
                "proxy": { "localhost": 9090 }
            }
        }"#;
        let encoded = base64_encode(json.as_bytes());
        let mut logger = test_logger();

        let req = load_request(&encoded, &mut logger, true).unwrap();
        assert_eq!(
            req.policy.network_proxy.address.as_ref().unwrap().port(),
            9090
        );
        assert_eq!(req.policy.default_network_policy, NetworkPolicy::Block);
    }

    #[test]
    fn proxy_rejected_with_an_unsupported_backend() {
        let json = r#"{"process":{"commandLine":"x"},"containment":"vm","network":{"proxy":{"localhost":8080}}}"#;
        let encoded = base64_encode(json.as_bytes());
        let mut logger = test_logger();

        let err = load_request(&encoded, &mut logger, true).unwrap_err();
        assert!(
            format!("{}", err).contains("Network proxy is only supported"),
            "expected the supported-backend gate to reject 'vm', got: {}",
            err
        );
    }

    #[test]
    fn proxy_accepted_with_lxc() {
        // LXC requires a routable proxy host: localhost/127.0.0.1 is the
        // container loopback and unreachable, so use network.proxy.url.
        // A firewall mode is required, because that is what makes the proxy an
        // exception to deny-all rather than an unenforced suggestion.
        let json = r#"{"process":{"commandLine":"x"},"containment":"lxc","network":{"proxy":{"url":"http://proxy.example.com:8080"},"enforcementMode":"firewall"}}"#;
        let encoded = base64_encode(json.as_bytes());
        let mut logger = test_logger();

        let req = load_request(&encoded, &mut logger, true).unwrap();
        assert!(req.policy.network_proxy.is_enabled());
        let addr = req.policy.network_proxy.address.as_ref().unwrap();
        assert_eq!(addr.host(), "proxy.example.com");
        assert_eq!(addr.port(), 8080);
    }

    #[test]
    fn proxy_with_lxc_accepts_both_mode() {
        // 'both' also installs the iptables rules, so it satisfies the guard.
        let json = r#"{"process":{"commandLine":"x"},"containment":"lxc","network":{"proxy":{"url":"http://proxy.example.com:8080"},"enforcementMode":"both"}}"#;
        let encoded = base64_encode(json.as_bytes());
        let mut logger = test_logger();

        let req = load_request(&encoded, &mut logger, true).unwrap();
        assert!(req.policy.network_proxy.is_enabled());
    }

    #[test]
    fn proxy_with_lxc_and_omitted_enforcement_mode_is_rejected() {
        // enforcementMode defaults to 'capabilities', under which
        // apply_firewall_rules installs nothing. Accepting this config would
        // inject HTTP(S)_PROXY while leaving direct egress unrestricted, so
        // anything ignoring the environment variables bypasses the proxy.
        let json = r#"{"process":{"commandLine":"x"},"containment":"lxc","network":{"proxy":{"url":"http://proxy.example.com:8080"}}}"#;
        let encoded = base64_encode(json.as_bytes());
        let mut logger = test_logger();

        let err = load_request(&encoded, &mut logger, true).unwrap_err();
        assert!(
            format!("{}", err).contains("network.proxy requires network.enforcementMode"),
            "expected the LXC enforcement-mode rejection, got: {}",
            err
        );
    }

    #[test]
    fn proxy_with_lxc_and_explicit_capabilities_mode_is_rejected() {
        // Stating 'capabilities' explicitly is the same fail-open as omitting
        // it, so it must be rejected identically rather than read as consent.
        let json = r#"{"process":{"commandLine":"x"},"containment":"lxc","network":{"proxy":{"url":"http://proxy.example.com:8080"},"enforcementMode":"capabilities"}}"#;
        let encoded = base64_encode(json.as_bytes());
        let mut logger = test_logger();

        let err = load_request(&encoded, &mut logger, true).unwrap_err();
        assert!(
            format!("{}", err).contains("network.proxy requires network.enforcementMode"),
            "expected the LXC enforcement-mode rejection, got: {}",
            err
        );
    }

    // The credential guard runs after `convert_wire_proxy`, so a
    // credential-bearing URL that fails an *earlier* check never reaches it.
    // Those earlier errors have to redact on their own, or they leak the
    // password the guard exists to keep out of the diagnostic stream.
    #[test]
    fn a_malformed_credential_bearing_proxy_url_does_not_leak_the_password() {
        let json = r#"{"process":{"commandLine":"x"},"containment":"lxc","network":{"proxy":{"url":"http://alice:hunter2@proxy.example.com"},"enforcementMode":"firewall"}}"#;
        let encoded = base64_encode(json.as_bytes());
        let mut logger = test_logger();

        let msg = format!("{}", load_request(&encoded, &mut logger, true).unwrap_err());

        assert!(
            msg.contains("must include a port"),
            "expected the port diagnostic, got: {msg}"
        );
        assert!(
            !msg.contains("hunter2"),
            "the password leaked into the port diagnostic: {msg}"
        );
        assert!(
            !msg.contains("alice:hunter2"),
            "the userinfo leaked into the port diagnostic: {msg}"
        );
    }
    #[test]
    fn proxy_url_with_credentials_is_rejected_for_lxc() {
        // LXC forwards the URL to lxc-attach as `--set-var=HTTP_PROXY=...`, and
        // argv is world-readable via /proc/<pid>/cmdline, so accepting this
        // would publish the password to every local user.
        let json = r#"{"process":{"commandLine":"x"},"containment":"lxc","network":{"proxy":{"url":"http://alice:hunter2@proxy.example.com:8080"},"enforcementMode":"firewall"}}"#;
        let encoded = base64_encode(json.as_bytes());
        let mut logger = test_logger();

        let err = load_request(&encoded, &mut logger, true).unwrap_err();
        let msg = format!("{}", err);
        assert!(
            msg.contains("must not carry credentials"),
            "expected the LXC credential rejection, got: {msg}"
        );
    }

    #[test]
    fn the_lxc_credential_rejection_does_not_leak_the_password() {
        // The error is the one place a rejected secret could still escape, so
        // it must name the URL only in redacted form.
        let json = r#"{"process":{"commandLine":"x"},"containment":"lxc","network":{"proxy":{"url":"http://alice:hunter2@proxy.example.com:8080"},"enforcementMode":"firewall"}}"#;
        let encoded = base64_encode(json.as_bytes());
        let mut logger = test_logger();

        let msg = format!("{}", load_request(&encoded, &mut logger, true).unwrap_err());
        assert!(
            !msg.contains("hunter2") && !msg.contains("alice"),
            "credentials leaked into the rejection: {msg}"
        );
        assert!(
            msg.contains("***@proxy.example.com:8080"),
            "expected the redacted authority in the rejection: {msg}"
        );
    }

    #[test]
    fn a_credential_free_proxy_url_is_still_accepted_for_lxc() {
        // Negative control: without this, a guard that rejected every LXC
        // proxy URL would pass both tests above.
        let json = r#"{"process":{"commandLine":"x"},"containment":"lxc","network":{"proxy":{"url":"http://proxy.example.com:8080"},"enforcementMode":"firewall"}}"#;
        let encoded = base64_encode(json.as_bytes());
        let mut logger = test_logger();

        let req = load_request(&encoded, &mut logger, true).unwrap();
        assert!(req.policy.network_proxy.is_enabled());
    }

    #[test]
    fn an_at_sign_in_the_path_is_not_mistaken_for_credentials() {
        // `@` after the authority is an ordinary path character. Rejecting on
        // a bare `@` would refuse a URL that carries no secret at all.
        let json = r#"{"process":{"commandLine":"x"},"containment":"lxc","network":{"proxy":{"url":"http://proxy.example.com:8080/route@v2"},"enforcementMode":"firewall"}}"#;
        let encoded = base64_encode(json.as_bytes());
        let mut logger = test_logger();

        let req = load_request(&encoded, &mut logger, true).unwrap();
        assert!(req.policy.network_proxy.is_enabled());
    }

    #[test]
    fn proxy_localhost_rejected_with_lxc() {
        // network.proxy.localhost maps to 127.0.0.1, unreachable from inside
        // the LXC network namespace — it must be rejected at parse time.
        let json = r#"{"process":{"commandLine":"x"},"containment":"lxc","network":{"proxy":{"localhost":8080}}}"#;
        let encoded = base64_encode(json.as_bytes());
        let mut logger = test_logger();

        let err = load_request(&encoded, &mut logger, true).unwrap_err();
        assert!(
            format!("{}", err).contains("network.proxy.localhost is not reachable"),
            "expected the LXC localhost rejection, got: {}",
            err
        );
    }

    #[test]
    fn proxy_loopback_url_rejected_with_lxc() {
        // The url form names the container's own loopback just as the
        // localhost shorthand does, so it is rejected for the same reason.
        // WSLc is deliberately the other way: see
        // `proxy_loopback_url_accepted_with_wslc`.
        for url in [
            "http://localhost:8080",
            "http://127.0.0.1:8080",
            "http://[::1]:8080",
        ] {
            let json = format!(
                r#"{{"process":{{"commandLine":"x"}},"containment":"lxc","network":{{"proxy":{{"url":"{}"}}}}}}"#,
                url
            );
            let encoded = base64_encode(json.as_bytes());
            let mut logger = test_logger();

            let err = load_request(&encoded, &mut logger, true).unwrap_err();
            assert!(
                format!("{}", err).contains("loopback address"),
                "expected the LXC loopback-url rejection for {}, got: {}",
                url,
                err
            );
        }
    }

    #[test]
    fn proxy_builtin_test_server_rejected_with_lxc() {
        // LXC enforces a configured proxy address with iptables; it does not
        // launch the builtin testing proxy.
        let json = r#"{"process":{"commandLine":"x"},"containment":"lxc","network":{"proxy":{"builtinTestServer":true}}}"#;
        let encoded = base64_encode(json.as_bytes());
        let mut logger = test_logger();

        let err = load_request(&encoded, &mut logger, true).unwrap_err();
        assert!(format!("{}", err).contains("builtinTestServer is not supported"));
    }

    #[test]
    fn proxy_rejects_port_zero() {
        let json = r#"{"process":{"commandLine":"x"},"network":{"proxy":{"localhost":0}}}"#;
        let encoded = base64_encode(json.as_bytes());
        let mut logger = test_logger();

        let result = load_request(&encoded, &mut logger, true);
        assert!(result.is_err());
    }

    #[test]
    fn proxy_rejects_missing_localhost() {
        let json = r#"{"process":{"commandLine":"x"},"network":{"proxy":{}}}"#;
        let encoded = base64_encode(json.as_bytes());
        let mut logger = test_logger();

        let result = load_request(&encoded, &mut logger, true);
        assert!(result.is_err());
    }

    #[test]
    fn proxy_rejects_non_object() {
        let json = r#"{"process":{"commandLine":"x"},"network":{"proxy":true}}"#;
        let encoded = base64_encode(json.as_bytes());
        let mut logger = test_logger();

        let result = load_request(&encoded, &mut logger, true);
        assert!(result.is_err());
    }

    #[test]
    fn proxy_builtin_test_server() {
        let json = r#"{
            "process": {"commandLine": "echo test"},
            "containment": "processcontainer",
            "network": {
                "proxy": { "builtinTestServer": true }
            }
        }"#;
        let encoded = base64_encode(json.as_bytes());
        let mut logger = test_logger();

        let req = load_request(&encoded, &mut logger, true).unwrap();
        assert!(req.policy.network_proxy.is_enabled());
        assert!(req.policy.network_proxy.builtin_test_server);
        assert!(req.policy.network_proxy.address.is_some());
    }

    #[test]
    fn proxy_builtin_test_server_rejects_extra_keys() {
        let json = r#"{"process":{"commandLine":"x"},"network":{"proxy":{"builtinTestServer":true,"localhost":8080}}}"#;
        let encoded = base64_encode(json.as_bytes());
        let mut logger = test_logger();

        let result = load_request(&encoded, &mut logger, true);
        assert!(result.is_err());
    }

    #[test]
    fn proxy_builtin_test_server_rejects_false() {
        let json =
            r#"{"process":{"commandLine":"x"},"network":{"proxy":{"builtinTestServer":false}}}"#;
        let encoded = base64_encode(json.as_bytes());
        let mut logger = test_logger();

        let result = load_request(&encoded, &mut logger, true);
        assert!(result.is_err());
    }

    #[test]
    fn proxy_builtin_test_server_rejected_with_non_processcontainer() {
        // lxc is not allowed -- proxy is gated to processcontainer + bubblewrap.
        let json = r#"{"process":{"commandLine":"x"},"containment":"lxc","network":{"proxy":{"builtinTestServer":true}}}"#;
        let encoded = base64_encode(json.as_bytes());
        let mut logger = test_logger();

        let result = load_request(&encoded, &mut logger, true);
        assert!(result.is_err());
    }

    #[test]
    fn proxy_accepted_with_bubblewrap() {
        let json = r#"{
            "version": "0.6.0-alpha",
            "containment": "bubblewrap",
            "process": {"commandLine": "echo hi"},
            "network": {"proxy": {"builtinTestServer": true}}
        }"#;
        let encoded = base64_encode(json.as_bytes());
        let mut logger = test_logger();

        let req = load_request(&encoded, &mut logger, true).unwrap();
        assert!(req.policy.network_proxy.is_enabled());
        assert!(req.policy.network_proxy.builtin_test_server);
    }

    #[test]
    fn proxy_accepted_with_seatbelt() {
        let json = r#"{
            "version": "0.7.0-alpha",
            "containment": "seatbelt",
            "process": {"commandLine": "echo hi"},
            "network": {"proxy": {"builtinTestServer": true}}
        }"#;
        let encoded = base64_encode(json.as_bytes());
        let mut logger = test_logger();

        let req = load_request(&encoded, &mut logger, true).unwrap();
        assert!(req.policy.network_proxy.is_enabled());
        assert!(req.policy.network_proxy.builtin_test_server);
    }

    #[test]
    fn proxy_url_accepted_with_seatbelt() {
        let json = r#"{
            "version": "0.7.0-alpha",
            "containment": "seatbelt",
            "process": {"commandLine": "echo hi"},
            "network": {"proxy": {"url": "http://127.0.0.1:8080"}}
        }"#;
        let encoded = base64_encode(json.as_bytes());
        let mut logger = test_logger();

        let req = load_request(&encoded, &mut logger, true).unwrap();
        assert!(req.policy.network_proxy.is_enabled());
        assert!(!req.policy.network_proxy.builtin_test_server);
        let addr = req.policy.network_proxy.address.as_ref().unwrap();
        assert_eq!(addr.port(), 8080);
    }

    #[test]
    fn proxy_with_seatbelt_and_firewall_enforcement_is_rejected() {
        let json = r#"{
            "version": "0.7.0-alpha",
            "containment": "seatbelt",
            "process": {"commandLine": "echo hi"},
            "network": {
                "proxy": {"builtinTestServer": true},
                "enforcementMode": "firewall"
            }
        }"#;
        let encoded = base64_encode(json.as_bytes());
        let mut logger = test_logger();

        let err = load_request(&encoded, &mut logger, true).unwrap_err();
        let msg = format!("{}", err);
        assert!(
            msg.contains("Seatbelt: network.proxy cannot be combined with"),
            "unexpected error message: {}",
            msg
        );
    }

    #[test]
    fn proxy_with_seatbelt_and_both_enforcement_is_rejected() {
        let json = r#"{
            "version": "0.7.0-alpha",
            "containment": "seatbelt",
            "process": {"commandLine": "echo hi"},
            "network": {
                "proxy": {"builtinTestServer": true},
                "enforcementMode": "both"
            }
        }"#;
        let encoded = base64_encode(json.as_bytes());
        let mut logger = test_logger();

        let err = load_request(&encoded, &mut logger, true).unwrap_err();
        let msg = format!("{}", err);
        assert!(
            msg.contains("network.proxy cannot be combined with"),
            "unexpected error message: {}",
            msg
        );
    }

    #[test]
    fn proxy_remote_url_with_seatbelt_and_default_block_is_rejected() {
        // A remote (non-loopback) proxy under default-deny would degrade the
        // Seatbelt profile to allow-all outbound — reject it at validation.
        let json = r#"{
            "version": "0.7.0-alpha",
            "containment": "seatbelt",
            "process": {"commandLine": "echo hi"},
            "network": {
                "defaultPolicy": "block",
                "proxy": {"url": "http://proxy.example.com:8080"}
            }
        }"#;
        let encoded = base64_encode(json.as_bytes());
        let mut logger = test_logger();

        let err = load_request(&encoded, &mut logger, true).unwrap_err();
        let msg = format!("{}", err);
        assert!(
            msg.contains("remote network.proxy") && msg.contains("defaultPolicy='block'"),
            "unexpected error message: {}",
            msg
        );
    }

    #[test]
    fn proxy_loopback_url_with_seatbelt_and_default_block_is_accepted() {
        // A loopback proxy is port-scoped under deny, so it must NOT be rejected.
        let json = r#"{
            "version": "0.7.0-alpha",
            "containment": "seatbelt",
            "process": {"commandLine": "echo hi"},
            "network": {
                "defaultPolicy": "block",
                "proxy": {"url": "http://127.0.0.1:8080"}
            }
        }"#;
        let encoded = base64_encode(json.as_bytes());
        let mut logger = test_logger();

        let req = load_request(&encoded, &mut logger, true).unwrap();
        assert!(req.policy.network_proxy.is_enabled());
        assert!(!req.policy.network_proxy.builtin_test_server);
    }

    #[test]
    fn proxy_builtin_with_seatbelt_and_default_block_is_accepted() {
        // builtinTestServer resolves to a loopback port at runtime → port-scoped,
        // so default-deny is safe and must be accepted.
        let json = r#"{
            "version": "0.7.0-alpha",
            "containment": "seatbelt",
            "process": {"commandLine": "echo hi"},
            "network": {
                "defaultPolicy": "block",
                "proxy": {"builtinTestServer": true}
            }
        }"#;
        let encoded = base64_encode(json.as_bytes());
        let mut logger = test_logger();

        let req = load_request(&encoded, &mut logger, true).unwrap();
        assert!(req.policy.network_proxy.builtin_test_server);
    }

    #[test]
    fn proxy_with_bubblewrap_and_firewall_enforcement_is_rejected() {
        let json = r#"{
            "version": "0.6.0-alpha",
            "containment": "bubblewrap",
            "process": {"commandLine": "echo hi"},
            "network": {
                "proxy": {"builtinTestServer": true},
                "enforcementMode": "firewall",
                "allowedHosts": ["example.com"]
            }
        }"#;
        let encoded = base64_encode(json.as_bytes());
        let mut logger = test_logger();

        let err = load_request(&encoded, &mut logger, true).unwrap_err();
        let msg = format!("{}", err);
        assert!(
            msg.contains("network.proxy cannot be combined with"),
            "unexpected error message: {}",
            msg
        );
    }

    #[test]
    fn proxy_with_bubblewrap_and_both_enforcement_is_rejected() {
        let json = r#"{
            "version": "0.6.0-alpha",
            "containment": "bubblewrap",
            "process": {"commandLine": "echo hi"},
            "network": {
                "proxy": {"builtinTestServer": true},
                "enforcementMode": "both",
                "blockedHosts": ["evil.example"]
            }
        }"#;
        let encoded = base64_encode(json.as_bytes());
        let mut logger = test_logger();

        assert!(load_request(&encoded, &mut logger, true).is_err());
    }

    #[test]
    fn proxy_with_bubblewrap_and_capabilities_enforcement_is_accepted() {
        // Capabilities mode never invokes iptables, so combining it with a
        // proxy is fine and must NOT trigger the conflict guard.
        let json = r#"{
            "version": "0.6.0-alpha",
            "containment": "bubblewrap",
            "process": {"commandLine": "echo hi"},
            "network": {
                "proxy": {"builtinTestServer": true},
                "enforcementMode": "capabilities",
                "allowedHosts": ["example.com"]
            }
        }"#;
        let encoded = base64_encode(json.as_bytes());
        let mut logger = test_logger();

        let req = load_request(&encoded, &mut logger, true).unwrap();
        assert!(req.policy.network_proxy.is_enabled());
        assert_eq!(req.policy.allowed_hosts, vec!["example.com".to_string()]);
    }

    #[test]
    fn external_proxy_url_with_bubblewrap_and_allowed_hosts_is_rejected() {
        // The external proxy enforces its own policy; the runner does not
        // forward host lists to it. Combining the two is a silent
        // policy-weakening trap and must be rejected at parse time.
        let json = r#"{
            "version": "0.6.0-alpha",
            "containment": "bubblewrap",
            "process": {"commandLine": "echo hi"},
            "network": {
                "proxy": {"url": "http://127.0.0.1:8080"},
                "allowedHosts": ["api.github.com"]
            }
        }"#;
        let encoded = base64_encode(json.as_bytes());
        let mut logger = test_logger();

        let err = load_request(&encoded, &mut logger, true).unwrap_err();
        let msg = format!("{}", err);
        assert!(
            msg.contains("external network.proxy") && msg.contains("allowedHosts"),
            "unexpected error message: {}",
            msg
        );
    }

    #[test]
    fn external_proxy_localhost_with_bubblewrap_and_blocked_hosts_is_rejected() {
        let json = r#"{
            "version": "0.6.0-alpha",
            "containment": "bubblewrap",
            "process": {"commandLine": "echo hi"},
            "network": {
                "proxy": {"localhost": 8080},
                "blockedHosts": ["evil.example.com"]
            }
        }"#;
        let encoded = base64_encode(json.as_bytes());
        let mut logger = test_logger();

        let err = load_request(&encoded, &mut logger, true).unwrap_err();
        assert!(format!("{}", err).contains("external network.proxy"));
    }

    #[test]
    fn external_proxy_with_bubblewrap_and_default_block_is_rejected() {
        // defaultPolicy=block is a hard-block intent; pairing it with an
        // external proxy whose policy we don't control silently weakens
        // enforcement.
        let json = r#"{
            "version": "0.6.0-alpha",
            "containment": "bubblewrap",
            "process": {"commandLine": "echo hi"},
            "network": {
                "proxy": {"url": "http://127.0.0.1:8080"},
                "defaultPolicy": "block"
            }
        }"#;
        let encoded = base64_encode(json.as_bytes());
        let mut logger = test_logger();

        let err = load_request(&encoded, &mut logger, true).unwrap_err();
        assert!(format!("{}", err).contains("defaultPolicy"));
    }

    #[test]
    fn external_proxy_with_bubblewrap_and_no_host_policy_is_accepted() {
        // Pure delegate-to-external-proxy with no MXC-side host policy is
        // the supported external-proxy use case. Under deny-by-default,
        // callers must explicitly set `defaultPolicy: "allow"` to opt
        // into trusting the external proxy with full policy delegation.
        let json = r#"{
            "version": "0.6.0-alpha",
            "containment": "bubblewrap",
            "process": {"commandLine": "echo hi"},
            "network": {
                "proxy": {"url": "http://127.0.0.1:8080"},
                "defaultPolicy": "allow"
            }
        }"#;
        let encoded = base64_encode(json.as_bytes());
        let mut logger = test_logger();

        let req = load_request(&encoded, &mut logger, true).unwrap();
        assert!(req.policy.network_proxy.is_enabled());
        assert!(!req.policy.network_proxy.builtin_test_server);
    }

    #[test]
    fn builtin_proxy_with_bubblewrap_and_host_policy_is_accepted() {
        // The builtin proxy DOES enforce host lists at the proxy layer, so
        // combining it with allowedHosts is fine.
        let json = r#"{
            "version": "0.6.0-alpha",
            "containment": "bubblewrap",
            "process": {"commandLine": "echo hi"},
            "network": {
                "proxy": {"builtinTestServer": true},
                "allowedHosts": ["api.github.com"],
                "defaultPolicy": "block"
            }
        }"#;
        let encoded = base64_encode(json.as_bytes());
        let mut logger = test_logger();

        let req = load_request(&encoded, &mut logger, true).unwrap();
        assert!(req.policy.network_proxy.builtin_test_server);
        assert_eq!(req.policy.allowed_hosts, vec!["api.github.com".to_string()]);
    }

    #[test]
    fn bubblewrap_proxy_with_default_block_and_empty_allowlist_warns() {
        // Cooperative mode with no allowlist denies HTTP_PROXY-aware clients
        // but raw-socket clients still reach the host network. Parser must
        // surface a warning (does not reject).
        let json = r#"{
            "version": "0.6.0-alpha",
            "containment": "bubblewrap",
            "process": {"commandLine": "echo hi"},
            "network": {
                "proxy": {"builtinTestServer": true},
                "defaultPolicy": "block"
            }
        }"#;
        let encoded = base64_encode(json.as_bytes());
        let mut logger = test_logger();

        let req = load_request(&encoded, &mut logger, true).unwrap();
        assert!(req.policy.network_proxy.is_enabled());
        assert_eq!(req.policy.default_network_policy, NetworkPolicy::Block);
        // Warning is best-effort surfaced via the logger; the request still
        // succeeds.
    }

    #[test]
    fn proxy_url_with_credentials_is_rejected_for_bubblewrap() {
        // Bubblewrap serializes the URL into a `bwrap --setenv HTTP_PROXY ...`
        // argument, and argv is world-readable via /proc/<pid>/cmdline, so
        // accepting this would publish the password to every local user.
        let json = r#"{"process":{"commandLine":"x"},"containment":"bubblewrap","network":{"proxy":{"url":"http://alice:hunter2@proxy.example.com:8080"},"defaultPolicy":"allow"}}"#;
        let encoded = base64_encode(json.as_bytes());
        let mut logger = test_logger();

        let err = load_request(&encoded, &mut logger, true).unwrap_err();
        let msg = format!("{}", err);
        assert!(
            msg.contains("must not carry credentials"),
            "expected the Bubblewrap credential rejection, got: {msg}"
        );
    }

    #[test]
    fn the_bubblewrap_credential_rejection_does_not_leak_the_password() {
        // The rejection is the one place a refused secret could still escape,
        // so it must name the URL only in redacted form.
        let json = r#"{"process":{"commandLine":"x"},"containment":"bubblewrap","network":{"proxy":{"url":"http://alice:hunter2@proxy.example.com:8080"},"defaultPolicy":"allow"}}"#;
        let encoded = base64_encode(json.as_bytes());
        let mut logger = test_logger();

        let msg = format!("{}", load_request(&encoded, &mut logger, true).unwrap_err());
        assert!(
            !msg.contains("hunter2") && !msg.contains("alice"),
            "credentials leaked into the rejection: {msg}"
        );
        assert!(
            msg.contains("***@proxy.example.com:8080"),
            "expected the redacted authority in the rejection: {msg}"
        );
    }

    #[test]
    fn a_credential_free_proxy_url_is_still_accepted_for_bubblewrap() {
        // Negative control: the guard must reject only credential-bearing URLs,
        // not every Bubblewrap proxy URL.
        let json = r#"{"process":{"commandLine":"x"},"containment":"bubblewrap","network":{"proxy":{"url":"http://proxy.example.com:8080"},"defaultPolicy":"allow"}}"#;
        let encoded = base64_encode(json.as_bytes());
        let mut logger = test_logger();

        let req = load_request(&encoded, &mut logger, true).unwrap();
        assert!(req.policy.network_proxy.is_enabled());
    }

    #[test]
    fn proxy_accepted_with_wslc_url_form() {
        // WSLc supports the cooperative env-var proxy via a routable `url`.
        let json = r#"{
            "version": "0.6.0-alpha",
            "containment": "wslc",
            "process": {"commandLine": "echo hi"},
            "network": {
                "proxy": {"url": "http://proxy.example:8080"},
                "defaultPolicy": "allow"
            }
        }"#;
        let encoded = base64_encode(json.as_bytes());
        let mut logger = test_logger();

        let req = load_request(&encoded, &mut logger, true).unwrap();
        assert!(req.policy.network_proxy.is_enabled());
        assert!(!req.policy.network_proxy.builtin_test_server);
        let addr = req.policy.network_proxy.address.as_ref().unwrap();
        assert_eq!(addr.to_url(), "http://proxy.example:8080");
    }

    #[test]
    fn proxy_rejects_wslc_localhost_form() {
        // The localhost form implies a host-loopback proxy, which a WSLc
        // container (own network namespace) cannot reach. Must be rejected.
        let json = r#"{
            "version": "0.6.0-alpha",
            "containment": "wslc",
            "process": {"commandLine": "echo hi"},
            "network": {"proxy": {"localhost": 8080}}
        }"#;
        let encoded = base64_encode(json.as_bytes());
        let mut logger = test_logger();

        let err = load_request(&encoded, &mut logger, true).unwrap_err();
        assert!(
            format!("{err}").contains("WSLc: network.proxy must use the 'url' form"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn proxy_rejects_wslc_builtin_test_server() {
        // builtinTestServer spins up an MXC-run in-host proxy, unreachable
        // from a WSLc container. Must be rejected with the url-form message.
        let json = r#"{
            "version": "0.6.0-alpha",
            "containment": "wslc",
            "process": {"commandLine": "echo hi"},
            "network": {"proxy": {"builtinTestServer": true}}
        }"#;
        let encoded = base64_encode(json.as_bytes());
        let mut logger = test_logger();

        let err = load_request(&encoded, &mut logger, true).unwrap_err();
        assert!(
            format!("{err}").contains("WSLc: network.proxy must use the 'url' form"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn proxy_loopback_url_accepted_with_wslc() {
        // A WSLc container runs in its own network namespace, and the supported
        // topology puts the proxy *inside* it. `tests/configs/wslc_network_proxy.json`
        // starts a marker server on 127.0.0.1:8888 and points the proxy at it,
        // because loopback is the only address both the client and a self-hosted
        // proxy can reach -- `run_wslc_proxy_test.ps1` says so directly.
        //
        // The `localhost` and `builtinTestServer` forms stay rejected above:
        // those name a proxy MXC runs on the *host*, which is the unreachable
        // one. The distinction is which side of the namespace the proxy is on,
        // not whether the literal is a loopback address.
        for url in [
            "http://localhost:8080",
            "http://127.0.0.1:8080",
            "http://[::1]:8080",
        ] {
            let json = format!(
                r#"{{"process":{{"commandLine":"x"}},"containment":"wslc","network":{{"proxy":{{"url":"{}"}},"defaultPolicy":"allow"}}}}"#,
                url
            );
            let encoded = base64_encode(json.as_bytes());
            let mut logger = test_logger();

            let req = load_request(&encoded, &mut logger, true).unwrap_or_else(|e| {
                panic!("WSLc must accept its in-container proxy {url}, got: {e}")
            });
            assert_eq!(
                req.policy
                    .network_proxy
                    .address
                    .as_ref()
                    .expect("the proxy address must survive parsing")
                    .to_url(),
                url
            );
        }
    }

    #[test]
    fn proxy_rejects_non_http_scheme() {
        // Non-HTTP schemes are silently ignored by many clients when injected
        // as HTTP(S)_PROXY, which fails open. Reject at parse time.
        for url in ["socks5://proxy.example:1080", "ftp://proxy.example:21"] {
            let json = format!(
                r#"{{
                    "process": {{"commandLine": "echo hi"}},
                    "containment": "processcontainer",
                    "network": {{"proxy": {{"url": "{url}"}}}}
                }}"#
            );
            let encoded = base64_encode(json.as_bytes());
            let mut logger = test_logger();
            let err = load_request(&encoded, &mut logger, true).unwrap_err();
            assert!(
                format!("{err}").contains("must use the 'http' or 'https' scheme"),
                "expected scheme rejection for {url}, got: {err}"
            );
        }
    }

    #[test]
    fn proxy_scheme_error_redacts_credentials() {
        // A rejected proxy URL must not echo embedded `user:password@`
        // userinfo into the error (which reaches the diagnostic/log stream).
        let json = r#"{
            "process": {"commandLine": "echo hi"},
            "containment": "processcontainer",
            "network": {"proxy": {"url": "socks5://alice:s3cr3t@proxy.example:1080"}}
        }"#;
        let encoded = base64_encode(json.as_bytes());
        let mut logger = test_logger();
        let err = load_request(&encoded, &mut logger, true).unwrap_err();
        let msg = format!("{err}");
        assert!(
            msg.contains("must use the 'http' or 'https' scheme"),
            "expected scheme rejection, got: {msg}"
        );
        assert!(
            !msg.contains("s3cr3t") && !msg.contains("alice:s3cr3t"),
            "credentials leaked into error: {msg}"
        );
        assert!(
            msg.contains("***@proxy.example"),
            "expected redacted userinfo in error: {msg}"
        );
    }

    #[test]
    fn proxy_rejects_wslc_url_with_block_default() {
        // A WSLc url proxy needs outbound networking; the default 'block'
        // policy (defaultPolicy omitted) leaves the proxy unreachable.
        let json = r#"{
            "version": "0.6.0-alpha",
            "containment": "wslc",
            "process": {"commandLine": "echo hi"},
            "network": {"proxy": {"url": "http://proxy.example:8080"}}
        }"#;
        let encoded = base64_encode(json.as_bytes());
        let mut logger = test_logger();

        let err = load_request(&encoded, &mut logger, true).unwrap_err();
        assert!(
            format!("{err}").contains("requires network.defaultPolicy='allow'"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn proxy_rejects_wslc_url_with_host_lists() {
        // Host lists are not forwarded to the proxy; reject to avoid silently
        // weaker enforcement.
        let json = r#"{
            "version": "0.6.0-alpha",
            "containment": "wslc",
            "process": {"commandLine": "echo hi"},
            "network": {
                "proxy": {"url": "http://proxy.example:8080"},
                "defaultPolicy": "allow",
                "allowedHosts": ["example.com"]
            }
        }"#;
        let encoded = base64_encode(json.as_bytes());
        let mut logger = test_logger();

        let err = load_request(&encoded, &mut logger, true).unwrap_err();
        assert!(
            format!("{err}").contains("allowedHosts/blockedHosts"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn wslc_rejects_host_filtering_block_with_allowed_hosts() {
        // 'block' default + an allowlist is the doomed in-container iptables path
        // (Privileged != CAP_NET_ADMIN). Reject at parse time instead of failing
        // the run at exec.
        let json = r#"{
            "version": "0.6.0-alpha",
            "containment": "wslc",
            "process": {"commandLine": "echo hi"},
            "network": {
                "defaultPolicy": "block",
                "allowedHosts": ["example.com"]
            }
        }"#;
        let encoded = base64_encode(json.as_bytes());
        let mut logger = test_logger();

        let err = load_request(&encoded, &mut logger, true).unwrap_err();
        assert!(
            format!("{err}").contains("per-host egress filtering"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn wslc_rejects_host_filtering_allow_with_blocked_hosts() {
        // 'allow' default + a blocklist is the other in-container iptables path.
        let json = r#"{
            "version": "0.6.0-alpha",
            "containment": "wslc",
            "process": {"commandLine": "echo hi"},
            "network": {
                "defaultPolicy": "allow",
                "blockedHosts": ["evil.example"]
            }
        }"#;
        let encoded = base64_encode(json.as_bytes());
        let mut logger = test_logger();

        let err = load_request(&encoded, &mut logger, true).unwrap_err();
        assert!(
            format!("{err}").contains("per-host egress filtering"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn wslc_accepts_block_default_without_host_lists() {
        // 'block' with no allowlist is a full cutoff (NetworkingMode::None) --
        // enforceable, so it must NOT be rejected.
        let json = r#"{
            "version": "0.6.0-alpha",
            "containment": "wslc",
            "process": {"commandLine": "echo hi"},
            "network": {"defaultPolicy": "block"}
        }"#;
        let encoded = base64_encode(json.as_bytes());
        let mut logger = test_logger();

        let req = load_request(&encoded, &mut logger, true).unwrap();
        assert_eq!(req.policy.default_network_policy, NetworkPolicy::Block);
        assert!(req.policy.allowed_hosts.is_empty());
    }

    #[test]
    fn wslc_accepts_allow_default_without_host_lists() {
        // 'allow' with no blocklist is full NAT (Bridged) -- enforceable, not rejected.
        let json = r#"{
            "version": "0.6.0-alpha",
            "containment": "wslc",
            "process": {"commandLine": "echo hi"},
            "network": {"defaultPolicy": "allow"}
        }"#;
        let encoded = base64_encode(json.as_bytes());
        let mut logger = test_logger();

        let req = load_request(&encoded, &mut logger, true).unwrap();
        assert_eq!(req.policy.default_network_policy, NetworkPolicy::Allow);
        assert!(req.policy.blocked_hosts.is_empty());
    }

    #[test]
    fn wslc_rejects_allow_local_network_true() {
        // A blanket inbound-listen grant is silently ignored by the WSLc runner
        // (only explicit portMappings have inbound effect), so accepting it would
        // promise reachability the backend never delivers. Reject at parse time.
        let json = r#"{
            "version": "0.6.0-alpha",
            "containment": "wslc",
            "process": {"commandLine": "echo hi"},
            "network": {"allowLocalNetwork": true}
        }"#;
        let encoded = base64_encode(json.as_bytes());
        let mut logger = test_logger();

        let err = load_request(&encoded, &mut logger, true).unwrap_err();
        assert!(
            format!("{err}").contains("allowLocalNetwork=true is not supported"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn wslc_accepts_allow_local_network_false() {
        // The default/explicit `false` is a no-op and must be accepted.
        let json = r#"{
            "version": "0.6.0-alpha",
            "containment": "wslc",
            "process": {"commandLine": "echo hi"},
            "network": {"allowLocalNetwork": false}
        }"#;
        let encoded = base64_encode(json.as_bytes());
        let mut logger = test_logger();

        let req = load_request(&encoded, &mut logger, true).unwrap();
        assert!(!req.policy.allow_local_network);
    }

    #[test]
    fn new_toplevel_fields_parsed() {
        let json = r#"{"version": "0.6.0-alpha", "containerId": "abc-123", "containment": "lxc", "process": {"commandLine": "echo hi"}}"#;
        let encoded = base64_encode(json.as_bytes());
        let mut logger = test_logger();

        let req = load_request(&encoded, &mut logger, true).unwrap();
        assert_eq!(req.schema_version, "0.6.0-alpha");
        assert_eq!(req.container_id, "abc-123");
    }

    #[test]
    fn new_toplevel_fields_default_when_absent() {
        let json = r#"{"process": {"commandLine": "echo hi"}}"#;
        let encoded = base64_encode(json.as_bytes());
        let mut logger = test_logger();

        let req = load_request(&encoded, &mut logger, true).unwrap();
        assert_eq!(req.schema_version, "");
        assert_eq!(req.container_id, "");
    }

    #[test]
    fn process_section_env_parsed() {
        let json = r#"{
            "process": {
                "commandLine": "echo hi",
                "env": ["FOO=bar", "BAZ=qux"]
            }
        }"#;
        let encoded = base64_encode(json.as_bytes());
        let mut logger = test_logger();

        let req = load_request(&encoded, &mut logger, true).unwrap();
        assert_eq!(req.env, vec!["FOO=bar", "BAZ=qux"]);
    }

    #[test]
    fn process_section_cwd_parsed() {
        let json = r#"{
            "process": {
                "commandLine": "echo hi",
                "cwd": "/workspace"
            }
        }"#;
        let encoded = base64_encode(json.as_bytes());
        let mut logger = test_logger();

        let req = load_request(&encoded, &mut logger, true).unwrap();
        assert_eq!(req.working_directory, "/workspace");
    }

    #[test]
    fn process_section_timeout_parsed() {
        let json = r#"{
            "process": {
                "commandLine": "echo hi",
                "timeout": 9000
            }
        }"#;
        let encoded = base64_encode(json.as_bytes());
        let mut logger = test_logger();

        let req = load_request(&encoded, &mut logger, true).unwrap();
        assert_eq!(req.script_timeout, 9000);
    }

    #[test]
    fn containment_microvm_accepted() {
        let json = r#"{"process": {"commandLine": "echo hi"}, "containment": "microvm"}"#;
        let encoded = base64_encode(json.as_bytes());
        let mut logger = test_logger();

        let req = load_request(&encoded, &mut logger, true).unwrap();
        assert_eq!(req.containment, ContainmentBackend::MicroVm);
    }

    #[test]
    fn unknown_top_level_field_rejected() {
        let json = r#"{"process": {"commandLine": "echo hi"}, "bogusField": true}"#;
        let encoded = base64_encode(json.as_bytes());
        let mut logger = test_logger();

        let result = load_request(&encoded, &mut logger, true);
        assert!(
            result.is_err(),
            "unknown top-level field should be rejected"
        );
    }

    #[test]
    fn filesystem_typo_rejected() {
        // `fileSystem` (capital S) used to be silently dropped, so the policy
        // never applied. It must now be rejected as an unknown field.
        let json = r#"{"process": {"commandLine": "echo hi"}, "fileSystem": {"readwritePaths": ["C:\\x"]}}"#;
        let encoded = base64_encode(json.as_bytes());
        let mut logger = test_logger();

        let result = load_request(&encoded, &mut logger, true);
        assert!(result.is_err(), "fileSystem typo should be rejected");
    }

    #[test]
    fn nested_unknown_field_rejected() {
        // The stable surface is closed at every level (deny_unknown_fields):
        // an unknown *nested* field must be rejected, not just top-level ones.
        let json = r#"{"process": {"commandLine": "echo hi", "bogus": 1}}"#;
        let encoded = base64_encode(json.as_bytes());
        let mut logger = test_logger();

        let err = load_request(&encoded, &mut logger, true).unwrap_err();
        let msg = format!("{err}");
        assert!(
            msg.contains("unknown field") && msg.contains("bogus"),
            "nested unknown field should be rejected, got: {msg}"
        );
        assert!(
            msg.contains("Invalid configuration at `process.bogus`"),
            "expected the unknown field path, got: {msg}"
        );
    }

    #[test]
    fn nested_proxy_unknown_field_rejected() {
        let json = r#"{"process": {"commandLine": "echo hi"}, "containment": "processcontainer", "network": {"proxy": {"localhost": 8080, "unexpected": true}}}"#;
        let encoded = base64_encode(json.as_bytes());
        let mut logger = test_logger();

        let err = load_request(&encoded, &mut logger, true).unwrap_err();
        let msg = format!("{err}");
        assert!(
            msg.contains("unknown field") && msg.contains("unexpected"),
            "nested proxy unknown field should be rejected, got: {msg}"
        );
    }

    #[test]
    fn invalid_clipboard_rejected() {
        // Strict enum: an out-of-range clipboard value is rejected at deserialize.
        let json = r#"{"process": {"commandLine": "echo hi"}, "ui": {"clipboard": "bogus"}}"#;
        let encoded = base64_encode(json.as_bytes());
        let mut logger = test_logger();

        let err = load_request(&encoded, &mut logger, true).unwrap_err();
        let msg = format!("{err}");
        assert!(
            msg.contains("unknown variant") && msg.contains("bogus"),
            "invalid clipboard value should be rejected, got: {msg}"
        );
    }

    #[test]
    fn experimental_port_mapping_unknown_field_accepted() {
        // The experimental surface is intentionally permissive (forward-compat):
        // an unknown field on a nested experimental struct must be tolerated and
        // the known fields preserved.
        let json = r#"{"process": {"commandLine": "echo hi"}, "containment": "wslc", "experimental": {"wslc": {"image": "python:3.12", "portMappings": [{"windowsPort": 8080, "containerPort": 80, "futureField": "ignored"}]}}}"#;
        let encoded = base64_encode(json.as_bytes());
        let mut logger = test_logger();

        let req = load_request(&encoded, &mut logger, true).unwrap();
        let wslc = req.experimental.wslc.expect("wslc config present");
        assert_eq!(wslc.port_mappings.len(), 1);
        assert_eq!(wslc.port_mappings[0].windows_port, 8080);
        assert_eq!(wslc.port_mappings[0].container_port, 80);
    }

    #[test]
    fn one_shot_ignores_stray_isolation_session_config_rather_than_rejecting() {
        // The one-shot surface takes no backend configuration at all, and the
        // `experimental` block is deliberately permissive, so an unrecognised
        // key there is silently ignored rather than rejected. Parsing must
        // succeed and select the backend normally.
        let json = r#"{"process": {"commandLine": "echo hi"}, "containment": "isolation_session", "experimental": {"isolation_session": {"unrecognizedSetting": {"nested": "value", "futureField": true}}}}"#;
        let encoded = base64_encode(json.as_bytes());
        let mut logger = test_logger();

        let req = load_request(&encoded, &mut logger, true)
            .expect("one-shot must accept and ignore a stray isolation_session key");
        assert_eq!(req.containment, ContainmentBackend::IsolationSession);
    }

    #[test]
    fn one_shot_accepts_empty_isolation_session_block() {
        let json = r#"{"process": {"commandLine": "echo hi"}, "containment": "isolation_session", "experimental": {"isolation_session": {}}}"#;
        let encoded = base64_encode(json.as_bytes());
        let mut logger = test_logger();

        let req = load_request(&encoded, &mut logger, true).unwrap();
        assert_eq!(req.containment, ContainmentBackend::IsolationSession);
    }

    #[test]
    fn one_shot_rejects_phase_field() {
        // A state-aware-shaped payload (carries `phase`) sent to a one-shot
        // entry point must be rejected, not silently run as a one-shot.
        let json = r#"{"process": {"commandLine": "echo hi"}, "phase": "provision"}"#;
        let encoded = base64_encode(json.as_bytes());
        let mut logger = test_logger();

        let err = load_request(&encoded, &mut logger, true).unwrap_err();
        let msg = format!("{err}");
        assert!(
            msg.contains("phase") && msg.contains("state-aware"),
            "one-shot path should reject 'phase', got: {msg}"
        );
    }

    #[test]
    fn one_shot_rejects_sandbox_id_field() {
        let json = r#"{"process": {"commandLine": "echo hi"}, "sandboxId": "abc"}"#;
        let encoded = base64_encode(json.as_bytes());
        let mut logger = test_logger();

        let err = load_request(&encoded, &mut logger, true).unwrap_err();
        let msg = format!("{err}");
        assert!(
            msg.contains("sandboxId") && msg.contains("state-aware"),
            "one-shot path should reject 'sandboxId', got: {msg}"
        );
    }

    #[test]
    fn one_shot_rejects_correlation_vector_field() {
        // `correlationVector` is a state-aware-only relay field; a one-shot
        // payload carrying it must be rejected, mirroring `phase`/`sandboxId`.
        let json = r#"{"process": {"commandLine": "echo hi"}, "correlationVector": "AAAAAAAAAAAAAAAAAAAAAA.0"}"#;
        let encoded = base64_encode(json.as_bytes());
        let mut logger = test_logger();

        let err = load_request(&encoded, &mut logger, true).unwrap_err();
        let msg = format!("{err}");
        assert!(
            msg.contains("correlationVector") && msg.contains("state-aware"),
            "one-shot path should reject 'correlationVector', got: {msg}"
        );
    }

    #[test]
    fn top_level_macos_sandbox_alias_maps_to_seatbelt() {
        // The deprecated `macos_sandbox` section-key alias on the top-level
        // `seatbelt` field is still accepted and maps to `req.seatbelt`.
        let json = r#"{"process": {"commandLine": "echo hi"}, "containment": "seatbelt", "macos_sandbox": {"guiAccess": true}}"#;
        let encoded = base64_encode(json.as_bytes());
        let mut logger = test_logger();

        let req = load_request(&encoded, &mut logger, true).unwrap();
        let sb = req.seatbelt.expect("seatbelt config present via alias");
        assert!(
            sb.gui_access,
            "guiAccess should be carried through the alias"
        );
    }

    #[test]
    fn top_level_annotations_allowed() {
        // `$schema` and `_comment` are permitted but ignored.
        let json = r#"{
            "$schema": "../schemas/dev/mxc-config.schema.0.7.0-dev.json",
            "_comment": "annotation that the parser ignores",
            "version": "0.7.0-alpha",
            "process": {"commandLine": "echo hi"}
        }"#;
        let encoded = base64_encode(json.as_bytes());
        let mut logger = test_logger();

        let req = load_request(&encoded, &mut logger, true).unwrap();
        assert_eq!(req.script_code, "echo hi");
    }

    #[test]
    fn state_aware_unknown_top_level_field_rejected() {
        let json = r#"{
            "phase": "provision",
            "containment": "isolation_session",
            "bogusField": true
        }"#;
        let result = load_mxc(json);
        assert!(
            result.is_err(),
            "unknown top-level field on a state-aware request should be rejected"
        );
    }

    #[test]
    fn state_aware_rejects_one_shot_seatbelt_section() {
        // A state-aware request carrying a one-shot-only `seatbelt` policy must
        // be rejected, not silently discarded (the caller might believe the
        // hardening is in effect).
        let json = r#"{
            "phase": "provision",
            "containment": "seatbelt",
            "seatbelt": {"guiAccess": true}
        }"#;
        let err = match load_mxc(json) {
            Err(ParseError::StateAware(e)) => e.to_string(),
            other => panic!("expected StateAware rejection, got: {other:?}"),
        };
        assert!(
            err.contains("seatbelt") && err.contains("do not accept"),
            "got: {err}"
        );
    }

    #[test]
    fn state_aware_rejects_one_shot_lifecycle_section() {
        let json = r#"{
            "phase": "provision",
            "containment": "isolation_session",
            "lifecycle": {"destroyOnExit": false}
        }"#;
        let err = match load_mxc(json) {
            Err(ParseError::StateAware(e)) => e.to_string(),
            other => panic!("expected StateAware rejection, got: {other:?}"),
        };
        assert!(
            err.contains("lifecycle") && err.contains("do not accept"),
            "got: {err}"
        );
    }

    #[test]
    fn state_aware_rejects_one_shot_processcontainer_section() {
        let json = r#"{
            "phase": "provision",
            "containment": "processcontainer",
            "processContainer": {"leastPrivilege": true}
        }"#;
        let err = match load_mxc(json) {
            Err(ParseError::StateAware(e)) => e.to_string(),
            other => panic!("expected StateAware rejection, got: {other:?}"),
        };
        assert!(
            err.contains("processContainer") && err.contains("do not accept"),
            "got: {err}"
        );
    }

    #[test]
    fn state_aware_rejects_one_shot_lxc_section() {
        let json = r#"{
            "phase": "provision",
            "containment": "lxc",
            "lxc": {"distribution": "alpine"}
        }"#;
        let err = match load_mxc(json) {
            Err(ParseError::StateAware(e)) => e.to_string(),
            other => panic!("expected StateAware rejection, got: {other:?}"),
        };
        assert!(
            err.contains("lxc") && err.contains("do not accept"),
            "got: {err}"
        );
    }

    #[test]
    fn state_aware_rejects_experimental_seatbelt() {
        // `experimental.seatbelt` moved to the stable section; the state-aware
        // path must reject it with the migration message, not silently discard
        // it.
        let json = r#"{
            "phase": "provision",
            "containment": "isolation_session",
            "experimental": {"seatbelt": {"guiAccess": true}}
        }"#;
        let err = match load_mxc(json) {
            Err(ParseError::StateAware(e)) => e.to_string(),
            other => panic!("expected StateAware rejection, got: {other:?}"),
        };
        assert!(
            err.contains("has moved to the stable section"),
            "got: {err}"
        );
    }

    #[test]
    fn state_aware_rejects_experimental_macos_sandbox_alias() {
        let json = r#"{
            "phase": "provision",
            "containment": "isolation_session",
            "experimental": {"macos_sandbox": {"guiAccess": true}}
        }"#;
        let err = match load_mxc(json) {
            Err(ParseError::StateAware(e)) => e.to_string(),
            other => panic!("expected StateAware rejection, got: {other:?}"),
        };
        assert!(
            err.contains("has moved to the stable section"),
            "got: {err}"
        );
    }

    #[test]
    fn state_aware_top_level_annotation_allowed() {
        let json = r#"{
            "$schema": "../schemas/dev/mxc-config.schema.0.7.0-dev.json",
            "phase": "provision",
            "containment": "isolation_session"
        }"#;
        match load_mxc(json).unwrap() {
            MxcRequest::StateAware(p) => assert_eq!(p.phase, Phase::Provision),
            _ => panic!("expected state-aware request"),
        }
    }

    #[test]
    fn state_aware_forwards_container_id() {
        // `containerId` is a documented top-level field and must be preserved
        // into the inner ExecutionRequest for state-aware requests, not dropped.
        let json = r#"{
            "phase": "provision",
            "containerId": "sa-container-1",
            "containment": "isolation_session"
        }"#;
        match load_mxc(json).unwrap() {
            MxcRequest::StateAware(p) => {
                assert_eq!(p.phase, Phase::Provision);
                assert_eq!(p.request.container_id, "sa-container-1");
            }
            _ => panic!("expected state-aware request"),
        }
    }

    #[test]
    fn schema_v08_parses_additive_network_policy() {
        let json = r#"{
            "version": "0.8.0-alpha",
            "containment": "processcontainer",
            "process": {"commandLine": "echo hi"},
            "network": {
                "egress": {
                    "default": "deny",
                    "allow": [{
                        "to": [{"cidr": "140.82.112.0/20", "except": ["140.82.113.0/24"]}],
                        "ports": [{"protocol": "tcp", "port": 443}]
                    }]
                },
                "ingress": {"default": "allow", "hostLoopback": "deny"}
            }
        }"#;
        let request = match load_mxc(json).unwrap() {
            MxcRequest::OneShot(request) => request,
            _ => panic!("expected one-shot request"),
        };
        let egress = request.policy.network_egress.expect("0.8 egress");
        assert_eq!(egress.default, NetworkAction::Deny);
        assert_eq!(egress.allow.len(), 1);
        assert_eq!(egress.allow[0].to[0].cidr.prefix_length, 20);
        assert_eq!(egress.allow[0].ports[0].port, Some(443));
        assert_eq!(
            request.policy.network_ingress.expect("0.8 ingress").default,
            NetworkAction::Allow
        );
        assert!(!request.policy.allow_local_network);
        assert_eq!(request.policy.default_network_policy, NetworkPolicy::Block);
        assert!(request.policy.network_mode_specified);
    }

    #[test]
    fn schema_v08_runtime_proxy_does_not_mark_network_posture_supplied() {
        let json = r#"{
            "version": "0.8.0-alpha",
            "containment": "bubblewrap",
            "process": {"commandLine": "echo hi"},
            "runtimeConfig": {"networkProxy": "http://127.0.0.1:8080"}
        }"#;
        let request = match load_mxc(json).unwrap() {
            MxcRequest::OneShot(request) => request,
            _ => panic!("expected one-shot request"),
        };

        assert!(!request.policy.network_mode_specified);
        assert!(request.policy.network_proxy.is_enabled());
    }

    #[test]
    fn schema_v08_parses_runtime_proxy_and_peer() {
        let json = r#"{
            "version": "0.8.0-alpha",
            "containment": "processcontainer",
            "process": {"commandLine": "echo hi"},
            "network": {
                "egress": {"default": "deny"},
                "ingress": {"default": "allow", "hostLoopback": "deny"}
            },
            "runtimeConfig": {"networkProxy": "http://127.0.0.1:8080"},
            "processContainer": {
                "network": {"allowedProxyPeer": "Contoso.Proxy_123"}
            }
        }"#;
        let request = match load_mxc(json).unwrap() {
            MxcRequest::OneShot(request) => request,
            _ => panic!("expected one-shot request"),
        };
        assert_eq!(
            request
                .policy
                .network_proxy
                .address
                .as_ref()
                .map(ProxyAddress::port),
            Some(8080)
        );
        assert_eq!(
            request.policy.allowed_proxy_peer.as_deref(),
            Some("Contoso.Proxy_123")
        );
    }

    #[test]
    fn schema_v08_parses_identityless_processcontainer_proxy() {
        let json = r#"{
            "version": "0.8.0-alpha",
            "containment": "processcontainer",
            "process": {"commandLine": "echo hi"},
            "network": {
                "egress": {"default": "deny"},
                "ingress": {"default": "allow", "hostLoopback": "allow"}
            },
            "runtimeConfig": {"networkProxy": "http://[::1]:8080"}
        }"#;
        let request = match load_mxc(json).unwrap() {
            MxcRequest::OneShot(request) => request,
            _ => panic!("expected one-shot request"),
        };
        assert_eq!(
            request
                .policy
                .network_proxy
                .address
                .as_ref()
                .map(ProxyAddress::port),
            Some(8080)
        );
        assert!(request.policy.allowed_proxy_peer.is_none());
    }

    #[test]
    fn schema_v08_treats_empty_proxy_peer_as_identityless() {
        let json = r#"{
            "version": "0.8.0-alpha",
            "containment": "processcontainer",
            "process": {"commandLine": "echo hi"},
            "network": {
                "egress": {"default": "deny"},
                "ingress": {"default": "allow", "hostLoopback": "allow"}
            },
            "runtimeConfig": {"networkProxy": "http://127.0.0.1:8080"},
            "processContainer": {
                "network": {"allowedProxyPeer": ""}
            }
        }"#;
        let request = match load_mxc(json).unwrap() {
            MxcRequest::OneShot(request) => request,
            _ => panic!("expected one-shot request"),
        };

        assert!(request.policy.allowed_proxy_peer.is_none());
    }

    #[test]
    fn schema_v08_rejects_runtime_proxy_with_direct_egress() {
        let json = r#"{
            "version": "0.8.0-alpha",
            "containment": "bubblewrap",
            "process": {"commandLine": "echo hi"},
            "network": {
                "egress": {"default": "allow"},
                "ingress": {"default": "allow", "hostLoopback": "allow"}
            },
            "runtimeConfig": {"networkProxy": "http://127.0.0.1:8080"}
        }"#;
        let error = match load_mxc(json) {
            Err(ParseError::OneShot(error)) => error.to_string(),
            other => panic!("expected one-shot rejection, got: {other:?}"),
        };
        assert!(error.contains("egress.default='deny'"));
    }

    #[test]
    fn schema_v08_rejects_runtime_proxy_with_direct_rules() {
        for rules in [
            r#""allow": [{"to": [{"cidr": "192.0.2.0/24"}]}]"#,
            r#""deny": [{"to": [{"cidr": "192.0.2.0/24"}]}]"#,
        ] {
            let json = format!(
                r#"{{
                    "version": "0.8.0-alpha",
                    "containment": "bubblewrap",
                    "process": {{"commandLine": "echo hi"}},
                    "network": {{
                        "egress": {{"default": "deny", {rules}}},
                        "ingress": {{"default": "deny", "hostLoopback": "deny"}}
                    }},
                    "runtimeConfig": {{"networkProxy": "http://127.0.0.1:8080"}}
                }}"#
            );
            let error = match load_mxc(&json) {
                Err(ParseError::OneShot(error)) => error.to_string(),
                other => panic!("expected one-shot rejection, got: {other:?}"),
            };
            assert!(error.contains("no direct allow or deny rules"));
        }
    }

    #[test]
    fn schema_v08_rejects_invalid_processcontainer_proxy_postures() {
        for (peer, ingress, expected) in [
            (
                "",
                r#"{"default": "deny", "hostLoopback": "allow"}"#,
                "network.ingress.default='allow'",
            ),
            (
                r#""allowedProxyPeer": "Contoso.Proxy_123""#,
                r#"{"default": "allow", "hostLoopback": "allow"}"#,
                "identity-scoped ProcessContainer proxy",
            ),
            (
                "",
                r#"{"default": "allow", "hostLoopback": "deny"}"#,
                "without allowedProxyPeer",
            ),
        ] {
            let process_container = if peer.is_empty() {
                String::new()
            } else {
                format!(r#","processContainer": {{"network": {{{peer}}}}}"#)
            };
            let json = format!(
                r#"{{
                    "version": "0.8.0-alpha",
                    "containment": "processcontainer",
                    "process": {{"commandLine": "echo hi"}},
                    "network": {{
                        "egress": {{"default": "deny"}},
                        "ingress": {ingress}
                    }},
                    "runtimeConfig": {{"networkProxy": "http://127.0.0.1:8080"}}
                    {process_container}
                }}"#
            );
            let error = match load_mxc(&json) {
                Err(ParseError::OneShot(error)) => error.to_string(),
                other => panic!("expected one-shot rejection, got: {other:?}"),
            };
            assert!(error.contains(expected), "got: {error}");
        }
    }

    #[test]
    fn schema_v08_rejects_proxy_peer_without_runtime_proxy() {
        let json = r#"{
            "version": "0.8.0-alpha",
            "containment": "processcontainer",
            "process": {"commandLine": "echo hi"},
            "processContainer": {
                "network": {"allowedProxyPeer": "Contoso.Proxy_123"}
            }
        }"#;
        let error = match load_mxc(json) {
            Err(ParseError::OneShot(error)) => error.to_string(),
            other => panic!("expected one-shot rejection, got: {other:?}"),
        };
        assert!(error.contains("requires runtimeConfig.networkProxy"));
    }

    #[test]
    fn schema_v08_parses_legacy_network_fields() {
        let json = r#"{
            "version": "0.8.0-alpha",
            "process": {"commandLine": "echo hi"},
            "network": {"defaultPolicy": "allow"}
        }"#;
        let request = match load_mxc(json).unwrap() {
            MxcRequest::OneShot(request) => request,
            _ => panic!("expected one-shot request"),
        };
        assert_eq!(request.policy.default_network_policy, NetworkPolicy::Allow);
        assert!(request.policy.network_egress.is_none());
    }

    #[test]
    fn schema_v08_rejects_mixed_network_formats() {
        for extra in [
            r#""egress": {"default": "deny"}"#,
            r#""ingress": {"default": "deny"}"#,
        ] {
            let json = format!(
                r#"{{
                    "version": "0.8.0-alpha",
                    "process": {{"commandLine": "echo hi"}},
                    "network": {{"defaultPolicy": "allow", {extra}}}
                }}"#
            );
            let error = match load_mxc(&json) {
                Err(ParseError::OneShot(error)) => error.to_string(),
                other => panic!("expected one-shot rejection, got: {other:?}"),
            };
            assert!(error.contains("cannot mix"));
        }
    }

    #[test]
    fn schema_v08_rejects_legacy_network_with_runtime_proxy() {
        let json = r#"{
            "version": "0.8.0-alpha",
            "process": {"commandLine": "echo hi"},
            "network": {"defaultPolicy": "allow"},
            "runtimeConfig": {"networkProxy": "http://127.0.0.1:8080"}
        }"#;
        let error = match load_mxc(json) {
            Err(ParseError::OneShot(error)) => error.to_string(),
            other => panic!("expected one-shot rejection, got: {other:?}"),
        };
        assert!(error.contains("cannot mix"));
    }

    #[test]
    fn schema_v08_allows_legacy_network_with_empty_directional_sections() {
        let json = r#"{
            "version": "0.8.0-alpha",
            "process": {"commandLine": "echo hi"},
            "containment": "processcontainer",
            "network": {"defaultPolicy": "allow"},
            "runtimeConfig": {},
            "processContainer": {"network": {}}
        }"#;
        let request = match load_mxc(json).expect("empty sections do not select directional format")
        {
            MxcRequest::OneShot(request) => request,
            _ => panic!("expected one-shot request"),
        };
        assert_eq!(request.policy.default_network_policy, NetworkPolicy::Allow);
        assert!(request.policy.network_egress.is_none());
    }

    #[test]
    fn schema_v07_rejects_v08_network_fields() {
        for extra in [
            r#""network": {"egress": {"default": "deny"}}"#,
            r#""network": {"egress": null}"#,
            r#""runtimeConfig": {}"#,
            r#""runtimeConfig": null"#,
            r#""processContainer": {"network": {}}"#,
            r#""processContainer": {"network": null}"#,
        ] {
            let json = format!(
                r#"{{
                    "version": "0.7.0-alpha",
                    "process": {{"commandLine": "echo hi"}},
                    "containment": "processcontainer",
                    {extra}
                }}"#
            );
            assert!(load_mxc(&json).is_err());
        }
    }

    #[test]
    fn schema_v08_rejects_remote_runtime_proxy() {
        for proxy in ["http://proxy.example:8080", "http://127.1.2.3:8080"] {
            let json = format!(
                r#"{{
                    "version": "0.8.0-alpha",
                    "process": {{"commandLine": "echo hi"}},
                    "runtimeConfig": {{"networkProxy": "{proxy}"}}
                }}"#
            );
            assert!(load_mxc(&json).is_err());
        }
    }

    #[test]
    fn schema_v08_runtime_proxy_errors_name_runtime_field() {
        let json = r#"{
            "version": "0.8.0-alpha",
            "process": {"commandLine": "echo hi"},
            "runtimeConfig": {"networkProxy": "http://localhost"}
        }"#;
        let error = match load_mxc(json) {
            Err(ParseError::OneShot(error)) => error.to_string(),
            other => panic!("expected one-shot rejection, got: {other:?}"),
        };
        assert!(error.contains("runtimeConfig.networkProxy must include a port"));
        assert!(!error.contains("network.proxy"));
    }

    #[test]
    fn schema_v08_rejects_invalid_cidr_and_port_range() {
        for network in [
            r#"{"egress": {"allow": [{"to": [{"cidr": "example.com"}]}]}}"#,
            r#"{"egress": {"allow": [{"to": [{
                "cidr": "10.0.0.0/8",
                "except": ["192.168.0.0/16"]
            }]}]}}"#,
            r#"{"egress": {"allow": [{"ports": [{"port": 445, "endPort": 443}]}]}}"#,
            r#"{"egress": {"allow": [{"ports": [{"protocol": "icmp", "port": 8}]}]}}"#,
        ] {
            let json = format!(
                r#"{{
                    "version": "0.8.0-alpha",
                    "process": {{"commandLine": "echo hi"}},
                    "network": {network}
                }}"#
            );
            assert!(load_mxc(&json).is_err());
        }
    }

    #[test]
    fn schema_v08_rejects_explicitly_empty_rule_selectors() {
        for (selector, expected_path) in [("\"to\": []", ".to"), ("\"ports\": []", ".ports")] {
            let json = format!(
                r#"{{
                    "version": "0.8.0-alpha",
                    "process": {{"commandLine": "echo hi"}},
                    "network": {{"egress": {{"allow": [{{{selector}}}]}}}}
                }}"#
            );
            let error = match load_mxc(&json) {
                Err(ParseError::OneShot(error)) => error.to_string(),
                other => panic!("expected one-shot rejection, got: {other:?}"),
            };
            assert!(error.contains(expected_path), "got: {error}");
            assert!(error.contains("must contain at least one"), "got: {error}");
        }
    }

    #[test]
    fn schema_v08_invalid_cidr_error_has_path_and_reason() {
        let json = r#"{
            "version": "0.8.0-alpha",
            "process": {"commandLine": "echo hi"},
            "network": {
                "egress": {
                    "allow": [{"to": [{"cidr": "10.0.0.1/8"}]}]
                }
            }
        }"#;

        let error = match load_mxc(json) {
            Err(ParseError::OneShot(error)) => error.to_string(),
            other => panic!("expected one-shot rejection, got: {other:?}"),
        };
        assert!(error.contains("network.egress.allow[0].to[0].cidr"));
        assert!(error.contains("must be a valid network CIDR"));
        assert!(error.contains("host part of address was not zero"));
    }

    #[test]
    fn schema_v08_rejects_explicit_zero_port() {
        let json = r#"{
            "version": "0.8.0-alpha",
            "process": {"commandLine": "echo hi"},
            "network": {
                "egress": {
                    "allow": [{
                        "ports": [{"protocol": "tcp", "port": 0}]
                    }]
                }
            }
        }"#;
        let error = match load_mxc(json) {
            Err(ParseError::OneShot(error)) => error.to_string(),
            other => panic!("expected one-shot rejection, got: {other:?}"),
        };
        assert!(error.contains("port must be between 1 and 65535"));
    }

    #[test]
    fn schema_v08_rejects_invalid_end_port_forms() {
        for (port, expected) in [
            (
                r#"{"protocol": "tcp", "port": 1, "endPort": 0}"#,
                "between 1 and 65535",
            ),
            (r#"{"protocol": "tcp", "endPort": 443}"#, "requires port"),
        ] {
            let json = format!(
                r#"{{
                    "version": "0.8.0-alpha",
                    "process": {{"commandLine": "echo hi"}},
                    "network": {{
                        "egress": {{"allow": [{{"ports": [{port}]}}]}}
                    }}
                }}"#
            );
            let error = match load_mxc(&json) {
                Err(ParseError::OneShot(error)) => error.to_string(),
                other => panic!("expected one-shot rejection, got: {other:?}"),
            };
            assert!(error.contains("network.egress.allow[0].ports[0].endPort"));
            assert!(error.contains(expected), "got: {error}");
        }
    }

    #[test]
    fn schema_version_max_accepted() {
        let json = format!(
            r#"{{"process": {{"commandLine": "echo hi"}}, "version": "{}"}}"#,
            CURRENT_SCHEMA_VERSION
        );
        let encoded = base64_encode(json.as_bytes());
        let mut logger = test_logger();

        let req = load_request(&encoded, &mut logger, true).unwrap();
        assert_eq!(req.schema_version, CURRENT_SCHEMA_VERSION);
    }

    #[test]
    fn schema_version_below_min_rejected() {
        let json = r#"{"process": {"commandLine": "echo hi"}, "version": "0.5.0-alpha"}"#;
        let encoded = base64_encode(json.as_bytes());
        let mut logger = test_logger();

        let err = load_request(&encoded, &mut logger, true).unwrap_err();
        assert!(
            err.to_string().contains("older than supported"),
            "expected an older-than-supported error, got: {err}"
        );
    }

    #[test]
    fn schema_version_min_accepted() {
        let json = r#"{"process": {"commandLine": "echo hi"}, "version": "0.6.0-alpha"}"#;
        let encoded = base64_encode(json.as_bytes());
        let mut logger = test_logger();

        let req = load_request(&encoded, &mut logger, true).unwrap();
        assert_eq!(req.schema_version, "0.6.0-alpha");
    }

    #[test]
    fn schema_version_between_bounds_accepted() {
        let json = r#"{"process": {"commandLine": "echo hi"}, "version": "0.7.0-alpha"}"#;
        let encoded = base64_encode(json.as_bytes());
        let mut logger = test_logger();

        let req = load_request(&encoded, &mut logger, true).unwrap();
        assert_eq!(req.schema_version, "0.7.0-alpha");
    }

    #[test]
    fn schema_version_above_max_rejected() {
        let json = r#"{"process": {"commandLine": "echo hi"}, "version": "0.10.0-alpha"}"#;
        let encoded = base64_encode(json.as_bytes());
        let mut logger = test_logger();

        let err = load_request(&encoded, &mut logger, true).unwrap_err();
        assert!(
            err.to_string().contains("newer than supported"),
            "expected a newer-than-supported error, got: {err}"
        );
    }

    #[test]
    fn full_config_with_0_6_0_alpha_accepted() {
        let json = r#"{
            "version": "0.6.0-alpha",
            "containerId": "test-060",
            "containment": "processcontainer",
            "process": { "commandLine": "echo hello", "timeout": 5000 },
            "filesystem": { "readwritePaths": ["C:\\workspace"] },
            "network": { "defaultPolicy": "block" }
        }"#;
        let encoded = base64_encode(json.as_bytes());
        let mut logger = test_logger();

        let req = load_request(&encoded, &mut logger, true).unwrap();
        assert_eq!(req.schema_version, "0.6.0-alpha");
        assert_eq!(req.container_id, "test-060");
        assert_eq!(req.script_timeout, 5000);
        assert_eq!(req.policy.readwrite_paths, vec!["C:\\workspace"]);
    }

    #[test]
    fn schema_version_absent_accepted() {
        let json = r#"{"process": {"commandLine": "echo hi"}}"#;
        let encoded = base64_encode(json.as_bytes());
        let mut logger = test_logger();

        let req = load_request(&encoded, &mut logger, true).unwrap();
        assert_eq!(req.schema_version, "");
    }

    #[test]
    fn schema_version_non_semver_rejected() {
        let json = r#"{"process": {"commandLine": "echo hi"}, "version": "x"}"#;
        let encoded = base64_encode(json.as_bytes());
        let mut logger = test_logger();

        let result = load_request(&encoded, &mut logger, true);
        assert!(result.is_err());
    }

    #[test]
    fn malformed_schema_version_precedes_directional_field_gate() {
        let json = r#"{
            "version": "0.8x",
            "process": {"commandLine": "echo hi"},
            "network": {"egress": {"default": "deny"}}
        }"#;
        let error = match load_mxc(json) {
            Err(ParseError::OneShot(error)) => error.to_string(),
            other => panic!("expected one-shot rejection, got: {other:?}"),
        };

        assert!(error.contains("Invalid schema version"));
        assert!(!error.contains("require schema version 0.8"));
    }

    #[test]
    fn schema_version_major_only_rejected() {
        let json = r#"{"process": {"commandLine": "echo hi"}, "version": "2"}"#;
        let encoded = base64_encode(json.as_bytes());
        let mut logger = test_logger();

        let result = load_request(&encoded, &mut logger, true);
        assert!(result.is_err());
    }

    #[test]
    fn schema_version_error_escapes_control_characters() {
        // The invalid version is free-form user input echoed into a manual
        // (non-serde) diagnostic; it must not carry raw ESC / newline bytes.
        let error = validate_schema_version("1.\u{1b}[31m0\nX").unwrap_err();
        let message = error.to_string();
        assert!(!message.contains('\u{1b}'), "got: {message}");
        assert!(!message.contains('\n'), "got: {message}");
        assert!(
            message.contains("\\u{1b}") || message.contains("\\x1b"),
            "got: {message}"
        );
    }

    #[test]
    fn root_object_expecting_text_is_pinned_across_both_parse_passes() {
        // serde's `expecting` attribute requires a string literal, so the
        // wording is duplicated on `RequestDiscriminator` and `wire::MxcConfig`.
        // Pin both diagnostics so the two parse passes cannot drift.
        let discriminator_err =
            match config_deserialize::from_str::<RequestDiscriminator<'_>>(r#""not an object""#) {
                Ok(_) => panic!("non-object root must fail discriminator parse"),
                Err(error) => error,
            };
        let wire_err = match config_deserialize::from_str::<wire::MxcConfig>(r#""not an object""#) {
            Ok(_) => panic!("non-object root must fail wire parse"),
            Err(error) => error,
        };

        assert!(discriminator_err
            .to_string()
            .contains("expected a configuration object"));
        assert!(wire_err
            .to_string()
            .contains("expected a configuration object"));
    }

    #[test]
    fn sandbox_idle_timeout_ms_accepted() {
        let json = r#"{"process": {"commandLine": "echo hi"}, "containment": "windows_sandbox", "experimental": {"windows_sandbox": {"idleTimeoutMs": 60000}}}"#;
        let encoded = base64_encode(json.as_bytes());
        let mut logger = test_logger();

        let req = load_request(&encoded, &mut logger, true).unwrap();
        assert_eq!(
            req.experimental.windows_sandbox.unwrap().idle_timeout_ms,
            60000
        );
    }

    #[test]
    fn sandbox_idle_timeout_ms_overrides_idle_timeout() {
        let json = r#"{"process": {"commandLine": "echo hi"}, "containment": "windows_sandbox", "experimental": {"windows_sandbox": {"idleTimeout": 10000, "idleTimeoutMs": 60000}}}"#;
        let encoded = base64_encode(json.as_bytes());
        let mut logger = test_logger();

        let req = load_request(&encoded, &mut logger, true).unwrap();
        assert_eq!(
            req.experimental.windows_sandbox.unwrap().idle_timeout_ms,
            60000
        );
    }

    #[test]
    fn container_id_parsed() {
        let json = r#"{"process": {"commandLine": "echo hi"}, "containerId": "my-container"}"#;
        let encoded = base64_encode(json.as_bytes());
        let mut logger = test_logger();

        let req = load_request(&encoded, &mut logger, true).unwrap();
        assert_eq!(req.container_id, "my-container");
    }

    #[test]
    fn lifecycle_destroy_on_exit_parsed() {
        let json =
            r#"{"process": {"commandLine": "echo hi"}, "lifecycle": {"destroyOnExit": false}}"#;
        let encoded = base64_encode(json.as_bytes());
        let mut logger = test_logger();

        let req = load_request(&encoded, &mut logger, true).unwrap();
        assert!(!req.lifecycle.destroy_on_exit);
    }

    #[test]
    fn lifecycle_preserve_policy_parsed() {
        let json =
            r#"{"process": {"commandLine": "echo hi"}, "lifecycle": {"preservePolicy": true}}"#;
        let encoded = base64_encode(json.as_bytes());
        let mut logger = test_logger();

        let req = load_request(&encoded, &mut logger, true).unwrap();
        assert!(req.lifecycle.preserve_policy);
    }

    #[test]
    fn lifecycle_defaults_when_absent() {
        let json = r#"{"process": {"commandLine": "echo hi"}}"#;
        let encoded = base64_encode(json.as_bytes());
        let mut logger = test_logger();

        let req = load_request(&encoded, &mut logger, true).unwrap();
        assert!(req.lifecycle.destroy_on_exit);
        assert!(!req.lifecycle.preserve_policy);
    }

    #[test]
    fn wslc_section_parsed() {
        let json = r#"{"process": {"commandLine": "echo hi"}, "containment": "wslc", "experimental": {"wslc": {"image": "python:3.12"}}}"#;
        let encoded = base64_encode(json.as_bytes());
        let mut logger = test_logger();

        let req = load_request(&encoded, &mut logger, true).unwrap();
        let wslc = req.experimental.wslc.unwrap();
        assert_eq!(wslc.image, "python:3.12");
        assert!(wslc.image_tar_path.is_none());
    }

    #[test]
    fn wslc_image_tar_path_parsed() {
        let json = r#"{"process": {"commandLine": "echo hi"}, "containment": "wslc", "experimental": {"wslc": {"image": "my-image:latest", "imageTarPath": "C:\\images\\alpine.tar"}}}"#;
        let encoded = base64_encode(json.as_bytes());
        let mut logger = test_logger();

        let req = load_request(&encoded, &mut logger, true).unwrap();
        let wslc = req.experimental.wslc.unwrap();
        assert_eq!(wslc.image, "my-image:latest");
        assert_eq!(
            wslc.image_tar_path.as_deref(),
            Some("C:\\images\\alpine.tar")
        );
    }

    #[test]
    fn wslc_port_mapping_basic_tcp_parsed() {
        let json = r#"{"process": {"commandLine": "echo hi"}, "containment": "wslc", "experimental": {"wslc": {"image": "python:3.12", "portMappings": [{"windowsPort": 8080, "containerPort": 80, "protocol": "tcp"}]}}}"#;
        let encoded = base64_encode(json.as_bytes());
        let mut logger = test_logger();

        let req = load_request(&encoded, &mut logger, true).unwrap();
        let wslc = req.experimental.wslc.unwrap();
        assert_eq!(wslc.port_mappings.len(), 1);
        assert_eq!(wslc.port_mappings[0].windows_port, 8080);
        assert_eq!(wslc.port_mappings[0].container_port, 80);
        assert_eq!(wslc.port_mappings[0].protocol, "tcp");
    }

    #[test]
    fn wslc_port_mappings_default_protocol_is_tcp() {
        let json = r#"{"process": {"commandLine": "echo hi"}, "containment": "wslc", "experimental": {"wslc": {"image": "python:3.12", "portMappings": [{"windowsPort": 8080, "containerPort": 80}]}}}"#;
        let encoded = base64_encode(json.as_bytes());
        let mut logger = test_logger();

        let req = load_request(&encoded, &mut logger, true).unwrap();
        let wslc = req.experimental.wslc.unwrap();
        assert_eq!(wslc.port_mappings[0].protocol, "tcp");
    }

    #[test]
    fn wslc_port_mapping_uppercase_protocol_rejected() {
        // Strict enums are case-sensitive: "TCP" is not the lowercase wire
        // value "tcp", so it is rejected at deserialize as an unknown variant.
        // Only lowercase "tcp" is accepted (see wslc_port_mapping_basic_tcp_parsed).
        let json = r#"{"process": {"commandLine": "echo hi"}, "containment": "wslc", "experimental": {"wslc": {"image": "python:3.12", "portMappings": [{"windowsPort": 8080, "containerPort": 80, "protocol": "TCP"}]}}}"#;
        let encoded = base64_encode(json.as_bytes());
        let mut logger = test_logger();

        let err = load_request(&encoded, &mut logger, true).unwrap_err();
        let msg = format!("{}", err);
        assert!(
            msg.contains("unknown variant"),
            "expected strict-enum rejection of uppercase protocol, got: {msg}"
        );
    }

    #[test]
    fn wslc_port_mapping_udp_rejected() {
        // The wire model's TransportProtocol is tcp-only (the WSLC SDK runtime
        // returns E_NOTIMPL for UDP), so "udp" is rejected at
        // deserialize as an unknown enum variant.
        let json = r#"{"process": {"commandLine": "echo hi"}, "containment": "wslc", "experimental": {"wslc": {"image": "python:3.12", "portMappings": [{"windowsPort": 5353, "containerPort": 53, "protocol": "udp"}]}}}"#;
        let encoded = base64_encode(json.as_bytes());
        let mut logger = test_logger();

        let err = load_request(&encoded, &mut logger, true).unwrap_err();
        let msg = format!("{}", err);
        assert!(
            msg.contains("udp") && msg.contains("unknown variant"),
            "got: {msg}"
        );
    }

    #[test]
    fn wslc_port_mapping_missing_windows_port_rejected() {
        let json = r#"{"process": {"commandLine": "echo hi"}, "containment": "wslc", "experimental": {"wslc": {"image": "python:3.12", "portMappings": [{"containerPort": 80}]}}}"#;
        let encoded = base64_encode(json.as_bytes());
        let mut logger = test_logger();

        let err = load_request(&encoded, &mut logger, true).unwrap_err();
        let msg = format!("{}", err);
        assert!(
            msg.contains("windows_port") || msg.contains("windowsPort"),
            "expected serde missing-field error mentioning windowsPort, got: {msg}"
        );
    }

    #[test]
    fn wslc_port_mapping_missing_container_port_rejected() {
        let json = r#"{"process": {"commandLine": "echo hi"}, "containment": "wslc", "experimental": {"wslc": {"image": "python:3.12", "portMappings": [{"windowsPort": 8080}]}}}"#;
        let encoded = base64_encode(json.as_bytes());
        let mut logger = test_logger();

        let err = load_request(&encoded, &mut logger, true).unwrap_err();
        let msg = format!("{}", err);
        assert!(
            msg.contains("container_port") || msg.contains("containerPort"),
            "expected serde missing-field error mentioning containerPort, got: {msg}"
        );
    }

    #[test]
    fn wslc_port_mapping_zero_windows_port_rejected() {
        let json = r#"{"process": {"commandLine": "echo hi"}, "containment": "wslc", "experimental": {"wslc": {"image": "python:3.12", "portMappings": [{"windowsPort": 0, "containerPort": 80}]}}}"#;
        let encoded = base64_encode(json.as_bytes());
        let mut logger = test_logger();

        let err = load_request(&encoded, &mut logger, true).unwrap_err();
        let msg = format!("{}", err);
        assert!(
            msg.contains("windowsPort") && msg.contains("> 0"),
            "got: {msg}"
        );
    }

    #[test]
    fn wslc_port_mapping_zero_container_port_rejected() {
        let json = r#"{"process": {"commandLine": "echo hi"}, "containment": "wslc", "experimental": {"wslc": {"image": "python:3.12", "portMappings": [{"windowsPort": 8080, "containerPort": 0}]}}}"#;
        let encoded = base64_encode(json.as_bytes());
        let mut logger = test_logger();

        let err = load_request(&encoded, &mut logger, true).unwrap_err();
        let msg = format!("{}", err);
        assert!(
            msg.contains("containerPort") && msg.contains("> 0"),
            "got: {msg}"
        );
    }

    #[test]
    fn wslc_port_mapping_unsupported_protocol_rejected() {
        // An unknown protocol like "sctp" is rejected at deserialize: the
        // tcp-only TransportProtocol enum has no matching variant.
        let json = r#"{"process": {"commandLine": "echo hi"}, "containment": "wslc", "experimental": {"wslc": {"image": "python:3.12", "portMappings": [{"windowsPort": 8080, "containerPort": 80, "protocol": "sctp"}]}}}"#;
        let encoded = base64_encode(json.as_bytes());
        let mut logger = test_logger();

        let err = load_request(&encoded, &mut logger, true).unwrap_err();
        let msg = format!("{}", err);
        assert!(
            msg.contains("sctp") && msg.contains("unknown variant"),
            "got: {msg}"
        );
    }

    #[test]
    fn wslc_port_mapping_duplicate_host_port_same_protocol_rejected() {
        let json = r#"{"process": {"commandLine": "echo hi"}, "containment": "wslc", "experimental": {"wslc": {"image": "python:3.12", "portMappings": [{"windowsPort": 8080, "containerPort": 80}, {"windowsPort": 8080, "containerPort": 81}]}}}"#;
        let encoded = base64_encode(json.as_bytes());
        let mut logger = test_logger();

        let err = load_request(&encoded, &mut logger, true).unwrap_err();
        let msg = format!("{}", err);
        assert!(
            msg.contains("duplicate") && msg.contains("8080"),
            "got: {msg}"
        );
    }

    #[test]
    fn wslc_port_mapping_empty_list_default() {
        let json = r#"{"process": {"commandLine": "echo hi"}, "containment": "wslc", "experimental": {"wslc": {"image": "python:3.12"}}}"#;
        let encoded = base64_encode(json.as_bytes());
        let mut logger = test_logger();

        let req = load_request(&encoded, &mut logger, true).unwrap();
        let wslc = req.experimental.wslc.unwrap();
        assert!(wslc.port_mappings.is_empty());
    }

    // ---------- Experimental feature tests ----------

    #[test]
    fn experimental_section_parsed_when_present() {
        let json = r#"{"process": {"commandLine": "echo hi"}, "experimental": {"test": {"message": "world"}}}"#;
        let encoded = base64_encode(json.as_bytes());
        let mut logger = test_logger();

        let req = load_request(&encoded, &mut logger, true).unwrap();
        assert!(req.experimental.test.is_some());
        assert_eq!(req.experimental.test.unwrap().message, "world");
    }

    #[test]
    fn experimental_section_absent_is_ok() {
        let json = r#"{"process": {"commandLine": "echo hi"}}"#;
        let encoded = base64_encode(json.as_bytes());
        let mut logger = test_logger();

        let req = load_request(&encoded, &mut logger, true).unwrap();
        assert!(req.experimental.test.is_none());
    }

    #[test]
    fn experimental_enabled_defaults_to_false() {
        let json = r#"{"process": {"commandLine": "echo hi"}, "experimental": {"test": {"message": "check"}}}"#;
        let encoded = base64_encode(json.as_bytes());
        let mut logger = test_logger();

        let req = load_request(&encoded, &mut logger, true).unwrap();
        assert!(!req.experimental_enabled);
    }

    #[test]
    fn unknown_experimental_fields_ignored() {
        let json = r#"{"process": {"commandLine": "echo hi"}, "experimental": {"futureFeature": {"x": 1}, "test": {"message": "hi"}}}"#;
        let encoded = base64_encode(json.as_bytes());
        let mut logger = test_logger();

        let req = load_request(&encoded, &mut logger, true).unwrap();
        assert!(req.experimental.test.is_some());
    }

    #[test]
    fn experimental_test_message_parsed() {
        let json = r#"{"process": {"commandLine": "echo hi"}, "experimental": {"test": {"message": "greetings"}}}"#;
        let encoded = base64_encode(json.as_bytes());
        let mut logger = test_logger();

        let req = load_request(&encoded, &mut logger, true).unwrap();
        let test = req.experimental.test.unwrap();
        assert_eq!(test.message, "greetings");
    }

    #[test]
    fn experimental_test_default_message() {
        let json = r#"{"process": {"commandLine": "echo hi"}, "experimental": {"test": {}}}"#;
        let encoded = base64_encode(json.as_bytes());
        let mut logger = test_logger();

        let req = load_request(&encoded, &mut logger, true).unwrap();
        let test = req.experimental.test.unwrap();
        assert!(test.message.is_empty());
    }

    #[test]
    fn ui_section_parsed() {
        let json = r#"{"process": {"commandLine": "echo hi"}, "ui": {"disable": false, "clipboard": "read", "injection": true}}"#;
        let encoded = base64_encode(json.as_bytes());
        let mut logger = test_logger();

        let req = load_request(&encoded, &mut logger, true).unwrap();
        assert!(!req.policy.ui.disable);
        assert_eq!(req.policy.ui.clipboard, ClipboardPolicy::Read);
        assert!(req.policy.ui.injection);
    }

    #[test]
    fn ui_section_defaults_when_omitted() {
        let json = r#"{"process": {"commandLine": "echo hi"}}"#;
        let encoded = base64_encode(json.as_bytes());
        let mut logger = test_logger();

        let req = load_request(&encoded, &mut logger, true).unwrap();
        assert!(req.policy.ui.disable); // default-deny: UI disabled
        assert_eq!(req.policy.ui.clipboard, ClipboardPolicy::None);
        assert!(!req.policy.ui.injection);
    }

    #[test]
    fn ui_clipboard_all_parsed() {
        let json = r#"{"process": {"commandLine": "echo hi"}, "ui": {"clipboard": "all"}}"#;
        let encoded = base64_encode(json.as_bytes());
        let mut logger = test_logger();

        let req = load_request(&encoded, &mut logger, true).unwrap();
        assert_eq!(req.policy.ui.clipboard, ClipboardPolicy::All);
    }

    // ====== Isolation Session containment and config tests ======

    #[test]
    fn containment_isolation_session_accepted() {
        let json = r#"{"process": {"commandLine": "echo hi"}, "containment": "isolation_session"}"#;
        let encoded = base64_encode(json.as_bytes());
        let mut logger = test_logger();

        let req = load_request(&encoded, &mut logger, true).unwrap();
        assert_eq!(req.containment, ContainmentBackend::IsolationSession);
    }

    #[test]
    fn isolation_session_section_still_marks_a_configured_backend() {
        // `experimental.isolation_session` no longer maps to any domain
        // config, but its presence on the WIRE model is what
        // `present_backend_sections` reads to detect a configured backend.
        // Pairing it with another backend section must still be refused, or
        // removing the domain slot would have silently dropped the check.
        let json = r#"{"process": {"commandLine": "echo hi"}, "containment": "isolation_session", "experimental": {"isolation_session": {}, "wslc": {"image": "alpine:latest"}}}"#;
        let encoded = base64_encode(json.as_bytes());
        let mut logger = test_logger();

        let err = load_request(&encoded, &mut logger, true)
            .expect_err("two backend sections must be refused");
        let msg = format!("{err}");
        assert!(
            msg.contains("experimental.wslc") || msg.contains("isolation_session"),
            "expected the conflicting section to be named, got: {msg}"
        );
    }

    #[test]
    fn containment_seatbelt_accepted() {
        let json = r#"{"process": {"commandLine": "echo hi"}, "containment": "seatbelt"}"#;
        let encoded = base64_encode(json.as_bytes());
        let mut logger = test_logger();

        let req = load_request(&encoded, &mut logger, true).unwrap();
        assert_eq!(req.containment, ContainmentBackend::Seatbelt);
    }

    #[test]
    fn seatbelt_config_defaults() {
        // When no seatbelt block is provided the parser leaves it unset.
        let json = r#"{"process": {"commandLine": "echo hi"}, "containment": "seatbelt"}"#;
        let encoded = base64_encode(json.as_bytes());
        let mut logger = test_logger();

        let req = load_request(&encoded, &mut logger, true).unwrap();
        assert!(req.seatbelt.is_none());
    }

    #[test]
    fn seatbelt_profile_override_passed_through() {
        let json = r#"{"process": {"commandLine": "echo hi"}, "containment": "seatbelt", "seatbelt": {"profileOverride": "(version 1)(deny default)"}}"#;
        let encoded = base64_encode(json.as_bytes());
        let mut logger = test_logger();

        let req = load_request(&encoded, &mut logger, true).unwrap();
        let cfg = req.seatbelt.expect("seatbelt should be populated");
        assert_eq!(
            cfg.profile_override.as_deref(),
            Some("(version 1)(deny default)")
        );
    }

    #[test]
    fn seatbelt_nested_pty_defaults_to_true_when_block_present_but_field_absent() {
        // seatbelt block is present but nestedPty is not specified;
        // the parser should fill in true to match the schema default.
        let json =
            r#"{"process": {"commandLine": "echo hi"}, "containment": "seatbelt", "seatbelt": {}}"#;
        let encoded = base64_encode(json.as_bytes());
        let mut logger = test_logger();

        let req = load_request(&encoded, &mut logger, true).unwrap();
        let cfg = req.seatbelt.expect("seatbelt should be populated");
        assert!(cfg.nested_pty);
        assert!(!cfg.keychain_access);
    }

    #[test]
    fn seatbelt_nested_pty_and_keychain_access_pass_through() {
        let json = r#"{"process": {"commandLine": "echo hi"}, "containment": "seatbelt", "seatbelt": {"nestedPty": false, "keychainAccess": true}}"#;
        let encoded = base64_encode(json.as_bytes());
        let mut logger = test_logger();

        let req = load_request(&encoded, &mut logger, true).unwrap();
        let cfg = req.seatbelt.expect("seatbelt should be populated");
        assert!(!cfg.nested_pty);
        assert!(cfg.keychain_access);
    }

    #[test]
    fn top_level_seatbelt_config_accepted() {
        let json = r#"{"process": {"commandLine": "echo hi"}, "containment": "seatbelt", "seatbelt": {"nestedPty": false, "keychainAccess": true}}"#;
        let encoded = base64_encode(json.as_bytes());
        let mut logger = test_logger();

        let req = load_request(&encoded, &mut logger, true).unwrap();
        let cfg = req.seatbelt.expect("seatbelt should be populated");
        assert!(!cfg.nested_pty);
        assert!(cfg.keychain_access);
    }

    #[test]
    fn experimental_seatbelt_errors_with_migration_message() {
        // After promotion, configs using experimental.seatbelt must error.
        let json = r#"{"process": {"commandLine": "echo hi"}, "containment": "seatbelt", "experimental": {"seatbelt": {"nestedPty": true}}}"#;
        let encoded = base64_encode(json.as_bytes());
        let mut logger = test_logger();

        let err = load_request(&encoded, &mut logger, true).unwrap_err();
        let msg = format!("{:?}", err);
        assert!(
            msg.contains("has moved to the stable section"),
            "expected migration error, got: {}",
            msg
        );
    }

    // Legacy wire-name aliases. The parser accepts the pre-0.6 wire vocabulary
    // (`appcontainer`, `macos_sandbox`, and the `appContainer` /
    // `experimental.macos_sandbox` sub-block keys) regardless of the declared
    // schema version, so configs carried forward from older spellings still
    // parse. Each alias maps to the canonical backend / sub-block and emits a
    // deprecation log so callers know to migrate.

    #[test]
    fn legacy_appcontainer_wire_value_aliases_processcontainer() {
        let json = r#"{"process": {"commandLine": "echo hi"}, "containment": "appcontainer"}"#;
        let encoded = base64_encode(json.as_bytes());
        let mut logger = test_logger();

        let req = load_request(&encoded, &mut logger, true).unwrap();
        assert_eq!(req.containment, ContainmentBackend::ProcessContainer);
    }

    #[test]
    fn legacy_macos_sandbox_wire_value_aliases_seatbelt() {
        let json = r#"{"process": {"commandLine": "echo hi"}, "containment": "macos_sandbox"}"#;
        let encoded = base64_encode(json.as_bytes());
        let mut logger = test_logger();

        let req = load_request(&encoded, &mut logger, true).unwrap();
        assert_eq!(req.containment, ContainmentBackend::Seatbelt);
    }

    #[test]
    fn legacy_app_container_subblock_alias_accepted() {
        // The `appContainer` JSON key is a deprecated spelling; serde's alias
        // routes it to the same `processContainer` parsing path regardless of
        // the declared schema version.
        let json = r#"{
            "process": {"commandLine": "print('test')"},
            "containment": "processcontainer",
            "appContainer": {
                "leastPrivilege": true,
                "capabilities": ["internetClient"]
            }
        }"#;
        let encoded = base64_encode(json.as_bytes());
        let mut logger = test_logger();

        let req = load_request(&encoded, &mut logger, true).unwrap();
        assert!(req.policy.least_privilege_mode);
        assert_eq!(req.policy.capabilities, vec!["internetClient".to_string()]);
    }

    #[test]
    fn legacy_experimental_macos_sandbox_subblock_alias_rejected() {
        // `experimental.macos_sandbox` is the pre-rename key; after promotion
        // it should be rejected with a migration error.
        let json = r#"{
            "process": {"commandLine": "echo hi"},
            "containment": "macos_sandbox",
            "experimental": {"macos_sandbox": {"profileOverride": "(version 1)(allow default)"}}
        }"#;
        let encoded = base64_encode(json.as_bytes());
        let mut logger = test_logger();

        let err = load_request(&encoded, &mut logger, true).unwrap_err();
        let msg = format!("{:?}", err);
        assert!(
            msg.contains("has moved to the stable section"),
            "expected migration error, got: {}",
            msg
        );
    }

    // ---- Single-backend-section enforcement ----

    fn make_multi_backend_config(containment: &str, extra_json: &str) -> String {
        let json = format!(
            r#"{{ "containment": "{containment}", "process": {{"commandLine": "echo hi"}}, {extra_json} }}"#
        );
        base64_encode(json.as_bytes())
    }

    fn assert_multi_backend_rejected(containment: &str, extra_json: &str, expected_extra: &str) {
        let encoded = make_multi_backend_config(containment, extra_json);
        let mut logger = test_logger();
        let err =
            load_request(&encoded, &mut logger, true).expect_err("expected rejection but got Ok");
        let msg = format!("{err:?}");
        assert!(
            msg.contains("Multiple containment backends configured"),
            "error did not mention multi-backend rejection: {msg}"
        );
        assert!(
            msg.contains(expected_extra),
            "error did not name the foreign section '{expected_extra}': {msg}"
        );
    }

    fn assert_config_accepted(containment: &str, extra_json: &str) {
        let encoded = make_multi_backend_config(containment, extra_json);
        let mut logger = test_logger();
        load_request(&encoded, &mut logger, true)
            .unwrap_or_else(|err| panic!("expected accept, got error: {err:?}"));
    }

    #[test]
    fn lxc_containment_with_processcontainer_section_rejected() {
        assert_multi_backend_rejected(
            "lxc",
            r#""lxc": {"distribution": "alpine", "release": "3.20"}, "processContainer": {"leastPrivilege": true}"#,
            "processContainer",
        );
    }

    // appContainer is a deprecated alias for processContainer.
    #[test]
    fn lxc_containment_with_legacy_app_container_alias_rejected() {
        assert_multi_backend_rejected(
            "lxc",
            r#""lxc": {"distribution": "alpine", "release": "3.20"}, "appContainer": {"leastPrivilege": true}"#,
            "processContainer",
        );
    }

    #[test]
    fn processcontainer_containment_with_lxc_section_rejected() {
        assert_multi_backend_rejected(
            "processcontainer",
            r#""lxc": {"distribution": "alpine", "release": "3.20"}"#,
            "lxc",
        );
    }

    // Per-backend blocks nested under `experimental` are subject to the same
    // check as top-level blocks.
    #[test]
    fn experimental_backend_section_for_other_containment_rejected() {
        // seatbelt is now top-level, so use it to test cross-backend rejection
        assert_multi_backend_rejected(
            "processcontainer",
            r#""seatbelt": {"guiAccess": true}"#,
            "seatbelt",
        );
    }

    // Sectionless backend: bubblewrap doesn't own any per-backend block, so
    // any backend block is foreign.
    #[test]
    fn bubblewrap_containment_with_lxc_section_rejected() {
        assert_multi_backend_rejected(
            "bubblewrap",
            r#""lxc": {"distribution": "alpine", "release": "3.20"}"#,
            "lxc",
        );
    }

    #[test]
    fn bubblewrap_containment_with_process_container_section_rejected() {
        assert_multi_backend_rejected(
            "bubblewrap",
            r#""processContainer": {"leastPrivilege": true}"#,
            "processContainer",
        );
    }

    #[test]
    fn lxc_containment_with_matching_lxc_section_accepted() {
        assert_config_accepted(
            "lxc",
            r#""lxc": {"distribution": "alpine", "release": "3.20"}"#,
        );
    }

    // `experimental.test` is a generic test feature, not a backend block,
    // so it should not trigger the multi-backend check.
    #[test]
    fn experimental_test_section_does_not_count_as_backend() {
        assert_config_accepted(
            "lxc",
            r#""lxc": {"distribution": "alpine", "release": "3.20"}, "experimental": {"test": {"message": "hello"}}"#,
        );
    }

    // State-aware path: an `experimental` block whose backend key doesn't
    // match the resolved `containment` is rejected the same way as in the
    // one-shot path.
    #[test]
    fn state_aware_foreign_experimental_backend_rejected() {
        let json = r#"{
            "phase": "provision",
            "containment": "isolation_session",
            "experimental": {
                "isolation_session": {},
                "wslc": {"image": "alpine:latest"}
            }
        }"#;
        let encoded = base64_encode(json.as_bytes());
        let mut logger = test_logger();
        let err = load_mxc_request(&encoded, &mut logger, true)
            .expect_err("state-aware config with foreign experimental backend should be rejected");
        let msg = format!("{err:?}");
        assert!(
            msg.contains("Multiple containment backends configured"),
            "error did not mention multi-backend rejection: {msg}"
        );
        assert!(
            msg.contains("experimental.wslc"),
            "error did not name the foreign section: {msg}"
        );
    }

    // ---- Abstract-intent coverage ----
    // Backend sections paired with `containment: "process"` / "vm" must be
    // accepted iff the intent resolves to the owning backend on this OS.

    #[cfg(target_os = "windows")]
    #[test]
    fn abstract_process_with_process_container_accepted_on_windows() {
        let json = r#"{
            "process": {"commandLine": "echo hi"},
            "containment": "process",
            "processContainer": {}
        }"#;
        let encoded = base64_encode(json.as_bytes());
        let mut logger = test_logger();
        load_request(&encoded, &mut logger, true)
            .expect("process resolves to ProcessContainer on Windows");
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn abstract_process_with_seatbelt_accepted_on_macos() {
        let json = r#"{
            "process": {"commandLine": "echo hi"},
            "containment": "process",
            "seatbelt": {}
        }"#;
        let encoded = base64_encode(json.as_bytes());
        let mut logger = test_logger();
        load_request(&encoded, &mut logger, true).expect("process resolves to Seatbelt on macOS");
    }

    #[cfg(not(any(target_os = "windows", target_os = "macos")))]
    #[test]
    fn abstract_process_with_process_container_rejected_off_windows() {
        let json = r#"{
            "process": {"commandLine": "echo hi"},
            "containment": "process",
            "processContainer": {}
        }"#;
        let encoded = base64_encode(json.as_bytes());
        let mut logger = test_logger();
        load_request(&encoded, &mut logger, true)
            .expect_err("processContainer is foreign when process resolves off Windows");
    }

    #[cfg(target_os = "windows")]
    #[test]
    fn abstract_vm_with_windows_sandbox_accepted_on_windows() {
        let json = r#"{
            "process": {"commandLine": "echo hi"},
            "containment": "vm",
            "experimental": {"windows_sandbox": {}}
        }"#;
        let encoded = base64_encode(json.as_bytes());
        let mut logger = test_logger();
        load_request(&encoded, &mut logger, true)
            .expect("vm resolves to WindowsSandbox on Windows");
    }

    #[cfg(not(target_os = "windows"))]
    #[test]
    fn abstract_vm_with_windows_sandbox_rejected_off_windows() {
        let json = r#"{
            "process": {"commandLine": "echo hi"},
            "containment": "vm",
            "experimental": {"windows_sandbox": {}}
        }"#;
        let encoded = base64_encode(json.as_bytes());
        let mut logger = test_logger();
        load_request(&encoded, &mut logger, true).expect_err("vm has no resolver off Windows");
    }

    // --- Filesystem policy normalization tests (most-restrictive-wins) ---

    #[test]
    fn same_path_in_readwrite_and_denied_becomes_denied() {
        let json = r#"{"process": {"commandLine": "echo hi"}, "containment": "process", "filesystem": {"readwritePaths": ["C:\\workspace"], "deniedPaths": ["C:\\workspace"]}}"#;
        let encoded = base64_encode(json.as_bytes());
        let mut logger = test_logger();

        let req = load_request(&encoded, &mut logger, true).unwrap();
        assert!(
            req.policy.readwrite_paths.is_empty(),
            "path should be removed from readwritePaths (denied wins)"
        );
        assert_eq!(req.policy.denied_paths, vec!["C:\\workspace"]);
    }

    #[test]
    fn same_path_in_readwrite_and_readonly_becomes_readonly() {
        let json = r#"{"process": {"commandLine": "echo hi"}, "containment": "process", "filesystem": {"readwritePaths": ["C:\\workspace"], "readonlyPaths": ["C:\\workspace"]}}"#;
        let encoded = base64_encode(json.as_bytes());
        let mut logger = test_logger();

        let req = load_request(&encoded, &mut logger, true).unwrap();
        assert!(
            req.policy.readwrite_paths.is_empty(),
            "path should be removed from readwritePaths (readonly wins)"
        );
        assert_eq!(req.policy.readonly_paths, vec!["C:\\workspace"]);
    }

    #[test]
    fn same_path_in_readonly_and_denied_becomes_denied() {
        let json = r#"{"process": {"commandLine": "echo hi"}, "containment": "process", "filesystem": {"readonlyPaths": ["C:\\tools"], "deniedPaths": ["C:\\tools"]}}"#;
        let encoded = base64_encode(json.as_bytes());
        let mut logger = test_logger();

        let req = load_request(&encoded, &mut logger, true).unwrap();
        assert!(
            req.policy.readonly_paths.is_empty(),
            "path should be removed from readonlyPaths (denied wins)"
        );
        assert_eq!(req.policy.denied_paths, vec!["C:\\tools"]);
    }

    #[test]
    fn same_path_in_all_three_lists_becomes_denied() {
        let json = r#"{"process": {"commandLine": "echo hi"}, "containment": "process", "filesystem": {"readwritePaths": ["C:\\x"], "readonlyPaths": ["C:\\x"], "deniedPaths": ["C:\\x"]}}"#;
        let encoded = base64_encode(json.as_bytes());
        let mut logger = test_logger();

        let req = load_request(&encoded, &mut logger, true).unwrap();
        assert!(req.policy.readwrite_paths.is_empty());
        assert!(req.policy.readonly_paths.is_empty());
        assert_eq!(req.policy.denied_paths, vec!["C:\\x"]);
    }

    #[test]
    fn distinct_paths_across_lists_preserved() {
        let json = r#"{"process": {"commandLine": "echo hi"}, "containment": "process", "filesystem": {"readwritePaths": ["C:\\workspace"], "readonlyPaths": ["C:\\tools"], "deniedPaths": ["C:\\secrets"]}}"#;
        let encoded = base64_encode(json.as_bytes());
        let mut logger = test_logger();

        // Distinct paths — nothing dropped.
        let req = load_request(&encoded, &mut logger, true).unwrap();
        assert_eq!(req.policy.readwrite_paths, vec!["C:\\workspace"]);
        assert_eq!(req.policy.readonly_paths, vec!["C:\\tools"]);
        assert_eq!(req.policy.denied_paths, vec!["C:\\secrets"]);
    }

    #[test]
    fn empty_filesystem_lists_accepted() {
        let json = r#"{"process": {"commandLine": "echo hi"}, "containment": "process", "filesystem": {"readwritePaths": [], "readonlyPaths": [], "deniedPaths": []}}"#;
        let encoded = base64_encode(json.as_bytes());
        let mut logger = test_logger();

        load_request(&encoded, &mut logger, true).unwrap();
    }

    // ── Telemetry ────────────────────────────────────────────────────

    #[test]
    fn telemetry_not_set() {
        let json = r#"{"process":{"commandLine":"echo hi"}}"#;
        let encoded = base64_encode(json.as_bytes());
        let mut logger = test_logger();
        let req = load_request(&encoded, &mut logger, true).unwrap();
        assert!(req.experimental.telemetry.is_none());
    }

    #[test]
    fn telemetry_enabled_true() {
        let json = r#"{"process":{"commandLine":"echo hi"},"experimental":{"telemetry":{"enabled":true}}}"#;
        let encoded = base64_encode(json.as_bytes());
        let mut logger = test_logger();
        let req = load_request(&encoded, &mut logger, true).unwrap();
        let telem = req.experimental.telemetry.expect("telemetry should be set");
        assert_eq!(telem.enabled, Some(true));
    }

    #[test]
    fn telemetry_enabled_false() {
        let json = r#"{"process":{"commandLine":"echo hi"},"experimental":{"telemetry":{"enabled":false}}}"#;
        let encoded = base64_encode(json.as_bytes());
        let mut logger = test_logger();
        let req = load_request(&encoded, &mut logger, true).unwrap();
        let telem = req.experimental.telemetry.expect("telemetry should be set");
        assert_eq!(telem.enabled, Some(false));
    }

    #[test]
    fn telemetry_empty_object() {
        let json = r#"{"process":{"commandLine":"echo hi"},"experimental":{"telemetry":{}}}"#;
        let encoded = base64_encode(json.as_bytes());
        let mut logger = test_logger();
        let req = load_request(&encoded, &mut logger, true).unwrap();
        let telem = req.experimental.telemetry.expect("telemetry should be set");
        assert_eq!(telem.enabled, None);
    }
}
