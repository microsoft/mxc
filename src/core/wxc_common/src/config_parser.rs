// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use std::{borrow::Cow, fs};

use crate::config_deserialize;
use crate::encoding::base64_decode;
use crate::error::WxcError;
use crate::logger::Logger;
use crate::models::{
    ContainerPolicy, ContainmentBackend, ExecutionRequest, ExperimentalConfig,
    IsolationSessionConfig, LifecycleConfig, LxcConfig, NetworkEnforcementMode, NetworkPolicy,
    PortMapping, ProxyAddress, ProxyConfig, SeatbeltConfig, TelemetryConfig, TestFeatureConfig,
    UiPolicy, WindowsSandboxConfig, WslcConfig,
};
use crate::mxc_error::MxcError;
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

        convert_wire_config(cfg, logger, true, opts.allow_missing_command)
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
        let cfg: wire::MxcConfig = config_deserialize::from_value(config)
            .map_err(|error| WxcError::ConfigParse(error.to_string()))?;

        convert_wire_config(cfg, logger, true, allow_missing_command)
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
    result
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
) -> Result<MxcRequest, ParseError> {
    let discriminator: RequestDiscriminator<'_> = config_deserialize::from_str(json_str)
        .map_err(|error| ParseError::Decode(WxcError::ConfigParse(error.to_string())))?;

    if discriminator.phase.is_some() {
        convert_wire_state_aware(
            json_str,
            discriminator.experimental,
            logger,
            allow_missing_command,
        )
        .map(MxcRequest::StateAware)
        .map_err(|e| ParseError::StateAware(MxcError::malformed_request(e.to_string())))
    } else {
        let cfg: wire::MxcConfig = config_deserialize::from_str(json_str)
            .map_err(|error| ParseError::OneShot(WxcError::ConfigParse(error.to_string())))?;
        convert_wire_config(cfg, logger, true, allow_missing_command)
            .map(MxcRequest::OneShot)
            .map_err(ParseError::OneShot)
    }
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
const SUPPORTED_VERSION: &str = ">=0.6, <=0.8";

/// Canonical "latest" schema version string used in samples and tests. Bump
/// alongside `SUPPORTED_VERSION`'s upper bound when a new dev schema lands.
#[cfg(test)]
const CURRENT_SCHEMA_VERSION: &str = "0.8.0-alpha";

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

/// Convert a typed `wire::Proxy` block into the validated domain `ProxyConfig`.
/// Exactly one of `builtinTestServer` / `localhost` / `url` may be set.
fn convert_wire_proxy(proxy: wire::Proxy) -> Result<ProxyConfig, WxcError> {
    // Destructure (no `..`) so a new wire field fails to compile until handled.
    let wire::Proxy {
        builtin_test_server,
        localhost,
        url,
    } = proxy;
    let mut proxy_addr = ProxyAddress::new("127.0.0.1".to_string(), 0);

    if let Some(builtin) = builtin_test_server {
        if !builtin {
            return Err(WxcError::ConfigParse(
                "network.proxy.builtinTestServer must be true when present".to_string(),
            ));
        }
        if localhost.is_some() || url.is_some() {
            return Err(WxcError::ConfigParse(
                "When builtinTestServer is true, no other proxy options may be set".to_string(),
            ));
        }
        return Ok(ProxyConfig {
            address: Some(proxy_addr),
            builtin_test_server: true,
        });
    }

    if let Some(port) = localhost {
        if port == 0 {
            return Err(WxcError::ConfigParse(
                "network.proxy.localhost must be a port between 1 and 65535".to_string(),
            ));
        }
        proxy_addr.port = port;
        return Ok(ProxyConfig {
            address: Some(proxy_addr),
            builtin_test_server: false,
        });
    }

    if let Some(url_str) = url {
        let parsed = url::Url::parse(&url_str)
            .map_err(|e| WxcError::ConfigParse(format!("network.proxy.url is invalid: {e}")))?;

        let host = parsed
            .host_str()
            .ok_or_else(|| {
                WxcError::ConfigParse(format!(
                    "network.proxy.url must include a host (e.g., http://localhost:8080), got: {url_str}"
                ))
            })?
            .to_string();
        let port = parsed.port().ok_or_else(|| {
            WxcError::ConfigParse(format!(
                "network.proxy.url must include a port (e.g., http://localhost:8080), got: {url_str}"
            ))
        })?;

        return Ok(ProxyConfig {
            address: Some(ProxyAddress::from_url(&url_str, host, port)),
            builtin_test_server: false,
        });
    }

    Err(WxcError::ConfigParse(
        "network.proxy must specify builtinTestServer, localhost, or url".to_string(),
    ))
}

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

// `allow_missing_command` relaxes the `require_process == true` arms so that a
// CLI command-line override (provided by the driver after parsing) can stand in
// for `process.commandLine`. When set, a missing or empty `commandLine` is
// silently accepted and `script_code` is left empty.
fn convert_wire_config(
    cfg: wire::MxcConfig,
    logger: &mut Logger,
    require_process: bool,
    allow_missing_command: bool,
) -> Result<ExecutionRequest, WxcError> {
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
    let (script_code, working_directory, script_timeout, env) = match cfg.process {
        Some(process) => {
            let script_code = match process.command_line {
                Some(s) if !s.is_empty() => s,
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
                _ => String::new(),
            };

            // Null bytes can hide malicious payloads from audit logs.
            if script_code.contains('\0') {
                return Err(WxcError::ConfigParse(
                    "process.commandLine must not contain null bytes".to_string(),
                ));
            }

            (
                script_code,
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
        None => (String::new(), String::new(), 0, Vec::new()),
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
    if let Some(ac) = cfg.process_container {
        if let Some(lp) = ac.least_privilege {
            policy.least_privilege_mode = lp;
        }

        // learningMode handling differs between debug and release.
        if ac.learning_mode.unwrap_or(false) {
            #[cfg(debug_assertions)]
            {
                policy
                    .capabilities
                    .push("permissiveLearningMode".to_string());
                logger.log("WARNING: 'learningMode' enabled - AppContainer restrictions will NOT be enforced (DEBUG BUILD ONLY)\n");
                logger.log(
                    "[mxc] permissiveLearningMode injected via 'learningMode: true' - AppContainer restrictions are NOT enforced\n",
                );
            }
            #[cfg(not(debug_assertions))]
            {
                logger.log("SECURITY: 'learningMode' is disabled in release builds. This capability has been removed.\n");
            }
        }

        if let Some(caps) = ac.capabilities {
            #[cfg(debug_assertions)]
            if caps.iter().any(|c| c == "permissiveLearningMode") {
                logger.log(
                    "[mxc] permissiveLearningMode present in policy capabilities - AppContainer restrictions are NOT enforced\n",
                );
            }
            policy.capabilities.extend(caps);
        }

        // SECURITY: Strip permissiveLearningMode in release builds.
        #[cfg(not(debug_assertions))]
        {
            policy.capabilities.retain(|cap| {
                if cap == "permissiveLearningMode" {
                    logger.log("SECURITY: Removed 'permissiveLearningMode' capability (not allowed in release builds)\n");
                    false
                } else {
                    true
                }
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

    // Network section
    if let Some(net) = cfg.network {
        if let Some(proxy) = net.proxy {
            let proxy_config = convert_wire_proxy(proxy)?;
            if proxy_config.is_enabled()
                && containment != ContainmentBackend::ProcessContainer
                && containment != ContainmentBackend::Bubblewrap
                && containment != ContainmentBackend::Seatbelt
            {
                let msg = "Network proxy is only supported with the 'processcontainer', \
                           'bubblewrap', or 'seatbelt' containment backends";
                return Err(WxcError::ConfigParse(msg.to_string()));
            }
            policy.network_proxy = proxy_config;
        }

        if let Some(p) = net.default_policy {
            policy.default_network_policy = p.into();
        }

        if let Some(m) = net.enforcement_mode {
            policy.network_enforcement_mode = m.into();
        }

        if let Some(v) = net.allow_local_network {
            policy.allow_local_network = v;
        }

        if let Some(v) = net.allowed_hosts {
            policy.allowed_hosts = v;
        }
        if let Some(v) = net.blocked_hosts {
            policy.blocked_hosts = v;
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
        let isolation_session = raw_exp.isolation_session.map(|as_cfg| {
            let mut config = IsolationSessionConfig::default();
            if let Some(id) = as_cfg.configuration_id {
                config.configuration_id = id.into();
            }
            config.user = as_cfg.user.map(Into::into);
            config
        });
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
            isolation_session,
            telemetry,
        }
    } else {
        ExperimentalConfig::default()
    };

    // Top-level `seatbelt` config. Configs using `experimental.seatbelt` are
    // rejected above.
    let seatbelt = cfg.seatbelt.map(make_seatbelt_config);

    // UI section
    if let Some(raw_ui) = cfg.ui {
        let clipboard = raw_ui.clipboard.map(Into::into).unwrap_or_default();
        policy.ui = UiPolicy {
            disable: raw_ui.disable.unwrap_or(true),
            clipboard,
            injection: raw_ui.injection.unwrap_or(false),
        };
    }

    Ok(ExecutionRequest {
        schema_version,
        container_id,
        env,
        script_code,
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
        audit: false,
    })
}

fn convert_wire_state_aware(
    json: &str,
    experimental: Option<&RawValue>,
    logger: &mut Logger,
    allow_missing_command: bool,
) -> Result<ParsedStateAwareRequest, WxcError> {
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

    // Mirror the one-shot rejection of moved-to-stable experimental sections.
    // The one-shot path errors on `experimental.seatbelt` in `convert_wire_config`,
    // but the state-aware path peels `experimental` into `experimental_raw`
    // before that runs, so without this check the block would be silently
    // discarded (the same silent-policy-drop class as the F1 stable sections).
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

    let require_process = phase == Phase::Exec;
    let mut request = convert_wire_config(cfg, logger, require_process, allow_missing_command)?;

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
                // well produced a duplicate auxiliary diagnostic (finding F2).
                // Returning the error keeps stdout clean (envelope-owned) and
                // yields a single auxiliary-sink line.
                WxcError::ConfigParse(format!("invalid experimental.telemetry: {e}"))
            })?;
        request.experimental.telemetry = Some(telemetry);
    }

    Ok(ParsedStateAwareRequest {
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
    use crate::models::ClipboardPolicy;

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
                "isolation_session": {"start": {"configurationId": "small"}}
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
                        "isolation_session": {"start": {"configurationId": "small"}}
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
            "experimental": {"isolation_session": {"start": {"configurationId": "small"}}}
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
    fn state_aware_malformed_telemetry_logs_once_and_keeps_primary_clean() {
        // F2 regression: the malformed-telemetry error must reach the auxiliary
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

    #[cfg(debug_assertions)]
    #[test]
    fn learning_mode_adds_capability_in_debug() {
        let json = r#"{"process": {"commandLine": "echo x"}, "containment": "processcontainer", "processContainer": {"learningMode": true}}"#;
        let encoded = base64_encode(json.as_bytes());
        let mut logger = test_logger();

        let req = load_request(&encoded, &mut logger, true).unwrap();
        assert!(req
            .policy
            .capabilities
            .contains(&"permissiveLearningMode".to_string()));
        assert!(logger.get_buffer().contains("WARNING"));
    }

    #[cfg(not(debug_assertions))]
    #[test]
    fn learning_mode_stripped_in_release() {
        let json = r#"{"process": {"commandLine": "echo x"}, "containment": "processcontainer", "processContainer": {"capabilities": ["permissiveLearningMode"]}}"#;
        let encoded = base64_encode(json.as_bytes());
        let mut logger = test_logger();

        let req = load_request(&encoded, &mut logger, true).unwrap();
        assert!(!req
            .policy
            .capabilities
            .contains(&"permissiveLearningMode".to_string()));
        assert!(logger.get_buffer().contains("SECURITY"));
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
        for version in ["0.6.0-alpha", "0.7.0-alpha", "0.8.0-alpha"] {
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
    fn proxy_rejected_with_non_processcontainer() {
        let json = r#"{"process":{"commandLine":"x"},"containment":"lxc","network":{"proxy":{"localhost":8080}}}"#;
        let encoded = base64_encode(json.as_bytes());
        let mut logger = test_logger();

        let result = load_request(&encoded, &mut logger, true);
        assert!(result.is_err());
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
        // the known fields preserved (positive proof of F2 / R2-5).
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
    fn experimental_isolation_user_unknown_field_accepted() {
        let json = r#"{"process": {"commandLine": "echo hi"}, "containment": "isolation_session", "experimental": {"isolation_session": {"user": {"upn": "alice@contoso.com", "wamToken": "tok", "futureField": true}}}}"#;
        let encoded = base64_encode(json.as_bytes());
        let mut logger = test_logger();

        let req = load_request(&encoded, &mut logger, true).unwrap();
        let iso = req
            .experimental
            .isolation_session
            .expect("iso config present");
        let user = iso.user.expect("user present");
        assert_eq!(user.upn, "alice@contoso.com");
        assert_eq!(user.wam_token, "tok");
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
        // it (R2-1 — the experimental-channel completion of F1).
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
        let json = r#"{"process": {"commandLine": "echo hi"}, "version": "0.9.0-alpha"}"#;
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
    fn isolation_session_config_defaults() {
        let json = r#"{"process": {"commandLine": "echo hi"}, "containment": "isolation_session", "experimental": {"isolation_session": {}}}"#;
        let encoded = base64_encode(json.as_bytes());
        let mut logger = test_logger();

        let req = load_request(&encoded, &mut logger, true).unwrap();
        let cfg = req.experimental.isolation_session.unwrap();
        assert_eq!(
            cfg.configuration_id,
            crate::models::IsolationSessionConfigurationId::Composable
        );
    }

    #[test]
    fn isolation_session_config_small() {
        let json = r#"{"process": {"commandLine": "echo hi"}, "containment": "isolation_session", "experimental": {"isolation_session": {"configurationId": "small"}}}"#;
        let encoded = base64_encode(json.as_bytes());
        let mut logger = test_logger();

        let req = load_request(&encoded, &mut logger, true).unwrap();
        let cfg = req.experimental.isolation_session.unwrap();
        assert_eq!(
            cfg.configuration_id,
            crate::models::IsolationSessionConfigurationId::Small
        );
    }

    #[test]
    fn isolation_session_config_medium() {
        let json = r#"{"process": {"commandLine": "echo hi"}, "containment": "isolation_session", "experimental": {"isolation_session": {"configurationId": "medium"}}}"#;
        let encoded = base64_encode(json.as_bytes());
        let mut logger = test_logger();

        let req = load_request(&encoded, &mut logger, true).unwrap();
        let cfg = req.experimental.isolation_session.unwrap();
        assert_eq!(
            cfg.configuration_id,
            crate::models::IsolationSessionConfigurationId::Medium
        );
    }

    #[test]
    fn isolation_session_config_large() {
        let json = r#"{"process": {"commandLine": "echo hi"}, "containment": "isolation_session", "experimental": {"isolation_session": {"configurationId": "large"}}}"#;
        let encoded = base64_encode(json.as_bytes());
        let mut logger = test_logger();

        let req = load_request(&encoded, &mut logger, true).unwrap();
        let cfg = req.experimental.isolation_session.unwrap();
        assert_eq!(
            cfg.configuration_id,
            crate::models::IsolationSessionConfigurationId::Large
        );
    }

    #[test]
    fn isolation_session_config_composable() {
        let json = r#"{"process": {"commandLine": "echo hi"}, "containment": "isolation_session", "experimental": {"isolation_session": {"configurationId": "composable"}}}"#;
        let encoded = base64_encode(json.as_bytes());
        let mut logger = test_logger();

        let req = load_request(&encoded, &mut logger, true).unwrap();
        let cfg = req.experimental.isolation_session.unwrap();
        assert_eq!(
            cfg.configuration_id,
            crate::models::IsolationSessionConfigurationId::Composable
        );
    }

    #[test]
    fn isolation_session_config_unknown_is_rejected() {
        // Strict enums: an unrecognized configurationId is rejected at
        // deserialize time rather than silently defaulting to `composable`.
        let json = r#"{"process": {"commandLine": "echo hi"}, "containment": "isolation_session", "experimental": {"isolation_session": {"configurationId": "xlarge"}}}"#;
        let encoded = base64_encode(json.as_bytes());
        let mut logger = test_logger();

        let err = load_request(&encoded, &mut logger, true).unwrap_err();
        let msg = err.to_string();
        assert!(
            msg.contains("unknown variant") && msg.contains("xlarge"),
            "expected an unknown-variant rejection for configurationId 'xlarge', got: {msg}"
        );
    }

    #[test]
    fn isolation_session_absent_from_experimental() {
        let json = r#"{"process": {"commandLine": "echo hi"}, "experimental": {}}"#;
        let encoded = base64_encode(json.as_bytes());
        let mut logger = test_logger();

        let req = load_request(&encoded, &mut logger, true).unwrap();
        assert!(req.experimental.isolation_session.is_none());
    }

    #[test]
    fn isolation_session_user_field_round_trips_through_one_shot_parser() {
        let json = r#"{"process": {"commandLine": "echo hi"}, "containment": "isolation_session", "experimental": {"isolation_session": {"user": {"upn": "alice@contoso.com", "wamToken": "tok"}}}}"#;
        let encoded = base64_encode(json.as_bytes());
        let mut logger = test_logger();

        let req = load_request(&encoded, &mut logger, true).unwrap();
        let cfg = req.experimental.isolation_session.unwrap();
        let user = cfg
            .user
            .expect("user field should round-trip through the one-shot parser");
        assert_eq!(user.upn, "alice@contoso.com");
        assert_eq!(user.wam_token, "tok");
    }

    #[test]
    fn isolation_session_user_absent_when_field_omitted() {
        let json = r#"{"process": {"commandLine": "echo hi"}, "containment": "isolation_session", "experimental": {"isolation_session": {"configurationId": "medium"}}}"#;
        let encoded = base64_encode(json.as_bytes());
        let mut logger = test_logger();

        let req = load_request(&encoded, &mut logger, true).unwrap();
        let cfg = req.experimental.isolation_session.unwrap();
        assert!(cfg.user.is_none());
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
