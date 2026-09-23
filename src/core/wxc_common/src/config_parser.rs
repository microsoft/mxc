// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use crate::cmdline::{cmdline_from_argv_for_context, CommandLineContext};
use crate::config_deserialize;
use crate::encoding::base64_decode;
use crate::error::WxcError;
use crate::logger::Logger;
use crate::models::{
    CaptureDenialsConfig, CaptureDenialsMode, ContainerPolicy, ContainmentBackend,
    ExecutionRequest, LifecycleConfig, LxcConfig, NetworkEnforcementMode, NetworkPolicy,
    PortMapping, SeatbeltConfig, TelemetryConfig, TestFeatureConfig, UiPolicy,
    WindowsSandboxConfig, WslcConfig,
};
use crate::mxc_error::MxcError;
use crate::network_parser::{host_is_any_loopback, parse_network_policy, NetworkSections};
use crate::state_aware_input::StateAwareInput;
use crate::state_aware_operation::{StateAwareOperation, StateAwareProvision};
use crate::state_aware_request::{MxcRequest, ParsedStateAwareRequest, Phase};
use crate::wire;
use mxc_config_contract::dev::{probe_phase, Phase as ContractPhase};
use mxc_config_contract::{probe_version, supported_versions, ContractVersion, VersionProbeError};
use std::fs;

/// Categorised error from `load_mxc_request`. The `wxc-exec` driver uses the
/// variant to choose the failure-output convention: state-aware failures
/// emit a JSON `{"error": ...}` envelope on stdout, while one-shot and
/// pre-discrimination failures keep the existing diagnostic-on-stderr path.
#[derive(Debug)]
pub enum ParseError {
    /// I/O, base64-decode, or top-level JSON parse failure — the input could
    /// not be discriminated as state-aware vs one-shot.
    Decode(WxcError),
    /// A missing, invalid, or unsupported version declaration, rejected before
    /// one-shot vs state-aware selection.
    Version(WxcError),
    /// Discriminated as one-shot; conversion to `ExecutionRequest` failed.
    OneShot(WxcError),
    /// Discriminated as one-shot, but the JSON payload was malformed.
    OneShotMalformed(WxcError),
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
            Self::Decode(_) | Self::Version(_) | Self::OneShot(_) | Self::OneShotMalformed(_) => {
                ErrorOutput::Primary
            }
            Self::StateAware(_) => ErrorOutput::DiagnosticOnly,
        }
    }

    fn message(&self) -> String {
        match self {
            Self::Decode(error)
            | Self::Version(error)
            | Self::OneShot(error)
            | Self::OneShotMalformed(error) => error.to_string(),
            Self::StateAware(error) => error.to_string(),
        }
    }
}

// ---------- Public API ----------

/// Options for [`load_mxc_request_with_options`].
///
/// Kept as a struct (rather than additional positional arguments) so future
/// loader-tuning knobs can be threaded through without re-spinning every
/// caller.
#[derive(Debug, Clone, Copy, Default)]
pub struct LoadOptions<'a> {
    /// Treat `input` as a base64-encoded JSON blob rather than a file path.
    pub is_base64: bool,
    /// Trailing CLI argv spliced into `process.commandLine` before parsing.
    /// Empty means no override.
    pub cli_command: &'a [String],
}

/// Workspace-internal exact one-shot contract selected by a trusted typed
/// producer.
///
/// This is not a stable external API.
#[doc(hidden)]
#[derive(Debug)]
#[non_exhaustive]
pub enum ExactOneShotContract {
    V0_6(Box<mxc_config_contract::published::v0_6_0_alpha::Request>),
    V0_7(Box<mxc_config_contract::published::v0_7_0_alpha::Request>),
    V0_8(Box<mxc_config_contract::published::v0_8_0_alpha::Request>),
    V0_9(Box<mxc_config_contract::published::v0_9_0_alpha::OneShotRequest>),
    Dev(Box<mxc_config_contract::dev::OneShotRequest>),
}

/// Convert a typed exact one-shot contract through its existing adapter and
/// shared semantic validation.
///
/// This workspace-internal bridge exists for `mxc_engine` policy builders.
#[doc(hidden)]
pub fn load_one_shot_request_from_contract(
    request: ExactOneShotContract,
    logger: &mut Logger,
) -> Result<ExecutionRequest, WxcError> {
    let config = match request {
        ExactOneShotContract::V0_6(request) => {
            crate::config_contract_adapters::v0_6::into_common_request_ir(*request)
        }
        ExactOneShotContract::V0_7(request) => {
            crate::config_contract_adapters::v0_7::into_common_request_ir(*request)
        }
        ExactOneShotContract::V0_8(request) => {
            crate::config_contract_adapters::v0_8::into_common_request_ir(*request)
        }
        ExactOneShotContract::V0_9(request) => {
            mxc_config_contract::published::v0_9_0_alpha::validate_one_shot_request(&request)
                .map_err(|error| WxcError::ConfigParse(error.to_string()))?;
            crate::config_contract_adapters::v0_9::one_shot_into_common_request_ir(*request)
        }
        ExactOneShotContract::Dev(request) => {
            mxc_config_contract::dev::validate_one_shot_request(&request)
                .map_err(|error| WxcError::ConfigParse(error.to_string()))?;
            crate::config_contract_adapters::dev::one_shot_into_common_request_ir(*request)
        }
    };

    let result = normalize_common_request_ir(config, logger, true, false);
    log_one_shot_error(logger, &result);
    result
}

fn exact_version_error(error: VersionProbeError) -> ParseError {
    use serde_json::error::Category;

    match error {
        VersionProbeError::InvalidDeclaration(source) => {
            let category = source.classify();
            let error = WxcError::ConfigParse(format!("Invalid version declaration: {source}"));
            match category {
                Category::Data => ParseError::Version(error),
                Category::Syntax | Category::Eof | Category::Io => ParseError::Decode(error),
            }
        }
        VersionProbeError::UnsupportedVersion(_) => {
            let supported = supported_versions()
                .iter()
                .map(|v| v.as_str())
                .collect::<Vec<_>>()
                .join(", ");
            ParseError::Version(WxcError::ConfigParse(format!(
                "Unsupported contract version. \
                 Registered versions are: {supported}"
            )))
        }
    }
}

fn parse_exact_published_one_shot<T>(
    json: &str,
    logger: &mut Logger,
    adapt: fn(T) -> crate::common_request_ir::CommonRequestIR,
) -> Result<MxcRequest, ParseError>
where
    T: serde::de::DeserializeOwned,
{
    let request = config_deserialize::from_str(json)
        .map_err(|error| ParseError::OneShot(WxcError::ConfigParse(error.to_string())))?;
    normalize_common_request_ir(adapt(request), logger, true, false)
        .map(MxcRequest::OneShot)
        .map_err(ParseError::OneShot)
}

fn exact_phase_error(error: mxc_config_contract::dev::PhaseProbeError) -> ParseError {
    let message = match error {
        mxc_config_contract::dev::PhaseProbeError::InvalidDeclaration(source) => {
            format!("Invalid phase declaration: {source}")
        }
        mxc_config_contract::dev::PhaseProbeError::UnsupportedPhase(_) => {
            "Unsupported phase".to_string()
        }
    };
    ParseError::StateAware(MxcError::malformed_request(message))
}

fn exact_containment_error(error: mxc_config_contract::dev::ContainmentProbeError) -> ParseError {
    let message = match error {
        mxc_config_contract::dev::ContainmentProbeError::InvalidDeclaration(source) => {
            format!("Invalid provision containment declaration: {source}")
        }
        mxc_config_contract::dev::ContainmentProbeError::UnsupportedContainment(_) => {
            "Unsupported containment for provision phase".to_string()
        }
    };
    ParseError::StateAware(MxcError::malformed_request(message))
}

fn development_network_migration(contract: &str, path: Option<&str>) -> Option<&'static str> {
    match (contract, path) {
        ("IsolationSession provision", Some("network.proxy")) => Some(
            "IsolationSession requires network.egress.default, network.ingress.default, and \
             network.ingress.hostLoopback all set to 'allow'; it does not support proxy \
             configuration",
        ),
        (
            "IsolationSession provision",
            Some(
                "network.defaultPolicy"
                | "network.enforcementMode"
                | "network.allowedHosts"
                | "network.blockedHosts"
                | "network.allowLocalNetwork",
            ),
        ) => Some(
            "IsolationSession requires network.egress.default, network.ingress.default, and \
             network.ingress.hostLoopback all set to 'allow'; it does not support network \
             filtering",
        ),
        ("WSLC provision", Some("network.proxy")) => {
            Some("move the proxy URL to top-level runtimeConfig.networkProxy on the exec phase")
        }
        ("WSLC provision", Some("network.defaultPolicy" | "network.allowLocalNetwork")) => Some(
            "set network.egress.default, network.ingress.default, and \
             network.ingress.hostLoopback consistently to 'allow' or 'deny'",
        ),
        ("WSLC provision", Some("network.enforcementMode")) => Some(
            "remove network.enforcementMode; WSLc selects its all-or-nothing network mechanism",
        ),
        ("WSLC provision", Some("network.allowedHosts" | "network.blockedHosts")) => Some(
            "WSLc does not support hostname or destination filtering; use an all-'allow' or \
             all-'deny' directional posture",
        ),
        (_, Some("network.defaultPolicy")) => {
            Some("use network.egress.default ('allow' or 'deny')")
        }
        (_, Some("network.enforcementMode")) => {
            Some("use directional network policy; enforcement is selected by the backend")
        }
        (_, Some("network.allowedHosts" | "network.blockedHosts")) => Some(
            "use network.egress.allow/deny CIDR rules; hostnames cannot be losslessly converted",
        ),
        (_, Some("network.allowLocalNetwork")) => {
            Some("use network.ingress.default and network.ingress.hostLoopback")
        }
        (_, Some("network.proxy")) => Some("use runtimeConfig.networkProxy with a proxy URL"),
        ("IsolationSession provision", Some("network")) => Some(
            "set network.egress.default, network.ingress.default, and \
             network.ingress.hostLoopback to 'allow'",
        ),
        _ => None,
    }
}

fn deserialize_development_root<T>(
    json: &str,
    contract: &'static str,
    version: &'static str,
    state_aware: bool,
) -> Result<T, ParseError>
where
    T: serde::de::DeserializeOwned,
{
    config_deserialize::from_str(json).map_err(|error| {
        let mut message = format!("Invalid {contract} request: {error}");
        if let Some(migration) = development_network_migration(contract, error.path()) {
            message.push_str(&format!("; schema {version} migration: {migration}"));
        }
        if state_aware {
            ParseError::StateAware(MxcError::malformed_request(message))
        } else {
            ParseError::OneShot(WxcError::ConfigParse(message))
        }
    })
}

fn v0_9_phase_error(
    error: mxc_config_contract::published::v0_9_0_alpha::PhaseProbeError,
) -> ParseError {
    let message = match error {
        mxc_config_contract::published::v0_9_0_alpha::PhaseProbeError::InvalidDeclaration(
            source,
        ) => format!("Invalid phase declaration: {source}"),
        mxc_config_contract::published::v0_9_0_alpha::PhaseProbeError::UnsupportedPhase(_) => {
            "Unsupported phase".to_string()
        }
    };
    ParseError::StateAware(MxcError::malformed_request(message))
}

fn v0_9_containment_error(
    error: mxc_config_contract::published::v0_9_0_alpha::ContainmentProbeError,
) -> ParseError {
    let message = match error {
        mxc_config_contract::published::v0_9_0_alpha::ContainmentProbeError::InvalidDeclaration(
            source,
        ) => format!("Invalid provision containment declaration: {source}"),
        mxc_config_contract::published::v0_9_0_alpha::ContainmentProbeError::UnsupportedContainment(
            _,
        ) => "Unsupported containment for provision phase".to_string(),
    };
    ParseError::StateAware(MxcError::malformed_request(message))
}

fn deserialize_v0_9_request(
    json: &str,
    phase: Option<mxc_config_contract::published::v0_9_0_alpha::Phase>,
) -> Result<mxc_config_contract::published::v0_9_0_alpha::Request, ParseError> {
    use mxc_config_contract::published::v0_9_0_alpha::{
        self as contract, Containment, Phase, ProvisionRequest, Request,
    };

    match phase {
        None => {
            let request: contract::OneShotRequest =
                deserialize_development_root(json, "one-shot", "0.9", false)?;
            contract::validate_one_shot_request(&request)
                .map_err(|error| ParseError::OneShot(WxcError::ConfigParse(error.to_string())))?;
            Ok(Request::OneShot(Box::new(request)))
        }
        Some(Phase::Provision) => {
            let request = match contract::probe_containment(json).map_err(v0_9_containment_error)? {
                Containment::IsolationSession => {
                    deserialize_development_root(json, "IsolationSession provision", "0.9", true)
                        .map(ProvisionRequest::IsolationSession)
                }
                Containment::Wslc => {
                    deserialize_development_root(json, "WSLC provision", "0.9", true)
                        .map(ProvisionRequest::Wslc)
                }
            }?;
            Ok(Request::Provision(request))
        }
        Some(Phase::Start) => {
            deserialize_development_root(json, "start", "0.9", true).map(Request::Start)
        }
        Some(Phase::Exec) => {
            deserialize_development_root(json, "exec", "0.9", true).map(Request::Exec)
        }
        Some(Phase::Stop) => {
            deserialize_development_root(json, "stop", "0.9", true).map(Request::Stop)
        }
        Some(Phase::Deprovision) => {
            deserialize_development_root(json, "deprovision", "0.9", true).map(Request::Deprovision)
        }
    }
}

fn parse_exact_v0_9(json: &str, logger: &mut Logger) -> Result<MxcRequest, ParseError> {
    let phase = mxc_config_contract::published::v0_9_0_alpha::probe_phase(json)
        .map_err(v0_9_phase_error)?;
    let request = deserialize_v0_9_request(json, phase)?;
    let adapted = crate::config_contract_adapters::v0_9::adapt_request(request)
        .map_err(|error| ParseError::StateAware(MxcError::malformed_request(error.to_string())))?;

    match adapted {
        crate::config_contract_adapters::v0_9::AdaptedConfigRequest::OneShot(config) => {
            normalize_common_request_ir(config, logger, true, false)
                .map(MxcRequest::OneShot)
                .map_err(ParseError::OneShot)
        }
        crate::config_contract_adapters::v0_9::AdaptedConfigRequest::StateAware(input) => {
            normalize_state_aware(input, logger)
                .map(MxcRequest::StateAware)
                .map_err(|error| {
                    ParseError::StateAware(MxcError::malformed_request(error.to_string()))
                })
        }
    }
}

fn deserialize_development_request(
    json: &str,
    phase: Option<mxc_config_contract::dev::Phase>,
) -> Result<mxc_config_contract::dev::Request, ParseError> {
    use mxc_config_contract::dev::{self, Containment, Phase, ProvisionRequest, Request};

    match phase {
        None => {
            let request: mxc_config_contract::dev::OneShotRequest =
                deserialize_development_root(json, "one-shot", "0.10", false)?;
            dev::validate_one_shot_request(&request)
                .map_err(|error| ParseError::OneShot(WxcError::ConfigParse(error.to_string())))?;
            Ok(Request::OneShot(Box::new(request)))
        }
        Some(Phase::Provision) => {
            let request = match dev::probe_containment(json).map_err(exact_containment_error)? {
                Containment::WindowsSandbox => {
                    deserialize_development_root(json, "Windows Sandbox provision", "0.10", true)
                        .map(ProvisionRequest::WindowsSandbox)
                }
                Containment::IsolationSession => {
                    deserialize_development_root(json, "IsolationSession provision", "0.10", true)
                        .map(ProvisionRequest::IsolationSession)
                }
                Containment::Wslc => {
                    deserialize_development_root(json, "WSLC provision", "0.10", true)
                        .map(ProvisionRequest::Wslc)
                }
            }?;
            Ok(Request::Provision(request))
        }
        Some(Phase::Start) => {
            deserialize_development_root(json, "start", "0.10", true).map(Request::Start)
        }
        Some(Phase::Exec) => {
            deserialize_development_root(json, "exec", "0.10", true).map(Request::Exec)
        }
        Some(Phase::Stop) => {
            deserialize_development_root(json, "stop", "0.10", true).map(Request::Stop)
        }
        Some(Phase::Deprovision) => deserialize_development_root(json, "deprovision", "0.10", true)
            .map(Request::Deprovision),
    }
}

fn parse_exact_development(json: &str, logger: &mut Logger) -> Result<MxcRequest, ParseError> {
    let phase = mxc_config_contract::dev::probe_phase(json).map_err(exact_phase_error)?;
    let request = deserialize_development_request(json, phase)?;
    let adapted = crate::config_contract_adapters::dev::adapt_request(request)
        .map_err(|error| ParseError::StateAware(MxcError::malformed_request(error.to_string())))?;

    match adapted {
        crate::config_contract_adapters::dev::AdaptedConfigRequest::OneShot(config) => {
            normalize_common_request_ir(config, logger, true, false)
                .map(MxcRequest::OneShot)
                .map_err(ParseError::OneShot)
        }
        crate::config_contract_adapters::dev::AdaptedConfigRequest::StateAware(input) => {
            normalize_state_aware(input, logger)
                .map(MxcRequest::StateAware)
                .map_err(|error| {
                    ParseError::StateAware(MxcError::malformed_request(error.to_string()))
                })
        }
    }
}

fn parse_exact_mxc_request_json(json: &str, logger: &mut Logger) -> Result<MxcRequest, ParseError> {
    match probe_version(json).map_err(exact_version_error)? {
        ContractVersion::V0_6_0Alpha => parse_exact_published_one_shot(
            json,
            logger,
            crate::config_contract_adapters::v0_6::into_common_request_ir,
        ),
        ContractVersion::V0_7_0Alpha => parse_exact_published_one_shot(
            json,
            logger,
            crate::config_contract_adapters::v0_7::into_common_request_ir,
        ),
        ContractVersion::V0_8_0Alpha => parse_exact_published_one_shot(
            json,
            logger,
            crate::config_contract_adapters::v0_8::into_common_request_ir,
        ),
        ContractVersion::V0_9_0Alpha => parse_exact_v0_9(json, logger),
        ContractVersion::V0_10_0Alpha => parse_exact_development(json, logger),
    }
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
            cli_command: &[],
        },
    )
}

/// Loads an exact-versioned one-shot request from a file or base64 input.
///
/// State-aware lifecycle documents are rejected because this entry point is
/// intended for executors that only support run-to-completion requests.
pub fn load_one_shot_request(
    input: &str,
    logger: &mut Logger,
    is_base64: bool,
) -> Result<ExecutionRequest, WxcError> {
    let result = (|| {
        let json = decode_request_input(input, is_base64)?;
        match parse_exact_mxc_request_json(&json, logger) {
            Ok(MxcRequest::OneShot(request)) => Ok(request),
            Ok(MxcRequest::StateAware(_)) => Err(WxcError::ConfigParse(
                "expected a one-shot request, got a state-aware lifecycle request".to_string(),
            )),
            Err(
                ParseError::Decode(error)
                | ParseError::Version(error)
                | ParseError::OneShot(error)
                | ParseError::OneShotMalformed(error),
            ) => Err(error),
            Err(ParseError::StateAware(error)) => Err(WxcError::ConfigParse(error.to_string())),
        }
    })();
    log_one_shot_error(logger, &result);
    result
}

/// Options-aware variant of [`load_mxc_request`]. When
/// `LoadOptions::cli_command` is non-empty, it is rendered for the request's
/// backend and spliced into `process.commandLine` before parsing, so the
/// parsed request is complete rather than being patched afterwards.
pub fn load_mxc_request_with_options(
    input: &str,
    logger: &mut Logger,
    opts: LoadOptions<'_>,
) -> Result<MxcRequest, ParseError> {
    let result: Result<MxcRequest, ParseError> = (|| {
        let json_str = decode_request_input(input, opts.is_base64).map_err(ParseError::Decode)?;
        parse_mxc_request_json_with_cli(&json_str, logger, opts.cli_command)
    })();

    if let Err(error) = &result {
        log_error(logger, &error.message(), error.output());
    }

    result
}

/// Parse an MXC request from a **raw JSON string** (already decoded — not a file
/// path or base64). The exact registered version is selected first. Published
/// versions use their registered one-shot or state-aware request root, and the
/// mutable development version does the same. This skips the file/base64 decode
/// step so an in-memory JSON string can be parsed directly.
///
/// This loader enforces exact registered contracts. No alternate whole-request
/// raw-JSON loader is available:
///
/// ```compile_fail
/// use wxc_common::config_parser::load_request_from_json;
/// ```
pub fn load_mxc_request_from_json(
    json_str: &str,
    logger: &mut Logger,
) -> Result<MxcRequest, ParseError> {
    load_mxc_request_from_json_with_options(
        json_str,
        logger,
        LoadOptions {
            is_base64: false,
            cli_command: &[],
        },
    )
}

/// Options-aware variant of [`load_mxc_request_from_json`].
///
/// Executor binaries call this after [`decode_request_input`] to avoid a
/// second read of the input source (file / named pipe / `/dev/stdin` /
/// process-substitution path) that the top-level [`load_mxc_request_with_options`]
/// would perform internally.
pub fn load_mxc_request_from_json_with_options(
    json_str: &str,
    logger: &mut Logger,
    opts: LoadOptions<'_>,
) -> Result<MxcRequest, ParseError> {
    // `is_base64` is meaningless on an already-decoded JSON string; the field
    // is kept in `LoadOptions` for signature parity with the from-input path.
    let _ = opts.is_base64;
    let result = parse_mxc_request_json_with_cli(json_str, logger, opts.cli_command);
    if let Err(error) = &result {
        log_error(logger, &error.message(), error.output());
    }
    result
}

fn parse_mxc_request_json_with_cli(
    json_str: &str,
    logger: &mut Logger,
    cli_command: &[String],
) -> Result<MxcRequest, ParseError> {
    if cli_command.is_empty() {
        return parse_exact_mxc_request_json(json_str, logger);
    }

    let (json_str, override_log) = apply_cli_command(json_str, cli_command)?;
    let request = parse_exact_mxc_request_json(&json_str, logger)?;
    if let Some(message) = override_log {
        logger.log_line(&message);
    }
    Ok(request)
}

/// Resolves a CLI command override by splicing it into the request source,
/// returning the effective document to parse.
///
/// Returns the input **unchanged** whenever the override cannot be applied for
/// a reason the parser will itself report. Those inputs then keep today's error
/// text and output routing rather than inheriting a probe's stricter, and
/// differently routed, diagnostic.
///
/// The exact version is resolved before the lifecycle discriminator. Published
/// contracts do not define `phase`, so a stray phase field must remain a
/// published one-shot contract error even when a CLI command is supplied.
///
/// [`load_mxc_request_with_options`] calls this only after confirming that
/// `LoadOptions::cli_command` is non-empty. The explicit empty-command
/// rejection remains defensive for direct internal callers and future call
/// sites rather than relying solely on that upstream guard.
fn apply_cli_command(json: &str, argv: &[String]) -> Result<(String, Option<String>), ParseError> {
    // An unreadable or unsupported version declaration is the parser's to
    // report without the CLI path reclassifying the request.
    let Ok(version) = probe_version(json) else {
        return Ok((json.to_string(), None));
    };
    let phase = match version {
        ContractVersion::V0_9_0Alpha => {
            let Ok(phase) = mxc_config_contract::published::v0_9_0_alpha::probe_phase(json) else {
                return Ok((json.to_string(), None));
            };
            phase.map(|phase| match phase {
                mxc_config_contract::published::v0_9_0_alpha::Phase::Provision => {
                    ContractPhase::Provision
                }
                mxc_config_contract::published::v0_9_0_alpha::Phase::Start => ContractPhase::Start,
                mxc_config_contract::published::v0_9_0_alpha::Phase::Exec => ContractPhase::Exec,
                mxc_config_contract::published::v0_9_0_alpha::Phase::Stop => ContractPhase::Stop,
                mxc_config_contract::published::v0_9_0_alpha::Phase::Deprovision => {
                    ContractPhase::Deprovision
                }
            })
        }
        ContractVersion::V0_10_0Alpha => {
            let Ok(phase) = probe_phase(json) else {
                return Ok((json.to_string(), None));
            };
            phase
        }
        ContractVersion::V0_6_0Alpha
        | ContractVersion::V0_7_0Alpha
        | ContractVersion::V0_8_0Alpha => None,
    };

    let Some(command_source) = crate::splice::CommandSource::parse(json) else {
        return Ok((json.to_string(), None));
    };

    let context = match phase {
        None => match command_source.one_shot_backend() {
            Some(backend) => CommandLineContext::for_backend(&backend),
            // Likewise an unreadable containment: the typed parse rejects it.
            None => return Ok((json.to_string(), None)),
        },
        Some(ContractPhase::Exec) => {
            // Not a passthrough: `resolve_backend` raises this same error after
            // parsing today, so surfacing it here preserves current behavior.
            // Swallowing it would silently drop the caller's override.
            let backend = command_source
                .state_aware_backend()
                .map_err(ParseError::StateAware)?;
            CommandLineContext::for_backend(&backend)
        }
        Some(_) => {
            return Err(ParseError::StateAware(MxcError::malformed_request(
                "CLI command override is only supported for state-aware exec requests",
            )))
        }
    };

    let command = cmdline_from_argv_for_context(argv, context).map_err(|e| match phase {
        None => ParseError::Decode(WxcError::ConfigParse(format!(
            "invalid CLI command override: {e}"
        ))),
        Some(_) => ParseError::StateAware(MxcError::malformed_request(format!(
            "invalid CLI command override: {e}"
        ))),
    })?;

    if command.is_empty() {
        return Err(ParseError::Decode(WxcError::ConfigParse(
            "CLI command override must not be empty".to_string(),
        )));
    }

    // A document the splice cannot transform is one the parser rejects anyway.
    let Some(spliced) = command_source.splice_command(&command) else {
        return Ok((json.to_string(), None));
    };

    let override_log = spliced
        .replaced_existing
        .then(|| format!("Overriding policy process.commandLine with CLI command: {command}"));

    Ok((spliced.json, override_log))
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

/// Decode a config/maintenance input supplied as a file path or base64 JSON.
///
/// This performs no logging so callers can apply the correct output contract
/// after discriminating execution requests from maintenance commands.
pub fn decode_request_input(input: &str, is_base64: bool) -> Result<String, WxcError> {
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

fn validate_filesystem_paths(policy: &ContainerPolicy) -> Result<(), WxcError> {
    validate_paths(&policy.readonly_paths)?;
    validate_paths(&policy.readwrite_paths)?;
    validate_paths(&policy.enumerate_paths)?;
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
        && policy.enumerate_paths.is_empty()
        && policy.denied_paths.is_empty()
    {
        return;
    }

    // 1. Same-path (string) conflict: drop a path from a list if it also appears
    //    in a more restrictive list.
    let denied: std::collections::HashSet<String> = policy.denied_paths.iter().cloned().collect();
    let enumerate: std::collections::HashSet<String> =
        policy.enumerate_paths.iter().cloned().collect();
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
        } else if enumerate.contains(p) {
            logger.log_line(&format!(
                "Filesystem path '{}' appears in 'filesystem.readwritePaths' and \
                 'processContainer.filesystem.enumeratePaths'; \
                 applying most-restrictive intent (enumerate)",
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
        } else if enumerate.contains(p) {
            logger.log_line(&format!(
                "Filesystem path '{}' appears in 'filesystem.readonlyPaths' and \
                 'processContainer.filesystem.enumeratePaths'; \
                 applying most-restrictive intent (enumerate)",
                config_deserialize::escape_diagnostic_text(p)
            ));
            false
        } else {
            true
        }
    });
    policy.enumerate_paths.retain(|p| {
        if denied.contains(p) {
            logger.log_line(&format!(
                "Filesystem path '{}' appears in 'processContainer.filesystem.enumeratePaths' and \
                 'filesystem.deniedPaths'; \
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

// ---------- Conversion from normalized config input to runtime model ----------

fn present_backend_sections(cfg: &crate::common_request_ir::CommonRequestIR) -> Vec<&'static str> {
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
    if cfg.wslc.is_some() {
        push(ContainmentBackend::Wslc);
    }
    if cfg.seatbelt.is_some() {
        push(ContainmentBackend::Seatbelt);
    }
    if cfg.windows_sandbox.is_some() {
        push(ContainmentBackend::WindowsSandbox);
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
pub(crate) fn map_wire_containment(c: Option<&wire::Containment>) -> ContainmentBackend {
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

fn requested_sandbox_kind(c: Option<&wire::Containment>) -> &'static str {
    match c {
        None | Some(wire::Containment::Process) => "process",
        Some(wire::Containment::ProcessContainer) => "processcontainer",
        Some(wire::Containment::Vm) => "vm",
        Some(wire::Containment::WindowsSandbox) => "windows_sandbox",
        Some(wire::Containment::Lxc) => "lxc",
        Some(wire::Containment::Microvm) => "microvm",
        Some(wire::Containment::Hyperlight) => "hyperlight",
        Some(wire::Containment::Wslc) => "wslc",
        Some(wire::Containment::Seatbelt) => "seatbelt",
        Some(wire::Containment::IsolationSession) => "isolation_session",
        Some(wire::Containment::Bubblewrap) => "bubblewrap",
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

// `state_aware_wslc_exec` identifies the state-aware exec exception: network
// mode was fixed at provision, so a proxy-only exec inherits that mode rather
// than restating `defaultPolicy`. Backend phase validation still rejects every
// post-provision network-mode or host-filtering field.
fn normalize_common_request_ir(
    cfg: crate::common_request_ir::CommonRequestIR,
    logger: &mut Logger,
    require_process: bool,
    state_aware_wslc_exec: bool,
) -> Result<ExecutionRequest, WxcError> {
    let _ignored_metadata = (&cfg.schema, &cfg.comment);

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

    // Backend sections present in the config (captured before fields move out).
    let present_backend_sections = present_backend_sections(&cfg);

    let source_contract = cfg.source_contract;
    let network_enforcement_compatibility = cfg.network_enforcement_compatibility;
    let default_env_compatibility = cfg.default_env_compatibility;
    let container_id = cfg.container_id.unwrap_or_default();

    // Process section: required for one-shot and state-aware exec; optional for
    // non-exec state-aware phases (require_process == false).
    let (script_code, working_directory, script_timeout, env, inherit_default_env) =
        match cfg.process {
            Some(process) => {
                let script_code = match process.command_line {
                    Some(s) if !s.is_empty() => s,
                    Some(_) if require_process => {
                        return Err(WxcError::ConfigParse(
                            "process.commandLine cannot be empty".to_string(),
                        ));
                    }
                    None if require_process => {
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
                    process.env,
                    process.inherit_default_env.unwrap_or(false),
                )
            }
            None if require_process => {
                return Err(WxcError::ConfigParse(
                    "'process' section is required".into(),
                ));
            }
            None => (String::new(), String::new(), 0, None, false),
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

        if let Some(filesystem) = ac.filesystem {
            if let Some(paths) = filesystem.enumerate_paths {
                policy.enumerate_paths = paths;
            }
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
        network_enforcement_compatibility,
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
                    if host_is_any_loopback(host) {
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
            && !state_aware_wslc_exec
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
            // wires explicit host->container port forwards (wslc
            // portMappings) into the WSL2 VM's NAT; it never consults
            // allowLocalNetwork. Reject `true` and point at portMappings.
            // (`false` is the default and a no-op.)
            if policy.allow_local_network {
                let msg = "WSLc: network.allowLocalNetwork=true is not supported. A WSLc \
                           container runs in the NAT'd WSL2 VM and MXC does not honor a \
                           blanket inbound-listen grant; expose specific ports with \
                           wslc.portMappings instead.";
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

        // LXC is the inverse of the guard above: it *does* have a
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
            logger.warning_line(
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

    let wslc = if let Some(cc) = cfg.wslc {
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
                    let msg = format!("wslc.portMappings[{idx}]: 'windowsPort' must be > 0");
                    return Err(WxcError::ConfigParse(msg));
                }
                if m.container_port == 0 {
                    let msg = format!("wslc.portMappings[{idx}]: 'containerPort' must be > 0");
                    return Err(WxcError::ConfigParse(msg));
                }
                // Only TCP is representable in the wire model
                // (TransportProtocol is tcp-only); a `udp` value is rejected
                // at deserialize. The WSLC SDK runtime returns E_NOTIMPL for
                // UDP, so only TCP is currently supported.
                converted.push(PortMapping {
                    windows_port: m.windows_port,
                    container_port: m.container_port,
                    protocol: "tcp".to_string(),
                });
            }
            // Reject duplicate (windowsPort, protocol) entries. Same host
            // port on TCP+UDP would in principle be legal, but UDP is
            // rejected at deserialize (the wire model is tcp-only); the
            // second protocol dimension is retained in the dedupe key in
            // case UDP support is enabled later.
            let mut seen: std::collections::HashSet<(u16, &str)> = std::collections::HashSet::new();
            for pm in &converted {
                if !seen.insert((pm.windows_port, pm.protocol.as_str())) {
                    let msg = format!(
                        "wslc.portMappings: duplicate windowsPort {} \
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

    let test_feature = cfg
        .test_feature
        .map(|test| TestFeatureConfig::from_raw(test.message));
    let windows_sandbox = cfg.windows_sandbox.map(|sandbox| {
        let mut config = WindowsSandboxConfig::default();
        if let Some(timeout) = sandbox.idle_timeout_ms.or(sandbox.idle_timeout) {
            config.idle_timeout_ms = timeout;
        }
        if let Some(name) = sandbox.daemon_pipe_name {
            config.daemon_pipe_name = name;
        }
        config
    });

    let seatbelt = cfg.seatbelt.map(make_seatbelt_config);
    let telemetry = cfg.telemetry.map(|raw| TelemetryConfig {
        enabled: raw.enabled,
        requested_sandbox_kind: Some(requested_sandbox_kind(cfg.containment.as_ref())),
    });

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

    Ok(ExecutionRequest {
        source_contract: Some(source_contract),
        network_enforcement_compatibility,
        default_env_compatibility,
        container_id,
        env,
        inherit_default_env,
        script_code,
        working_directory,
        script_timeout,
        containment,
        lifecycle,
        policy,
        lxc_config,
        wslc,
        seatbelt,
        telemetry,
        test_feature,
        windows_sandbox,
        experimental_enabled: false,
        testing_features_enabled: false,
        dry_run: false,
    })
}

/// Normalize checked exact input without retaining source or backend JSON.
fn normalize_state_aware(
    input: StateAwareInput,
    logger: &mut Logger,
) -> Result<ParsedStateAwareRequest, WxcError> {
    let (common, operation) = input.into_parts();
    let request = normalize_state_aware_common(
        common,
        NormalizationContext {
            phase: operation.phase(),
            containment: match &operation {
                StateAwareOperation::Provision(provision) => Some(match provision {
                    StateAwareProvision::IsolationSession(_) => wire::Containment::IsolationSession,
                    StateAwareProvision::WindowsSandbox => wire::Containment::WindowsSandbox,
                    StateAwareProvision::Wslc(_) => wire::Containment::Wslc,
                }),
                StateAwareOperation::Start { .. }
                | StateAwareOperation::Exec { .. }
                | StateAwareOperation::Stop { .. }
                | StateAwareOperation::Deprovision { .. } => None,
            },
            sandbox_id: operation.sandbox_id(),
        },
        logger,
    )?;
    Ok(ParsedStateAwareRequest::new(request, operation))
}

/// Temporary routing view; production derives it exclusively from the operation.
struct NormalizationContext<'a> {
    phase: Phase,
    containment: Option<wire::Containment>,
    sandbox_id: Option<&'a str>,
}

fn normalize_state_aware_common(
    mut common: crate::common_request_ir::CommonRequestIR,
    context: NormalizationContext<'_>,
    logger: &mut Logger,
) -> Result<ExecutionRequest, WxcError> {
    let network_supplied = common.network.is_some();
    common.containment = if context.phase == Phase::Provision {
        context.containment
    } else {
        context.sandbox_id.and_then(state_aware_containment_from_id)
    };
    let require_process = context.phase == Phase::Exec;
    let state_aware_wslc_exec = require_process
        && common
            .containment
            .as_ref()
            .is_some_and(|value| map_wire_containment(Some(value)) == ContainmentBackend::Wslc);
    let mut request =
        normalize_common_request_ir(common, logger, require_process, state_aware_wslc_exec)?;
    if context.phase != Phase::Provision && !network_supplied {
        request.policy.network_egress = None;
        request.policy.network_ingress = None;
    }
    Ok(request)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::encoding::base64_encode;
    use crate::logger::Mode;
    use crate::models::{NetworkAction, ProxyAddress};
    use crate::mxc_error::MxcErrorCode;
    use std::path::{Path, PathBuf};

    fn argv(args: &[&str]) -> Vec<String> {
        args.iter().map(|s| s.to_string()).collect()
    }

    fn test_logger() -> Logger {
        Logger::new(Mode::Buffer)
    }

    fn repository_root() -> PathBuf {
        Path::new(env!("CARGO_MANIFEST_DIR"))
            .ancestors()
            .nth(3)
            .unwrap()
            .to_path_buf()
    }

    fn assert_exact_contract_bridge(
        request: ExactOneShotContract,
        expected_contract: ContractVersion,
        expected_compatibility: crate::models::NetworkEnforcementCompatibility,
    ) {
        let mut logger = test_logger();
        let execution = load_one_shot_request_from_contract(request, &mut logger).unwrap();

        assert_eq!(execution.source_contract, Some(expected_contract));
        assert_eq!(
            execution.network_enforcement_compatibility,
            expected_compatibility
        );
        assert_eq!(
            execution.source_contract_version(),
            expected_contract.as_str()
        );
        assert_eq!(execution.script_code, "echo hello");
    }

    #[test]
    fn private_exact_parser_path_compiles_and_accepts_a_published_request() {
        let json = r#"{
            "version": "0.6.0-alpha",
            "process": {"commandLine": "echo hello"}
        }"#;

        let parsed = parse_exact_mxc_request_json(json, &mut test_logger()).unwrap();
        assert!(matches!(parsed, MxcRequest::OneShot(_)));
    }

    fn parse_exact_for_test(json: &str) -> Result<MxcRequest, ParseError> {
        parse_exact_mxc_request_json(json, &mut test_logger())
    }

    #[derive(Debug, Clone, PartialEq)]
    struct ProxySnapshot {
        address: Option<String>,
        port: Option<u16>,
        original_url: Option<String>,
        builtin_test_server: bool,
    }

    #[derive(Debug, Clone, PartialEq)]
    struct ExecutionSnapshot {
        serialized: serde_json::Value,
        network_proxy: ProxySnapshot,
        network_specified: bool,
        network_mode_specified: bool,
        runtime_network_proxy_specified: bool,
        ui_specified: bool,
        requested_sandbox_kind: Option<&'static str>,
    }

    impl From<&ExecutionRequest> for ExecutionSnapshot {
        fn from(request: &ExecutionRequest) -> Self {
            let proxy = request.policy.network_proxy.address.as_ref();
            Self {
                serialized: serde_json::to_value(request).unwrap(),
                network_proxy: ProxySnapshot {
                    address: proxy.map(|address| address.address.clone()),
                    port: proxy.map(|address| address.port),
                    original_url: proxy.and_then(|address| address.original_url.clone()),
                    builtin_test_server: request.policy.network_proxy.builtin_test_server,
                },
                // These are the complete set of ExecutionRequest model fields hidden by
                // `#[serde(skip)]`; compare them explicitly so serialization cannot mask
                // parser drift.
                network_specified: request.policy.network_specified,
                network_mode_specified: request.policy.network_mode_specified,
                runtime_network_proxy_specified: request.policy.runtime_network_proxy_specified,
                ui_specified: request.policy.ui_specified,
                requested_sandbox_kind: request
                    .telemetry
                    .as_ref()
                    .and_then(|telemetry| telemetry.requested_sandbox_kind),
            }
        }
    }

    #[derive(Debug, Clone, PartialEq)]
    enum RequestSnapshot {
        OneShot(ExecutionSnapshot),
        StateAware {
            request: ExecutionSnapshot,
            phase: Phase,
            containment: Option<ContainmentBackend>,
            sandbox_id: Option<String>,
            provision: Option<ProvisionSnapshot>,
        },
    }

    #[derive(Debug, Clone, PartialEq)]
    enum ProvisionSnapshot {
        IsolationSession(Option<Option<String>>),
        WindowsSandbox,
        Wslc(Option<(Option<String>, Option<String>)>),
    }

    impl From<&MxcRequest> for RequestSnapshot {
        fn from(request: &MxcRequest) -> Self {
            match request {
                MxcRequest::OneShot(request) => Self::OneShot(request.into()),
                MxcRequest::StateAware(request) => Self::StateAware {
                    request: request.request().into(),
                    phase: request.phase(),
                    containment: request.containment(),
                    sandbox_id: request.sandbox_id().map(str::to_owned),
                    provision: match request.operation() {
                        StateAwareOperation::Provision(provision) => Some(match provision {
                            StateAwareProvision::IsolationSession(config) => {
                                ProvisionSnapshot::IsolationSession(
                                    config.as_ref().map(|config| config.app_id.clone()),
                                )
                            }
                            StateAwareProvision::WindowsSandbox => {
                                ProvisionSnapshot::WindowsSandbox
                            }
                            StateAwareProvision::Wslc(config) => {
                                ProvisionSnapshot::Wslc(config.as_ref().map(|config| {
                                    (config.image.clone(), config.image_tar_path.clone())
                                }))
                            }
                        }),
                        _ => None,
                    },
                },
            }
        }
    }

    fn assert_exact_published_requests_equivalent(
        case: &str,
        expected_version: &str,
        canonical_json: &str,
        alias_json: &str,
    ) {
        let canonical = parse_exact_for_test(canonical_json)
            .unwrap_or_else(|error| panic!("{case}: canonical request failed: {error:?}"));
        let alias = parse_exact_for_test(alias_json)
            .unwrap_or_else(|error| panic!("{case}: alias request failed: {error:?}"));

        for request in [&canonical, &alias] {
            match request {
                MxcRequest::OneShot(request) => {
                    assert_eq!(
                        request.source_contract.map(ContractVersion::as_str),
                        Some(expected_version),
                        "{case}"
                    );
                }
                MxcRequest::StateAware(_) => {
                    panic!("{case}: expected one-shot request");
                }
            }
        }

        assert_eq!(
            RequestSnapshot::from(&canonical),
            RequestSnapshot::from(&alias),
            "{case}: alias changed the runtime request"
        );
    }

    #[test]
    fn exact_parser_preserves_source_aware_typed_diagnostics() {
        for (version, state_aware) in [
            ("0.6.0-alpha", false),
            ("0.7.0-alpha", false),
            ("0.8.0-alpha", false),
            ("0.9.0-alpha", false),
            ("0.9.0-alpha", true),
        ] {
            let phase_fields = if state_aware {
                "  \"phase\": \"exec\",\n  \"sandboxId\": \"iso:abcd1234\",\n"
            } else {
                ""
            };
            let json = format!(
                "{{\n  \"version\": \"{version}\",\n{phase_fields}  \"process\": {{\n    \"commandLine\": \"echo hello\",\n    \"cwd\": 42\n  }}\n}}"
            );
            let error = parse_exact_for_test(&json).unwrap_err();
            let message = error.message();
            assert!(
                message.contains("Invalid configuration at `process.cwd`"),
                "{message}"
            );
            assert!(message.contains("line "), "{message}");
            assert!(message.contains("column "), "{message}");
            assert_eq!(matches!(error, ParseError::StateAware(_)), state_aware);
        }
    }

    #[test]
    fn load_mxc_request_uses_exact_dispatch_for_file_and_base64_inputs() {
        let json = r#"{
            "version": "0.8.0-alpha",
            "process": {"commandLine": "echo hello"},
            "experimental": {}
        }"#;
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("exact-route-proof.json");
        fs::write(&path, json).unwrap();

        for error in [
            load_mxc_request(path.to_str().unwrap(), &mut test_logger(), false).unwrap_err(),
            load_mxc_request(&base64_encode(json.as_bytes()), &mut test_logger(), true)
                .unwrap_err(),
            parse_exact_for_test(json).unwrap_err(),
        ] {
            assert!(matches!(error, ParseError::OneShot(_)), "{error:?}");
            assert!(error.message().contains("unknown field `experimental`"));
        }
    }

    #[test]
    fn exact_parser_accepts_every_published_one_shot_version() {
        for (version, command) in [
            ("0.6.0-alpha", "echo v06"),
            ("0.7.0-alpha", "echo v07"),
            ("0.8.0-alpha", "echo v08"),
        ] {
            let json = format!(
                r#"{{
                    "version": "{version}",
                    "process": {{"commandLine": "{command}"}}
                }}"#
            );

            match parse_exact_for_test(&json).unwrap() {
                MxcRequest::OneShot(request) => {
                    assert_eq!(
                        request.source_contract.map(ContractVersion::as_str),
                        Some(version)
                    );
                    assert_eq!(request.script_code, command);
                }
                MxcRequest::StateAware(_) => {
                    panic!("{version}: expected one-shot request")
                }
            }
        }
    }

    #[test]
    fn exact_published_parser_preserves_compatibility_alias_equivalence() {
        for (
            case,
            version,
            canonical_containment,
            canonical_fields,
            alias_containment,
            alias_fields,
        ) in [
            (
                "v0.6 ProcessContainer containment",
                "0.6.0-alpha",
                "processcontainer",
                "",
                "appcontainer",
                "",
            ),
            (
                "v0.6 ProcessContainer section",
                "0.6.0-alpha",
                "processcontainer",
                r#",
                    "processContainer": {
                        "leastPrivilege": true,
                        "capabilities": ["internetClient"]
                    }"#,
                "processcontainer",
                r#",
                    "appContainer": {
                        "leastPrivilege": true,
                        "capabilities": ["internetClient"]
                    }"#,
            ),
            (
                "v0.7 ProcessContainer containment",
                "0.7.0-alpha",
                "processcontainer",
                "",
                "appcontainer",
                "",
            ),
            (
                "v0.7 ProcessContainer section",
                "0.7.0-alpha",
                "processcontainer",
                r#",
                    "processContainer": {
                        "leastPrivilege": true,
                        "capabilities": ["internetClient"]
                    }"#,
                "processcontainer",
                r#",
                    "appContainer": {
                        "leastPrivilege": true,
                        "capabilities": ["internetClient"]
                    }"#,
            ),
            (
                "v0.7 Seatbelt containment",
                "0.7.0-alpha",
                "seatbelt",
                "",
                "macos_sandbox",
                "",
            ),
            (
                "v0.7 Seatbelt section",
                "0.7.0-alpha",
                "seatbelt",
                r#",
                    "seatbelt": {
                        "guiAccess": true
                    }"#,
                "seatbelt",
                r#",
                    "macos_sandbox": {
                        "guiAccess": true
                    }"#,
            ),
            (
                "v0.8 ProcessContainer containment",
                "0.8.0-alpha",
                "processcontainer",
                "",
                "appcontainer",
                "",
            ),
            (
                "v0.8 ProcessContainer section",
                "0.8.0-alpha",
                "processcontainer",
                r#",
                    "processContainer": {
                        "leastPrivilege": true,
                        "capabilities": ["internetClient"]
                    }"#,
                "processcontainer",
                r#",
                    "appContainer": {
                        "leastPrivilege": true,
                        "capabilities": ["internetClient"]
                    }"#,
            ),
            (
                "v0.8 Seatbelt containment",
                "0.8.0-alpha",
                "seatbelt",
                "",
                "macos_sandbox",
                "",
            ),
            (
                "v0.8 Seatbelt section",
                "0.8.0-alpha",
                "seatbelt",
                r#",
                    "seatbelt": {
                        "guiAccess": true
                    }"#,
                "seatbelt",
                r#",
                    "macos_sandbox": {
                        "guiAccess": true
                    }"#,
            ),
        ] {
            let canonical_json = format!(
                r#"{{
                    "version": "{version}",
                    "containment": "{canonical_containment}",
                    "process": {{"commandLine": "echo hello"}}{canonical_fields}
                }}"#
            );
            let alias_json = format!(
                r#"{{
                    "version": "{version}",
                    "containment": "{alias_containment}",
                    "process": {{"commandLine": "echo hello"}}{alias_fields}
                }}"#
            );

            assert_exact_published_requests_equivalent(case, version, &canonical_json, &alias_json);
        }
    }

    #[test]
    fn exact_parser_rejects_unregistered_nearby_versions_without_fallback() {
        for version in [
            "0.6.0",
            "0.6.1-alpha",
            "0.8.0-dev",
            "0.9.0",
            "0.9.1-alpha",
            "0.10.1-alpha",
        ] {
            let json = format!(
                r#"{{
                "version": "{version}",
                "process": {{"commandLine": "echo hello"}}
            }}"#
            );

            let error = parse_exact_for_test(&json).unwrap_err();
            assert!(
                matches!(error, ParseError::Version(_)),
                "{version}: got {error:?}"
            );
            assert!(
                error.message().contains("Unsupported contract version"),
                "{version}: {}",
                error.message()
            );
        }
    }

    #[test]
    fn exact_parser_does_not_fallback_to_later_contracts() {
        for (case, json, expected_message) in [
            (
                "v0.6 rejects a v0.7 annotation",
                r#"{
                    "version": "0.6.0-alpha",
                    "_comment": "introduced in v0.7",
                    "process": {"commandLine": "echo hello"}
                }"#,
                "unknown field `_comment`",
            ),
            (
                "v0.7 rejects v0.8 directional networking",
                r#"{
                    "version": "0.7.0-alpha",
                    "process": {"commandLine": "echo hello"},
                    "network": {"egress": {"default": "deny"}}
                }"#,
                "unknown field `egress`",
            ),
            (
                "v0.8 rejects the v0.9 experimental block",
                r#"{
                    "version": "0.8.0-alpha",
                    "process": {"commandLine": "echo hello"},
                    "experimental": {}
                }"#,
                "unknown field `experimental`",
            ),
        ] {
            let error = parse_exact_for_test(json).unwrap_err();
            assert!(matches!(error, ParseError::OneShot(_)), "{case}: {error:?}");
            assert!(
                error.message().contains(expected_message),
                "{case}: expected {expected_message:?}, got {}",
                error.message()
            );
        }
    }

    #[test]
    fn exact_parser_accepts_the_development_one_shot_contract() {
        let json = r#"{
            "version": "0.10.0-alpha",
            "process": {"commandLine": "echo dev"}
        }"#;

        match parse_exact_for_test(json).unwrap() {
            MxcRequest::OneShot(request) => {
                assert_eq!(request.source_contract, Some(ContractVersion::V0_10_0Alpha));
                assert_eq!(
                    request.network_enforcement_compatibility,
                    crate::models::NetworkEnforcementCompatibility::Strict
                );
                assert_eq!(request.script_code, "echo dev");
            }
            MxcRequest::StateAware(_) => panic!("expected one-shot request"),
        }
    }

    struct DevelopmentStateAwareRootCase {
        name: &'static str,
        json: &'static str,
        expected_phase: Phase,
        expected_declared_containment: Option<ContainmentBackend>,
        expected_runtime_containment: ContainmentBackend,
        expected_sandbox_id: Option<&'static str>,
        expected_script: &'static str,
    }

    const DEVELOPMENT_STATE_AWARE_ROOT_CASES: &[DevelopmentStateAwareRootCase] = &[
        DevelopmentStateAwareRootCase {
            name: "Windows Sandbox provision",
            json: r#"{"version":"0.10.0-alpha","phase":"provision","containment":"windows_sandbox"}"#,
            expected_phase: Phase::Provision,
            expected_declared_containment: Some(ContainmentBackend::WindowsSandbox),
            expected_runtime_containment: ContainmentBackend::WindowsSandbox,
            expected_sandbox_id: None,
            expected_script: "",
        },
        DevelopmentStateAwareRootCase {
            name: "IsolationSession provision",
            json: r#"{"version":"0.10.0-alpha","phase":"provision","containment":"isolation_session","network":{"egress":{"default":"allow"},"ingress":{"default":"allow","hostLoopback":"allow"}}}"#,
            expected_phase: Phase::Provision,
            expected_declared_containment: Some(ContainmentBackend::IsolationSession),
            expected_runtime_containment: ContainmentBackend::IsolationSession,
            expected_sandbox_id: None,
            expected_script: "",
        },
        DevelopmentStateAwareRootCase {
            name: "WSLC provision",
            json: r#"{"version":"0.10.0-alpha","phase":"provision","containment":"wslc"}"#,
            expected_phase: Phase::Provision,
            expected_declared_containment: Some(ContainmentBackend::Wslc),
            expected_runtime_containment: ContainmentBackend::Wslc,
            expected_sandbox_id: None,
            expected_script: "",
        },
        DevelopmentStateAwareRootCase {
            name: "start",
            json: r#"{"version":"0.10.0-alpha","phase":"start","sandboxId":"wsb:abcd1234"}"#,
            expected_phase: Phase::Start,
            expected_declared_containment: None,
            expected_runtime_containment: ContainmentBackend::WindowsSandbox,
            expected_sandbox_id: Some("wsb:abcd1234"),
            expected_script: "",
        },
        DevelopmentStateAwareRootCase {
            name: "exec",
            json: r#"{"version":"0.10.0-alpha","phase":"exec","sandboxId":"wslc:abcd1234","process":{"commandLine":"echo state-aware"}}"#,
            expected_phase: Phase::Exec,
            expected_declared_containment: None,
            expected_runtime_containment: ContainmentBackend::Wslc,
            expected_sandbox_id: Some("wslc:abcd1234"),
            expected_script: "echo state-aware",
        },
        DevelopmentStateAwareRootCase {
            name: "stop",
            json: r#"{"version":"0.10.0-alpha","phase":"stop","sandboxId":"iso:abcd1234"}"#,
            expected_phase: Phase::Stop,
            expected_declared_containment: None,
            expected_runtime_containment: ContainmentBackend::IsolationSession,
            expected_sandbox_id: Some("iso:abcd1234"),
            expected_script: "",
        },
        DevelopmentStateAwareRootCase {
            name: "deprovision",
            json: r#"{"version":"0.10.0-alpha","phase":"deprovision","sandboxId":"wslc:abcd1234"}"#,
            expected_phase: Phase::Deprovision,
            expected_declared_containment: None,
            expected_runtime_containment: ContainmentBackend::Wslc,
            expected_sandbox_id: Some("wslc:abcd1234"),
            expected_script: "",
        },
    ];

    fn assert_development_state_aware_root(
        parsed: &ParsedStateAwareRequest,
        case: &DevelopmentStateAwareRootCase,
    ) {
        assert_eq!(parsed.phase(), case.expected_phase, "{}", case.name);
        assert_eq!(
            parsed.containment(),
            case.expected_declared_containment,
            "{}: declared containment",
            case.name
        );
        assert_eq!(
            parsed.request().containment,
            case.expected_runtime_containment,
            "{}: runtime containment",
            case.name
        );
        assert_eq!(
            parsed.sandbox_id(),
            case.expected_sandbox_id,
            "{}: sandbox id",
            case.name
        );
        assert_eq!(
            parsed.request().script_code,
            case.expected_script,
            "{}",
            case.name
        );
    }

    #[test]
    fn exact_parser_accepts_every_development_state_aware_root() {
        for case in DEVELOPMENT_STATE_AWARE_ROOT_CASES {
            let parsed = match parse_exact_for_test(case.json).unwrap() {
                MxcRequest::StateAware(parsed) => parsed,
                MxcRequest::OneShot(_) => {
                    panic!("{}: expected state-aware request", case.name)
                }
            };
            assert_development_state_aware_root(&parsed, case);
        }
    }

    fn development_configuration_json(telemetry_enabled: bool) -> String {
        format!(
            r#"{{
                "version": "0.10.0-alpha",
                "phase": "provision",
                "containment": "isolation_session",
                "telemetry": {{"enabled": {telemetry_enabled}}},
                "network": {{"egress":{{"default":"allow"}},"ingress":{{"default":"allow","hostLoopback":"allow"}}}},
                "isolationSession": {{
                    "provision": {{
                        "appId": "Contoso.App"
                    }}
                }}
            }}"#
        )
    }

    fn assert_development_configuration(parsed: &ParsedStateAwareRequest, telemetry_enabled: bool) {
        assert_eq!(
            parsed.operation(),
            &StateAwareOperation::Provision(StateAwareProvision::IsolationSession(Some(
                crate::models::IsolationSessionProvisionConfig {
                    app_id: Some("Contoso.App".into()),
                },
            )))
        );
        assert_eq!(
            parsed
                .request()
                .telemetry
                .as_ref()
                .and_then(|telemetry| telemetry.enabled),
            Some(telemetry_enabled)
        );
    }

    #[test]
    fn exact_parser_preserves_development_configuration_and_telemetry() {
        for telemetry_enabled in [false, true] {
            let json = development_configuration_json(telemetry_enabled);
            let parsed = match parse_exact_for_test(&json).unwrap() {
                MxcRequest::StateAware(parsed) => parsed,
                MxcRequest::OneShot(_) => panic!("expected state-aware request"),
            };
            assert_development_configuration(&parsed, telemetry_enabled);
        }
    }

    #[test]
    fn exact_parser_routes_version_declaration_failures_separately_from_decode_errors() {
        for (case, json) in [
            ("missing", r#"{"process":{"commandLine":"echo hello"}}"#),
            (
                "null",
                r#"{"version":null,"process":{"commandLine":"echo hello"}}"#,
            ),
            (
                "wrong type",
                r#"{"version":42,"process":{"commandLine":"echo hello"}}"#,
            ),
            (
                "duplicate",
                r#"{"version":"0.8.0-alpha","version":"0.9.0-alpha","process":{"commandLine":"echo hello"}}"#,
            ),
            (
                "unsupported",
                r#"{"version":"99.99.99-secret","process":{"commandLine":"echo hello"}}"#,
            ),
            (
                "unsupported state-aware",
                r#"{"version":"0.6.1-alpha","phase":"start","sandboxId":"wsb:abcd1234"}"#,
            ),
        ] {
            let mut logger = test_logger();
            let error = load_mxc_request_from_json(json, &mut logger).unwrap_err();
            assert!(
                matches!(error, ParseError::Version(_)),
                "{case}: got {error:?}"
            );
            assert!(matches!(error.output(), ErrorOutput::Primary));
            assert!(logger.get_buffer().contains(&error.message()), "{case}");
            if case == "unsupported" {
                assert!(
                    !error.message().contains("99.99.99-secret"),
                    "unsupported user input must not be rendered"
                );
                for version in supported_versions() {
                    assert!(
                        error.message().contains(version.as_str()),
                        "missing registered version {}: {}",
                        version.as_str(),
                        error.message()
                    );
                }
                assert!(!error.message().contains("older than supported"));
                assert!(!error.message().contains("newer than supported"));
            }
        }
    }

    #[test]
    fn public_loader_keeps_syntax_and_input_failures_as_decode_errors() {
        for json in [
            "{ not json",
            r#"{"version":"0.9.0-alpha","process":"#,
            r#"{"version":"0.9.0-alpha"} {}"#,
        ] {
            let error = load_mxc_request_from_json(json, &mut test_logger()).unwrap_err();
            assert!(matches!(error, ParseError::Decode(_)), "{error:?}");
            assert!(matches!(error.output(), ErrorOutput::Primary));
        }
        let error = load_mxc_request("!!!", &mut test_logger(), true).unwrap_err();
        assert!(matches!(error, ParseError::Decode(_)));

        let directory = tempfile::tempdir().unwrap();
        let missing = directory.path().join("missing.json");
        let error =
            load_mxc_request(missing.to_str().unwrap(), &mut test_logger(), false).unwrap_err();
        assert!(matches!(error, ParseError::Decode(_)));
    }

    #[test]
    fn public_preflight_duplicate_fields_follow_the_selected_request_kind() {
        for (fields, state_aware) in [
            (r#""process":{"commandLine":"echo hello"}"#, false),
            (
                r#""phase":"provision","containment":"windows_sandbox""#,
                true,
            ),
            (r#""phase":"start","sandboxId":"wsb:abcd1234""#, true),
            (
                r#""phase":"exec","sandboxId":"wsb:abcd1234","process":{"commandLine":"echo hello"}"#,
                true,
            ),
            (r#""phase":"stop","sandboxId":"wsb:abcd1234""#, true),
            (r#""phase":"deprovision","sandboxId":"wsb:abcd1234""#, true),
        ] {
            let valid = format!(r#"{{"version":"0.10.0-alpha",{fields},"telemetry":{{}}}}"#);
            load_mxc_request_from_json(&valid, &mut test_logger()).unwrap();
            let duplicate = format!(
                r#"{{"version":"0.10.0-alpha",{fields},"telemetry":{{}},"telemetry":{{}}}}"#
            );
            let mut logger = test_logger();
            let error = load_mxc_request_from_json(&duplicate, &mut logger).unwrap_err();
            assert!(
                error.message().contains("duplicate field `telemetry`"),
                "{error:?}"
            );
            if state_aware {
                assert!(matches!(error, ParseError::StateAware(_)), "{error:?}");
                assert!(matches!(error.output(), ErrorOutput::DiagnosticOnly));
                assert!(logger.get_buffer().is_empty());
            } else {
                assert!(matches!(error, ParseError::OneShot(_)), "{error:?}");
                assert!(matches!(error.output(), ErrorOutput::Primary));
                assert!(logger.get_buffer().contains(&error.message()));
            }
        }
    }

    #[test]
    fn exact_parser_routes_contract_failures_by_request_kind() {
        for (case, json, state_aware) in [
            (
                "published experimental field",
                r#"{"version":"0.6.0-alpha","process":{"commandLine":"echo hello"},"experimental":{}}"#,
                false,
            ),
            (
                "v0.7 directional network field",
                r#"{"version":"0.7.0-alpha","process":{"commandLine":"echo hello"},"network":{"egress":{"default":"deny"}}}"#,
                false,
            ),
            (
                "published state-aware field",
                r#"{"version":"0.8.0-alpha","phase":"start","sandboxId":"iso:abcd1234"}"#,
                false,
            ),
            (
                "development one-shot unknown field",
                r#"{"version":"0.9.0-alpha","process":{"commandLine":"echo hello"},"unknown":true}"#,
                false,
            ),
            (
                "development state-aware unknown field",
                r#"{"version":"0.9.0-alpha","phase":"start","sandboxId":"iso:abcd1234","unknown":true}"#,
                true,
            ),
            (
                "development unknown phase",
                r#"{"version":"0.9.0-alpha","phase":"teleport"}"#,
                true,
            ),
        ] {
            let error = parse_exact_for_test(json).unwrap_err();
            assert_eq!(
                matches!(error, ParseError::StateAware(_)),
                state_aware,
                "{case}: got {error:?}"
            );
            if !state_aware {
                assert!(
                    matches!(error, ParseError::OneShot(_)),
                    "{case}: got {error:?}"
                );
            }
        }
    }

    #[test]
    fn exact_one_shot_parser_preserves_typed_error_path_and_location() {
        for version in [
            "0.6.0-alpha",
            "0.7.0-alpha",
            "0.8.0-alpha",
            "0.9.0-alpha",
            "0.10.0-alpha",
        ] {
            let json = format!(
                "{{\n  \"version\": \"{version}\",\n  \"process\": {{\n    \"commandLine\": \"echo hello\",\n    \"cwd\": 42\n  }}\n}}"
            );
            assert_exact_typed_error(&json, "process.cwd", "42", false);
        }
    }

    fn assert_exact_typed_error(json: &str, path: &str, invalid_value: &str, state_aware: bool) {
        let error = parse_exact_for_test(json).unwrap_err();
        assert_eq!(matches!(error, ParseError::StateAware(_)), state_aware);
        if !state_aware {
            assert!(matches!(error, ParseError::OneShot(_)), "{json}: {error:?}");
        }
        let message = error.message();
        assert!(
            message.contains(&format!("Invalid configuration at `{path}`")),
            "{message}"
        );
        let (line, source_line) = json
            .lines()
            .enumerate()
            .find(|(_, line)| line.contains(invalid_value))
            .unwrap();
        let column = source_line.find(invalid_value).unwrap() + invalid_value.len();
        assert!(
            message.contains(&format!("line {} column {column}", line + 1)),
            "{message}"
        );
    }

    #[test]
    fn exact_development_parser_preserves_nested_diagnostics_for_every_root() {
        for (root, json, state_aware) in [
            (
                "one-shot",
                r#"{"version":"0.10.0-alpha","process":{"commandLine":"echo hello"}}"#,
                false,
            ),
            (
                "Windows Sandbox provision",
                r#"{"version":"0.10.0-alpha","phase":"provision","containment":"windows_sandbox"}"#,
                true,
            ),
            (
                "IsolationSession provision",
                r#"{"version":"0.10.0-alpha","phase":"provision","containment":"isolation_session","network":{"egress":{"default":"allow"},"ingress":{"default":"allow","hostLoopback":"allow"}}}"#,
                true,
            ),
            (
                "WSLC provision",
                r#"{"version":"0.10.0-alpha","phase":"provision","containment":"wslc"}"#,
                true,
            ),
            (
                "start",
                r#"{"version":"0.10.0-alpha","phase":"start","sandboxId":"wsb:abcd1234"}"#,
                true,
            ),
            (
                "exec",
                r#"{"version":"0.10.0-alpha","phase":"exec","sandboxId":"wslc:abcd1234","process":{"commandLine":"echo hello"}}"#,
                true,
            ),
            (
                "stop",
                r#"{"version":"0.10.0-alpha","phase":"stop","sandboxId":"iso:abcd1234"}"#,
                true,
            ),
            (
                "deprovision",
                r#"{"version":"0.10.0-alpha","phase":"deprovision","sandboxId":"wslc:abcd1234"}"#,
                true,
            ),
        ] {
            parse_exact_for_test(json).unwrap();
            let mut value: serde_json::Value = serde_json::from_str(json).unwrap();
            value["telemetry"] = serde_json::json!({"enabled": "invalid-telemetry-flag"});
            let json = serde_json::to_string_pretty(&value).unwrap();
            assert_exact_typed_error(
                &json,
                "telemetry.enabled",
                "\"invalid-telemetry-flag\"",
                state_aware,
            );
            assert!(
                parse_exact_for_test(&json)
                    .unwrap_err()
                    .message()
                    .contains(&format!("Invalid {root} request:")),
                "{root}"
            );
        }
    }

    #[test]
    fn exact_development_parser_preserves_nested_backend_payload_paths() {
        for (json, path) in [
            (
                r#"{"version":"0.10.0-alpha","phase":"exec","sandboxId":"wslc:abcd1234","process":{"commandLine":"echo hello","cwd":42}}"#,
                "process.cwd",
            ),
            (
                r#"{"version":"0.10.0-alpha","phase":"provision","containment":"wslc","wslc":{"provision":{"image":42}}}"#,
                "wslc.provision.image",
            ),
        ] {
            let value: serde_json::Value = serde_json::from_str(json).unwrap();
            let json = serde_json::to_string_pretty(&value).unwrap();
            assert_exact_typed_error(&json, path, "42", true);
        }
    }

    #[test]
    fn exact_development_parser_uses_shared_diagnostic_escaping_and_redaction() {
        for json in [
            r#"{"version":"0.10.0-alpha","process":{"commandLine":"echo hello"}}"#,
            r#"{"version":"0.10.0-alpha","phase":"start","sandboxId":"wsb:abcd1234"}"#,
        ] {
            let mut value: serde_json::Value = serde_json::from_str(json).unwrap();
            value["telemetry"] =
                serde_json::json!({"unexpected\n\u{1b}[31m\u{202e}": "do-not-log"});
            let message = parse_exact_for_test(&serde_json::to_string(&value).unwrap())
                .unwrap_err()
                .message();
            for character in ['\n', '\u{1b}', '\u{202e}'] {
                assert!(!message.contains(character), "{message:?}");
            }
            for escaped in ["\\n", "\\u{1b}", "\\u{202e}"] {
                assert!(message.contains(escaped), "{message}");
            }

            // No credential field is currently accepted here, but the shared
            // renderer must still recognize a secret-bearing error path.
            value["telemetry"] = serde_json::json!({"apiToken": "do-not-log"});
            let message = parse_exact_for_test(&serde_json::to_string(&value).unwrap())
                .unwrap_err()
                .message();
            assert!(message.contains("`telemetry.apiToken`"), "{message}");
            assert!(message.contains("invalid secret value"), "{message}");
            assert!(!message.contains("do-not-log"), "{message}");
        }
    }

    #[test]
    fn exact_development_parser_preserves_typed_error_path_and_sanitizes_diagnostics() {
        let json = "{\n  \"version\": \"0.10.0-alpha\",\n  \"phase\": \"provision\",\n  \"containment\": \"isolation_session\",\n  \"network\": {\"defaultPolicy\": \"block\", \"allowLocalNetwork\": true}\n}";

        let error = parse_exact_for_test(json).unwrap_err();
        assert!(matches!(error, ParseError::StateAware(_)));
        let message = error.message();
        assert!(message.contains("`network.defaultPolicy`"), "{message}");
        assert!(message.contains("line 5"), "{message}");

        let spoofed =
            r#"{"version":"0.9.0-alpha","process":{"commandLine":"echo"},"bad\u202ename":true}"#;
        let error = parse_exact_for_test(spoofed).unwrap_err();
        let message = error.message();
        assert!(message.contains(r"bad\u{202e}name"), "{message}");
    }

    #[test]
    fn exact_development_network_migration_guidance_is_contract_aware() {
        for (json, expected, rejected) in [
            (
                r#"{
                    "version": "0.10.0-alpha",
                    "phase": "provision",
                    "containment": "wslc",
                    "network": {"proxy": {"url": "http://proxy.example:8080"}}
                }"#,
                "top-level runtimeConfig.networkProxy on the exec phase",
                "use runtimeConfig.networkProxy with a proxy URL",
            ),
            (
                r#"{
                    "version": "0.10.0-alpha",
                    "phase": "provision",
                    "containment": "isolation_session",
                    "network": {"allowedHosts": ["example.com"]}
                }"#,
                "IsolationSession requires network.egress.default, network.ingress.default, and network.ingress.hostLoopback all set to 'allow'",
                "CIDR rules",
            ),
            (
                r#"{
                    "version": "0.10.0-alpha",
                    "phase": "provision",
                    "containment": "isolation_session",
                    "network": {"defaultPolicy": "allow"}
                }"#,
                "IsolationSession requires network.egress.default, network.ingress.default, and network.ingress.hostLoopback all set to 'allow'",
                "('allow' or 'deny')",
            ),
        ] {
            let message = parse_exact_for_test(json).unwrap_err().message();
            assert!(message.contains("schema 0.10 migration"), "{message}");
            assert!(message.contains(expected), "{message}");
            assert!(!message.contains(rejected), "{message}");
        }
    }

    #[test]
    fn published_v0_9_network_migration_guidance_names_its_contract() {
        let message = parse_exact_for_test(
            r#"{
                "version": "0.9.0-alpha",
                "phase": "provision",
                "containment": "isolation_session",
                "network": {"defaultPolicy": "allow"}
            }"#,
        )
        .unwrap_err()
        .message();

        assert!(message.contains("schema 0.9 migration"), "{message}");
    }

    #[test]
    fn exact_development_production_parser_requires_isolation_session_network() {
        let missing_network = r#"{
            "version": "0.9.0-alpha",
            "containment": "isolation_session",
            "process": {"commandLine": "echo hello"}
        }"#;
        let error = parse_exact_for_test(missing_network).unwrap_err();
        assert!(matches!(error, ParseError::OneShot(_)));
        assert!(
            error
                .message()
                .contains("IsolationSession requires an explicit network policy"),
            "{}",
            error.message()
        );

        let directional = r#"{
            "version": "0.9.0-alpha",
            "containment": "isolation_session",
            "process": {"commandLine": "echo hello"},
            "network": {
                "egress": {"default": "allow"},
                "ingress": {"default": "allow", "hostLoopback": "allow"}
            }
        }"#;
        assert!(matches!(
            parse_exact_for_test(directional).unwrap(),
            MxcRequest::OneShot(_)
        ));
    }

    #[test]
    fn exact_contract_bridge_accepts_every_registered_one_shot_version() {
        let v0_6 = serde_json::from_str::<mxc_config_contract::published::v0_6_0_alpha::Request>(
            r#"{
                    "version": "0.6.0-alpha",
                    "process": {"commandLine": "echo hello"}
                }"#,
        )
        .unwrap();
        assert_exact_contract_bridge(
            ExactOneShotContract::V0_6(Box::new(v0_6)),
            ContractVersion::V0_6_0Alpha,
            crate::models::NetworkEnforcementCompatibility::LegacyCompatible,
        );

        let v0_7 = serde_json::from_str::<mxc_config_contract::published::v0_7_0_alpha::Request>(
            r#"{
                    "version": "0.7.0-alpha",
                    "process": {"commandLine": "echo hello"}
                }"#,
        )
        .unwrap();
        assert_exact_contract_bridge(
            ExactOneShotContract::V0_7(Box::new(v0_7)),
            ContractVersion::V0_7_0Alpha,
            crate::models::NetworkEnforcementCompatibility::LegacyCompatible,
        );

        let v0_8 = serde_json::from_str::<mxc_config_contract::published::v0_8_0_alpha::Request>(
            r#"{
                    "version": "0.8.0-alpha",
                    "process": {"commandLine": "echo hello"}
                }"#,
        )
        .unwrap();
        assert_exact_contract_bridge(
            ExactOneShotContract::V0_8(Box::new(v0_8)),
            ContractVersion::V0_8_0Alpha,
            crate::models::NetworkEnforcementCompatibility::Strict,
        );

        let v0_9 =
            serde_json::from_str::<mxc_config_contract::published::v0_9_0_alpha::OneShotRequest>(
                r#"{
                "version": "0.9.0-alpha",
                "process": {"commandLine": "echo hello"}
            }"#,
            )
            .unwrap();
        assert_exact_contract_bridge(
            ExactOneShotContract::V0_9(Box::new(v0_9)),
            ContractVersion::V0_9_0Alpha,
            crate::models::NetworkEnforcementCompatibility::Strict,
        );

        let dev = serde_json::from_str::<mxc_config_contract::dev::OneShotRequest>(
            r#"{
                "version": "0.10.0-alpha",
                "process": {"commandLine": "echo hello"}
            }"#,
        )
        .unwrap();
        assert_exact_contract_bridge(
            ExactOneShotContract::Dev(Box::new(dev)),
            ContractVersion::V0_10_0Alpha,
            crate::models::NetworkEnforcementCompatibility::Strict,
        );
    }

    #[test]
    fn exact_contract_bridge_runs_shared_semantic_validation() {
        let request =
            serde_json::from_str::<mxc_config_contract::published::v0_7_0_alpha::Request>(
                r#"{
                    "version": "0.7.0-alpha",
                    "containment": "processcontainer",
                    "process": {"commandLine": "echo hello"},
                    "processContainer": {
                        "capabilities": [
                            "internetClient,privateNetworkClientServer"
                        ]
                    }
                }"#,
            )
            .unwrap();
        let mut logger = test_logger();

        let error = load_one_shot_request_from_contract(
            ExactOneShotContract::V0_7(Box::new(request)),
            &mut logger,
        )
        .unwrap_err();

        assert!(
            error.to_string().contains("must not contain a comma"),
            "unexpected semantic error: {error}"
        );
        assert!(
            logger.get_buffer().contains("must not contain a comma"),
            "semantic failure should be logged"
        );
    }

    #[test]
    fn exact_development_contract_bridge_requires_isolation_session_network() {
        let request = serde_json::from_str::<mxc_config_contract::dev::OneShotRequest>(
            r#"{
                "version": "0.10.0-alpha",
                "containment": "isolation_session",
                "process": {"commandLine": "echo hello"}
            }"#,
        )
        .unwrap();
        let mut logger = test_logger();

        let error = load_one_shot_request_from_contract(
            ExactOneShotContract::Dev(Box::new(request)),
            &mut logger,
        )
        .unwrap_err();

        assert!(
            error
                .to_string()
                .contains("IsolationSession requires an explicit network policy"),
            "unexpected semantic error: {error}"
        );
    }
    #[test]
    fn reused_phase_probe_classifies_one_shot_and_state_aware_phases() {
        assert_eq!(
            probe_phase(r#"{"process":{"commandLine":"echo hi"}}"#).unwrap(),
            None
        );
        assert_eq!(
            probe_phase(r#"{"phase":"exec","sandboxId":"iso:abcd1234"}"#).unwrap(),
            Some(ContractPhase::Exec),
        );

        for (phase, expected) in [
            ("provision", ContractPhase::Provision),
            ("start", ContractPhase::Start),
            ("stop", ContractPhase::Stop),
            ("deprovision", ContractPhase::Deprovision),
        ] {
            assert_eq!(
                probe_phase(&format!(r#"{{"phase":"{phase}"}}"#)).unwrap(),
                Some(expected),
            );
        }
    }

    #[test]
    fn reused_phase_probe_rejects_invalid_discriminators() {
        assert!(probe_phase(r#"{"phase":null}"#).is_err());
        assert!(probe_phase(r#"{"phase":42}"#).is_err());
        assert!(probe_phase(r#"{"phase":"start","phase":"exec"}"#).is_err());
        assert!(probe_phase(r#"{"phase":"nope"}"#).is_err());
    }

    #[cfg(target_os = "windows")]
    #[test]
    fn wslc_proxy_template_migration_keeps_backend_context() {
        let unprefixed = r#"{
            "version":"0.9.0-alpha","phase":"exec","sandboxId":"{{SANDBOX_ID}}",
            "process":{"commandLine":"echo proxy"},
            "runtimeConfig":{"networkProxy":"http://127.0.0.1:8888"}
        }"#;
        let error = parse_exact_for_test(unprefixed).unwrap_err();
        assert!(
            error
                .message()
                .contains("ProcessContainer runtimeConfig.networkProxy requires"),
            "{}",
            error.message()
        );
        let prefixed = unprefixed.replace("{{SANDBOX_ID}}", "wslc:{{SANDBOX_ID}}");
        let parsed = parse_exact_for_test(&prefixed).unwrap();
        let MxcRequest::StateAware(parsed) = parsed else {
            panic!("expected state-aware request");
        };
        assert_eq!(parsed.request().containment, ContainmentBackend::Wslc);
        assert!(parsed.request().policy.network_proxy.is_enabled());
    }

    #[test]
    fn state_aware_wslc_exec_accepts_proxy_without_redeclaring_network_mode() {
        let json = r#"{
            "version": "0.9.0-alpha",
            "phase": "exec",
            "sandboxId": "wslc:0123456789abcdef0123456789abcdef",
            "process": {"commandLine": "echo hi"},
            "runtimeConfig": {"networkProxy": "http://proxy.example:8080"}
        }"#;
        let mut logger = test_logger();

        let parsed = load_mxc_request_from_json(json, &mut logger).unwrap();
        let MxcRequest::StateAware(parsed) = parsed else {
            panic!("expected a state-aware request");
        };
        assert!(parsed.request().policy.network_proxy.is_enabled());
        assert!(!parsed.request().policy.network_mode_specified);
        assert!(parsed.request().policy.allowed_hosts.is_empty());
        assert!(parsed.request().policy.blocked_hosts.is_empty());
    }

    fn load_mxc(json: &str) -> Result<MxcRequest, ParseError> {
        let encoded = base64_encode(json.as_bytes());
        let mut logger = test_logger();
        load_mxc_request(&encoded, &mut logger, true)
    }

    fn load_mxc_with_cli(json: &str, cli_command: &[String]) -> Result<MxcRequest, ParseError> {
        let encoded = base64_encode(json.as_bytes());
        let mut logger = test_logger();
        load_mxc_request_with_options(
            &encoded,
            &mut logger,
            LoadOptions {
                is_base64: true,
                cli_command,
            },
        )
    }

    fn load_state_aware(json: &str) -> ParsedStateAwareRequest {
        match load_mxc(json).expect("state-aware request should parse") {
            MxcRequest::StateAware(parsed) => parsed,
            MxcRequest::OneShot(_) => panic!("expected state-aware request"),
        }
    }

    #[test]
    fn state_aware_public_loaders_deliver_expected_provision_configuration() {
        for (fixture, expected) in [
            (
                "isolation_session_state_aware_provision_appid.json",
                StateAwareProvision::IsolationSession(Some(
                    crate::models::IsolationSessionProvisionConfig {
                        app_id: Some("PFN:Contoso.App_8wekyb3d8bbwe".into()),
                    },
                )),
            ),
            (
                "isolation_session_state_aware_provision_appid_empty.json",
                StateAwareProvision::IsolationSession(Some(
                    crate::models::IsolationSessionProvisionConfig {
                        app_id: Some(String::new()),
                    },
                )),
            ),
            (
                "wslc_state_aware_provision.json",
                StateAwareProvision::Wslc(Some(crate::models::WslcProvisionConfig {
                    image: Some("alpine:latest".into()),
                    image_tar_path: None,
                })),
            ),
        ] {
            let path = repository_root()
                .join("tests")
                .join("configs")
                .join(fixture);
            let json = fs::read_to_string(&path).unwrap();
            let encoded = base64_encode(json.as_bytes());
            let requests = [
                load_mxc_request(path.to_str().unwrap(), &mut test_logger(), false).unwrap(),
                load_mxc_request(&encoded, &mut test_logger(), true).unwrap(),
                load_mxc_request_from_json(&json, &mut test_logger()).unwrap(),
            ];
            let reference = RequestSnapshot::from(&requests[0]);
            for request in &requests {
                assert_eq!(RequestSnapshot::from(request), reference, "{fixture}");
                let MxcRequest::StateAware(parsed) = request else {
                    panic!("{fixture}: expected state-aware request");
                };
                assert_eq!(
                    parsed.operation(),
                    &StateAwareOperation::Provision(expected.clone())
                );
                assert_eq!(parsed.phase(), Phase::Provision);
                assert_eq!(parsed.containment(), Some(expected.containment()));
                assert!(parsed.sandbox_id().is_none());
                assert!(!parsed.request().experimental_enabled);
                assert!(!parsed.request().dry_run);
                assert!(!parsed.request().policy.ui_specified);
            }
        }
    }

    #[test]
    fn v0_9_non_provision_requests_route_by_registered_sandbox_id_prefix() {
        // Post-provision roots are backend-neutral by design. Holding a valid
        // sandbox ID is the routing authority even when its backend was
        // provisioned through a newer exact contract.
        for (id, backend) in [
            ("iso:example", ContainmentBackend::IsolationSession),
            ("wsb:example", ContainmentBackend::WindowsSandbox),
            ("wslc:example", ContainmentBackend::Wslc),
        ] {
            for phase in [Phase::Start, Phase::Exec, Phase::Stop, Phase::Deprovision] {
                let process = if phase == Phase::Exec {
                    r#","process":{"commandLine":"echo typed","env":["KEY=value"],"timeout":12}"#
                } else {
                    ""
                };
                let json = format!(
                    r#"{{"version":"0.9.0-alpha","phase":"{phase}","sandboxId":"{id}","telemetry":{{"enabled":false}}{process}}}"#
                );
                let encoded = base64_encode(json.as_bytes());
                for parsed in [
                    load_mxc_request_from_json(&json, &mut test_logger()).unwrap(),
                    load_mxc_request(&encoded, &mut test_logger(), true).unwrap(),
                ] {
                    let MxcRequest::StateAware(parsed) = parsed else {
                        panic!("expected state-aware request");
                    };
                    assert_eq!(parsed.phase(), phase);
                    assert_eq!(parsed.sandbox_id(), Some(id));
                    assert!(parsed.containment().is_none());
                    assert_eq!(parsed.request().containment, backend);
                    assert!(!parsed.request().policy.network_specified);
                    assert!(!parsed.request().policy.network_mode_specified);
                    assert!(!parsed.request().policy.ui_specified);
                    assert!(parsed.request().policy.network_egress.is_none());
                    assert!(parsed.request().policy.network_ingress.is_none());
                    assert_eq!(
                        parsed.request().telemetry.as_ref().unwrap().enabled,
                        Some(false)
                    );
                    assert_eq!(
                        parsed.request().script_code,
                        if phase == Phase::Exec {
                            "echo typed"
                        } else {
                            ""
                        }
                    );
                }
            }
        }
    }

    #[test]
    fn exact_loader_accepts_every_development_state_aware_root() {
        for case in DEVELOPMENT_STATE_AWARE_ROOT_CASES {
            let parsed = load_state_aware(case.json);
            assert_development_state_aware_root(&parsed, case);
        }
    }

    #[test]
    fn exact_loader_preserves_development_configuration_and_telemetry() {
        for telemetry_enabled in [false, true] {
            let json = development_configuration_json(telemetry_enabled);
            let parsed = load_state_aware(&json);

            assert_development_configuration(&parsed, telemetry_enabled);
            assert!(parsed.request().test_feature.is_none());
            assert!(parsed.request().windows_sandbox.is_none());
            assert!(parsed.request().wslc.is_none());
        }
    }

    #[test]
    fn exact_loader_preserves_post_provision_network_presence() {
        let omitted = load_state_aware(
            r#"{"version":"0.9.0-alpha","phase":"start","sandboxId":"wslc:abcd1234"}"#,
        );
        assert!(!omitted.request().policy.network_specified);
        assert!(!omitted.request().policy.network_mode_specified);
        assert!(omitted.request().policy.network_egress.is_none());
        assert!(omitted.request().policy.network_ingress.is_none());
        assert!(!omitted.request().policy.network_proxy.is_enabled());

        let proxy_only = load_state_aware(
            r#"{
                "version": "0.9.0-alpha",
                "phase": "exec",
                "sandboxId": "wslc:abcd1234",
                "process": {"commandLine": "echo hi"},
                "runtimeConfig": {"networkProxy": "http://proxy.example:8080"}
            }"#,
        );
        assert!(!proxy_only.request().policy.network_specified);
        assert!(proxy_only.request().policy.runtime_network_proxy_specified);
        assert!(!proxy_only.request().policy.network_mode_specified);
        assert!(proxy_only.request().policy.network_proxy.is_enabled());

        let mode = load_state_aware(
            r#"{
                "version": "0.9.0-alpha",
                "phase": "exec",
                "sandboxId": "wslc:abcd1234",
                "process": {"commandLine": "echo hi"},
                "network": {"egress": {"default": "allow"}}
            }"#,
        );
        assert!(mode.request().policy.network_specified);
        assert!(mode.request().policy.network_mode_specified);
        assert_eq!(
            mode.request()
                .policy
                .network_egress
                .as_ref()
                .unwrap()
                .default,
            crate::models::NetworkAction::Allow
        );
        assert!(!mode.request().policy.network_proxy.is_enabled());
    }

    #[test]
    fn cli_command_supplies_a_missing_one_shot_command_line() {
        let json = r#"{"version":"0.9.0-alpha","process":{"cwd":"C:\\tmp"}}"#;
        match load_mxc_with_cli(json, &argv(&["app.exe", "--flag"])).unwrap() {
            MxcRequest::OneShot(req) => {
                assert_eq!(req.script_code, "app.exe --flag");
                assert_eq!(req.working_directory, "C:\\tmp");
            }
            MxcRequest::StateAware(_) => panic!("expected one-shot"),
        }
    }

    #[test]
    fn cli_command_supplies_an_absent_one_shot_process_block() {
        let json = r#"{"version":"0.9.0-alpha","containment":"processcontainer"}"#;
        match load_mxc_with_cli(json, &argv(&["app.exe", "--flag"])).unwrap() {
            MxcRequest::OneShot(req) => assert_eq!(req.script_code, "app.exe --flag"),
            MxcRequest::StateAware(_) => panic!("expected one-shot"),
        }
    }

    #[test]
    fn cli_command_supplies_a_missing_state_aware_exec_command_line() {
        let json = r#"{
        "version": "0.9.0-alpha",
        "phase": "exec",
        "sandboxId": "iso:abcd1234",
        "process": {"cwd": "C:\\tmp"}
    }"#;
        match load_mxc_with_cli(json, &argv(&["app.exe", "--flag"])).unwrap() {
            MxcRequest::StateAware(p) => {
                assert_eq!(p.phase(), Phase::Exec);
                assert_eq!(p.request().script_code, "app.exe --flag");
                assert_eq!(p.request().working_directory, "C:\\tmp");
            }
            MxcRequest::OneShot(_) => panic!("expected state-aware"),
        }
    }

    #[test]
    fn cli_command_replaces_a_state_aware_exec_command_line() {
        let json = r#"{
            "version": "0.9.0-alpha",
            "phase": "exec",
            "sandboxId": "iso:abcd1234",
            "process": {"commandLine": "policy.exe", "cwd": "C:\\tmp"}
        }"#;
        match load_mxc_with_cli(json, &argv(&["app.exe", "--flag"])).unwrap() {
            MxcRequest::StateAware(p) => {
                assert_eq!(p.phase(), Phase::Exec);
                assert_eq!(p.request().script_code, "app.exe --flag");
                assert_eq!(p.request().working_directory, "C:\\tmp");
            }
            MxcRequest::OneShot(_) => panic!("expected state-aware"),
        }
    }

    #[test]
    fn state_aware_exec_cli_command_preserves_duplicate_field_errors() {
        for (field, json) in [
            (
                "process",
                r#"{
                "version": "0.9.0-alpha",
                "phase": "exec",
                "sandboxId": "iso:abcd1234",
                "process": {"commandLine": "first.exe"},
                "process": {"commandLine": "second.exe"}
            }"#,
            ),
            (
                "commandLine",
                r#"{
                "version": "0.9.0-alpha",
                "phase": "exec",
                "sandboxId": "iso:abcd1234",
                "process": {
                    "commandLine": "first.exe",
                    "commandLine": "second.exe"
                }
            }"#,
            ),
            (
                "_comment",
                r#"{
                "version": "0.9.0-alpha",
                "phase": "exec",
                "sandboxId": "iso:abcd1234",
                "process": {"commandLine": "policy.exe"},
                "_comment": "first",
                "_comment": "second"
            }"#,
            ),
        ] {
            let error = load_mxc_with_cli(json, &argv(&["cli.exe"]))
                .expect_err("CLI command must not hide the duplicate field");

            assert!(
                matches!(error, ParseError::StateAware(_)),
                "{field}: expected state-aware error, got {error:?}"
            );
            assert!(
                error.message().contains("duplicate field"),
                "{field}: unexpected error: {}",
                error.message()
            );
        }
    }

    #[test]
    fn state_aware_exec_cli_diagnostics_match_the_effective_document() {
        for (case, json, command) in [
            (
                "replacement",
                r#"{
                "version":"0.9.0-alpha",
                "phase":"exec",
                "sandboxId":"iso:abcd1234",
                "process":{"commandLine":"x","cwd":42}
            }"#,
                argv(&["a-much-longer-command.exe"]),
            ),
            (
                "insertion",
                r#"{
                "version":"0.9.0-alpha",
                "phase":"exec",
                "sandboxId":"iso:abcd1234",
                "process":{"cwd":42}
            }"#,
                argv(&["cli.exe"]),
            ),
        ] {
            let (effective_json, _) =
                apply_cli_command(json, &command).expect("command preparation");

            let expected = load_mxc(&effective_json)
                .expect_err("effective document should retain the policy error");
            let actual = load_mxc_with_cli(json, &command)
                .expect_err("CLI path should retain the effective-document error");

            assert!(
                matches!(&actual, ParseError::StateAware(_)),
                "{case}: expected state-aware error, got {actual:?}"
            );
            assert_eq!(actual.message(), expected.message(), "{case}");
        }
    }

    #[test]
    fn cli_command_preserves_duplicate_field_errors() {
        for (field, json) in [
            (
                "filesystem",
                r#"{
                    "process": {"commandLine": "policy.exe"},
                    "filesystem": {"readwritePaths": ["first"]},
                    "filesystem": {"readwritePaths": ["second"]}
                }"#,
            ),
            (
                "process",
                r#"{
                    "process": {"commandLine": "first.exe"},
                    "process": {"commandLine": "second.exe"}
                }"#,
            ),
            (
                "commandLine",
                r#"{
                    "process": {
                        "commandLine": "first.exe",
                        "commandLine": "second.exe"
                    }
                }"#,
            ),
        ] {
            assert!(load_mxc(json).is_err(), "sanity: duplicate {field}");
            assert!(
                load_mxc_with_cli(json, &argv(&["cli.exe"])).is_err(),
                "CLI override must not hide duplicate {field}"
            );
        }
    }

    #[test]
    fn cli_command_preserves_invalid_command_line_type_errors() {
        for value in ["42", "true", "[]", "{}"] {
            let json =
                format!(r#"{{"version":"0.9.0-alpha","process":{{"commandLine":{value}}}}}"#);

            assert!(load_mxc(&json).is_err(), "sanity: commandLine={value}");
            assert!(
                load_mxc_with_cli(&json, &argv(&["cli.exe"])).is_err(),
                "CLI override must not hide commandLine={value}"
            );
        }
    }

    #[test]
    fn cli_command_diagnostics_match_the_effective_document() {
        for (case, json, command) in [
            (
                "longer replacement",
                r#"{"version":"0.9.0-alpha","process":{"commandLine":"x","cwd":42}}"#,
                argv(&["a-much-longer-command.exe"]),
            ),
            (
                "shorter replacement",
                r#"{"version":"0.9.0-alpha","process":{"commandLine":"a-much-longer-policy-command.exe","cwd":42}}"#,
                argv(&["x"]),
            ),
            (
                "insertion",
                r#"{"version":"0.9.0-alpha","process":{"cwd":42}}"#,
                argv(&["cli.exe"]),
            ),
        ] {
            let (effective_json, _) =
                apply_cli_command(json, &command).expect("command preparation");
            let expected = load_mxc(&effective_json)
                .expect_err("effective document should retain the policy error")
                .message();
            let actual = load_mxc_with_cli(json, &command)
                .expect_err("CLI path should retain the effective-document error")
                .message();

            assert_eq!(actual, expected, "{case}");
        }
    }

    #[test]
    fn cli_command_render_error_precedes_an_unrelated_one_shot_policy_error() {
        let json = r#"{"version":"0.9.0-alpha","process":{"commandLine":"policy.exe","cwd":42}}"#;
        let error = load_mxc_with_cli(json, &argv(&["cli.exe", "hidden\0payload"]))
            .expect_err("command rendering should fail before typed policy validation");

        assert!(matches!(error, ParseError::Decode(_)));
        assert!(
            error.message().contains("invalid CLI command override"),
            "unexpected error: {}",
            error.message()
        );
    }

    #[test]
    fn state_aware_backend_probe_errors_precede_unrelated_policy_errors() {
        for (case, json, expected_code) in [
            (
                "missing sandbox id",
                r#"{"version":"0.9.0-alpha","phase":"exec","process":{"commandLine":42}}"#,
                MxcErrorCode::MalformedRequest,
            ),
            (
                "unsupported sandbox id",
                r#"{"version":"0.9.0-alpha","phase":"exec","sandboxId":"zzz:abcd","process":{"commandLine":42}}"#,
                MxcErrorCode::UnsupportedContainment,
            ),
        ] {
            let error = load_mxc_with_cli(json, &argv(&["cli.exe"]))
                .expect_err("backend probing should fail before typed policy validation");

            match error {
                ParseError::StateAware(error) => {
                    assert_eq!(error.code, expected_code, "{case}");
                }
                other => panic!("{case}: expected state-aware error, got {other:?}"),
            }
        }
    }

    #[test]
    fn missing_command_line_is_rejected_without_a_cli_command() {
        // Sanity: without the flag, the legacy contract holds — missing
        // commandLine is a hard parse error.
        let json = r#"{"version":"0.9.0-alpha","process": {"cwd": "C:\\tmp"}}"#;
        assert!(load_mxc_with_cli(json, &[]).is_err());
    }

    #[test]
    fn apply_cli_command_returns_override_log_for_a_one_shot_replacement() {
        let (out, override_log) = apply_cli_command(
            r#"{"version":"0.9.0-alpha","process":{"commandLine":"policy.exe"}}"#,
            &argv(&["app.exe", "--flag"]),
        )
        .unwrap();

        let doc: serde_json::Value = serde_json::from_str(&out).unwrap();
        assert_eq!(doc["process"]["commandLine"], "app.exe --flag");
        assert_eq!(
            override_log.as_deref(),
            Some("Overriding policy process.commandLine with CLI command: app.exe --flag")
        );
    }

    #[test]
    fn apply_cli_command_returns_no_override_log_when_the_policy_had_no_command() {
        let (out, override_log) = apply_cli_command(
            r#"{"version":"0.9.0-alpha","process":{"cwd":"/usr/tmp"}}"#,
            &argv(&["app.exe", "--flag"]),
        )
        .unwrap();

        let doc: serde_json::Value = serde_json::from_str(&out).unwrap();
        assert_eq!(doc["process"]["commandLine"], "app.exe --flag");
        assert!(override_log.is_none());
    }

    #[test]
    fn cli_command_does_not_log_override_when_the_effective_policy_is_invalid() {
        let json = r#"{
            "version": "0.9.0-alpha",
            "process": {
                "commandLine": "policy.exe",
                "cwd": 42
            }
        }"#;
        let encoded = base64_encode(json.as_bytes());
        let command = argv(&["app.exe", "--flag"]);
        let mut logger = test_logger();

        let result = load_mxc_request_with_options(
            &encoded,
            &mut logger,
            LoadOptions {
                is_base64: true,
                cli_command: &command,
            },
        );

        assert!(result.is_err());
        assert!(!logger
            .get_buffer()
            .contains("Overriding policy process.commandLine"));
    }

    #[test]
    fn apply_cli_command_splices_into_a_state_aware_exec_request() {
        // The `sandboxId` prefix selects the quoting context, so the argument
        // carries `&`: cmd.exe quotes it because `&` separates commands, a
        // POSIX shell single-quotes it, and the direct Windows path leaves it
        // bare. An argument needing no quoting would render identically under
        // all three and prove nothing about the prefix.
        for (version, sandbox_id, expected) in [
            // iso -> IsolationSession -> WindowsCommandProcessor
            ("0.9.0-alpha", "iso:abcd1234", "app.exe \"a&b\""),
            // wsb -> WindowsSandbox -> WindowsCommandProcessor
            ("0.10.0-alpha", "wsb:abcd1234", "app.exe \"a&b\""),
            // wslc -> Wslc -> PosixShell
            ("0.10.0-alpha", "wslc:abcd1234", "app.exe 'a&b'"),
        ] {
            let json =
                format!(r#"{{"version":"{version}","phase":"exec","sandboxId":"{sandbox_id}"}}"#);
            let (out, override_log) = apply_cli_command(&json, &argv(&["app.exe", "a&b"])).unwrap();

            let doc: serde_json::Value = serde_json::from_str(&out).unwrap();
            assert_eq!(
                doc["process"]["commandLine"], expected,
                "wrong quoting context for {sandbox_id}"
            );
            assert!(override_log.is_none());
        }
    }

    #[test]
    fn apply_cli_command_rejects_a_non_exec_phase_with_an_envelope_error() {
        for json in [
            r#"{"version":"0.9.0-alpha","phase":"start","sandboxId":"iso:abcd1234"}"#,
            r#"{"version":"0.10.0-alpha","phase":"start","sandboxId":"wsb:abcd1234"}"#,
        ] {
            let err = apply_cli_command(json, &argv(&["echo", "hi"])).unwrap_err();
            assert!(matches!(err, ParseError::StateAware(_)), "{json}");
        }
    }

    #[test]
    fn cli_command_does_not_reclassify_a_published_contract_as_state_aware() {
        let json = r#"{"version":"0.8.0-alpha","phase":"start","sandboxId":"iso:abcd1234"}"#;

        let without_cli = load_mxc(json).unwrap_err();
        let with_cli = load_mxc_with_cli(json, &argv(&["echo", "hi"])).unwrap_err();

        assert!(matches!(without_cli, ParseError::OneShot(_)));
        assert!(matches!(with_cli, ParseError::OneShot(_)));
        assert_eq!(with_cli.message(), without_cli.message());
    }

    #[test]
    fn apply_cli_command_surfaces_an_unregistered_sandbox_id_prefix() {
        for version in ["0.9.0-alpha", "0.10.0-alpha"] {
            let json =
                format!(r#"{{"version":"{version}","phase":"exec","sandboxId":"zzz:abcd"}}"#);
            let err = apply_cli_command(&json, &argv(&["app.exe", "--flag"])).unwrap_err();
            assert!(matches!(err, ParseError::StateAware(_)), "{version}");
        }
    }

    #[test]
    fn apply_cli_command_returns_the_source_unchanged_when_it_cannot_classify() {
        // Each passthrough path: unreadable phase ({"phase":null}), unreadable
        // containment ({"containment":"nope"}), unspliceable document
        // ({"process":42}). Assert the output is byte-identical to the input.

        for json in [
            r#"{"version":"0.9.0-alpha","phase":null,"sandboxId":"iso:abcd1234"}"#,
            r#"{"version":"0.9.0-alpha","containment":"nope"}"#,
            r#"{"version":"0.9.0-alpha","process":42}"#,
        ] {
            let (out, override_log) =
                apply_cli_command(json, &argv(&["app.exe", "--flag"])).unwrap();
            assert_eq!(out, json);
            assert!(override_log.is_none());
        }
    }

    #[test]
    fn apply_cli_command_rejects_an_empty_argv() {
        let err = apply_cli_command(
            r#"{"version":"0.9.0-alpha","process":{"commandLine":"policy.exe"}}"#,
            &[],
        )
        .unwrap_err();
        assert!(matches!(err, ParseError::Decode(_)));
    }

    #[test]
    fn apply_cli_command_rejects_an_unconvertible_command() {
        // A null byte fails argv rendering, which is an entry-point error
        // rather than a parse error: the document is never spliced.
        let err = apply_cli_command(
            r#"{"version":"0.9.0-alpha","process":{"commandLine":"policy.exe"}}"#,
            &argv(&["app.exe", "hidden\0payload"]),
        )
        .unwrap_err();

        assert!(matches!(err, ParseError::Decode(_)));
        assert!(
            err.message().contains("invalid CLI command override"),
            "unexpected message: {}",
            err.message()
        );
    }

    #[test]
    fn apply_cli_command_routes_an_unconvertible_state_aware_exec_command_to_an_envelope() {
        let err = apply_cli_command(
            r#"{"version":"0.9.0-alpha","phase":"exec","sandboxId":"iso:abcd1234"}"#,
            &argv(&["app.exe", "hidden\0payload"]),
        )
        .unwrap_err();

        assert!(matches!(err, ParseError::StateAware(_)));
        assert!(
            err.message().contains("invalid CLI command override"),
            "unexpected message: {}",
            err.message()
        );
    }

    #[test]
    fn one_shot_routes_via_load_mxc_request() {
        let json = r#"{"version":"0.9.0-alpha","process":{"commandLine":"echo hello"}}"#;
        match load_mxc(json).unwrap() {
            MxcRequest::OneShot(req) => assert_eq!(req.script_code, "echo hello"),
            MxcRequest::StateAware(_) => panic!("expected one-shot"),
        }
    }
    #[test]
    fn state_aware_telemetry_populates_typed_field() {
        // Telemetry is a stable cross-cutting setting parsed identically for
        // one-shot and state-aware requests.
        let json = r#"{
            "version": "0.9.0-alpha",
            "phase": "provision",
            "containment": "isolation_session",
            "telemetry": {"enabled": true},
            "network": {"egress":{"default":"allow"},"ingress":{"default":"allow","hostLoopback":"allow"}}
        }"#;
        match load_mxc(json).unwrap() {
            MxcRequest::StateAware(p) => {
                let telem = p
                    .request()
                    .telemetry
                    .as_ref()
                    .expect("telemetry should be populated");
                assert_eq!(telem.enabled, Some(true));
                assert_eq!(
                    p.operation(),
                    &StateAwareOperation::Provision(StateAwareProvision::IsolationSession(None)),
                );
            }
            MxcRequest::OneShot(_) => panic!("expected state-aware"),
        }
    }

    #[test]
    fn state_aware_request_rejects_published_contract_version() {
        let error = load_mxc(
            r#"{
                "version": "0.8.0-alpha",
                "phase": "start",
                "sandboxId": "iso:abcd1234",
                "telemetry": {"enabled": true}
            }"#,
        )
        .unwrap_err();
        assert!(matches!(error, ParseError::OneShot(_)), "got {error:?}");
    }
    #[test]
    fn state_aware_malformed_telemetry_is_rejected() {
        // A present-but-malformed telemetry block is a client error rejected at
        // parse time (surfaced as a state-aware envelope), not a silent disable.
        let json = r#"{
            "version": "0.9.0-alpha",
            "phase": "provision",
            "containment": "isolation_session",
            "telemetry": 42
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
                    "version": "0.9.0-alpha",
                    "phase": "{phase}",
                    "sandboxId": "iso:abcd1234",
                    "containment": "wslc",
                    "process": {{"commandLine": "echo hi"}}
                }}"#
            );
            let r = load_mxc_with_cli(&json, &[]);
            assert!(
                matches!(r, Err(ParseError::StateAware(_))),
                "phase {phase}: expected state-aware rejection, got {:?}",
                r
            );
        }
    }
    #[test]
    fn state_aware_malformed_telemetry_logs_once_and_keeps_primary_clean() {
        // The malformed-telemetry error must reach the auxiliary
        // diagnostic sink exactly once (routed centrally by the outer
        // `load_mxc_request` wrapper), never duplicated, and must never touch the
        // primary buffer/stdout that the state-aware JSON envelope owns.
        let json = r#"{
            "version": "0.9.0-alpha",
            "phase": "provision",
            "containment": "isolation_session",
            "telemetry": 42
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
            logged
                .matches("invalid type: integer `42`, expected struct Telemetry")
                .count(),
            1,
            "expected exactly one auxiliary diagnostic, got: {logged:?}"
        );
    }

    #[test]
    fn state_aware_legacy_experimental_section_is_rejected() {
        let json = r#"{
            "version": "0.9.0-alpha",
            "phase": "provision",
            "containment": "isolation_session",
            "experimental": {"telemetry": {"enabled": true}}
        }"#;
        let error = load_mxc(json).unwrap_err();
        let message = match &error {
            ParseError::StateAware(error) => error.message.as_str(),
            _ => panic!("expected state-aware error, got {error:?}"),
        };
        assert!(
            message.contains("unknown field `experimental`"),
            "got {error:?}"
        );
    }
    #[test]
    fn state_aware_exec_request_requires_command_line() {
        let json = r#"{
            "version": "0.9.0-alpha",
            "phase": "exec",
            "sandboxId": "iso:abcd1234",
            "process": {"commandLine": "echo hello"}
        }"#;
        match load_mxc(json).unwrap() {
            MxcRequest::StateAware(p) => {
                assert_eq!(p.phase(), Phase::Exec);
                assert_eq!(p.request().script_code, "echo hello");
            }
            MxcRequest::OneShot(_) => panic!("expected state-aware"),
        }
    }

    #[test]
    fn state_aware_exec_without_process_is_rejected() {
        // Exec phase still requires the process.commandLine wire field.
        let json = r#"{
            "version": "0.9.0-alpha",
            "phase": "exec",
            "sandboxId": "iso:abcd1234"
        }"#;
        let r = load_mxc(json);
        assert!(matches!(r, Err(ParseError::StateAware(_))), "got {:?}", r);
    }

    #[test]
    fn state_aware_unknown_phase_is_rejected() {
        let json = r#"{"version":"0.9.0-alpha","phase":"teleport"}"#;
        let error = match load_mxc(json) {
            Err(ParseError::StateAware(error)) => error,
            other => panic!("expected state-aware error, got {other:?}"),
        };
        assert!(error.message.contains("Unsupported phase"));
    }

    #[test]
    fn present_null_phase_is_still_discriminated_as_state_aware() {
        let error = match load_mxc(r#"{"version":"0.9.0-alpha","phase":null}"#) {
            Err(ParseError::StateAware(error)) => error,
            other => panic!("expected state-aware error, got {other:?}"),
        };

        assert!(error.message.contains("Invalid phase declaration"));
    }

    #[test]
    fn state_aware_unknown_containment_is_rejected() {
        let json = r#"{
            "version": "0.9.0-alpha",
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
                .contains("Unsupported containment for provision phase"),
            "got: {}",
            error.message
        );
    }

    #[test]
    fn state_aware_parse_errors_reach_diagnostic_file_without_stderr_duplication() {
        let directory = tempfile::tempdir().unwrap();
        let log_path = directory.path().join("mxc.log");
        let mut logger = test_logger();
        logger.enable_file_sink(&log_path).unwrap();
        let encoded = base64_encode(br#"{"version":"0.9.0-alpha","phase":"teleport"}"#);

        let result = load_mxc_request(&encoded, &mut logger, true);
        assert!(matches!(result, Err(ParseError::StateAware(_))));
        assert!(
            logger.get_buffer().is_empty(),
            "the JSON error envelope owns the primary state-aware output"
        );

        drop(logger);
        let log = std::fs::read_to_string(log_path).unwrap();
        assert!(log.contains("Unsupported phase"));
    }

    #[test]
    fn state_aware_semantic_errors_stay_off_primary_output() {
        let directory = tempfile::tempdir().unwrap();
        let log_path = directory.path().join("mxc.log");
        let mut logger = test_logger();
        logger.enable_file_sink(&log_path).unwrap();
        let encoded = base64_encode(
            br#"{"version":"0.9.0-alpha","phase":"provision","containment":"isolation_session","experimental":{"seatbelt":{}}}"#,
        );

        let result = load_mxc_request(&encoded, &mut logger, true);
        assert!(matches!(result, Err(ParseError::StateAware(_))));
        assert!(
            logger.get_buffer().is_empty(),
            "the JSON envelope owns primary state-aware error output"
        );

        drop(logger);
        let log = std::fs::read_to_string(log_path).unwrap();
        assert_eq!(
            log.matches("unknown field `experimental`").count(),
            1,
            "state-aware diagnostics should reach auxiliary sinks exactly once"
        );
    }

    #[test]
    fn state_aware_request_rejects_correlation_vector_field() {
        let json = r#"{
            "version": "0.9.0-alpha",
            "phase": "start",
            "sandboxId": "wsb:12345678",
            "correlationVector": "AAAAAAAAAAAAAAAAAAAAAA.0"
        }"#;
        let mut logger = test_logger();

        let err = load_mxc_request_from_json(json, &mut logger).unwrap_err();
        let msg = match err {
            ParseError::StateAware(error) => error.to_string(),
            ParseError::Decode(error)
            | ParseError::Version(error)
            | ParseError::OneShotMalformed(error)
            | ParseError::OneShot(error) => error.to_string(),
        };
        assert!(
            msg.contains("correlationVector"),
            "state-aware path should reject 'correlationVector', got: {msg}"
        );
    }

    #[test]
    fn state_aware_unknown_top_level_field_rejected() {
        let json = r#"{
            "version": "0.9.0-alpha",
            "phase": "provision",
            "containment": "isolation_session",
            "network": {
                "defaultPolicy": "allow",
                "allowLocalNetwork": true
            },
            "bogusField": true
        }"#;
        let result = load_mxc(json);
        assert!(
            result.is_err(),
            "unknown top-level field on a state-aware request should be rejected"
        );
    }
    #[test]
    fn state_aware_rejects_one_shot_lifecycle_section() {
        let json = r#"{
            "version": "0.9.0-alpha",
            "phase": "provision",
            "containment": "isolation_session",
            "lifecycle": {"destroyOnExit": false}
        }"#;
        let err = match load_mxc(json) {
            Err(ParseError::StateAware(e)) => e.to_string(),
            other => panic!("expected StateAware rejection, got: {other:?}"),
        };
        assert!(err.contains("unknown field `lifecycle`"), "got: {err}");
    }
    #[test]
    fn state_aware_rejects_experimental_seatbelt() {
        // `experimental.seatbelt` moved to the stable section; the state-aware
        // path must reject it with the migration message, not silently discard
        // it.
        let json = r#"{
            "version": "0.9.0-alpha",
            "phase": "provision",
            "containment": "isolation_session",
            "experimental": {"seatbelt": {"guiAccess": true}}
        }"#;
        let err = match load_mxc(json) {
            Err(ParseError::StateAware(e)) => e.to_string(),
            other => panic!("expected StateAware rejection, got: {other:?}"),
        };
        assert!(err.contains("unknown field `experimental`"), "got: {err}");
    }

    #[test]
    fn state_aware_rejects_experimental_macos_sandbox_alias() {
        let json = r#"{
            "version": "0.9.0-alpha",
            "phase": "provision",
            "containment": "isolation_session",
            "experimental": {"macos_sandbox": {"guiAccess": true}}
        }"#;
        let err = match load_mxc(json) {
            Err(ParseError::StateAware(e)) => e.to_string(),
            other => panic!("expected StateAware rejection, got: {other:?}"),
        };
        assert!(err.contains("unknown field `experimental`"), "got: {err}");
    }

    #[test]
    fn state_aware_top_level_annotation_allowed() {
        let json = r#"{
            "$schema": "../schemas/dev/mxc-config.schema.0.9.0-alpha.json",
            "version": "0.9.0-alpha",
            "phase": "provision",
            "containment": "isolation_session",
            "network": {"egress":{"default":"allow"},"ingress":{"default":"allow","hostLoopback":"allow"}}
        }"#;
        match load_mxc(json).unwrap() {
            MxcRequest::StateAware(p) => assert_eq!(p.phase(), Phase::Provision),
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
            assert!(error.contains("array must not be empty"), "got: {error}");
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
        assert!(error.contains("network.egress.allow[0].ports[0].port"));
        assert!(error.contains("expected a nonzero u16"));
    }

    #[test]
    fn schema_v08_rejects_invalid_end_port_forms() {
        for (port, expected) in [
            (
                r#"{"protocol": "tcp", "port": 1, "endPort": 0}"#,
                "expected a nonzero u16",
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
    fn malformed_contract_version_precedes_directional_field_gate() {
        let json = r#"{
            "version": "0.8x",
            "process": {"commandLine": "echo hi"},
            "network": {"egress": {"default": "deny"}}
        }"#;
        let error = match load_mxc(json) {
            Err(ParseError::Version(error)) => error.to_string(),
            other => panic!("expected version rejection, got: {other:?}"),
        };

        assert!(error.contains("Unsupported contract version"));
        for version in supported_versions() {
            assert!(error.contains(version.as_str()), "got: {error}");
        }
        assert!(!error.contains("0.8x"));
        assert!(!error.contains("require schema version 0.8"));
    }

    #[test]
    fn schema_version_error_escapes_control_characters() {
        let json = r#"{
            "version": "1.\u001b[31m0\nX",
            "process": {"commandLine": "echo hi"}
        }"#;
        let message = match load_mxc(json) {
            Err(ParseError::Version(error)) => error.to_string(),
            other => panic!("expected version rejection, got: {other:?}"),
        };

        assert!(!message.contains('\u{1b}'), "got: {message}");
        assert!(!message.contains('\n'), "got: {message}");
        assert!(message.contains("Unsupported contract version"));
    }

    #[test]
    fn exact_v0_9_maps_enumerate_paths() {
        let json = r#"{"version":"0.9.0-alpha","process":{"commandLine":"echo hi"},"containment":"processcontainer","processContainer":{"filesystem":{"enumeratePaths":["C:\\tools"]}}}"#;
        let MxcRequest::OneShot(request) =
            load_mxc_request_from_json(json, &mut test_logger()).unwrap()
        else {
            panic!("expected one-shot request");
        };

        assert_eq!(request.policy.enumerate_paths, vec!["C:\\tools"]);
    }

    #[test]
    fn exact_v0_9_readonly_and_enumerate_prefers_enumerate() {
        let json = r#"{"version":"0.9.0-alpha","process":{"commandLine":"echo hi"},"containment":"processcontainer","filesystem":{"readonlyPaths":["C:\\tools"]},"processContainer":{"filesystem":{"enumeratePaths":["C:\\tools"]}}}"#;
        let MxcRequest::OneShot(request) =
            load_mxc_request_from_json(json, &mut test_logger()).unwrap()
        else {
            panic!("expected one-shot request");
        };

        assert!(request.policy.readonly_paths.is_empty());
        assert_eq!(request.policy.enumerate_paths, vec!["C:\\tools"]);
    }

    #[test]
    fn exact_v0_9_readwrite_and_enumerate_prefers_enumerate() {
        let json = r#"{"version":"0.9.0-alpha","process":{"commandLine":"echo hi"},"containment":"processcontainer","filesystem":{"readwritePaths":["C:\\tools"]},"processContainer":{"filesystem":{"enumeratePaths":["C:\\tools"]}}}"#;
        let mut logger = test_logger();
        let MxcRequest::OneShot(request) = load_mxc_request_from_json(json, &mut logger).unwrap()
        else {
            panic!("expected one-shot request");
        };

        assert!(request.policy.readwrite_paths.is_empty());
        assert_eq!(request.policy.enumerate_paths, vec!["C:\\tools"]);
        assert!(logger
            .get_buffer()
            .contains("applying most-restrictive intent (enumerate)"));
    }

    #[test]
    fn exact_v0_9_enumerate_and_denied_prefers_denied() {
        let json = r#"{"version":"0.9.0-alpha","process":{"commandLine":"echo hi"},"containment":"processcontainer","filesystem":{"deniedPaths":["C:\\tools"]},"processContainer":{"filesystem":{"enumeratePaths":["C:\\tools"]}}}"#;
        let mut logger = test_logger();
        let MxcRequest::OneShot(request) = load_mxc_request_from_json(json, &mut logger).unwrap()
        else {
            panic!("expected one-shot request");
        };

        assert!(request.policy.enumerate_paths.is_empty());
        assert_eq!(request.policy.denied_paths, vec!["C:\\tools"]);
        assert!(logger
            .get_buffer()
            .contains("applying most-restrictive intent (denied)"));
    }

    #[test]
    fn exact_v0_9_enumerate_conflict_diagnostic_escapes_control_characters() {
        let json = r#"{"version":"0.9.0-alpha","process":{"commandLine":"echo hi"},"containment":"processcontainer","filesystem":{"readonlyPaths":["C:\\tools\nforged"]},"processContainer":{"filesystem":{"enumeratePaths":["C:\\tools\nforged"]}}}"#;
        let mut logger = test_logger();

        load_mxc_request_from_json(json, &mut logger).unwrap();

        assert!(!logger.get_buffer().contains("C:\\tools\nforged"));
        assert!(logger.get_buffer().contains("C:\\tools\\nforged"));
    }

    // ── Telemetry ────────────────────────────────────────────────────

    #[test]
    fn exact_loaders_reject_seatbelt_launch_method_from_v0_9_and_v0_10() {
        for version in ["0.9.0-alpha", "0.10.0-alpha"] {
            for section in ["seatbelt", "macos_sandbox"] {
                let json = format!(
                    r#"{{"version":"{version}","containment":"seatbelt","process":{{"commandLine":"echo hi"}},"{section}":{{"launchMethod":"open"}}}}"#
                );
                let directory = tempfile::tempdir().unwrap();
                let path = directory.path().join("removed-launch-method.json");
                fs::write(&path, &json).unwrap();
                let encoded = base64_encode(json.as_bytes());

                for error in [
                    load_mxc_request(path.to_str().unwrap(), &mut test_logger(), false)
                        .unwrap_err(),
                    load_mxc_request(&encoded, &mut test_logger(), true).unwrap_err(),
                    load_mxc_request_from_json(&json, &mut test_logger()).unwrap_err(),
                ] {
                    assert!(matches!(error, ParseError::OneShot(_)), "got {error:?}");
                    assert!(
                        error.message().contains("unknown field `launchMethod`"),
                        "got {error:?}"
                    );
                }
            }
        }
    }

    #[test]
    fn exact_loaders_accept_seatbelt_launch_method_before_v0_9() {
        for version in ["0.7.0-alpha", "0.8.0-alpha"] {
            let json = format!(
                r#"{{"version":"{version}","containment":"seatbelt","process":{{"commandLine":"echo hi"}},"seatbelt":{{"launchMethod":"open"}}}}"#
            );

            let request = load_mxc_request_from_json(&json, &mut test_logger())
                .unwrap_or_else(|error| panic!("{version} should still accept it: {error:?}"));
            let MxcRequest::OneShot(request) = request else {
                panic!("{version} should parse as one-shot");
            };
            assert!(matches!(
                request
                    .seatbelt
                    .expect("seatbelt should be populated")
                    .launch_method,
                crate::models::LaunchMethod::Open
            ));
        }
    }

    #[test]
    fn exact_loaders_reject_telemetry_before_v0_9() {
        let json = r#"{"version":"0.8.0-alpha","process":{"commandLine":"echo hi"},"telemetry":{"enabled":true}}"#;
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("pre-v09-telemetry.json");
        fs::write(&path, json).unwrap();
        let encoded = base64_encode(json.as_bytes());
        for error in [
            load_mxc_request(path.to_str().unwrap(), &mut test_logger(), false).unwrap_err(),
            load_mxc_request(&encoded, &mut test_logger(), true).unwrap_err(),
            load_mxc_request_from_json(json, &mut test_logger()).unwrap_err(),
        ] {
            assert!(matches!(error, ParseError::OneShot(_)), "got {error:?}");
            assert!(
                error.message().contains("unknown field `telemetry`"),
                "got {error:?}"
            );
        }
    }

    #[test]
    fn inherit_default_env_rejects_pre_09_and_absent_versions() {
        for version in ["0.6.0-alpha", "0.8.0-alpha"] {
            let json = format!(
                r#"{{"version":"{version}","process":{{"commandLine":"echo hi","inheritDefaultEnv":true}}}}"#
            );

            let error = load_mxc_request_from_json(&json, &mut test_logger()).unwrap_err();
            assert!(matches!(error, ParseError::OneShot(_)), "got {error:?}");
            assert!(
                error
                    .message()
                    .contains("unknown field `inheritDefaultEnv`"),
                "got {error:?}"
            );
        }
        let absent = r#"{"process":{"commandLine":"echo hi","inheritDefaultEnv":true}}"#;
        let error = load_mxc_request_from_json(absent, &mut test_logger()).unwrap_err();
        assert!(matches!(error, ParseError::Version(_)), "got {error:?}");

        let state_aware = r#"{
            "version": "0.8.0-alpha",
            "phase": "exec",
            "sandboxId": "wslc:0123456789abcdef0123456789abcdef",
            "process": {
                "commandLine": "echo hi",
                "inheritDefaultEnv": true
            }
        }"#;
        // Under authoritative exact dispatch the declared version selects a
        // published contract, which defines neither `phase` nor
        // `process.inheritDefaultEnv`. The lifecycle discriminator is therefore
        // rejected as an unknown field on the published one-shot root before the
        // field gate is ever reached.
        let mut logger = test_logger();
        let error = load_mxc_request_from_json(state_aware, &mut logger).unwrap_err();
        assert!(
            error
                .message()
                .contains("Invalid configuration at `phase`: unknown field `phase`"),
            "got {error:?}"
        );
    }

    #[test]
    fn inherit_default_env_accepts_09_for_one_shot_and_state_aware() {
        let one_shot = r#"{
            "version": "0.9.0-alpha",
            "process": {
                "commandLine": "echo hi",
                "env": ["EXTRA=1"],
                "inheritDefaultEnv": true
            }
        }"#;
        let request = load_mxc_request_from_json(one_shot, &mut test_logger()).unwrap();
        let MxcRequest::OneShot(request) = request else {
            panic!("expected one-shot request");
        };
        assert!(request.inherit_default_env);

        let state_aware = r#"{
            "version": "0.9.0-alpha",
            "phase": "exec",
            "sandboxId": "iso:abc",
            "process": {
                "commandLine": "echo hi",
                "env": ["EXTRA=1"],
                "inheritDefaultEnv": true
            }
        }"#;
        let mut logger = test_logger();
        load_mxc_request_from_json(state_aware, &mut logger)
            .expect("0.9 state-aware inheritance should parse");
    }

    #[test]
    fn exact_contracts_reject_experimental_telemetry() {
        for (version, telemetry) in [
            ("0.7.0-alpha", r#"{"enabled":true}"#),
            ("0.8.0-alpha", "null"),
            ("0.9.0-alpha", r#"{"enabled":true}"#),
        ] {
            let json = format!(
                r#"{{
                    "version":"{version}",
                    "process":{{"commandLine":"echo hi"}},
                    "experimental":{{"telemetry":{telemetry}}}
                }}"#
            );
            let error = load_mxc_request_from_json(&json, &mut test_logger()).unwrap_err();
            assert!(
                error.message().contains("unknown field `experimental`"),
                "{version}: got {error:?}"
            );
        }
    }
}
