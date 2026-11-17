// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use super::{CheckoutMetadata, ProvisionResult};
use crate::mxc_common::models::W365AgentsProvisionConfig;
use crate::mxc_common::mxc_error::MxcError;
use serde_json::{json, Value};
use std::time::{Duration, Instant};
use ureq::tls::{RootCerts, TlsConfig, TlsProvider};

const CHECKOUT_TIMEOUT: Duration = Duration::from_secs(45);
const RELEASE_TIMEOUT: Duration = Duration::from_secs(30);
const MAX_RESPONSE: u64 = 1024 * 1024;
pub(super) const USER_AGENT: &str = concat!("mxc/", env!("CARGO_PKG_VERSION"), " (w365_agents)");

pub(super) fn transport_budget(default: Duration) -> Result<Duration, MxcError> {
    #[cfg(feature = "test-support")]
    if let Some(value) = std::env::var_os("MXC_W365_TEST_TIMEOUT_MS") {
        return Ok(Duration::from_millis(
            value
                .to_str()
                .and_then(|value| value.parse::<std::num::NonZeroU64>().ok())
                .ok_or_else(|| MxcError::policy_validation("invalid W365 fixture timeout"))?
                .get(),
        ));
    }
    Ok(default)
}

pub(super) fn with_transport_stack<T: Send>(
    operation: impl FnOnce() -> Result<T, MxcError> + Send,
) -> Result<T, MxcError> {
    // TLS must not run on a foreign FFI caller's small stack. Join before returning.
    std::thread::scope(|scope| {
        std::thread::Builder::new()
            .name("mxc-w365-transport".into())
            .stack_size(2 * 1024 * 1024)
            .spawn_scoped(scope, operation)
            .map_err(|error| {
                MxcError::backend_error(format!("could not start W365 transport: {error}"))
            })?
            .join()
            .unwrap_or_else(|panic| std::panic::resume_unwind(panic))
    })
}

pub(super) fn guid(value: &str) -> bool {
    // UUID parsing also accepts simple, braced and URN forms; the contract does not.
    value.len() == uuid::fmt::Hyphenated::LENGTH && uuid::Uuid::try_parse(value).is_ok()
}

pub(crate) struct Identity {
    pub(super) pool_id: String,
    pub(super) session_id: String,
}

impl Identity {
    pub(super) fn parse(value: &str) -> Result<Self, MxcError> {
        let parts: Vec<_> = value.split(':').collect();
        if parts.len() != 3 || parts[0] != "w365" || !guid(parts[1]) || !guid(parts[2]) {
            return Err(MxcError::malformed_id(
                "w365 sandboxId must contain exactly a pool GUID and a session GUID",
            ));
        }
        Ok(Self {
            pool_id: parts[1].to_ascii_lowercase(),
            session_id: parts[2].to_ascii_lowercase(),
        })
    }

    pub(super) fn encode(&self) -> String {
        format!("w365:{}:{}", self.pool_id, self.session_id)
    }
}

pub(super) fn validate_provision(
    config: Option<&W365AgentsProvisionConfig>,
) -> Result<&W365AgentsProvisionConfig, MxcError> {
    let config = config.ok_or_else(|| {
        MxcError::policy_validation("w365Agents.provision.userObjectId is required")
    })?;
    if config.pool_id.as_deref().is_some_and(|id| !guid(id))
        || config.user_object_id.as_deref().is_some_and(|id| !guid(id))
        || config
            .user_type
            .as_deref()
            .is_some_and(|kind| !matches!(kind, "Local" | "HumanUser" | "Agentic"))
    {
        return Err(MxcError::policy_validation(
            "invalid W365 pool or user identity",
        ));
    }
    if config
        .user_object_id
        .as_deref()
        .is_none_or(|id| uuid::Uuid::try_parse(id).is_ok_and(|id| id.is_nil()))
    {
        return Err(MxcError::policy_validation(
            "W365 API 3.0 checkout requires w365Agents.provision.userObjectId",
        ));
    }
    if config.user_type.as_deref() == Some("Agentic") {
        return Err(MxcError::policy_validation(
            "W365 Agentic checkout requires auxiliary authentication that MXC does not support",
        ));
    }
    Ok(config)
}

pub(super) fn valid_host(host: &str) -> bool {
    !host.is_empty()
        && host.len() <= 253
        && host.split('.').all(|label| {
            !label.is_empty()
                && label.len() <= 63
                && !label.starts_with('-')
                && !label.ends_with('-')
                && label
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b == b'-')
        })
}

pub(super) fn read_token(key: &str) -> Result<String, MxcError> {
    let token = std::env::var(key).map_err(|_| {
        MxcError::policy_validation(format!(
            "w365_agents requires {key} in the caller environment"
        ))
    })?;
    if token.is_empty() || !token.bytes().all(|b| b.is_ascii_graphic()) {
        return Err(MxcError::policy_validation(format!(
            "{key} must be nonempty ASCII without whitespace or control characters"
        )));
    }
    Ok(token)
}

// Deliberately no Debug: the client owns the caller's bearer token.
pub(super) struct Client {
    pub(super) host: String,
    pub(super) token: String,
}

impl Client {
    pub(super) fn from_env() -> Result<Self, MxcError> {
        Self::from_env_keys("W365A_CONTROLPLANE_URL", "W365A_CP_TOKEN")
    }

    pub(super) fn from_env_keys(host_key: &str, token_key: &str) -> Result<Self, MxcError> {
        let read = |name: &str| {
            std::env::var(name).map_err(|_| {
                MxcError::policy_validation(format!(
                    "w365_agents requires {name} in the caller environment"
                ))
            })
        };
        let host = read(host_key)?;
        if !valid_host(&host) {
            return Err(MxcError::policy_validation(format!(
                "{host_key} must be a bare ASCII DNS hostname (no URL, port or path)"
            )));
        }
        Self::for_host(host, token_key)
    }

    pub(super) fn for_host(host: String, token_key: &str) -> Result<Self, MxcError> {
        if !valid_host(&host) {
            return Err(MxcError::policy_validation("invalid W365 service hostname"));
        }
        Ok(Self {
            host,
            token: read_token(token_key)?,
        })
    }

    pub(super) fn agent(&self, timeout: Duration) -> Result<(ureq::Agent, String), MxcError> {
        let timeout = timeout.min(transport_budget(timeout)?);
        let tls = TlsConfig::builder()
            .provider(TlsProvider::NativeTls)
            .root_certs(RootCerts::PlatformVerifier);
        #[cfg(feature = "test-support")]
        let (tls, port) = test_tls(tls)?;
        #[cfg(feature = "test-support")]
        if port != 443 && self.host != "localhost" {
            return Err(MxcError::policy_validation(
                "W365 fixture ports require localhost",
            ));
        }
        #[cfg(not(feature = "test-support"))]
        let port = 443;
        let config = ureq::Agent::config_builder()
            .user_agent(USER_AGENT)
            .tls_config(tls.build())
            .timeout_global(Some(timeout))
            .max_redirects(0)
            .http_status_as_error(false)
            // Never send caller credentials through an ambient HTTP proxy.
            .proxy(None)
            .build();
        Ok((config.into(), format!("https://{}:{port}", self.host)))
    }

    pub(super) fn checkout(
        &self,
        pool_id: &str,
        config: &W365AgentsProvisionConfig,
        source: &str,
    ) -> Result<ProvisionResult<CheckoutMetadata>, MxcError> {
        with_transport_stack(|| self.checkout_once(pool_id, config, source)).map_err(|mut error| {
            if let Some(details) = error.details.as_mut() {
                details["poolId"] = json!(pool_id.to_ascii_lowercase());
                details["controlPlaneHost"] = json!(self.host);
                if let Some(id) = details.get("sandboxId").and_then(Value::as_str)
                    .and_then(|id| Identity::parse(id).ok())
                {
                    if let Err(state_error) = super::routing::save(&id, &self.host, source, None) {
                        details["routingError"] = json!(state_error.message);
                        error.message.push_str(&format!(
                            "; local routing could not be saved; controlPlaneHost={}; retain the ID and host for service-operator cleanup; do not retry provision",
                            self.host,
                        ));
                    }
                }
            }
            error
        })
    }

    fn checkout_once(
        &self,
        pool_id: &str,
        config: &W365AgentsProvisionConfig,
        source: &str,
    ) -> Result<ProvisionResult<CheckoutMetadata>, MxcError> {
        let pool = pool_id.to_ascii_lowercase();
        let request_id = uuid::Uuid::new_v4().to_string();
        let deadline = Instant::now() + CHECKOUT_TIMEOUT.min(transport_budget(CHECKOUT_TIMEOUT)?);
        let mut identity: Option<Identity> = None;
        let mut last_status = None;
        let mut server_id = None;
        let mut body = json!({"userObjectId":config.user_object_id});
        if let Some(kind) = config.user_type.as_deref() {
            body["sessionKind"] = json!(match kind {
                "Local" => "local",
                "HumanUser" => "human",
                _ =>
                    return Err(MxcError::policy_validation(
                        "unsupported W365 checkout kind"
                    )),
            });
        }
        loop {
            let remaining = deadline.saturating_duration_since(Instant::now());
            if remaining.is_zero() {
                return Err(failure(
                    "checkout_timeout",
                    "checkout",
                    last_status,
                    &request_id,
                    server_id.as_deref(),
                    true,
                    identity.as_ref(),
                ));
            }
            let (agent, base) = self.agent(remaining)?;
            let url = format!("{base}/api/pools/{pool}/sessions?api-version=3.0");
            let mut request = agent
                .post(&url)
                .header("Authorization", format!("Bearer {}", self.token))
                .header("x-ms-client-request-id", &request_id)
                .header("Content-Type", "application/json");
            if let Some(id) = identity.as_ref() {
                request = request.header("x-ms-sessionId", &id.session_id);
            }
            let continuation = identity.is_some();
            // Only the first POST allocates; completion addresses the same reservation.
            let mut response = request.send(body.to_string()).map_err(|_| {
                failure(
                    "checkout_transport",
                    "checkout",
                    None,
                    &request_id,
                    server_id.as_deref(),
                    true,
                    identity.as_ref(),
                )
            })?;
            let status = response.status().as_u16();
            last_status = Some(status);
            server_id = safe_request_id(&response);
            let value = response
                .body_mut()
                .with_config()
                .limit(MAX_RESPONSE)
                .read_to_string()
                .map_err(|_| {
                    failure(
                        "checkout_response",
                        "checkout",
                        Some(status),
                        &request_id,
                        server_id.as_deref(),
                        true,
                        identity.as_ref(),
                    )
                })
                .and_then(|body| {
                    // Never include response bodies or ticket-bearing metadata in diagnostics.
                    serde_json::from_str::<Value>(&body).map_err(|_| {
                        failure(
                            "unparsable_response",
                            "checkout",
                            Some(status),
                            &request_id,
                            server_id.as_deref(),
                            true,
                            identity.as_ref(),
                        )
                    })
                });
            let session = value
                .as_ref()
                .ok()
                .and_then(|value| value.get("sessionId"))
                .and_then(Value::as_str)
                .filter(|id| guid(id))
                .map(str::to_owned);
            if identity.is_none() {
                identity = session.as_deref().map(|id| Identity {
                    pool_id: pool.clone(),
                    session_id: id.to_ascii_lowercase(),
                });
            }
            if !(200..300).contains(&status) {
                let code = match status {
                    401 | 403 => "auth_denied",
                    404 => "pool_not_found",
                    429 => "checkout_throttled",
                    500 => "provision_timeout",
                    _ => "checkout_failed",
                };
                // Body failures must not replace the HTTP error; a valid ID still permits cleanup.
                return Err(failure(
                    code,
                    "checkout",
                    Some(status),
                    &request_id,
                    server_id.as_deref(),
                    continuation || status >= 500 || status == 408 || (200..400).contains(&status),
                    identity.as_ref(),
                ));
            }
            let value = value?;
            let reject = |code| {
                failure(
                    code,
                    "checkout",
                    Some(status),
                    &request_id,
                    server_id.as_deref(),
                    true,
                    identity.as_ref(),
                )
            };
            let id = identity
                .as_ref()
                .ok_or_else(|| reject("malformed_session_id"))?;
            if !session
                .as_deref()
                .is_some_and(|returned| returned.eq_ignore_ascii_case(&id.session_id))
            {
                return Err(reject("checkout_id_mismatch"));
            }
            if !matches!(status, 200..=202) {
                return Err(reject("checkout_failed"));
            }
            if Instant::now() >= deadline {
                return Err(reject("checkout_timeout"));
            }
            if let Some(computer) = value.get("computerId") {
                if !computer.as_str().is_some_and(|computer| {
                    guid(computer) && computer.eq_ignore_ascii_case(&id.session_id)
                }) {
                    return Err(reject("id_mismatch"));
                }
            }
            if value.get("status").and_then(Value::as_str) == Some("Created") {
                super::routing::save(id, &self.host, source, None).map_err(|state_error| {
                    let mut error = reject("routing_state_write");
                    if let Some(details) = error.details.as_mut() {
                        details["routingError"] = json!(state_error.message);
                    }
                    error
                })?;
                body = json!({});
                std::thread::sleep(
                    Duration::from_secs(1).min(deadline.saturating_duration_since(Instant::now())),
                );
                continue;
            } else if value.get("status").and_then(Value::as_str) != Some("Succeeded") {
                return Err(reject("provision_failed"));
            }
            let computer_url = value
                .get("computerUrl")
                .and_then(Value::as_str)
                .ok_or_else(|| reject("missing_computer_url"))?;
            let computer_host = super::routing::computer_host(computer_url, id)
                .map_err(|_| reject("invalid_computer_url"))?;
            super::routing::save(id, &self.host, source, Some(computer_host)).map_err(
                |state_error| {
                    let mut error = reject("routing_state_write");
                    if let Some(details) = error.details.as_mut() {
                        details["routingError"] = json!(state_error.message);
                    }
                    error
                },
            )?;
            return Ok(ProvisionResult {
                sandbox_id: id.encode(),
                metadata: Some(CheckoutMetadata {
                    pool_id: pool,
                    session_id: id.session_id.clone(),
                    computer_id: id.session_id.clone(),
                }),
            });
        }
    }

    pub(super) fn release(&self, identity: &Identity) -> Result<(), MxcError> {
        with_transport_stack(|| self.release_once(identity))
    }

    fn release_once(&self, identity: &Identity) -> Result<(), MxcError> {
        let request_id = uuid::Uuid::new_v4().to_string();
        let (agent, base) = self.agent(RELEASE_TIMEOUT)?;
        let url = format!(
            "{base}/api/sessions/{}?api-version=2.0",
            identity.session_id
        );
        let response = agent
            .delete(&url)
            .header("Authorization", format!("Bearer {}", self.token))
            .header("x-ms-client-request-id", &request_id)
            .header("x-ms-sessionId", &identity.session_id)
            .call()
            .map_err(|_| {
                failure(
                    "release_transport",
                    "release",
                    None,
                    &request_id,
                    None,
                    true,
                    Some(identity),
                )
            })?;
        let status = response.status().as_u16();
        if matches!(status, 200 | 202 | 204 | 404) {
            return Ok(());
        }
        Err(failure(
            if matches!(status, 401 | 403) {
                "auth_denied"
            } else {
                "release_failed"
            },
            "release",
            Some(status),
            &request_id,
            safe_request_id(&response).as_deref(),
            status >= 500 || status == 408 || (200..400).contains(&status),
            Some(identity),
        ))
    }
}

pub(super) fn can_try_next_pool(error: &MxcError) -> bool {
    error.details.as_ref().is_some_and(|details| {
        details.get("operation").and_then(Value::as_str) == Some("checkout")
            && details.get("possiblySucceeded").and_then(Value::as_bool) == Some(false)
            && details.get("sessionId").is_none()
            && details.get("sandboxId").is_none()
            && details
                .get("httpStatus")
                .and_then(Value::as_u64)
                .is_some_and(|status| (400..500).contains(&status) && status != 408)
    })
}

pub(super) fn safe_request_id(response: &ureq::http::Response<ureq::Body>) -> Option<String> {
    response
        .headers()
        .get("x-ms-request-id")
        .and_then(|v| v.to_str().ok())
        .filter(|v| {
            v.len() <= 128
                && v.bytes()
                    .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_'))
        })
        .map(str::to_owned)
}

pub(super) fn failure(
    code: &str,
    operation: &str,
    status: Option<u16>,
    client_id: &str,
    server_id: Option<&str>,
    uncertain: bool,
    identity: Option<&Identity>,
) -> MxcError {
    let mut details = json!({
        "code": code, "operation": operation, "possiblySucceeded": uncertain,
        "clientRequestId": client_id,
    });
    if let Some(status) = status {
        details["httpStatus"] = json!(status);
    }
    if let Some(id) = server_id {
        details["requestId"] = json!(id);
    }
    if let Some(id) = identity {
        details["poolId"] = json!(id.pool_id);
        details["sessionId"] = json!(id.session_id);
        details["sandboxId"] = json!(id.encode());
    }
    let mut message = format!("w365_agents {operation} failed: {code}");
    if operation == "checkout" {
        message.push_str(&format!(
            "; clientRequestId={client_id}; possiblySucceeded={uncertain}"
        ));
        if let Some(id) = server_id {
            message.push_str(&format!("; requestId={id}"));
        }
        if let Some(id) = identity {
            message.push_str(&format!(
                "; checkout returned sandboxId {}; retain this ID for explicit release",
                id.encode()
            ));
        }
    }
    MxcError::backend_error(message).with_details(details)
}

#[cfg(feature = "test-support")]
fn test_tls(
    builder: ureq::tls::TlsConfigBuilder,
) -> Result<(ureq::tls::TlsConfigBuilder, u16), MxcError> {
    use ureq::tls::Certificate;
    let ca = std::env::var("MXC_W365_TEST_CA").ok();
    let port = std::env::var("MXC_W365_TEST_PORT").ok();
    match (ca, port) {
        (None, None) => Ok((builder, 443)),
        (Some(path), Some(port)) => {
            let bytes = std::fs::read(path)
                .map_err(|_| MxcError::policy_validation("cannot read fixture CA"))?;
            let cert = Certificate::from_pem(&bytes)
                .map_err(|_| MxcError::policy_validation("invalid fixture CA"))?;
            let port = port
                .parse()
                .map_err(|_| MxcError::policy_validation("invalid fixture port"))?;
            Ok((
                builder.root_certs(RootCerts::Specific(vec![cert].into())),
                port,
            ))
        }
        _ => Err(MxcError::policy_validation(
            "fixture CA and port must be supplied together",
        )),
    }
}
