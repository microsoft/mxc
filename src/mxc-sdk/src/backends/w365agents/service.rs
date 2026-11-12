// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use super::{CheckoutMetadata, ProvisionResult};
use crate::mxc_common::mxc_error::MxcError;
use crate::mxc_common::state_aware_operation::W365AgentsProvisionConfig;
use serde_json::{json, Value};
use std::time::Duration;
use ureq::tls::{RootCerts, TlsConfig, TlsProvider};

const CHECKOUT_TIMEOUT: Duration = Duration::from_secs(45);
const RELEASE_TIMEOUT: Duration = Duration::from_secs(30);
const MAX_RESPONSE: u64 = 1024 * 1024;

fn guid(value: &str) -> bool {
    value.len() == 36
        && value.bytes().enumerate().all(|(i, b)| {
            if matches!(i, 8 | 13 | 18 | 23) {
                b == b'-'
            } else {
                b.is_ascii_hexdigit()
            }
        })
}

pub(super) struct Identity {
    pool_id: String,
    session_id: String,
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

    fn encode(&self) -> String {
        format!("w365:{}:{}", self.pool_id, self.session_id)
    }
}

pub(super) fn validate_provision(
    config: Option<&W365AgentsProvisionConfig>,
) -> Result<&W365AgentsProvisionConfig, MxcError> {
    let config = config
        .ok_or_else(|| MxcError::policy_validation("w365Agents.provision.poolId is required"))?;
    if !guid(&config.pool_id)
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
    Ok(config)
}

// Deliberately no Debug: the client owns the caller's bearer token.
pub(super) struct Client {
    host: String,
    token: String,
}

impl Client {
    pub(super) fn from_env() -> Result<Self, MxcError> {
        let read = |name: &str| {
            std::env::var(name).map_err(|_| {
                MxcError::policy_validation(format!(
                    "w365_agents requires {name} in the caller environment"
                ))
            })
        };
        let host = read("W365A_CONTROLPLANE_URL")?;
        let token = read("W365A_CP_TOKEN")?;
        let valid_host = host.len() <= 253
            && host.split('.').all(|label| {
                !label.is_empty()
                    && label.len() <= 63
                    && !label.starts_with('-')
                    && !label.ends_with('-')
                    && label
                        .bytes()
                        .all(|b| b.is_ascii_alphanumeric() || b == b'-')
            });
        if !valid_host {
            return Err(MxcError::policy_validation(
                "W365A_CONTROLPLANE_URL must be a bare ASCII DNS hostname (no URL, port or path)",
            ));
        }
        if token.is_empty() || !token.bytes().all(|b| b.is_ascii_graphic()) {
            return Err(MxcError::policy_validation(
                "W365A_CP_TOKEN must be nonempty ASCII without whitespace or control characters",
            ));
        }
        Ok(Self { host, token })
    }

    fn agent(&self, timeout: Duration) -> Result<(ureq::Agent, String), MxcError> {
        let tls = TlsConfig::builder()
            .provider(TlsProvider::NativeTls)
            .root_certs(RootCerts::PlatformVerifier);
        #[cfg(any(test, feature = "test-support"))]
        let (tls, port) = test_tls(tls)?;
        #[cfg(any(test, feature = "test-support"))]
        if port != 443 && self.host != "localhost" {
            return Err(MxcError::policy_validation(
                "W365 fixture ports require localhost",
            ));
        }
        #[cfg(not(any(test, feature = "test-support")))]
        let port = 443;
        let config = ureq::Agent::config_builder()
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
        config: &W365AgentsProvisionConfig,
    ) -> Result<ProvisionResult<CheckoutMetadata>, MxcError> {
        service_call(|| self.checkout_once(config)).map_err(|mut error| {
            if let Some(details) = error.details.as_mut() {
                details["poolId"] = json!(config.pool_id.to_ascii_lowercase());
            }
            error
        })
    }

    fn checkout_once(
        &self,
        config: &W365AgentsProvisionConfig,
    ) -> Result<ProvisionResult<CheckoutMetadata>, MxcError> {
        let pool = config.pool_id.to_ascii_lowercase();
        let request_id = uuid::Uuid::new_v4().to_string();
        let (agent, base) = self.agent(CHECKOUT_TIMEOUT)?;
        let url = format!("{base}/api/pools/{pool}/sessions?api-version=2.0");
        let mut request = agent
            .post(&url)
            .header("Authorization", format!("Bearer {}", self.token))
            .header("x-ms-client-request-id", &request_id);
        if let Some(kind) = &config.user_type {
            request = request.header("user-type", kind);
        }
        if let Some(oid) = &config.user_object_id {
            request = request.header("user-object-id", oid);
        }
        // One allocation attempt. No polling, retry, redirect or compensating release.
        let response = request.send_empty().map_err(|_| {
            failure(
                "checkout_transport",
                "checkout",
                None,
                &request_id,
                None,
                true,
                None,
            )
        })?;
        let status = response.status().as_u16();
        let server_id = safe_request_id(&response);
        let mut response = response;
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
                    None,
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
                        None,
                    )
                })
            });
        let session = value
            .as_ref()
            .ok()
            .and_then(|value| value.get("sessionId"))
            .and_then(Value::as_str)
            .filter(|id| guid(id));
        let identity = session.map(|id| Identity {
            pool_id: pool.clone(),
            session_id: id.to_ascii_lowercase(),
        });
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
                status >= 500 || status == 408 || (200..400).contains(&status),
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
        let identity = identity
            .as_ref()
            .ok_or_else(|| reject("malformed_session_id"))?;
        if status != 200 {
            return Err(reject("checkout_failed"));
        }
        if let Some(computer) = value.get("computerId") {
            if !computer
                .as_str()
                .is_some_and(|id| guid(id) && id.eq_ignore_ascii_case(&identity.session_id))
            {
                return Err(reject("id_mismatch"));
            }
        }
        if value.get("status").and_then(Value::as_str) != Some("Succeeded") {
            return Err(reject("provision_failed"));
        }
        Ok(ProvisionResult {
            sandbox_id: identity.encode(),
            metadata: Some(CheckoutMetadata {
                pool_id: pool,
                session_id: identity.session_id.clone(),
                computer_id: identity.session_id.clone(),
            }),
        })
    }

    pub(super) fn release(&self, identity: &Identity) -> Result<(), MxcError> {
        service_call(|| self.release_once(identity))
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

fn service_call<T: Send>(call: impl FnOnce() -> Result<T, MxcError> + Send) -> Result<T, MxcError> {
    // Platform TLS can exceed SDK callers' small native stacks (Koffi uses 128 KiB).
    std::thread::scope(|scope| {
        let worker = std::thread::Builder::new()
            .name("mxc-w365-service".to_string())
            .stack_size(1024 * 1024)
            .spawn_scoped(scope, call)
            .map_err(|error| {
                MxcError::backend_error(format!("cannot start W365 service thread: {error}"))
            })?;
        worker
            .join()
            .unwrap_or_else(|panic| std::panic::resume_unwind(panic))
    })
}

fn safe_request_id(response: &ureq::http::Response<ureq::Body>) -> Option<String> {
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

fn failure(
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

#[cfg(any(test, feature = "test-support"))]
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
