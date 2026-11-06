// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Azure Resource Manager (ARM) and ACI data-plane REST calls.

use std::time::{Duration, Instant};

use crate::mxc_common::mxc_error::MxcError;

use super::credentials::Secret;

pub(super) const ARM_ENDPOINT: &str = "https://management.azure.com";
pub(super) const API_VERSION: &str = "2026-06-01-preview";

const REQUEST_TIMEOUT: Duration = Duration::from_secs(60);
const CONNECT_TIMEOUT: Duration = Duration::from_secs(30);
const ATTEMPTS: u32 = 4;
const RETRY_BASE: Duration = Duration::from_millis(500);
const MESSAGE_LIMIT: usize = 512;
/// Reconnect before deleting when the data-plane token expires this soon.
const TOKEN_REFRESH_MARGIN: chrono::TimeDelta = chrono::TimeDelta::minutes(5);

/// The parts of a sandbox group ARM resource ID that MXC uses.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct SandboxGroup {
    pub id: String,
    pub subscription: String,
}

impl SandboxGroup {
    pub fn parse(id: &str) -> Result<Self, MxcError> {
        crate::mxc_contract::dev::AciSandboxGroupId::validate(id)
            .map_err(|error| MxcError::malformed_request(format!("aci.sandboxGroup: {error}")))?;
        // Validation guarantees the subscription is the second segment.
        let subscription = id.split('/').nth(2).unwrap_or_default().to_owned();
        Ok(Self {
            id: id.to_owned(),
            subscription,
        })
    }
}

/// A sandbox resource as reported by the data plane.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct SandboxResource {
    pub provisioning_state: String,
    pub connection_string: Option<Secret>,
    pub error_message: Option<String>,
}

/// A data-plane session returned by the sandbox group's `connect` action.
#[derive(Debug)]
pub(super) struct DataPlane {
    endpoint: url::Url,
    token: Secret,
    not_after: Option<chrono::DateTime<chrono::Utc>>,
}

/// Blocking REST client with bounded timeouts and transient-failure retries.
pub(super) struct Rest {
    agent: ureq::Agent,
}

impl Rest {
    pub fn new() -> Self {
        let agent = ureq::Agent::config_builder()
            .timeout_connect(Some(CONNECT_TIMEOUT))
            .timeout_global(Some(REQUEST_TIMEOUT))
            .http_status_as_error(false)
            // The gateway client connects directly, so REST must too; honoring
            // proxy variables here would fail runs only once they reach the gateway.
            .proxy(None)
            // ureq's default TLS provider is rustls, which is not compiled in.
            // Use the operating system's trusted roots, as the gateway client does.
            .tls_config(
                ureq::tls::TlsConfig::builder()
                    .provider(ureq::tls::TlsProvider::NativeTls)
                    .root_certs(ureq::tls::RootCerts::PlatformVerifier)
                    .build(),
            )
            .build()
            .new_agent();
        Self { agent }
    }

    /// Sends a request and returns its status and body, retrying throttling,
    /// server errors, and transport failures. Every method used here is
    /// idempotent, including `connect`, which issues a fresh session.
    fn send(
        &self,
        method: &str,
        url: &str,
        token: &Secret,
        body: Option<&serde_json::Value>,
    ) -> Result<(u16, Vec<u8>), String> {
        let mut last_error = String::new();
        for attempt in 0..ATTEMPTS {
            if attempt > 0 {
                std::thread::sleep(RETRY_BASE * 2u32.pow(attempt - 1));
            }
            match self.send_once(method, url, token, body) {
                Ok((status, bytes)) if !is_transient(status) || attempt + 1 == ATTEMPTS => {
                    return Ok((status, bytes));
                }
                Ok((status, _)) => last_error = format!("HTTP {status}"),
                Err(error) => last_error = error,
            }
        }
        Err(last_error)
    }

    fn send_once(
        &self,
        method: &str,
        url: &str,
        token: &Secret,
        body: Option<&serde_json::Value>,
    ) -> Result<(u16, Vec<u8>), String> {
        let authorization = format!("Bearer {}", token.expose());
        let response = match (method, body) {
            ("GET", _) => self
                .agent
                .get(url)
                .header("Authorization", &authorization)
                .call(),
            ("DELETE", _) => self
                .agent
                .delete(url)
                .header("Authorization", &authorization)
                .call(),
            ("PUT", Some(body)) => self
                .agent
                .put(url)
                .header("Authorization", &authorization)
                .header("Content-Type", "application/json")
                .send(body.to_string()),
            ("POST", Some(body)) => self
                .agent
                .post(url)
                .header("Authorization", &authorization)
                .header("Content-Type", "application/json")
                .send(body.to_string()),
            _ => return Err(format!("unsupported request {method}")),
        };
        // Transport errors never include request headers, so the token stays private.
        let mut response = response.map_err(|error| error.to_string())?;
        let status = response.status().as_u16();
        let bytes = response
            .body_mut()
            .read_to_vec()
            .map_err(|error| format!("cannot read the response: {error}"))?;
        Ok((status, bytes))
    }
}

fn is_transient(status: u16) -> bool {
    matches!(status, 408 | 429 | 500 | 502 | 503 | 504)
}

/// The sandbox group's Azure region.
pub(super) fn group_location(
    rest: &Rest,
    group: &SandboxGroup,
    arm_token: &Secret,
) -> Result<String, MxcError> {
    let url = format!("{ARM_ENDPOINT}{}?api-version={API_VERSION}", group.id);
    let (status, body) = rest
        .send("GET", &url, arm_token, None)
        .map_err(|error| unreachable_service("read the sandbox group", &error))?;
    if status != 200 {
        return Err(group_error("read the sandbox group", group, status, &body));
    }
    #[derive(serde::Deserialize)]
    struct Group {
        location: String,
    }
    let parsed: Group = serde_json::from_slice(&body).map_err(|error| {
        MxcError::backend_error(format!(
            "ACI returned an unexpected sandbox group description: {error}"
        ))
    })?;
    Ok(parsed.location)
}

/// Opens a data-plane session with the sandbox group's `connect` action.
pub(super) fn connect(
    rest: &Rest,
    group: &SandboxGroup,
    arm_token: &Secret,
) -> Result<DataPlane, MxcError> {
    let url = format!(
        "{ARM_ENDPOINT}{}/connect?api-version={API_VERSION}",
        group.id
    );
    let (status, body) = rest
        .send("POST", &url, arm_token, Some(&serde_json::json!({})))
        .map_err(|error| unreachable_service("connect to the sandbox group", &error))?;
    if status != 200 {
        return Err(group_error(
            "connect to the sandbox group",
            group,
            status,
            &body,
        ));
    }
    DataPlane::from_connect_response(&body)
}

impl DataPlane {
    fn from_connect_response(body: &[u8]) -> Result<Self, MxcError> {
        #[derive(serde::Deserialize)]
        #[serde(rename_all = "camelCase")]
        struct Connect {
            endpoint: String,
            access_token: String,
            not_after: Option<String>,
        }
        let parsed: Connect = serde_json::from_slice(body).map_err(|error| {
            MxcError::backend_error(format!(
                "ACI returned an unexpected sandbox group connection: {error}"
            ))
        })?;
        let endpoint = url::Url::parse(&parsed.endpoint)
            .ok()
            .filter(|url| {
                url.scheme() == "https"
                    && url.host_str().is_some()
                    && url.username().is_empty()
                    && url.password().is_none()
                    && url.query().is_none()
                    && url.fragment().is_none()
            })
            .ok_or_else(|| {
                MxcError::backend_error(
                    "ACI returned a data-plane endpoint that is not an https URL",
                )
            })?;
        let not_after = parsed.not_after.as_deref().and_then(|value| {
            chrono::DateTime::parse_from_rfc3339(value)
                .ok()
                .map(|time| time.with_timezone(&chrono::Utc))
        });
        Ok(Self {
            endpoint,
            token: Secret::new(parsed.access_token, "data-plane token")?,
            not_after,
        })
    }

    /// Whether the session token expires within the refresh margin.
    pub fn expires_soon(&self) -> bool {
        self.not_after
            .is_some_and(|not_after| not_after - chrono::Utc::now() < TOKEN_REFRESH_MARGIN)
    }

    fn sandbox_url(&self, name: &str) -> String {
        let mut url = self.endpoint.clone();
        if let Ok(mut segments) = url.path_segments_mut() {
            segments.pop_if_empty().extend(["sandboxes", name]);
        }
        url.set_query(Some(&format!("api-version={API_VERSION}")));
        url.into()
    }

    /// Creates the sandbox, or reports the existing one with this name.
    pub fn put_sandbox(
        &self,
        rest: &Rest,
        name: &str,
        body: &serde_json::Value,
    ) -> Result<SandboxResource, MxcError> {
        let (status, response) = rest
            .send("PUT", &self.sandbox_url(name), &self.token, Some(body))
            .map_err(|error| unreachable_service("create the sandbox", &error))?;
        match status {
            200 | 201 => SandboxResource::parse(&response),
            _ => Err(sandbox_error("create the sandbox", name, status, &response)),
        }
    }

    /// The sandbox, or `None` once it no longer exists.
    pub fn get_sandbox(
        &self,
        rest: &Rest,
        name: &str,
    ) -> Result<Option<SandboxResource>, MxcError> {
        let (status, response) = rest
            .send("GET", &self.sandbox_url(name), &self.token, None)
            .map_err(|error| unreachable_service("read the sandbox", &error))?;
        match status {
            200 => SandboxResource::parse(&response).map(Some),
            404 => Ok(None),
            _ => Err(sandbox_error("read the sandbox", name, status, &response)),
        }
    }

    /// Requests deletion. The service completes it asynchronously; a sandbox
    /// that no longer exists is already deleted.
    pub fn delete_sandbox(&self, rest: &Rest, name: &str) -> Result<(), MxcError> {
        let (status, response) = rest
            .send("DELETE", &self.sandbox_url(name), &self.token, None)
            .map_err(|error| unreachable_service("delete the sandbox", &error))?;
        match status {
            200 | 202 | 204 | 404 => Ok(()),
            _ => Err(sandbox_error("delete the sandbox", name, status, &response)),
        }
    }
}

impl SandboxResource {
    fn parse(body: &[u8]) -> Result<Self, MxcError> {
        #[derive(serde::Deserialize)]
        #[serde(rename_all = "camelCase")]
        struct Resource {
            properties: Properties,
        }
        #[derive(serde::Deserialize)]
        #[serde(rename_all = "camelCase")]
        struct Properties {
            #[serde(default)]
            provisioning_state: String,
            connection_string: Option<String>,
            instance_view: Option<InstanceView>,
        }
        #[derive(serde::Deserialize)]
        #[serde(rename_all = "camelCase")]
        struct InstanceView {
            error_message: Option<String>,
        }
        let parsed: Resource = serde_json::from_slice(body).map_err(|error| {
            MxcError::backend_error(format!(
                "ACI returned an unexpected sandbox description: {error}"
            ))
        })?;
        let properties = parsed.properties;
        Ok(Self {
            provisioning_state: properties.provisioning_state,
            connection_string: properties
                .connection_string
                .filter(|value| !value.is_empty())
                .map(|value| Secret::new(value, "sandbox connection string"))
                .transpose()?,
            error_message: properties
                .instance_view
                .and_then(|view| view.error_message)
                .map(|message| bounded(&message)),
        })
    }
}

fn unreachable_service(operation: &str, error: &str) -> MxcError {
    MxcError::backend_error(format!("ACI could not {operation}: {}", bounded(error)))
}

fn group_error(operation: &str, group: &SandboxGroup, status: u16, body: &[u8]) -> MxcError {
    let detail = service_message(body);
    match status {
        401 | 403 => MxcError::backend_unavailable(format!(
            "ACI could not {operation} {}: access denied (HTTP {status}){detail}; sign in with \
             `az login` as an account that can use the sandbox group, or set {}",
            group.id,
            super::credentials::ARM_TOKEN_ENV
        )),
        404 => MxcError::backend_unavailable(format!(
            "ACI sandbox group {} was not found (HTTP 404){detail}",
            group.id
        )),
        _ => MxcError::backend_error(format!(
            "ACI could not {operation} {} (HTTP {status}){detail}",
            group.id
        )),
    }
}

fn sandbox_error(operation: &str, name: &str, status: u16, body: &[u8]) -> MxcError {
    let detail = service_message(body);
    match status {
        400 => MxcError::malformed_request(format!(
            "ACI rejected the request to {operation} {name} (HTTP 400){detail}"
        )),
        401 | 403 => MxcError::backend_unavailable(format!(
            "ACI could not {operation} {name}: access denied (HTTP {status}){detail}"
        )),
        _ => MxcError::backend_error(format!(
            "ACI could not {operation} {name} (HTTP {status}){detail}"
        )),
    }
}

/// The service's error code and message, without details such as stack traces.
fn service_message(body: &[u8]) -> String {
    let Ok(serde_json::Value::Object(root)) = serde_json::from_slice::<serde_json::Value>(body)
    else {
        return String::new();
    };
    let Some(serde_json::Value::Object(error)) = field(&root, "error") else {
        return String::new();
    };
    let text = |name| field(error, name).and_then(serde_json::Value::as_str);
    match (text("code"), text("message")) {
        (Some(code), Some(message)) if message.starts_with(code) => {
            format!(": {}", bounded(message))
        }
        (Some(code), Some(message)) => format!(": {}: {}", bounded(code), bounded(message)),
        (Some(text), None) | (None, Some(text)) => format!(": {}", bounded(text)),
        (None, None) => String::new(),
    }
}

/// A JSON object member matched case-insensitively; the data plane
/// capitalizes error members that ARM spells in lowercase.
fn field<'a>(
    object: &'a serde_json::Map<String, serde_json::Value>,
    name: &str,
) -> Option<&'a serde_json::Value> {
    object
        .iter()
        .find(|(key, _)| key.eq_ignore_ascii_case(name))
        .map(|(_, value)| value)
}

pub(super) fn bounded(text: &str) -> String {
    let text = text.trim();
    match text.char_indices().nth(MESSAGE_LIMIT) {
        Some((end, _)) => format!("{}...", &text[..end]),
        None => text.to_owned(),
    }
}

/// Polls `poll` until it returns `Some`, or fails once `deadline` passes.
pub(super) fn poll_until<T>(
    deadline: Instant,
    interval: Duration,
    mut poll: impl FnMut() -> Result<Option<T>, MxcError>,
) -> Result<Option<T>, MxcError> {
    loop {
        if let Some(value) = poll()? {
            return Ok(Some(value));
        }
        if Instant::now() >= deadline {
            return Ok(None);
        }
        std::thread::sleep(interval.min(deadline.saturating_duration_since(Instant::now())));
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::mxc_common::mxc_error::MxcErrorCode;

    const GROUP: &str = "/subscriptions/51aca303-03da-4510-849d-d4f32d3f39ac/resourceGroups/tryme-01/providers/Microsoft.ContainerInstance/sandboxGroups/sbg-001";

    fn data_plane(endpoint: &str) -> DataPlane {
        DataPlane::from_connect_response(
            serde_json::json!({
                "endpoint": endpoint,
                "accessToken": "eyJ0.eyJ1.sig",
                "notAfter": "2099-11-06T18:34:41.2186655Z"
            })
            .to_string()
            .as_bytes(),
        )
        .unwrap()
    }

    #[test]
    fn sandbox_group_ids_yield_their_subscription() {
        let group = SandboxGroup::parse(GROUP).unwrap();
        assert_eq!(group.subscription, "51aca303-03da-4510-849d-d4f32d3f39ac");
        let error = SandboxGroup::parse("/subscriptions/x").unwrap_err();
        assert_eq!(error.code, MxcErrorCode::MalformedRequest);
        assert!(error.message.starts_with("aci.sandboxGroup: "), "{error}");
    }

    #[test]
    fn connect_responses_require_an_https_endpoint_and_token() {
        let plane = data_plane(
            "https://example.azurefd.net/subscriptions/s/resourcegroups/r/providers/Microsoft.ContainerInstance/sandboxGroups/sbxg-1",
        );
        assert!(!plane.expires_soon());
        assert_eq!(
            plane.sandbox_url("mxc-0123"),
            "https://example.azurefd.net/subscriptions/s/resourcegroups/r/providers/Microsoft.ContainerInstance/sandboxGroups/sbxg-1/sandboxes/mxc-0123?api-version=2026-06-01-preview"
        );
        assert_eq!(
            data_plane("https://example.net/").sandbox_url("n"),
            "https://example.net/sandboxes/n?api-version=2026-06-01-preview"
        );
        for endpoint in [
            "http://example.net/group",
            "https://user:pass@example.net/group",
            "https://example.net/group?x=1",
            "not a url",
        ] {
            let body = serde_json::json!({"endpoint": endpoint, "accessToken": "t"}).to_string();
            let error = DataPlane::from_connect_response(body.as_bytes()).unwrap_err();
            assert_eq!(error.code, MxcErrorCode::BackendError, "{endpoint}");
        }
        let body = serde_json::json!({"endpoint": "https://example.net", "accessToken": ""});
        assert!(DataPlane::from_connect_response(body.to_string().as_bytes()).is_err());
    }

    #[test]
    fn expiring_sessions_are_refreshed_before_cleanup() {
        let body = serde_json::json!({
            "endpoint": "https://example.net",
            "accessToken": "t",
            "notAfter": (chrono::Utc::now() + chrono::TimeDelta::minutes(1)).to_rfc3339(),
        });
        assert!(
            DataPlane::from_connect_response(body.to_string().as_bytes())
                .unwrap()
                .expires_soon()
        );
        let body = serde_json::json!({"endpoint": "https://example.net", "accessToken": "t"});
        assert!(
            !DataPlane::from_connect_response(body.to_string().as_bytes())
                .unwrap()
                .expires_soon()
        );
    }

    #[test]
    fn sandbox_descriptions_keep_state_connection_and_failure() {
        let resource = SandboxResource::parse(
            br#"{"name":"g/n","properties":{"provisioningState":"Succeeded","connectionString":"address=a;token=t;token_type=bearer","attachToAgentFabric":false}}"#,
        )
        .unwrap();
        assert_eq!(resource.provisioning_state, "Succeeded");
        assert_eq!(
            resource.connection_string.unwrap().expose(),
            "address=a;token=t;token_type=bearer"
        );
        let failed = SandboxResource::parse(
            br#"{"properties":{"provisioningState":"Failed","instanceView":{"errorMessage":"Allocation failed permanently (compute: Failed, ip: Ready)."}}}"#,
        )
        .unwrap();
        assert_eq!(failed.provisioning_state, "Failed");
        assert!(failed.connection_string.is_none());
        assert_eq!(
            failed.error_message.as_deref(),
            Some("Allocation failed permanently (compute: Failed, ip: Ready).")
        );
        assert!(SandboxResource::parse(b"[]").is_err());
    }

    #[test]
    fn service_errors_keep_code_and_message_but_drop_details() {
        let body = br#"{"Error":{"Details":[{"Code":"Exception","Message":"Common.Exceptions.ServiceException: BadRequest. at Stack.Trace()"}],"Code":"BadRequest","Message":"BadRequest. Image 'x' is not a valid OCI image reference."}}"#;
        let error = sandbox_error("create the sandbox", "mxc-1", 400, body);
        assert_eq!(error.code, MxcErrorCode::MalformedRequest);
        assert_eq!(
            error.message,
            "ACI rejected the request to create the sandbox mxc-1 (HTTP 400): BadRequest. Image 'x' is not a valid OCI image reference."
        );
        assert!(!error.message.contains("Stack.Trace"));

        let arm = br#"{"error":{"code":"AuthorizationFailed","message":"The client does not have authorization."}}"#;
        let group = SandboxGroup::parse(GROUP).unwrap();
        let denied = group_error("connect to the sandbox group", &group, 403, arm);
        assert_eq!(denied.code, MxcErrorCode::BackendUnavailable);
        assert!(denied
            .message
            .contains("AuthorizationFailed: The client does not have authorization."));
        assert!(denied.message.contains("az login"));
        let missing = group_error("read the sandbox group", &group, 404, b"");
        assert_eq!(missing.code, MxcErrorCode::BackendUnavailable);
        assert!(missing.message.contains("was not found"));
        let other = group_error("read the sandbox group", &group, 500, b"<html>");
        assert_eq!(other.code, MxcErrorCode::BackendError);
        assert!(other.message.ends_with("(HTTP 500)"), "{other}");

        let long = format!(r#"{{"error":{{"message":"{}"}}}}"#, "m".repeat(2000));
        assert!(service_message(long.as_bytes()).len() < MESSAGE_LIMIT + 10);
    }

    #[test]
    fn only_throttling_and_server_errors_are_retried() {
        for status in [408, 429, 500, 502, 503, 504] {
            assert!(is_transient(status), "{status}");
        }
        for status in [200, 201, 400, 401, 403, 404, 409] {
            assert!(!is_transient(status), "{status}");
        }
    }

    #[test]
    fn polling_stops_at_the_first_value_or_the_deadline() {
        let mut calls = 0;
        let found = poll_until(
            Instant::now() + Duration::from_secs(5),
            Duration::from_millis(1),
            || {
                calls += 1;
                Ok((calls == 3).then_some(calls))
            },
        )
        .unwrap();
        assert_eq!(found, Some(3));
        let expired =
            poll_until(Instant::now(), Duration::from_millis(1), || Ok(None::<()>)).unwrap();
        assert_eq!(expired, None);
    }
}
