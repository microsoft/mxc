// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use super::service::{failure, safe_request_id, Client, Identity};
use crate::mxc_common::mxc_error::MxcError;
use serde::Serialize;
use serde_json::Value;
use std::time::{Duration, Instant};

const READY_BUDGET: Duration = Duration::from_secs(120);
const POLL_INTERVAL: Duration = Duration::from_secs(1);

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct ReadyMetadata {
    status: &'static str,
    capability: &'static str,
}

pub(super) fn client(identity: &Identity) -> Result<Client, MxcError> {
    let mut client = Client::from_env_keys("W365A_DP_SUFFIX", "W365A_DP_TOKEN")?;
    // Service routing is pool-scoped, not a URL returned by checkout.
    #[cfg(any(test, feature = "test-support"))]
    if client.host == "localhost" && std::env::var_os("MXC_W365_TEST_PORT").is_some() {
        return Ok(client);
    }
    client.host = format!("{}.{}", identity.pool_id, client.host);
    if client.host.len() > 253 {
        return Err(MxcError::policy_validation(
            "W365 data-plane hostname is too long",
        ));
    }
    Ok(client)
}

pub(super) fn ready(identity: &Identity) -> Result<ReadyMetadata, MxcError> {
    let client = client(identity)?;
    super::service::with_transport_stack(|| poll(identity, &client, READY_BUDGET, POLL_INTERVAL))?;
    Ok(ReadyMetadata {
        status: "Ready",
        capability: "microsoft.exec",
    })
}

pub(super) fn poll(
    identity: &Identity,
    client: &Client,
    budget: Duration,
    interval: Duration,
) -> Result<(), MxcError> {
    let deadline = Instant::now()
        .checked_add(budget)
        .ok_or_else(|| MxcError::policy_validation("W365 readiness budget is too large"))?;
    let mut last_state = None;
    loop {
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            let mut error = failure(
                "attach_timeout",
                "start",
                None,
                "",
                None,
                false,
                Some(identity),
            );
            if let Some(details) = &mut error.details {
                details["lastState"] = serde_json::json!(last_state);
            }
            return Err(error);
        }
        let request_id = uuid::Uuid::new_v4().to_string();
        let (agent, base) = client.agent(remaining.min(Duration::from_secs(30)))?;
        let url = format!(
            "{base}/computers/{}/status?api-version=1.0",
            identity.session_id
        );
        let mut response = agent
            .get(&url)
            .header("Authorization", format!("Bearer {}", client.token))
            .header("x-ms-computerId", &identity.session_id)
            .header("x-ms-client-request-id", &request_id)
            .call()
            .map_err(|_| {
                failure(
                    "status_transport",
                    "start",
                    None,
                    &request_id,
                    None,
                    false,
                    Some(identity),
                )
            })?;
        let status = response.status().as_u16();
        let server_id = safe_request_id(&response);
        let reject = |code| {
            failure(
                code,
                "start",
                Some(status),
                &request_id,
                server_id.as_deref(),
                false,
                Some(identity),
            )
        };
        if status != 200 {
            return Err(reject(match status {
                401 | 403 => "auth_denied",
                404 | 410 => "reservation_unavailable",
                _ => "status_failed",
            }));
        }
        let body = response
            .body_mut()
            .with_config()
            .limit(1024 * 1024)
            .read_to_string()
            .map_err(|_| reject("status_response"))?;
        let body: Value = serde_json::from_str(&body).map_err(|_| reject("unparsable_response"))?;
        let state = body
            .get("status")
            .and_then(Value::as_str)
            .ok_or_else(|| reject("unparsable_response"))?;
        // A late Ready response cannot turn an expired client budget into success.
        if Instant::now() >= deadline {
            return Err(reject("attach_timeout"));
        }
        match state {
            "Ready" => return Ok(()),
            "Waiting" | "Live" => last_state = Some(state.to_owned()),
            _ => return Err(reject("unknown_device_status")),
        }
        std::thread::sleep(interval.min(deadline.saturating_duration_since(Instant::now())));
    }
}
