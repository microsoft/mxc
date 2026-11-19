// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use super::{routing, service};
use crate::mxc_common::mxc_error::MxcError;
use serde_json::Value;
use std::collections::HashSet;
use std::time::{Duration, Instant};
use url::Url;

const DISCOVERY_BUDGET: Duration = Duration::from_secs(30);

fn configuration() -> Result<(service::Client, Url), MxcError> {
    let (host, path) = match std::env::var("W365A_GRAPH_ENVIRONMENT") {
        Err(std::env::VarError::NotPresent) => ("graph.microsoft.com", "/beta/me/cloudPcPools"),
        Ok(value) if value == "public" => ("graph.microsoft.com", "/beta/me/cloudPcPools"),
        Ok(value) if value == "canary" => (
            "canary.graph.microsoft.com",
            "/testprodbeta_cpc_sh/me/cloudPcPools",
        ),
        _ => {
            return Err(MxcError::policy_validation(
                "W365A_GRAPH_ENVIRONMENT must be public or canary",
            ))
        }
    };
    let url = Url::parse(&format!("https://{host}{path}"))
        .map_err(|_| routing::error("graph_configuration", "invalid fixed Graph endpoint"))?;
    #[cfg(feature = "test-support")]
    let host = if std::env::var("MXC_W365_TEST_GRAPH_LOCALHOST").as_deref() == Ok("1") {
        "localhost"
    } else {
        host
    };
    Ok((
        service::Client::for_host(host.to_owned(), "W365A_GRAPH_TOKEN")?,
        url,
    ))
}

pub(super) fn validate() -> Result<(), MxcError> {
    configuration()?;
    service::read_token("W365A_CP_TOKEN").map(|_| ())
}

pub(super) fn control_plane(
    pool_id: &str,
) -> Result<Option<(service::Client, Url, &'static str)>, MxcError> {
    service::with_transport_stack(|| pool_resource(pool_id))
}

pub(super) fn assigned_pools() -> Result<Vec<String>, MxcError> {
    service::with_transport_stack(list_assigned_pools)
}

fn get(client: &service::Client, url: &Url, deadline: Instant) -> Result<Value, MxcError> {
    let remaining = deadline.saturating_duration_since(Instant::now());
    if remaining.is_zero() {
        return Err(routing::error(
            "graph_timeout",
            "Graph discovery budget expired",
        ));
    }
    let (agent, base) = client.agent(remaining)?;
    let mut target = format!("{base}{}", url.path());
    if let Some(query) = url.query() {
        target.push('?');
        target.push_str(query);
    }
    let mut response = agent
        .get(&target)
        .header("Authorization", format!("Bearer {}", client.token))
        .call()
        .map_err(|_| routing::error("graph_transport", "Graph request failed"))?;
    if response.status().as_u16() != 200 {
        return Err(routing::error(
            "graph_http",
            format!("Graph returned HTTP {}", response.status().as_u16()),
        ));
    }
    let body = response
        .body_mut()
        .with_config()
        .limit(1024 * 1024)
        .read_to_string()
        .map_err(|_| routing::error("graph_response", "could not read bounded Graph response"))?;
    serde_json::from_str(&body)
        .map_err(|_| routing::error("graph_response", "invalid Graph JSON response"))
}

fn list_assigned_pools() -> Result<Vec<String>, MxcError> {
    let (client, origin) = configuration()?;
    let mut next = Some(origin.clone());
    let mut visited = HashSet::new();
    let deadline = Instant::now() + service::transport_budget(DISCOVERY_BUDGET)?;
    let mut pool_ids = Vec::new();
    let mut seen = HashSet::new();
    while let Some(url) = next.take() {
        if visited.len() == 100 || !visited.insert(url.as_str().to_owned()) {
            return Err(routing::error(
                "graph_pagination",
                "Graph pagination exceeded its bound or repeated a page",
            ));
        }
        let value = get(&client, &url, deadline)?;
        let pools = value
            .get("value")
            .and_then(Value::as_array)
            .ok_or_else(|| {
                routing::error("graph_response", "Graph response lacks a pool collection")
            })?;
        for pool in pools {
            let id = pool
                .get("id")
                .and_then(Value::as_str)
                .filter(|id| service::guid(id))
                .ok_or_else(|| routing::error("graph_response", "Graph pool lacks a valid GUID"))?
                .to_ascii_lowercase();
            if !seen.insert(id.clone()) {
                return Err(routing::error(
                    "graph_response",
                    "Graph returned an assigned pool more than once",
                ));
            }
            pool_ids.push(id);
        }
        next = match value.get("@odata.nextLink") {
            None => None,
            Some(Value::String(value)) => {
                let url = routing::validate_url(value)?;
                if url.origin() != origin.origin() || url.path() != origin.path() {
                    return Err(routing::error(
                        "graph_pagination",
                        "Graph nextLink left the selected collection",
                    ));
                }
                Some(url)
            }
            _ => {
                return Err(routing::error(
                    "graph_pagination",
                    "Graph nextLink has an invalid type",
                ))
            }
        };
    }
    Ok(pool_ids)
}

fn pool_resource(pool_id: &str) -> Result<Option<(service::Client, Url, &'static str)>, MxcError> {
    let (client, origin) = configuration()?;
    let deadline = Instant::now() + service::transport_budget(DISCOVERY_BUDGET)?;
    let resource = origin
        .join(&format!(
            "../deviceManagement/virtualEndpoint/cloudPcPools/{pool_id}"
        ))
        .map_err(|_| routing::error("graph_configuration", "invalid pool resource endpoint"))?;
    let pool = get(&client, &resource, deadline)?;
    if !pool
        .get("id")
        .and_then(Value::as_str)
        .is_some_and(|id| id.eq_ignore_ascii_case(pool_id))
    {
        return Err(routing::error(
            "graph_response",
            "Graph pool resource does not match the selected pool ID",
        ));
    }
    let available_sessions = pool
        .get("sessionUsage")
        .and_then(|usage| usage.get("availableSessionsCount"))
        .and_then(Value::as_i64)
        .and_then(|count| i32::try_from(count).ok())
        .ok_or_else(|| {
            routing::error(
                "graph_response",
                "Graph pool resource requires sessionUsage.availableSessionsCount as an Int32",
            )
        })?;
    if available_sessions <= 0 {
        return Ok(None);
    }
    let value = pool
        .get("poolUrl")
        .and_then(Value::as_str)
        .filter(|value| !value.is_empty())
        .ok_or_else(|| {
            routing::error("invalid_pool_url", "Graph pool resource requires poolUrl")
        })?;
    let url = routing::validate_url(value)?;
    let host = url
        .host_str()
        .ok_or_else(|| routing::error("invalid_pool_url", "missing pool host"))?;
    Ok(Some((
        service::Client::for_host(host.to_owned(), "W365A_CP_TOKEN")?,
        url,
        "graph",
    )))
}
