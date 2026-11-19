// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

mod storage;

use super::service::{Client, Identity};
use crate::mxc_common::mxc_error::MxcError;
use serde::{Deserialize, Serialize};
use std::io::{Read, Write};
use url::Url;

const MAX_RECORD: u64 = 16 * 1024;
const RECORD_NAME: &str = "connection.json";

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Record {
    version: u32,
    pool_id: String,
    session_id: String,
    control_plane_host: String,
    control_plane_source: String,
    computer_host: Option<String>,
}

pub(super) fn error(code: &str, message: impl std::fmt::Display) -> MxcError {
    MxcError::backend_error(format!("W365 routing: {message}"))
        .with_details(serde_json::json!({"code": code}))
}

pub(super) fn validate_url(value: &str) -> Result<Url, MxcError> {
    let url = Url::parse(value).map_err(|_| error("invalid_routing_url", "invalid service URL"))?;
    let raw_path = value
        .strip_prefix("https://")
        .and_then(|authority| authority.find('/').map(|index| &authority[index..]))
        .and_then(|path| path.split(['?', '#']).next());
    if !value.starts_with("https://")
        || !value.is_ascii()
        || value
            .bytes()
            .any(|b| b.is_ascii_control() || b.is_ascii_whitespace() || b == b'\\')
        || value
            .strip_prefix("https://")
            .and_then(|v| v.split(['/', '?', '#']).next())
            .is_some_and(|authority| authority.contains('@'))
        || url.scheme() != "https"
        || !url.username().is_empty()
        || url.password().is_some()
        || url.fragment().is_some()
        || raw_path != Some(url.path())
        || url.port_or_known_default() != Some(443)
        || !url.host_str().is_some_and(super::service::valid_host)
    {
        return Err(error(
            "invalid_routing_url",
            "service URLs require HTTPS port 443, an ASCII DNS host, and no credentials or fragment",
        ));
    }
    Ok(url)
}

pub(super) fn service_host(host: &str, service: &str, pool: Option<&str>) -> bool {
    #[cfg(feature = "test-support")]
    if host == "localhost" && std::env::var_os("MXC_W365_TEST_PORT").is_some() {
        return true;
    }
    let Some(region) = [
        ".regional.cloudinferenceplatform.azure.com",
        ".regional.cloudinferenceplatform-int.azure.com",
    ]
    .iter()
    .find_map(|suffix| host.strip_suffix(suffix))
    .and_then(|prefix| prefix.strip_suffix(&format!(".{service}"))) else {
        return false;
    };
    let region = match pool {
        Some(pool) => match region.strip_prefix(&format!("{pool}.")) {
            Some(region) => region,
            None => return false,
        },
        None => region,
    };
    !region.contains('.') && super::service::valid_host(region)
}

pub(super) fn computer_host(value: &str, identity: &Identity) -> Result<String, MxcError> {
    let url = validate_url(value)?;
    let host = url
        .host_str()
        .ok_or_else(|| error("invalid_computer_url", "missing computer host"))?;
    if !service_host(host, "remotinginterface", Some(&identity.pool_id))
        || url.path() != format!("/computers/{}", identity.session_id)
        || url.query() != Some("api-version=1.0")
    {
        return Err(error(
            "invalid_computer_url",
            "computerUrl must identify this session's supported RemotingInterface computer resource",
        ));
    }
    Ok(host.to_owned())
}

fn validate_record(record: &Record, identity: &Identity) -> Result<(), MxcError> {
    if record.version != 1
        || record.pool_id != identity.pool_id
        || record.session_id != identity.session_id
        || !super::service::valid_host(&record.control_plane_host)
        || !matches!(
            record.control_plane_source.as_str(),
            "graph" | "environment"
        )
        || record
            .computer_host
            .as_deref()
            .is_some_and(|host| !service_host(host, "remotinginterface", Some(&identity.pool_id)))
    {
        return Err(error(
            "invalid_routing_record",
            "record version, identity or destination is invalid; no environment fallback is allowed",
        ));
    }
    Ok(())
}

fn read(directory: &storage::Directory, identity: &Identity) -> Result<Option<Record>, MxcError> {
    let Some(file) = directory.read(RECORD_NAME)? else {
        return Ok(None);
    };
    let mut bytes = Vec::new();
    file.take(MAX_RECORD + 1)
        .read_to_end(&mut bytes)
        .map_err(|e| error("routing_state_read", e))?;
    if bytes.len() as u64 > MAX_RECORD {
        return Err(error("invalid_routing_record", "record is too large"));
    }
    let record = serde_json::from_slice(&bytes)
        .map_err(|_| error("invalid_routing_record", "record is not valid routing JSON"))?;
    validate_record(&record, identity)?;
    Ok(Some(record))
}

pub(super) fn preflight() -> Result<(), MxcError> {
    let directory = storage::Directory::root()?;
    let name = format!("preflight.{}.tmp", uuid::Uuid::new_v4());
    let result = (|| {
        let file = directory.create(&name)?;
        file.sync_all().map_err(|e| error("routing_state_write", e))
    })();
    let cleanup = directory.remove(&name);
    match (result, cleanup) {
        (Err(mut primary), Err(cleanup)) => {
            primary
                .message
                .push_str(&format!("; preflight cleanup failed: {}", cleanup.message));
            Err(primary)
        }
        (Err(error), _) | (_, Err(error)) => Err(error),
        (Ok(()), Ok(())) => Ok(()),
    }
}

pub(super) fn save(
    identity: &Identity,
    control_plane_host: &str,
    source: &str,
    computer_host: Option<String>,
) -> Result<(), MxcError> {
    let record = Record {
        version: 1,
        pool_id: identity.pool_id.clone(),
        session_id: identity.session_id.clone(),
        control_plane_host: control_plane_host.to_owned(),
        control_plane_source: source.to_owned(),
        computer_host,
    };
    validate_record(&record, identity)?;
    let directory = storage::Directory::session(identity)?;
    let _lock = directory.lock()?;
    if let Some(previous) = read(&directory, identity)? {
        if previous.control_plane_host != record.control_plane_host
            || (previous.computer_host.is_some()
                && record.computer_host.is_some()
                && previous.computer_host != record.computer_host)
        {
            return Err(error(
                "routing_state_conflict",
                "an existing record names different destinations",
            ));
        }
        if previous.computer_host.is_some() || record.computer_host.is_none() {
            return Ok(());
        }
    }
    let bytes = serde_json::to_vec(&record).map_err(|e| error("routing_state_write", e))?;
    let name = format!("connection.{}.tmp", uuid::Uuid::new_v4());
    let result = (|| {
        let mut file = directory.create(&name)?;
        file.write_all(&bytes)
            .and_then(|_| file.sync_all())
            .map_err(|e| error("routing_state_write", e))?;
        drop(file);
        #[cfg(feature = "test-support")]
        if std::env::var("MXC_W365_TEST_STATE_WRITE_FAIL").as_deref() == Ok("1") {
            return Err(error(
                "routing_state_write",
                "fixture atomic publication failure",
            ));
        }
        directory.publish(&name, RECORD_NAME)
    })();
    result.map_err(|mut primary| {
        if let Err(cleanup) = directory.remove(&name) {
            primary.message.push_str(&format!(
                "; temporary record cleanup failed: {}",
                cleanup.message
            ));
        }
        primary
    })
}

pub(super) fn client(identity: &Identity, data_plane: bool) -> Result<Client, MxcError> {
    let directory = storage::Directory::session(identity)?;
    let _lock = directory.lock()?;
    let record = read(&directory, identity)?.ok_or_else(|| {
        error(
            "routing_state_missing",
            "no local connection record for this ID; legacy/cross-machine recovery requires service-operator assistance",
        )
    })?;
    let (host, token) = if data_plane {
        (
            record.computer_host.ok_or_else(|| {
                error(
                    "routing_state_incomplete",
                    "checkout did not supply usable computerUrl; retain the ID for explicit release",
                )
            })?,
            "W365A_DP_TOKEN",
        )
    } else {
        (record.control_plane_host, "W365A_CP_TOKEN")
    };
    Client::for_host(host, token)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn graph_control_plane_does_not_require_a_service_host_pattern() {
        let identity = Identity {
            pool_id: "11111111-1111-1111-1111-111111111111".to_owned(),
            session_id: "22222222-2222-2222-2222-222222222222".to_owned(),
        };
        let mut record = Record {
            version: 1,
            pool_id: identity.pool_id.clone(),
            session_id: identity.session_id.clone(),
            control_plane_host: "control.example.test".to_owned(),
            control_plane_source: "graph".to_owned(),
            computer_host: None,
        };
        assert!(validate_record(&record, &identity).is_ok());
        record.computer_host = Some("control.example.test".to_owned());
        assert!(validate_record(&record, &identity).is_err());
    }
}
