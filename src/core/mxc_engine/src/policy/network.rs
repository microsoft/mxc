// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Network policy authoring types and wire-format helpers.

/// Network proxy configuration.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub enum ProxySpec {
    /// Built-in test proxy mode used by executor test flows.
    ///
    /// The in-process Rust SDK cannot enable testing features, so
    /// [`build_request`](super::build_request) and
    /// [`build_request_with_containment`](super::build_request_with_containment)
    /// reject this variant. Use [`Localhost`](Self::Localhost) or
    /// [`Url`](Self::Url) instead.
    BuiltinTestServer,
    /// Route through `127.0.0.1:<port>`.
    Localhost(u16),
    /// Route through an explicit proxy URL.
    Url(String),
}

impl<'de> serde::Deserialize<'de> for ProxySpec {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        #[derive(serde::Deserialize)]
        #[serde(rename_all = "camelCase", deny_unknown_fields)]
        struct Raw {
            #[serde(default)]
            builtin_test_server: Option<bool>,
            #[serde(default)]
            localhost: Option<u16>,
            #[serde(default)]
            url: Option<String>,
        }

        let raw = <Raw as serde::Deserialize>::deserialize(deserializer)?;
        match (raw.builtin_test_server, raw.localhost, raw.url) {
            (Some(true), None, None) => Ok(ProxySpec::BuiltinTestServer),
            (Some(false), None, None) => Err(serde::de::Error::custom(
                "network.proxy.builtinTestServer must be true; omit the proxy to disable it",
            )),
            (None, Some(port), None) => Ok(ProxySpec::Localhost(port)),
            (None, None, Some(url)) => Ok(ProxySpec::Url(url)),
            _ => Err(serde::de::Error::custom(
                "network.proxy must set exactly one of builtinTestServer, localhost, or url",
            )),
        }
    }
}

/// Network section of a [`SandboxPolicy`](super::SandboxPolicy).
///
/// The legacy fields preserve schema 0.6 and 0.7 authoring. The directional
/// fields model schema 0.8. Legacy fields cannot be combined with either these
/// fields or ProcessContainer directional network settings.
#[derive(Debug, Clone, Default, serde::Deserialize)]
#[serde(rename_all = "camelCase", default)]
#[non_exhaustive]
pub struct NetworkSection {
    pub allow_outbound: bool,
    pub allow_local_network: bool,
    pub allowed_hosts: Vec<String>,
    pub blocked_hosts: Vec<String>,
    pub proxy: Option<ProxySpec>,
    /// Schema 0.8 outbound network policy.
    pub egress: Option<NetworkEgressSection>,
    /// Schema 0.8 inbound and host-loopback network policy.
    pub ingress: Option<NetworkIngressSection>,
    /// Schema 0.8 runtime values supplied separately from sandbox policy.
    pub runtime_config: Option<RuntimeConfigSection>,
}

impl NetworkSection {
    pub(super) fn has_directional_fields(&self) -> bool {
        self.egress.is_some() || self.ingress.is_some() || self.runtime_config.is_some()
    }

    pub(super) fn has_legacy_fields(&self) -> bool {
        self.allow_outbound
            || self.allow_local_network
            || !self.allowed_hosts.is_empty()
            || !self.blocked_hosts.is_empty()
            || self.proxy.is_some()
    }
}

/// Wire network format selected for one authored request.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum NetworkFormat {
    Legacy,
    Directional,
}

pub(crate) fn supports_schema_v0_8(version: &str) -> bool {
    version
        .split_once('.')
        .and_then(|(major, rest)| {
            let minor = rest.split_once('.').map_or(rest, |(minor, _)| minor);
            Some((major.parse::<u64>().ok()?, minor.parse::<u64>().ok()?))
        })
        .is_some_and(|(major, minor)| major > 0 || minor >= 8)
}

/// Selects one wire format before backend-specific fields are applied.
pub(super) fn select_network_format(
    version: &str,
    network: Option<&NetworkSection>,
    has_process_container_network: bool,
) -> Result<NetworkFormat, wxc_common::mxc_error::MxcError> {
    let has_legacy = network.is_some_and(NetworkSection::has_legacy_fields);
    let has_directional = has_process_container_network
        || network.is_some_and(NetworkSection::has_directional_fields);
    let supports_directional = supports_schema_v0_8(version);

    if has_legacy && has_directional {
        return Err(wxc_common::mxc_error::MxcError::malformed_request(
            "legacy network fields cannot be combined with network egress/ingress/runtimeConfig or processContainer.network",
        ));
    }

    if has_directional && !supports_directional {
        return Err(wxc_common::mxc_error::MxcError::malformed_request(
            "network egress/ingress/runtimeConfig and processContainer.network require schema version 0.8 or later",
        ));
    }

    if has_directional {
        Ok(NetworkFormat::Directional)
    } else {
        Ok(NetworkFormat::Legacy)
    }
}

/// Allow or deny a network action.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "lowercase")]
#[non_exhaustive]
pub enum NetworkAction {
    Allow,
    Deny,
}

/// Transport protocol selector.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "lowercase")]
#[non_exhaustive]
pub enum NetworkProtocol {
    Tcp,
    Udp,
    Icmp,
    Any,
}

/// CIDR network peer.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
#[non_exhaustive]
pub struct NetworkPeerSection {
    pub cidr: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub except: Option<Vec<String>>,
}

impl NetworkPeerSection {
    /// Creates a peer matching `cidr` with no exclusions.
    pub fn new(cidr: impl Into<String>) -> Self {
        Self {
            cidr: cidr.into(),
            except: None,
        }
    }
}

/// Protocol and destination-port selector.
#[derive(Debug, Clone, Default, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
#[non_exhaustive]
pub struct NetworkPortSection {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub protocol: Option<NetworkProtocol>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub port: Option<u16>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub end_port: Option<u16>,
}

/// Outbound network rule.
#[derive(Debug, Clone, Default, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
#[non_exhaustive]
pub struct NetworkRuleSection {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub to: Option<Vec<NetworkPeerSection>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ports: Option<Vec<NetworkPortSection>>,
}

/// Schema 0.8 outbound network policy.
#[derive(Debug, Clone, Default, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
#[non_exhaustive]
pub struct NetworkEgressSection {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub default: Option<NetworkAction>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub allow: Option<Vec<NetworkRuleSection>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub deny: Option<Vec<NetworkRuleSection>>,
}

/// Schema 0.8 inbound and host-loopback network policy.
#[derive(Debug, Clone, Default, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
#[non_exhaustive]
pub struct NetworkIngressSection {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub default: Option<NetworkAction>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub host_loopback: Option<NetworkAction>,
}

/// Schema 0.8 runtime values supplied separately from sandbox policy.
#[derive(Debug, Clone, Default, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
#[non_exhaustive]
pub struct RuntimeConfigSection {
    /// HTTP/S loopback proxy URL.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub network_proxy: Option<String>,
}

pub(super) fn proxy_to_wire(proxy: &ProxySpec) -> serde_json::Value {
    use serde_json::json;
    match proxy {
        ProxySpec::BuiltinTestServer => json!({ "builtinTestServer": true }),
        ProxySpec::Localhost(port) => json!({ "localhost": port }),
        ProxySpec::Url(url) => json!({ "url": url }),
    }
}

/// True when the network section carries any host allow/deny rules.
pub(crate) fn has_host_rules(network: &serde_json::Value) -> bool {
    let non_empty = |key: &str| {
        network
            .get(key)
            .and_then(serde_json::Value::as_array)
            .is_some_and(|values| !values.is_empty())
    };
    non_empty("allowedHosts") || non_empty("blockedHosts")
}

#[cfg(test)]
mod tests {
    use super::{
        proxy_to_wire, select_network_format, NetworkEgressSection, NetworkFormat,
        NetworkPeerSection, NetworkPortSection, NetworkRuleSection, NetworkSection, ProxySpec,
    };

    #[test]
    fn format_selection_defaults_to_legacy_without_directional_intent() {
        assert_eq!(
            select_network_format("0.8.0-alpha", None, false)
                .expect("an absent network policy should retain legacy authoring defaults"),
            NetworkFormat::Legacy
        );
        assert_eq!(
            select_network_format("0.7.0-alpha", None, false)
                .expect("schema 0.7 should select legacy defaults"),
            NetworkFormat::Legacy
        );
    }

    #[test]
    fn directional_fields_require_schema_0_8() {
        let error = select_network_format(
            "0.7.0-alpha",
            Some(&NetworkSection {
                egress: Some(Default::default()),
                ..Default::default()
            }),
            false,
        )
        .expect_err("directional fields must be rejected before schema 0.8");

        assert!(error.message.contains("require schema version 0.8"));
    }

    #[test]
    fn builtin_test_server_true_is_accepted() {
        let proxy = serde_json::from_str::<ProxySpec>(r#"{ "builtinTestServer": true }"#)
            .expect("builtinTestServer");

        assert!(matches!(proxy, ProxySpec::BuiltinTestServer));
        assert_eq!(
            proxy_to_wire(&proxy),
            serde_json::json!({ "builtinTestServer": true })
        );
    }

    #[test]
    fn builtin_test_server_false_is_rejected() {
        let error = serde_json::from_str::<ProxySpec>(r#"{ "builtinTestServer": false }"#)
            .expect_err("builtinTestServer false must fail closed");

        assert!(error.to_string().contains("must be true"));
    }

    #[test]
    fn conflicting_proxy_modes_are_rejected() {
        for json in [
            r#"{ "builtinTestServer": true, "localhost": 8080 }"#,
            r#"{ "builtinTestServer": true, "url": "http://proxy" }"#,
            r#"{ "localhost": 8080, "url": "http://proxy" }"#,
        ] {
            let error = serde_json::from_str::<ProxySpec>(json)
                .expect_err("conflicting proxy modes must be rejected");

            assert!(error.to_string().contains("exactly one"));
        }
    }

    #[test]
    fn localhost_and_url_proxy_modes_parse() {
        assert!(matches!(
            serde_json::from_str::<ProxySpec>(r#"{ "localhost": 8080 }"#).expect("localhost"),
            ProxySpec::Localhost(8080)
        ));
        assert!(matches!(
            serde_json::from_str::<ProxySpec>(r#"{ "url": "http://proxy" }"#).expect("url"),
            ProxySpec::Url(_)
        ));
    }

    #[test]
    fn directional_serialization_omits_absent_optional_fields() {
        let egress = NetworkEgressSection {
            allow: Some(vec![NetworkRuleSection {
                to: Some(vec![NetworkPeerSection::new("192.0.2.0/24")]),
                ports: Some(vec![NetworkPortSection::default()]),
            }]),
            ..Default::default()
        };

        let value = serde_json::to_value(egress).expect("directional policy serializes");

        fn assert_no_null(value: &serde_json::Value) {
            match value {
                serde_json::Value::Array(values) => {
                    values.iter().for_each(assert_no_null);
                }
                serde_json::Value::Object(fields) => {
                    assert!(
                        fields.values().all(|value| !value.is_null()),
                        "optional fields must be omitted rather than null: {value}"
                    );
                    fields.values().for_each(assert_no_null);
                }
                _ => {}
            }
        }

        assert_no_null(&value);
        assert!(value.get("default").is_none());
        assert!(value["allow"][0]["to"][0].get("except").is_none());
        assert!(value["allow"][0]["ports"][0].get("protocol").is_none());
    }
}
