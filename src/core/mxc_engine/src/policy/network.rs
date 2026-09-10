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
/// Legacy fields preserve schema 0.6, 0.7 and 0.8 authoring. Schema 0.9 accepts
/// only directional fields and runtime configuration; legacy authoring returns
/// a migration error rather than silently discarding policy. Default-constructed
/// false/empty legacy members carry no authored intent. Deserialized legacy
/// properties retain presence, including false, empty arrays and a null proxy.
#[derive(Debug, Clone, Default)]
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
    pub(crate) legacy_fields_specified: bool,
}

impl<'de> serde::Deserialize<'de> for NetworkSection {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        #[derive(serde::Deserialize)]
        #[serde(field_identifier, rename_all = "camelCase")]
        enum Field {
            AllowOutbound,
            AllowLocalNetwork,
            AllowedHosts,
            BlockedHosts,
            Proxy,
            Egress,
            Ingress,
            RuntimeConfig,
            DefaultPolicy,
            EnforcementMode,
            #[serde(other)]
            Ignore,
        }

        struct NetworkVisitor;

        impl<'de> serde::de::Visitor<'de> for NetworkVisitor {
            type Value = NetworkSection;

            fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                formatter.write_str("struct NetworkSection")
            }

            fn visit_map<A>(self, mut map: A) -> Result<Self::Value, A::Error>
            where
                A: serde::de::MapAccess<'de>,
            {
                let mut result = NetworkSection::default();
                let mut seen = 0u8;
                macro_rules! read_field {
                    ($field:ident, $name:literal, $index:literal) => {{
                        let bit = 1 << $index;
                        if seen & bit != 0 {
                            return Err(serde::de::Error::duplicate_field($name));
                        }
                        seen |= bit;
                        result.$field = map.next_value()?;
                    }};
                }
                while let Some(field) = map.next_key::<Field>()? {
                    match field {
                        Field::AllowOutbound => read_field!(allow_outbound, "allowOutbound", 0),
                        Field::AllowLocalNetwork => {
                            read_field!(allow_local_network, "allowLocalNetwork", 1)
                        }
                        Field::AllowedHosts => read_field!(allowed_hosts, "allowedHosts", 2),
                        Field::BlockedHosts => read_field!(blocked_hosts, "blockedHosts", 3),
                        Field::Proxy => read_field!(proxy, "proxy", 4),
                        Field::Egress => read_field!(egress, "egress", 5),
                        Field::Ingress => read_field!(ingress, "ingress", 6),
                        Field::RuntimeConfig => read_field!(runtime_config, "runtimeConfig", 7),
                        Field::DefaultPolicy | Field::EnforcementMode => {
                            // These wire-only names were ignored by the SDK authoring
                            // model, including repeated occurrences. Preserve that
                            // deserialization behavior; the v0.9 builder rejects presence.
                            result.legacy_fields_specified = true;
                            map.next_value::<serde::de::IgnoredAny>()?;
                        }
                        Field::Ignore => {
                            map.next_value::<serde::de::IgnoredAny>()?;
                        }
                    }
                }
                result.legacy_fields_specified |= seen & 0b0001_1111 != 0;
                Ok(result)
            }

            fn visit_seq<A>(self, mut sequence: A) -> Result<Self::Value, A::Error>
            where
                A: serde::de::SeqAccess<'de>,
            {
                // Keep the original eight authoring-field positions. Presence
                // metadata and wire-only migration names are not sequence fields.
                let allow_outbound = sequence.next_element::<bool>()?;
                let allow_local_network = sequence.next_element::<bool>()?;
                let allowed_hosts = sequence.next_element::<Vec<String>>()?;
                let blocked_hosts = sequence.next_element::<Vec<String>>()?;
                let proxy = sequence.next_element::<Option<ProxySpec>>()?;
                let egress = sequence.next_element::<Option<NetworkEgressSection>>()?;
                let ingress = sequence.next_element::<Option<NetworkIngressSection>>()?;
                let runtime_config = sequence.next_element::<Option<RuntimeConfigSection>>()?;
                let legacy_fields_specified = allow_outbound.is_some()
                    || allow_local_network.is_some()
                    || allowed_hosts.is_some()
                    || blocked_hosts.is_some()
                    || proxy.is_some();
                Ok(NetworkSection {
                    allow_outbound: allow_outbound.unwrap_or_default(),
                    allow_local_network: allow_local_network.unwrap_or_default(),
                    allowed_hosts: allowed_hosts.unwrap_or_default(),
                    blocked_hosts: blocked_hosts.unwrap_or_default(),
                    proxy: proxy.flatten(),
                    egress: egress.flatten(),
                    ingress: ingress.flatten(),
                    runtime_config: runtime_config.flatten(),
                    legacy_fields_specified,
                })
            }
        }

        deserializer.deserialize_struct(
            "NetworkSection",
            &[
                "allowOutbound",
                "allowLocalNetwork",
                "allowedHosts",
                "blockedHosts",
                "proxy",
                "egress",
                "ingress",
                "runtimeConfig",
            ],
            NetworkVisitor,
        )
    }
}

impl NetworkSection {
    pub(super) fn has_directional_fields(&self) -> bool {
        self.egress.is_some()
            || self.ingress.is_some()
            || self
                .runtime_config
                .as_ref()
                .is_some_and(|runtime| runtime.network_proxy.is_some())
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

/// Selects one wire format before backend-specific fields are applied.
pub(super) fn select_network_format(
    version: &str,
    network: Option<&NetworkSection>,
    has_process_container_network: bool,
) -> Result<NetworkFormat, wxc_common::mxc_error::MxcError> {
    let has_legacy = network.is_some_and(NetworkSection::has_legacy_fields);
    if version == "0.9.0-alpha" {
        if has_legacy || network.is_some_and(|network| network.legacy_fields_specified) {
            return Err(wxc_common::mxc_error::MxcError::malformed_request(
                "schema 0.9.0-alpha no longer accepts legacy network authoring \
                 (defaultPolicy, enforcementMode, allowOutbound, allowLocalNetwork, \
                 allowedHosts, blockedHosts, proxy); \
                 use network.egress, network.ingress, and network.runtimeConfig.networkProxy, \
                 or select published version 0.8.0-alpha to retain legacy policy semantics",
            ));
        }
        return Ok(NetworkFormat::Directional);
    }

    select_compatible_network_format(version, network, has_process_container_network)
}

/// Retained Phase 11 characterization oracle, never used by production builders.
#[cfg(test)]
pub(super) fn select_rolling_network_format(
    version: &str,
    network: Option<&NetworkSection>,
    has_process_container_network: bool,
) -> Result<NetworkFormat, wxc_common::mxc_error::MxcError> {
    select_compatible_network_format(version, network, has_process_container_network)
}

fn select_compatible_network_format(
    version: &str,
    network: Option<&NetworkSection>,
    has_process_container_network: bool,
) -> Result<NetworkFormat, wxc_common::mxc_error::MxcError> {
    let has_legacy = network.is_some_and(NetworkSection::has_legacy_fields);
    let has_directional = has_process_container_network
        || network.is_some_and(NetworkSection::has_directional_fields);
    let supports_directional = wxc_common::directional_network_support(version);

    if has_legacy && has_directional {
        return Err(wxc_common::mxc_error::MxcError::malformed_request(
            "legacy network fields cannot be combined with network egress/ingress/runtimeConfig or processContainer.network",
        ));
    }

    if has_directional && supports_directional == Some(false) {
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
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "lowercase")]
#[non_exhaustive]
pub enum NetworkAction {
    Allow,
    #[default]
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
    /// HTTP/S proxy URL. Host-process backends require localhost; WSLc requires
    /// a container-routable endpoint and does not filter egress through it.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub network_proxy: Option<String>,
}

#[cfg(test)]
pub(super) fn proxy_to_wire(proxy: &ProxySpec) -> serde_json::Value {
    use serde_json::json;
    match proxy {
        ProxySpec::BuiltinTestServer => json!({ "builtinTestServer": true }),
        ProxySpec::Localhost(port) => json!({ "localhost": port }),
        ProxySpec::Url(url) => json!({ "url": url }),
    }
}

/// True when the network section carries any host allow/deny rules.
#[cfg(test)]
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
        proxy_to_wire, select_network_format, NetworkAction, NetworkEgressSection, NetworkFormat,
        NetworkPeerSection, NetworkPortSection, NetworkRuleSection, NetworkSection, ProxySpec,
        RuntimeConfigSection,
    };

    #[test]
    fn network_action_defaults_to_deny() {
        assert_eq!(NetworkAction::default(), NetworkAction::Deny);
    }

    #[test]
    fn development_rejects_every_legacy_authoring_field_including_neutral_values() {
        for field in [
            r#""defaultPolicy":"allow""#,
            r#""enforcementMode":"capabilities""#,
            r#""allowOutbound":false"#,
            r#""allowOutbound":true"#,
            r#""allowLocalNetwork":false"#,
            r#""allowLocalNetwork":true"#,
            r#""allowedHosts":[]"#,
            r#""blockedHosts":[]"#,
            r#""proxy":null"#,
            r#""proxy":{"url":"http://localhost:8080"}"#,
        ] {
            let network: NetworkSection = serde_json::from_str(&format!("{{{field}}}")).unwrap();
            let error = select_network_format("0.9.0-alpha", Some(&network), false).unwrap_err();
            assert!(
                error
                    .message
                    .contains("schema 0.9.0-alpha no longer accepts legacy"),
                "{field}"
            );
            assert_eq!(
                select_network_format("0.8.0-alpha", Some(&network), false).unwrap(),
                NetworkFormat::Legacy,
                "published authoring remains unchanged: {field}"
            );
        }
        assert_eq!(
            select_network_format("0.9.0-alpha", None, false).unwrap(),
            NetworkFormat::Directional
        );
        assert_eq!(
            select_network_format("0.9.0-alpha", Some(&NetworkSection::default()), false).unwrap(),
            NetworkFormat::Directional
        );
    }

    #[test]
    fn authoring_deserialization_preserves_the_original_json_semantics() {
        #[derive(Default, serde::Deserialize)]
        #[serde(rename = "NetworkSection", rename_all = "camelCase", default)]
        struct FrozenNetworkSection {
            allow_outbound: bool,
            allow_local_network: bool,
            allowed_hosts: Vec<String>,
            blocked_hosts: Vec<String>,
            proxy: Option<ProxySpec>,
            egress: Option<NetworkEgressSection>,
            ingress: Option<super::NetworkIngressSection>,
            runtime_config: Option<RuntimeConfigSection>,
        }

        for source in [
            "{}",
            "[]",
            "[true]",
            r#"[false,true,["example.com"],[]]"#,
            r#"[false,false,[],[],null,{"default":"allow"},{"default":"allow","hostLoopback":"allow"},{"networkProxy":"http://localhost:8080"}]"#,
            r#"{"allowOutbound":false,"allowLocalNetwork":false,"allowedHosts":[],"blockedHosts":[],"proxy":null,"egress":{"default":"deny"}}"#,
            r#"{"defaultPolicy":false,"defaultPolicy":[],"enforcementMode":null,"enforcementMode":{}}"#,
            r#"{"unrecognized":{"nested":[null,true,42]},"defaultPolicy":1e999}"#,
            r#"{"allowOutbound":null}"#,
            r#"{"allowLocalNetwork":null}"#,
            r#"{"allowedHosts":null}"#,
            r#"{"blockedHosts":null}"#,
            r#"{"allowOutbound":false,"allowOutbound":true}"#,
            r#"{"proxy":null,"proxy":null}"#,
            "[null]",
            "[false,false,[],[],null,null,null,null,42]",
        ] {
            let original = serde_json::from_str::<FrozenNetworkSection>(source);
            let current = serde_json::from_str::<NetworkSection>(source);
            match (original, current) {
                (Ok(original), Ok(current)) => {
                    assert_eq!(current.allow_outbound, original.allow_outbound, "{source}");
                    assert_eq!(
                        current.allow_local_network, original.allow_local_network,
                        "{source}"
                    );
                    assert_eq!(current.allowed_hosts, original.allowed_hosts, "{source}");
                    assert_eq!(current.blocked_hosts, original.blocked_hosts, "{source}");
                    assert_eq!(
                        current.proxy.as_ref().map(proxy_to_wire),
                        original.proxy.as_ref().map(proxy_to_wire),
                        "{source}"
                    );
                    assert_eq!(current.egress, original.egress, "{source}");
                    assert_eq!(current.ingress, original.ingress, "{source}");
                    assert_eq!(current.runtime_config, original.runtime_config, "{source}");
                }
                (Err(original), Err(current)) => {
                    assert_eq!(current.to_string(), original.to_string(), "{source}");
                }
                _ => panic!("authoring acceptance changed: {source}"),
            }
        }
    }

    #[test]
    fn old_version_neutral_defaults_with_directionals_remain_accepted() {
        let source = r#"{"allowOutbound":false,"allowLocalNetwork":false,"allowedHosts":[],"blockedHosts":[],"proxy":null,"egress":{"default":"deny"},"ingress":{"default":"deny","hostLoopback":"deny"}}"#;
        let network: NetworkSection = serde_json::from_str(source).unwrap();
        assert!(network.legacy_fields_specified);
        assert_eq!(
            select_network_format("0.8.0-alpha", Some(&network), false).unwrap(),
            NetworkFormat::Directional
        );
        assert!(select_network_format("0.9.0-alpha", Some(&network), false).is_err());

        for source in [
            "[false,false,[],[],null]",
            r#"{"defaultPolicy":null,"defaultPolicy":false}"#,
            r#"{"enforcementMode":[],"enforcementMode":null}"#,
        ] {
            let network: NetworkSection = serde_json::from_str(source).unwrap();
            assert!(network.legacy_fields_specified, "{source}");
            assert!(
                select_network_format("0.8.0-alpha", Some(&network), false).is_ok(),
                "{source}"
            );
            assert!(
                select_network_format("0.9.0-alpha", Some(&network), false).is_err(),
                "{source}"
            );
        }
    }

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
    fn empty_runtime_config_does_not_conflict_with_legacy_fields() {
        let format = select_network_format(
            "0.8.0-alpha",
            Some(&NetworkSection {
                allow_outbound: true,
                runtime_config: Some(RuntimeConfigSection::default()),
                ..Default::default()
            }),
            false,
        )
        .expect("an empty runtime config does not select directional networking");

        assert_eq!(format, NetworkFormat::Legacy);
    }

    #[test]
    fn malformed_version_is_deferred_to_the_schema_parser() {
        let format = select_network_format(
            "0.8x",
            Some(&NetworkSection {
                egress: Some(NetworkEgressSection::default()),
                ..Default::default()
            }),
            false,
        )
        .expect("network selection should not replace malformed-version diagnostics");

        assert_eq!(format, NetworkFormat::Directional);
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
