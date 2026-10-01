// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Caller-owned revisions expressed in MXC request terms, not native capabilities.

use crate::mxc_common::models::{CaptureDenialsMode, ContainerPolicy, NetworkAction};
use crate::process_container_common::network_policy_helpers::{
    capture_requests_internet_capability, network_policy_owns_capability,
};

use super::{PolicyDetail, ACTIONABLE, KNOWN_FLAGS, RESOURCE_COMPLETE, RESOURCE_UNAVAILABLE};

pub(super) fn request_guidance(
    detail: &PolicyDetail,
    resource: Option<&str>,
    policy: &ContainerPolicy,
    capture_network_decisions: bool,
) -> Option<String> {
    if detail.flags & ACTIONABLE == 0 || detail.flags & !KNOWN_FLAGS != 0 {
        return None;
    }
    match (
        detail.failure_class.0,
        detail.failure_reason.0,
        detail.required_action.0,
        detail.resource_kind.0,
        detail.value_kind.0,
    ) {
        (1..=3, 1, 1, 2, 0) if detail.requested_value == 0 && detail.required_value == 0 => {
            if detail.flags & RESOURCE_COMPLETE == 0 || detail.flags & RESOURCE_UNAVAILABLE != 0 {
                return None;
            }
            capability_guidance(resource?, policy, capture_network_decisions)
        }
        (2, 2 | 3, 2, 1, 1)
            if detail.requested_value <= 2
                && detail.required_value < detail.requested_value
                && (detail.failure_reason.0 != 3 || detail.required_value == 0) =>
        {
            if detail.flags & RESOURCE_COMPLETE == 0
                || detail.flags & RESOURCE_UNAVAILABLE != 0
                || !is_absolute_windows_path(resource?)
            {
                return None;
            }
            let requested_field = if detail.requested_value == 2 {
                "filesystem.readwritePaths"
            } else {
                "filesystem.readonlyPaths"
            };
            let mut guidance = format!(
                "MXC request: review {requested_field} grants that cover this resource, \
                 including ancestor grants and aliases. "
            );
            match detail.required_value {
                0 => guidance.push_str(
                    "Remove or narrow the covering grants, or add this resource to \
                     filesystem.deniedPaths and remove/narrow any more-specific grants \
                     that reopen it. ",
                ),
                1 => guidance.push_str(
                    "Move the relevant read-write grant to filesystem.readonlyPaths, \
                     narrow it, or add a read-only exception for this resource and \
                     remove/narrow more-specific read-write grants. ",
                ),
                _ => return None,
            }
            guidance.push_str(
                "Keep existing deny/read-only exceptions: removing one beneath a writable \
                 ancestor can increase access. The resource is a comparison witness, not \
                 the complete policy ceiling or a pinned object. Do not use a resource \
                 marked truncated below as a configuration path.",
            );
            Some(guidance)
        }
        (2, 4, 3, 0, 2)
            if detail.requested_value > detail.required_value
                && detail.flags & (RESOURCE_COMPLETE | RESOURCE_UNAVAILABLE) == 0
                && detail.resource.is_none() =>
        {
            Some(format!(
                "MXC request: reduce the total number of entries in filesystem.readwritePaths, \
                 filesystem.readonlyPaths and filesystem.deniedPaths from {} to at most {}. \
                 processContainer.filesystem.enumeratePaths is not part of this native count. \
                 Remove unnecessary grants rather than combining them into broader grants \
                 or dropping deny/read-only exceptions.",
                detail.requested_value, detail.required_value,
            ))
        }
        _ => None,
    }
}

fn capability_guidance(
    capability: &str,
    policy: &ContainerPolicy,
    capture_network_decisions: bool,
) -> Option<String> {
    let explicit = policy.capabilities.iter().any(|entry| {
        !network_policy_owns_capability(policy, entry)
            && entry
                .trim_matches([' ', '\t'])
                .eq_ignore_ascii_case(capability)
    });
    let mut sources = Vec::new();
    let mut changes = Vec::new();
    if capability.eq_ignore_ascii_case("internetClient") {
        if capture_requests_internet_capability(policy, capture_network_decisions) {
            sources.push("processContainer.captureDenials (network-decision capture)");
            changes.push(
                "omit processContainer.captureDenials; recording network decisions requires \
                 this capability even with network.egress.default='deny' and mode='block'",
            );
        }
        if let Some(egress) = &policy.network_egress {
            if egress.default == NetworkAction::Allow {
                sources.push("network.egress.default='allow'");
                changes.push("set network.egress.default='deny'");
            }
            if !egress.allow.is_empty() {
                sources.push("network.egress.allow");
                changes.push("remove the network.egress.allow rules that enable egress");
            }
        }
    } else if capability.eq_ignore_ascii_case("privateNetworkClientServer") {
        if policy
            .network_ingress
            .as_ref()
            .is_some_and(|ingress| ingress.default == NetworkAction::Allow)
        {
            sources.push("network.ingress.default='allow'");
            changes.push("set network.ingress.default='deny'");
        }
        if policy.network_proxy.is_enabled() {
            changes.push(
                "omit runtimeConfig.networkProxy and processContainer.network.allowedProxyPeer \
                 when disabling private-network access; a ProcessContainer proxy requires \
                 network.ingress.default='allow'",
            );
        }
    } else if capability.eq_ignore_ascii_case("networkLoopback") {
        if policy
            .network_ingress
            .as_ref()
            .is_some_and(|ingress| ingress.host_loopback == NetworkAction::Allow)
        {
            sources.push("network.ingress.hostLoopback='allow'");
            changes.push("set network.ingress.hostLoopback='deny'");
            if policy.network_proxy.is_enabled() && policy.allowed_proxy_peer.is_none() {
                changes.push(
                    "also omit runtimeConfig.networkProxy, or use a supported identity-scoped \
                     proxy via processContainer.network.allowedProxyPeer; an identity-less \
                     host proxy requires hostLoopback='allow'",
                );
            }
        }
    } else if capability.eq_ignore_ascii_case("permissiveLearningMode") {
        if policy
            .capture_denials
            .as_ref()
            .is_some_and(|capture| capture.mode == CaptureDenialsMode::Allow)
        {
            return Some(
                "MXC request: processContainer.captureDenials.mode='allow' requests permissive \
                 access. Set its mode to 'block' to retain denial capture without this \
                 capability, or omit processContainer.captureDenials. Disable --audit or \
                 the SDK audit option as well if used; reserved learning-mode capabilities \
                 cannot be removed through processContainer.capabilities."
                    .into(),
            );
        }
        return explicit.then(|| {
            "MXC request: permissive learning/audit behavior is enabled in the effective \
             request. Disable --audit or the SDK audit option; use deny-and-record mode \
             if diagnostics are still needed. The normalized request does not retain \
             which audit entry point supplied this capability, and reserved learning-mode \
             capabilities cannot be removed through processContainer.capabilities."
                .into()
        });
    } else if capability.eq_ignore_ascii_case("learningModeLogging") {
        return explicit.then(|| {
            "MXC request: deny-and-record behavior supplies this reserved capability. \
             Review processContainer.learningMode, processContainer.captureDenials and \
             diagnostic-console settings rather than processContainer.capabilities. \
             The normalized request does not identify which of those entry points enabled it."
                .into()
        });
    }
    if explicit {
        sources.push("processContainer.capabilities");
        changes.push("remove the matching entry from processContainer.capabilities");
    }
    if sources.is_empty() {
        return None;
    }
    Some(format!(
        "MXC request: this capability is requested by {}. To stop requesting it, {}. \
         Changing only a capability-list entry does not disable a capability synthesized \
         by another setting. Narrower egress destinations or a proxy cannot compensate \
         for a capability that IT policy forbids.",
        sources.join(" and "),
        changes.join("; "),
    ))
}

fn is_absolute_windows_path(path: &str) -> bool {
    let bytes = path.as_bytes();
    (bytes.len() >= 3 && bytes[0].is_ascii_alphabetic() && bytes[1] == b':' && bytes[2] == b'\\')
        || path.starts_with("\\??\\")
        || path.starts_with("\\\\?\\")
        || path
            .strip_prefix("\\\\")
            .and_then(|unc| unc.split_once('\\'))
            .is_some_and(|(server, share)| !server.is_empty() && !share.is_empty())
}

#[cfg(test)]
mod tests {
    use super::super::layout;
    use super::*;
    use crate::mxc_common::models::{
        CaptureDenialsConfig, NetworkEgressPolicy, NetworkIngressPolicy, NetworkRule, ProxyAddress,
        ProxyConfig,
    };

    fn capability() -> PolicyDetail {
        PolicyDetail {
            failure_class: layout::FailureClass::Network,
            failure_reason: layout::FailureReason::CapabilityNotAllowed,
            required_action: layout::RequiredAction::RemoveCapability,
            resource_kind: layout::ResourceKind::Capability,
            flags: 3,
            ..Default::default()
        }
    }

    fn guidance(resource: &str, policy: &ContainerPolicy) -> String {
        request_guidance(&capability(), Some(resource), policy, false).unwrap()
    }

    #[test]
    fn internet_capability_identifies_both_effective_egress_sources() {
        for (default, rules) in [
            (NetworkAction::Allow, false),
            (NetworkAction::Deny, true),
            (NetworkAction::Allow, true),
        ] {
            let policy = ContainerPolicy {
                capabilities: vec!["InternetClient".into()],
                network_egress: Some(NetworkEgressPolicy {
                    default,
                    allow: if rules {
                        vec![NetworkRule::default()]
                    } else {
                        vec![]
                    },
                    ..Default::default()
                }),
                ..Default::default()
            };
            let message = guidance("internetclient", &policy);
            assert_eq!(
                message.contains("network.egress.default='allow'"),
                default == NetworkAction::Allow,
            );
            assert_eq!(message.contains("network.egress.allow"), rules);
            assert!(!message.contains("remove the matching entry"));
            assert!(message.contains("synthesized"));
            assert!(message.contains("IT policy forbids"));
        }
    }

    #[test]
    fn network_capture_guidance_uses_actual_trace_sources_and_excludes_proxy_mode() {
        for mode in [CaptureDenialsMode::Block, CaptureDenialsMode::Allow] {
            let mut policy = ContainerPolicy {
                capture_denials: Some(CaptureDenialsConfig {
                    mode,
                    ..Default::default()
                }),
                network_egress: Some(NetworkEgressPolicy::default()),
                ..Default::default()
            };
            let message =
                request_guidance(&capability(), Some("internetclient"), &policy, true).unwrap();
            assert!(message.contains("processContainer.captureDenials (network-decision capture)"));
            assert!(message.contains("omit processContainer.captureDenials"));
            assert!(message.contains("even with network.egress.default='deny' and mode='block'"));
            assert!(!message.contains("network.egress.allow"));
            assert!(!message.contains("remove the matching entry"));
            assert!(
                request_guidance(&capability(), Some("internetclient"), &policy, false).is_none()
            );
            policy.network_proxy = ProxyConfig {
                address: Some(ProxyAddress::new("127.0.0.1".into(), 8080)),
            };
            assert!(
                request_guidance(&capability(), Some("internetclient"), &policy, true).is_none()
            );
        }
    }

    #[test]
    fn network_capture_and_authored_egress_sources_must_all_be_narrowed() {
        let policy = ContainerPolicy {
            capture_denials: Some(Default::default()),
            network_egress: Some(NetworkEgressPolicy {
                default: NetworkAction::Allow,
                allow: vec![NetworkRule::default()],
                ..Default::default()
            }),
            ..Default::default()
        };
        let message =
            request_guidance(&capability(), Some("internetclient"), &policy, true).unwrap();
        for source in [
            "omit processContainer.captureDenials",
            "set network.egress.default='deny'",
            "remove the network.egress.allow rules",
        ] {
            assert!(message.contains(source), "{message}");
        }
    }

    #[test]
    fn ingress_and_loopback_are_independent_native_capability_sources() {
        let policy = ContainerPolicy {
            network_ingress: Some(NetworkIngressPolicy {
                default: NetworkAction::Allow,
                host_loopback: NetworkAction::Allow,
            }),
            ..Default::default()
        };
        let private = guidance("privatenetworkclientserver", &policy);
        assert!(private.contains("network.ingress.default='deny'"));
        assert!(!private.contains("hostLoopback"));
        let loopback = guidance("networkloopback", &policy);
        assert!(loopback.contains("network.ingress.hostLoopback='deny'"));
        assert!(!loopback.contains("network.ingress.default"));
    }

    #[test]
    fn proxy_guidance_preserves_the_request_dependencies() {
        let mut policy = ContainerPolicy {
            network_proxy: ProxyConfig {
                address: Some(ProxyAddress::new("127.0.0.1".into(), 8080)),
            },
            network_ingress: Some(NetworkIngressPolicy {
                default: NetworkAction::Allow,
                host_loopback: NetworkAction::Allow,
            }),
            ..Default::default()
        };
        let private = guidance("privatenetworkclientserver", &policy);
        assert!(private.contains("omit runtimeConfig.networkProxy"));
        assert!(private.contains("processContainer.network.allowedProxyPeer"));
        let loopback = guidance("networkloopback", &policy);
        assert!(loopback.contains("identity-less host proxy requires"));
        assert!(loopback.contains("supported identity-scoped proxy"));
        policy.allowed_proxy_peer = Some("Contoso.Proxy".into());
        assert!(!guidance("networkloopback", &policy).contains("identity-less host proxy"));
    }

    #[test]
    fn explicit_capabilities_map_to_the_list_without_echoing_input() {
        for (class, resource) in [
            (1, "internetclientserver"),
            (2, "broadfilesystemaccess"),
            (2, "documentslibrary"),
        ] {
            let policy = ContainerPolicy {
                capabilities: vec![format!(" \t{resource}\t ")],
                ..Default::default()
            };
            let mut detail = capability();
            detail.failure_class = layout::FailureClass(class);
            let message = request_guidance(&detail, Some(resource), &policy, false).unwrap();
            assert!(
                message.contains("remove the matching entry from processContainer.capabilities")
            );
            assert!(!message.contains(resource));
        }
    }

    #[test]
    fn filtered_network_list_entries_are_not_attributed_as_sources() {
        let policy = ContainerPolicy {
            capabilities: vec![
                "internetClient".into(),
                "internetClientServer".into(),
                "networkLoopback".into(),
            ],
            network_egress: Some(NetworkEgressPolicy::default()),
            network_ingress: Some(NetworkIngressPolicy::default()),
            ..Default::default()
        };
        for resource in ["internetclient", "internetclientserver", "networkloopback"] {
            assert!(request_guidance(&capability(), Some(resource), &policy, false).is_none());
        }
    }

    #[test]
    fn unfiltered_spaced_capabilities_keep_their_explicit_source() {
        let policy = ContainerPolicy {
            capabilities: vec![" internetClient ".into()],
            network_egress: Some(NetworkEgressPolicy::default()),
            ..Default::default()
        };
        assert!(guidance("internetclient", &policy).contains("processContainer.capabilities"));
    }

    #[test]
    fn permissive_capture_maps_to_the_capture_mode_not_the_reserved_list() {
        let policy = ContainerPolicy {
            capture_denials: Some(CaptureDenialsConfig {
                mode: CaptureDenialsMode::Allow,
                ..Default::default()
            }),
            capabilities: vec!["permissiveLearningMode".into()],
            ..Default::default()
        };
        let message = guidance("permissivelearningmode", &policy);
        assert!(message.contains("processContainer.captureDenials.mode='allow'"));
        assert!(message.contains("Set its mode to 'block'"));
        assert!(message.contains("Disable --audit"));
        assert!(message.contains("cannot be removed through processContainer.capabilities"));
        assert!(!message.contains("remove the matching entry"));
    }

    #[test]
    fn audit_source_is_not_invented_when_normalization_lost_the_entry_point() {
        let policy = ContainerPolicy {
            capabilities: vec!["permissiveLearningMode".into()],
            ..Default::default()
        };
        let message = guidance("permissivelearningmode", &policy);
        assert!(message.contains("does not retain which audit entry point"));
        assert!(!message.contains("captureDenials.mode='allow'"));
        assert!(request_guidance(
            &capability(),
            Some("permissivelearningmode"),
            &ContainerPolicy::default(),
            false,
        )
        .is_none());
    }

    #[test]
    fn filesystem_remedies_preserve_more_restrictive_exceptions() {
        for (requested, required, field) in [
            (2, 1, "filesystem.readwritePaths"),
            (2, 0, "filesystem.readwritePaths"),
            (1, 0, "filesystem.readonlyPaths"),
        ] {
            let detail = PolicyDetail {
                failure_class: layout::FailureClass::Filesystem,
                failure_reason: layout::FailureReason(if required == 0 { 3 } else { 2 }),
                required_action: layout::RequiredAction::RestrictFilesystemAccess,
                resource_kind: layout::ResourceKind::Path,
                value_kind: layout::ValueKind::Access,
                flags: 3,
                requested_value: requested,
                required_value: required,
                ..Default::default()
            };
            let message = request_guidance(
                &detail,
                Some("C:\\work\\sensitive"),
                &ContainerPolicy::default(),
                false,
            )
            .unwrap();
            assert!(message.contains(field));
            assert!(message.contains("more-specific"));
            assert!(message.contains("increase access"));
            assert!(message.contains("not the complete policy ceiling or a pinned object"));
            assert!(message
                .contains("Do not use a resource marked truncated below as a configuration path."));
            assert!(!message.contains("C:\\work"));
        }
    }

    #[test]
    fn path_budget_names_only_the_native_counted_fields() {
        let detail = PolicyDetail {
            failure_class: layout::FailureClass::Filesystem,
            failure_reason: layout::FailureReason::RequestPathLimit,
            required_action: layout::RequiredAction::ReducePathCount,
            value_kind: layout::ValueKind::PathCount,
            flags: 1,
            requested_value: 1100,
            required_value: 1024,
            ..Default::default()
        };
        let message = request_guidance(&detail, None, &ContainerPolicy::default(), false).unwrap();
        assert!(message.contains("from 1100 to at most 1024"));
        assert!(message.contains("filesystem.readwritePaths"));
        assert!(message.contains("filesystem.readonlyPaths"));
        assert!(message.contains("filesystem.deniedPaths"));
        assert!(message.contains("enumeratePaths is not part"));
        assert!(message.contains("rather than combining them into broader grants"));
    }

    #[test]
    fn unknown_incomplete_and_contradictory_details_never_become_edits() {
        let policy = ContainerPolicy {
            capabilities: vec!["internetClient".into()],
            ..Default::default()
        };
        for detail in [
            PolicyDetail {
                flags: 0,
                ..capability()
            },
            PolicyDetail {
                flags: 1,
                ..capability()
            },
            PolicyDetail {
                flags: 5,
                ..capability()
            },
            PolicyDetail {
                flags: 7,
                ..capability()
            },
            PolicyDetail {
                flags: 11,
                ..capability()
            },
            PolicyDetail {
                failure_class: layout::FailureClass(99),
                ..capability()
            },
            PolicyDetail {
                failure_reason: layout::FailureReason(99),
                ..capability()
            },
            PolicyDetail {
                required_action: layout::RequiredAction(99),
                ..capability()
            },
            PolicyDetail {
                resource_kind: layout::ResourceKind(99),
                ..capability()
            },
            PolicyDetail {
                value_kind: layout::ValueKind(99),
                ..capability()
            },
            PolicyDetail {
                requested_value: 1,
                ..capability()
            },
        ] {
            assert!(request_guidance(&detail, Some("internetclient"), &policy, false).is_none());
        }
        assert!(request_guidance(&capability(), None, &policy, false).is_none());
        assert!(request_guidance(&capability(), Some("unrelated"), &policy, false).is_none());
    }
}
