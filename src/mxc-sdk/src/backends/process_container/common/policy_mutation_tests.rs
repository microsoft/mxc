// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use super::*;
use crate::mxc_common::models::{
    CaptureDenialsConfig, NetworkEgressPolicy, NetworkIngressPolicy, NetworkRule, ProxyAddress,
    ProxyConfig,
};

fn canonical(path: &str) -> Result<PathCanonical, String> {
    Ok(PathCanonical::Canonical(path.to_string()))
}

fn request(policy: ContainerPolicy) -> ExecutionRequest {
    ExecutionRequest {
        script_code: "cmd /c exit 0".into(),
        policy,
        policy_mutation_enabled: true,
        ..Default::default()
    }
}

fn remove(capability: &str) -> MutationHint {
    MutationHint::RemoveCapability(capability.into())
}

fn restrict(path: &str, requested: u64, maximum: u64) -> MutationHint {
    MutationHint::RestrictPath {
        path: path.into(),
        requested,
        maximum,
    }
}

#[test]
fn mutation_filesystem_repairs_preserve_and_ignore_enumeration_bootstrap() {
    let desktop = r"C:\Users\AdminUser\Desktop";
    let enumeration = vec![
        r"C:\Users\AdminUser".to_string(),
        r"C:\bootstrap".to_string(),
        r"C:\bootstrap".to_string(),
    ];
    for (path, maximum) in [(r"C:\Users\AdminUser\Desktop\denied", 0), (desktop, 1)] {
        let original = request(ContainerPolicy {
            readwrite_paths: vec![desktop.into()],
            enumerate_paths: enumeration.clone(),
            ..Default::default()
        });
        let (candidate, _) = repair(
            &original,
            &[restrict(path, 2, maximum)],
            false,
            &mut |path| {
                assert!(
                    !enumeration.iter().any(|entry| entry == path),
                    "enumeration-only paths must not enter access-repair resolution",
                );
                canonical(path)
            },
        )
        .expect("a valid filesystem narrowing must not depend on enumeration grants");
        assert_eq!(candidate.policy.enumerate_paths, enumeration);
        assert_eq!(access_at(&candidate.policy, path), maximum);
        assert_eq!(original.policy.readwrite_paths, [desktop]);
    }
}

#[test]
fn mutation_removes_all_internet_sources_without_dropping_deny_rules() {
    let original = request(ContainerPolicy {
        capabilities: vec![
            "internetClient".into(),
            "registryRead".into(),
            "learningModeLogging".into(),
        ],
        network_egress: Some(NetworkEgressPolicy {
            default: NetworkAction::Allow,
            allow: vec![NetworkRule::default()],
            deny: vec![NetworkRule::default()],
        }),
        capture_denials: Some(CaptureDenialsConfig::default()),
        ..Default::default()
    });
    let before = serde_json::to_string(&original).unwrap();
    let (candidate, text) =
        repair(&original, &[remove("InternetClient")], true, &mut canonical).unwrap();
    assert_eq!(
        candidate.policy.network_egress.as_ref().unwrap().default,
        NetworkAction::Deny
    );
    assert!(candidate
        .policy
        .network_egress
        .as_ref()
        .unwrap()
        .allow
        .is_empty());
    assert_eq!(
        candidate.policy.network_egress.as_ref().unwrap().deny.len(),
        1
    );
    assert!(candidate.policy.capture_denials.is_none());
    assert_eq!(candidate.policy.capabilities, ["registryRead"]);
    assert!(!has_capability(&candidate, "internetClient", true));
    assert!(text.iter().any(|text| text.contains("network.egress")));
    assert!(text
        .iter()
        .any(|text| text.contains("processContainer.captureDenials")));
    assert_eq!(serde_json::to_string(&original).unwrap(), before);
}

#[test]
fn mutation_preserves_unchanged_capability_spellings_and_does_not_log_proxy_credentials() {
    let original = request(ContainerPolicy {
        capabilities: vec![" registryRead\t".into(), " registryWrite ".into()],
        network_ingress: Some(NetworkIngressPolicy {
            default: NetworkAction::Allow,
            host_loopback: NetworkAction::Allow,
        }),
        network_proxy: ProxyConfig {
            address: Some(ProxyAddress::from_url(
                "http://user:password@127.0.0.1:8080",
                "127.0.0.1".into(),
                8080,
            )),
        },
        runtime_network_proxy_specified: true,
        ..Default::default()
    });
    let (candidate, text) = repair(
        &original,
        &[remove("registryRead"), remove("networkLoopback")],
        false,
        &mut canonical,
    )
    .unwrap();
    assert_eq!(candidate.policy.capabilities, [" registryWrite "]);
    assert!(!candidate.policy.network_proxy.is_enabled());
    let text = text.join("\n");
    assert!(text.contains("runtimeConfig.networkProxy enabled: true -> false"));
    assert!(!text.contains("user:password"));
    assert!(!text.contains("password"));
}

#[test]
fn mutation_network_capture_uses_the_sources_of_the_submitted_attempt() {
    let original = request(ContainerPolicy {
        network_egress: Some(NetworkEgressPolicy::default()),
        capture_denials: Some(CaptureDenialsConfig::default()),
        ..Default::default()
    });
    assert!(repair(
        &original,
        &[remove("internetClient")],
        false,
        &mut canonical
    )
    .is_err());
    assert!(
        repair(&original, &[remove("internetClient")], true, &mut canonical)
            .unwrap()
            .0
            .policy
            .capture_denials
            .is_none()
    );
}

#[test]
fn mutation_disables_proxy_without_synthesizing_direct_network_capture_access() {
    let original = request(ContainerPolicy {
        capabilities: vec!["learningModeLogging".into()],
        network_egress: Some(NetworkEgressPolicy::default()),
        network_ingress: Some(NetworkIngressPolicy {
            default: NetworkAction::Allow,
            host_loopback: NetworkAction::Allow,
        }),
        network_proxy: ProxyConfig {
            address: Some(ProxyAddress::new("127.0.0.1".into(), 8080)),
        },
        runtime_network_proxy_specified: true,
        capture_denials: Some(CaptureDenialsConfig::default()),
        ..Default::default()
    });
    let (candidate, changes) = repair(
        &original,
        &[remove("privateNetworkClientServer")],
        true,
        &mut canonical,
    )
    .unwrap();
    assert!(!candidate.policy.network_proxy.is_enabled());
    assert!(!candidate.policy.runtime_network_proxy_specified);
    assert!(candidate.policy.capture_denials.is_none());
    assert!(!has_capability(&candidate, "internetClient", true));
    assert!(!has_capability(
        &candidate,
        "privateNetworkClientServer",
        true
    ));
    assert!(changes
        .iter()
        .any(|change| change.contains("runtimeConfig.networkProxy")));
}

#[test]
fn mutation_proxy_removal_never_activates_hidden_direct_network_allowances() {
    use crate::process_container_common::base_container_helpers::build_psec_v1_security_environment_spec;
    use crate::process_security_environment_spec::process_security_environment_layout as psec;

    for capability in ["privateNetworkClientServer", "networkLoopback"] {
        let original = request(ContainerPolicy {
            network_egress: Some(NetworkEgressPolicy {
                default: NetworkAction::Allow,
                allow: vec![NetworkRule::default()],
                deny: vec![NetworkRule::default()],
            }),
            network_ingress: Some(NetworkIngressPolicy {
                default: NetworkAction::Allow,
                host_loopback: NetworkAction::Allow,
            }),
            network_proxy: ProxyConfig {
                address: Some(ProxyAddress::new("127.0.0.1".into(), 8080)),
            },
            runtime_network_proxy_specified: true,
            ..Default::default()
        });
        let before = build_psec_v1_security_environment_spec(
            &original,
            SecurityEnvironmentVersion::V1_1,
            false,
        );
        let before = psec::root_as_process_security_environment(&before).unwrap();
        let before = before.network_policy().unwrap();
        assert!(before.proxy().is_some());
        assert!(before.egress().is_none());
        assert!(before.ingress().is_none());

        let (candidate, changes) =
            repair(&original, &[remove(capability)], false, &mut canonical).unwrap();
        let after = build_psec_v1_security_environment_spec(
            &candidate,
            SecurityEnvironmentVersion::V1_1,
            false,
        );
        let after = psec::root_as_process_security_environment(&after).unwrap();
        let after = after.network_policy().unwrap();
        assert!(after.proxy().is_none());
        let egress = after.egress().unwrap();
        assert_eq!(egress.default_action(), psec::FilterAction::deny);
        assert!(egress.allow().is_none());
        assert_eq!(egress.deny().unwrap().len(), 1);
        assert!(after.ingress().is_none());
        assert_eq!(
            candidate.policy.network_ingress,
            Some(NetworkIngressPolicy::default())
        );
        assert!(after.allowed_appcontainer_peer().is_none());
        assert!(changes
            .iter()
            .any(|change| change.contains("network.egress")));
        assert!(changes
            .iter()
            .any(|change| change.contains("network.ingress")));
    }
}

#[test]
fn mutation_private_network_removal_preserves_unrelated_direct_capture() {
    let original = request(ContainerPolicy {
        capabilities: vec!["learningModeLogging".into()],
        network_egress: Some(NetworkEgressPolicy::default()),
        network_ingress: Some(NetworkIngressPolicy {
            default: NetworkAction::Allow,
            host_loopback: NetworkAction::Deny,
        }),
        capture_denials: Some(CaptureDenialsConfig::default()),
        ..Default::default()
    });
    let (candidate, _) = repair(
        &original,
        &[remove("privateNetworkClientServer")],
        true,
        &mut canonical,
    )
    .unwrap();
    assert!(candidate.policy.capture_denials.is_some());
    assert!(has_capability(&candidate, "internetClient", true));
    assert!(!has_capability(
        &candidate,
        "privateNetworkClientServer",
        true
    ));
}

#[test]
fn mutation_restricts_derived_host_loopback_without_network_capture() {
    let original = request(ContainerPolicy {
        network_ingress: Some(NetworkIngressPolicy {
            default: NetworkAction::Deny,
            host_loopback: NetworkAction::Allow,
        }),
        ..Default::default()
    });
    assert!(effective_capabilities(&original, false)
        .iter()
        .any(|capability| { capability.eq_ignore_ascii_case("networkLoopback") }));
    let (candidate, _) = repair(
        &original,
        &[remove("networkLoopback")],
        false,
        &mut canonical,
    )
    .unwrap();
    assert_eq!(
        candidate
            .policy
            .network_ingress
            .as_ref()
            .unwrap()
            .host_loopback,
        NetworkAction::Deny,
    );
    assert!(!effective_capabilities(&candidate, false)
        .iter()
        .any(|capability| capability.eq_ignore_ascii_case("networkLoopback")));
}

#[test]
fn mutation_can_restrict_permissive_capture_or_disable_reserved_logging() {
    let original = request(ContainerPolicy {
        capabilities: vec!["permissiveLearningMode".into(), "registryRead".into()],
        capture_denials: Some(CaptureDenialsConfig {
            mode: CaptureDenialsMode::Allow,
            ..Default::default()
        }),
        ..Default::default()
    });
    let (blocked, _) = repair(
        &original,
        &[remove("permissiveLearningMode")],
        false,
        &mut canonical,
    )
    .unwrap();
    assert_eq!(
        blocked.policy.capture_denials.as_ref().unwrap().mode,
        CaptureDenialsMode::Block
    );
    assert!(has_capability(&blocked, "learningModeLogging", false));
    assert!(!has_capability(&blocked, "permissiveLearningMode", false));
    let (disabled, _) = repair(
        &blocked,
        &[remove("learningModeLogging")],
        false,
        &mut canonical,
    )
    .unwrap();
    assert!(disabled.policy.capture_denials.is_none());
    assert_eq!(disabled.policy.capabilities, ["registryRead"]);
}

#[test]
fn mutation_moves_only_the_existing_writable_spelling_and_preserves_exceptions() {
    let original = request(ContainerPolicy {
        readwrite_paths: vec![r"C:\work".into(), r"C:\work\child".into()],
        readonly_paths: vec![r"C:\work\read".into()],
        denied_paths: vec![r"C:\work\secret".into()],
        ..Default::default()
    });
    let (candidate, _) = repair(
        &original,
        &[restrict(r"C:\WORK", 2, 1)],
        false,
        &mut canonical,
    )
    .unwrap();
    assert_eq!(candidate.policy.readwrite_paths, [r"C:\work\child"]);
    assert_eq!(
        candidate.policy.readonly_paths,
        [r"C:\work\read", r"C:\work"]
    );
    assert_eq!(candidate.policy.denied_paths, original.policy.denied_paths);
    for point in [
        r"C:\work",
        r"C:\work\child",
        r"C:\work\read",
        r"C:\work\secret",
    ] {
        assert!(access_at(&candidate.policy, point) <= access_at(&original.policy, point));
    }
    assert!(repair(
        &original,
        &[restrict(r"C:\work\new", 2, 1)],
        false,
        &mut canonical
    )
    .is_err());
}

#[test]
fn mutation_can_add_deny_but_cannot_remove_a_readonly_exception_under_a_write_grant() {
    let original = request(ContainerPolicy {
        readwrite_paths: vec![r"C:\work".into()],
        readonly_paths: vec![r"C:\work\read".into()],
        denied_paths: vec![r"C:\work\secret".into()],
        ..Default::default()
    });
    let (candidate, _) = repair(
        &original,
        &[restrict(r"C:\work\read", 1, 0)],
        false,
        &mut canonical,
    )
    .unwrap();
    assert_eq!(access_at(&candidate.policy, r"C:\work\read\child"), 0);
    assert!(candidate
        .policy
        .denied_paths
        .contains(&r"C:\work\secret".into()));
    assert_eq!(
        candidate.policy.readwrite_paths,
        original.policy.readwrite_paths
    );
}

#[test]
fn mutation_rejects_ambiguous_filesystem_policy_atomically() {
    let original = request(ContainerPolicy {
        capabilities: vec!["registryRead".into()],
        readwrite_paths: vec![r"C:\work".into()],
        ..Default::default()
    });
    for path in [
        r"relative",
        r"C:relative",
        r"\\",
        r"\\\",
        r"\\\\",
        r"\\server",
        r"\\?\C:\work",
        r"C:\work\..\other",
        r"C:\work\*",
        r"C:\work\\child",
        r"C:\work\child.",
        r"C:\work:stream",
    ] {
        assert!(
            repair(
                &original,
                &[remove("registryRead"), restrict(path, 2, 0)],
                false,
                &mut canonical,
            )
            .is_err(),
            "{path}"
        );
        assert_eq!(original.policy.capabilities, ["registryRead"]);
    }
    assert!(
        repair(&original, &[restrict(r"C:\work", 2, 1)], false, &mut |_| {
            Ok(PathCanonical::Canonical(r"C:\elsewhere".into()))
        })
        .is_err()
    );
    assert!(
        repair(&original, &[restrict(r"C:\work", 2, 1)], false, &mut |_| {
            Ok(PathCanonical::Unknown)
        })
        .is_err()
    );
    let mut enumeration = original.clone();
    enumeration.policy.enumerate_paths.push(r"C:\index".into());
    let repaired = repair(
        &enumeration,
        &[restrict(r"C:\work", 2, 1)],
        false,
        &mut canonical,
    )
    .expect("enumeration-only paths do not affect access repairs");
    assert_eq!(
        repaired.0.policy.enumerate_paths,
        enumeration.policy.enumerate_paths
    );
    for root in [r"C:\", r"\\server\share"] {
        let root_request = request(ContainerPolicy {
            readwrite_paths: vec![root.into()],
            ..Default::default()
        });
        assert!(repair(
            &root_request,
            &[restrict(root, 2, 1)],
            false,
            &mut canonical
        )
        .is_err());
    }
}

#[test]
fn mutation_path_count_only_deduplicates_exact_entries() {
    let original = request(ContainerPolicy {
        readwrite_paths: vec![r"C:\work".into(), r"C:\work".into()],
        readonly_paths: vec![r"C:\work\read".into()],
        denied_paths: vec![r"C:\work\secret".into(), r"C:\work\secret".into()],
        enumerate_paths: vec![r"C:\index".into()],
        ..Default::default()
    });
    let hint = MutationHint::ReducePathCount {
        requested: 5,
        maximum: 3,
    };
    let (candidate, _) = repair(&original, &[hint], false, &mut canonical).unwrap();
    assert_eq!(native_path_count(&candidate.policy), 3);
    assert_eq!(candidate.policy.denied_paths, [r"C:\work\secret"]);
    assert_eq!(
        candidate.policy.enumerate_paths,
        original.policy.enumerate_paths
    );
    assert!(repair(
        &original,
        &[MutationHint::ReducePathCount {
            requested: 5,
            maximum: 2
        }],
        false,
        &mut canonical,
    )
    .is_err());
    assert!(repair(
        &original,
        &[MutationHint::ReducePathCount {
            requested: 4,
            maximum: 3
        }],
        false,
        &mut canonical,
    )
    .is_err());
}

#[test]
fn mutation_rejects_contradictory_and_unmatched_constraints() {
    let original = request(ContainerPolicy {
        readwrite_paths: vec![r"C:\work".into()],
        ..Default::default()
    });
    assert!(repair(
        &original,
        &[restrict(r"C:\work", 2, 1), restrict(r"C:\work", 2, 0)],
        false,
        &mut canonical,
    )
    .is_err());
    assert!(repair(
        &original,
        &[restrict(r"C:\work", 1, 0)],
        false,
        &mut canonical
    )
    .is_err());
    assert!(repair(&original, &[remove("unknown")], false, &mut canonical).is_err());
}

#[test]
fn mutation_text_quotes_data_and_is_bounded() {
    let mut changes = Vec::new();
    record_change(
        "field",
        &"before",
        &"after\nnot an instruction",
        &mut changes,
    )
    .unwrap();
    assert!(changes[0].contains(r"after\nnot an instruction"));
    assert!(!changes[0].contains('\n'));
    assert!(record_change(
        "field",
        &"",
        &"x".repeat(MAX_CHANGE_TEXT_BYTES),
        &mut changes
    )
    .is_err());
}
