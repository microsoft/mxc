// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use super::*;
use crate::mxc_common::models::{
    CaptureDenialsConfig, NetworkEgressPolicy, NetworkIngressPolicy, NetworkRule, ProxyAddress,
    ProxyConfig,
};
use crate::process_container_common::secenv::SecurityEnvironmentVersion;

fn canonical(path: &str) -> Result<PathCanonical, String> {
    Ok(PathCanonical::Canonical(path.to_string()))
}

fn request(policy: ContainerPolicy) -> ExecutionRequest {
    ExecutionRequest {
        script_code: "cmd /c exit 0".into(),
        policy,
        ..Default::default()
    }
}

const ABSOLUTE_PATH: &str = "filesystem restriction requires an absolute literal DOS or UNC path";
const NON_CANONICAL: &str =
    "filesystem restriction cannot reinterpret non-canonical path components";
const ROOT_GRANT: &str = "volume/share-root write grants have no supported automatic restriction";
const READONLY_NEEDS_GRANT: &str = "read-only restriction requires an existing matching read-write grant; MXC will not introduce a new grant name or downgrade an unrelated ancestor";

fn remove(capability: &str) -> RestrictionHint {
    RestrictionHint::RemoveCapability(capability.into())
}

const NO_ACCESS: u64 = Detail::ACCESS_NONE;
const RO: u64 = Detail::ACCESS_READ_ONLY;
const RW: u64 = Detail::ACCESS_READ_WRITE;

fn restrict(path: &str, requested: u64, maximum: u64) -> RestrictionHint {
    RestrictionHint::RestrictPath {
        path: path.into(),
        requested,
        maximum,
    }
}

fn rejection(
    original: &ExecutionRequest,
    hints: &[RestrictionHint],
    capture: bool,
    resolve: &mut impl FnMut(&str) -> Result<PathCanonical, String>,
) -> String {
    restrict_with_hints(original, hints, capture, resolve).expect_err("the hints must be rejected")
}

fn observation(
    hints: &[RestrictionHint],
) -> crate::mxc_common::policy_failures::PolicyFailureResult {
    use crate::mxc_common::policy_failures::{
        PolicyFailureDetail as Detail, PolicyFailureResult as Batch,
    };
    Batch {
        outcome: Batch::OUTCOME_BLOCKED,
        details: hints
            .iter()
            .map(|hint| match hint {
                RestrictionHint::RemoveCapability(capability) => Detail {
                    failure_class: Detail::CLASS_FILESYSTEM,
                    failure_reason: Detail::REASON_CAPABILITY_NOT_ALLOWED,
                    required_action: Detail::ACTION_REMOVE_CAPABILITY,
                    resource_kind: Detail::RESOURCE_KIND_CAPABILITY,
                    flags: Detail::FLAG_HAS_ACTIONABLE_DETAILS | Detail::FLAG_RESOURCE_COMPLETE,
                    resource: Some(capability.clone()),
                    ..Default::default()
                },
                RestrictionHint::RestrictPath {
                    path,
                    requested,
                    maximum,
                } => Detail {
                    failure_class: Detail::CLASS_FILESYSTEM,
                    failure_reason: Detail::REASON_ACCESS_EXCEEDS_CEILING,
                    required_action: Detail::ACTION_RESTRICT_FILESYSTEM_ACCESS,
                    resource_kind: Detail::RESOURCE_KIND_PATH,
                    value_kind: Detail::VALUE_KIND_ACCESS,
                    flags: Detail::FLAG_HAS_ACTIONABLE_DETAILS | Detail::FLAG_RESOURCE_COMPLETE,
                    requested_value: *requested,
                    required_value: *maximum,
                    resource: Some(path.clone()),
                    ..Default::default()
                },
                RestrictionHint::ReducePathCount { requested, maximum } => Detail {
                    failure_class: Detail::CLASS_FILESYSTEM,
                    failure_reason: Detail::REASON_REQUEST_PATH_LIMIT,
                    required_action: Detail::ACTION_REDUCE_PATH_COUNT,
                    value_kind: Detail::VALUE_KIND_PATH_COUNT,
                    flags: Detail::FLAG_HAS_ACTIONABLE_DETAILS,
                    requested_value: *requested,
                    required_value: *maximum,
                    ..Default::default()
                },
            })
            .collect(),
        ..Default::default()
    }
}

#[test]
fn policy_restriction_replays_strengthened_observations_against_fresh_requests() {
    let original = request(ContainerPolicy {
        readwrite_paths: vec![r"C:\work".into(), r"C:\unrelated".into()],
        ..Default::default()
    });
    let mut failures = PolicyFailures::default();
    failures.append(observation(&[restrict(r"C:\work", RW, RO)]));
    failures.append(observation(&[restrict(r"C:\work", RO, NO_ACCESS)]));
    let candidate = restrict_request(&original, &failures, false, &mut canonical).unwrap();
    assert_eq!(access_at(&candidate.policy, r"C:\work"), NO_ACCESS);
    assert_eq!(candidate.policy.readwrite_paths, [r"C:\unrelated"]);
    assert_eq!(
        original.policy.readwrite_paths,
        [r"C:\work", r"C:\unrelated"]
    );
    assert_eq!(failures.results[1].details[0].requested_value, RO);
    let already_satisfied = restrict_request(&candidate, &failures, false, &mut canonical).unwrap();
    assert_eq!(
        already_satisfied.policy.denied_paths,
        candidate.policy.denied_paths
    );

    let mut changed = original.clone();
    changed
        .policy
        .readwrite_paths
        .push(r"C:\new-request".into());
    let candidate = restrict_request(&changed, &failures, false, &mut canonical).unwrap();
    assert!(candidate
        .policy
        .readwrite_paths
        .contains(&r"C:\new-request".into()));
}

#[test]
fn policy_restriction_enforces_constraints_reintroduced_by_another_reduction() {
    let mut policy = ContainerPolicy {
        capabilities: vec!["permissiveLearningMode".into()],
        capture_denials: Some(CaptureDenialsConfig::default()),
        ..Default::default()
    };
    policy.capture_denials.as_mut().unwrap().mode = CaptureDenialsMode::Allow;
    let original = request(policy);
    let mut failures = PolicyFailures::default();
    failures.append(observation(&[remove("learningModeLogging")]));
    failures.append(observation(&[remove("permissiveLearningMode")]));
    let candidate = restrict_request(&original, &failures, false, &mut canonical).unwrap();
    assert!(candidate.policy.capture_denials.is_none());
    assert!(!has_capability(&candidate, "learningModeLogging", false));
    assert!(!has_capability(&candidate, "permissiveLearningMode", false));
    assert_eq!(
        original.policy.capture_denials.as_ref().unwrap().mode,
        CaptureDenialsMode::Allow
    );
}

#[test]
fn policy_preparation_empty_and_satisfied_observations_preserve_the_request() {
    let original = request(ContainerPolicy {
        capabilities: vec!["registryRead".into()],
        ..Default::default()
    });
    let mut failures = PolicyFailures::default();
    for hint in [None, Some(remove("registryWrite"))] {
        if let Some(hint) = hint {
            failures.append(observation(&[hint]));
        }
        let candidate = restrict_request(&original, &failures, false, &mut canonical).unwrap();
        assert_eq!(
            serde_json::to_value(&candidate).unwrap(),
            serde_json::to_value(&original).unwrap(),
        );
    }
}

#[test]
fn policy_restriction_rejects_unknown_and_contradictory_batches_before_creation() {
    let original = request(ContainerPolicy {
        readwrite_paths: vec![r"C:\work".into()],
        ..Default::default()
    });
    let mut failures = PolicyFailures::default();
    failures.append(observation(&[
        restrict(r"C:\work", RW, RO),
        restrict(r"C:\work", RW, NO_ACCESS),
    ]));
    assert_eq!(
        restrict_request(&original, &failures, false, &mut canonical).unwrap_err(),
        "a native policy-result batch contains contradictory constraints"
    );
    failures.results[0].details.truncate(1);
    failures.results[0].details[0].required_action = u32::MAX;
    assert_eq!(
        restrict_request(&original, &failures, false, &mut canonical).unwrap_err(),
        "the observations contain an unsupported or non-actionable policy result"
    );
}

#[test]
fn policy_restriction_unsafe_replay_keeps_specifics_out_of_error_and_warning_text() {
    let mut failures = PolicyFailures::default();
    let mut result = observation(&[remove("POLICY_RESOURCE_MARKER")]);
    result.details[0].required_action = u32::MAX;
    failures.append(result);
    let original = request(ContainerPolicy::default());
    let response = prepare_request(&original, &failures, false).unwrap_err();
    assert_eq!(
        response.error_message,
        "Policy preparation cannot apply these observations safely."
    );
    assert!(response.warnings().is_empty());
    let error = crate::mxc_engine::Error::from(response.into_mxc_error());
    assert!(!error.to_string().contains("POLICY_RESOURCE_MARKER"));
    assert_eq!(PolicyFailures::from_error(&error).unwrap(), Some(failures));
    let diagnostic = &error.details.as_deref().unwrap()["policyFeedbackError"];
    assert_eq!(diagnostic["code"], "unsafeReplay");
    assert!(diagnostic["reason"]
        .as_str()
        .is_some_and(|reason| !reason.is_empty()));
}

#[test]
fn restriction_filesystem_narrowing_preserves_and_ignores_enumeration_bootstrap() {
    let desktop = r"C:\Users\AdminUser\Desktop";
    let enumeration = vec![
        r"C:\Users\AdminUser".to_string(),
        r"C:\bootstrap".to_string(),
        r"C:\bootstrap".to_string(),
    ];
    for (path, maximum) in [
        (r"C:\Users\AdminUser\Desktop\denied", NO_ACCESS),
        (desktop, RO),
    ] {
        let original = request(ContainerPolicy {
            readwrite_paths: vec![desktop.into()],
            enumerate_paths: enumeration.clone(),
            ..Default::default()
        });
        let candidate = restrict_with_hints(
            &original,
            &[restrict(path, RW, maximum)],
            false,
            &mut |path| {
                assert!(
                    !enumeration.iter().any(|entry| entry == path),
                    "enumeration-only paths must not enter access-restriction resolution",
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
fn restriction_removes_all_internet_sources_without_dropping_deny_rules() {
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
    let candidate =
        restrict_with_hints(&original, &[remove("InternetClient")], true, &mut canonical).unwrap();
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
    assert_eq!(serde_json::to_string(&original).unwrap(), before);
}

#[test]
fn restriction_preserves_unchanged_capability_spellings() {
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
    let candidate = restrict_with_hints(
        &original,
        &[remove("registryRead"), remove("networkLoopback")],
        false,
        &mut canonical,
    )
    .unwrap();
    assert_eq!(candidate.policy.capabilities, [" registryWrite "]);
    assert!(!candidate.policy.network_proxy.is_enabled());
    assert!(original.policy.network_proxy.is_enabled());
}

#[test]
fn restriction_network_capture_uses_the_sources_of_the_submitted_attempt() {
    let original = request(ContainerPolicy {
        network_egress: Some(NetworkEgressPolicy::default()),
        capture_denials: Some(CaptureDenialsConfig::default()),
        ..Default::default()
    });
    assert_eq!(
        rejection(
            &original,
            &[remove("internetClient")],
            false,
            &mut canonical
        ),
        "the forbidden capability does not match the submitted request"
    );
    assert!(
        restrict_with_hints(&original, &[remove("internetClient")], true, &mut canonical)
            .unwrap()
            .policy
            .capture_denials
            .is_none()
    );
}

#[test]
fn restriction_disables_proxy_without_synthesizing_direct_network_capture_access() {
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
    let candidate = restrict_with_hints(
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
}

#[test]
fn restriction_proxy_removal_never_activates_hidden_direct_network_allowances() {
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

        let candidate =
            restrict_with_hints(&original, &[remove(capability)], false, &mut canonical).unwrap();
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
    }
}

#[test]
fn restriction_private_network_removal_preserves_unrelated_direct_capture() {
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
    let candidate = restrict_with_hints(
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
fn restriction_restricts_derived_host_loopback_without_network_capture() {
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
    let candidate = restrict_with_hints(
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
fn restriction_can_restrict_permissive_capture_or_disable_reserved_logging() {
    let original = request(ContainerPolicy {
        capabilities: vec!["permissiveLearningMode".into(), "registryRead".into()],
        capture_denials: Some(CaptureDenialsConfig {
            mode: CaptureDenialsMode::Allow,
            ..Default::default()
        }),
        ..Default::default()
    });
    let blocked = restrict_with_hints(
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
    let disabled = restrict_with_hints(
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
fn restriction_moves_only_the_existing_writable_spelling_and_preserves_exceptions() {
    let original = request(ContainerPolicy {
        readwrite_paths: vec![r"C:\work".into(), r"C:\work\child".into()],
        readonly_paths: vec![r"C:\work\read".into()],
        denied_paths: vec![r"C:\work\secret".into()],
        ..Default::default()
    });
    let candidate = restrict_with_hints(
        &original,
        &[restrict(r"C:\WORK", RW, RO)],
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
    assert_eq!(
        rejection(
            &original,
            &[restrict(r"C:\work\new", RW, RO)],
            false,
            &mut canonical
        ),
        READONLY_NEEDS_GRANT
    );
}

#[test]
fn restriction_can_add_deny_but_cannot_remove_a_readonly_exception_under_a_write_grant() {
    let original = request(ContainerPolicy {
        readwrite_paths: vec![r"C:\work".into()],
        readonly_paths: vec![r"C:\work\read".into()],
        denied_paths: vec![r"C:\work\secret".into()],
        ..Default::default()
    });
    let candidate = restrict_with_hints(
        &original,
        &[restrict(r"C:\work\read", RO, NO_ACCESS)],
        false,
        &mut canonical,
    )
    .unwrap();
    assert_eq!(
        access_at(&candidate.policy, r"C:\work\read\child"),
        NO_ACCESS
    );
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
fn restriction_rejects_ambiguous_filesystem_policy() {
    let original = request(ContainerPolicy {
        capabilities: vec!["registryRead".into()],
        readwrite_paths: vec![r"C:\work".into()],
        ..Default::default()
    });
    for (path, message) in [
        (r"relative", ABSOLUTE_PATH),
        (r"C:relative", ABSOLUTE_PATH),
        (r"\\?\C:\work", ABSOLUTE_PATH),
        (r"C:\work\*", ABSOLUTE_PATH),
        (r"\\", NON_CANONICAL),
        (r"\\\", NON_CANONICAL),
        (r"\\\\", NON_CANONICAL),
        (r"\\server", NON_CANONICAL),
        (r"C:\work\..\other", NON_CANONICAL),
        (r"C:\work\\child", NON_CANONICAL),
        (r"C:\work\child.", NON_CANONICAL),
        (r"C:\work:stream", NON_CANONICAL),
    ] {
        assert_eq!(
            rejection(
                &original,
                &[remove("registryRead"), restrict(path, RW, NO_ACCESS)],
                false,
                &mut canonical,
            ),
            message,
            "{path}"
        );
    }
    assert_eq!(
        rejection(
            &original,
            &[restrict(r"C:\work", RW, RO)],
            false,
            &mut |_| { Ok(PathCanonical::Canonical(r"C:\elsewhere".into())) }
        ),
        "filesystem restriction will not guess the provenance of an aliased path"
    );
    assert_eq!(
        rejection(
            &original,
            &[restrict(r"C:\work", RW, RO)],
            false,
            &mut |_| { Ok(PathCanonical::Unknown) }
        ),
        "filesystem restriction cannot resolve every relevant path safely"
    );
    let mut enumeration = original.clone();
    enumeration.policy.enumerate_paths.push(r"C:\index".into());
    let restricted = restrict_with_hints(
        &enumeration,
        &[restrict(r"C:\work", RW, RO)],
        false,
        &mut canonical,
    )
    .expect("enumeration-only paths do not affect access restrictions");
    assert_eq!(
        restricted.policy.enumerate_paths,
        enumeration.policy.enumerate_paths
    );
    for root in [r"C:\", r"\\server\share"] {
        let root_request = request(ContainerPolicy {
            readwrite_paths: vec![root.into()],
            ..Default::default()
        });
        assert_eq!(
            rejection(
                &root_request,
                &[restrict(root, RW, RO)],
                false,
                &mut canonical
            ),
            ROOT_GRANT,
            "{root}"
        );
    }
}

#[test]
fn restriction_path_count_only_deduplicates_exact_entries() {
    let original = request(ContainerPolicy {
        readwrite_paths: vec![r"C:\work".into(), r"C:\work".into()],
        readonly_paths: vec![r"C:\work\read".into()],
        denied_paths: vec![r"C:\work\secret".into(), r"C:\work\secret".into()],
        enumerate_paths: vec![r"C:\index".into()],
        ..Default::default()
    });
    let hint = RestrictionHint::ReducePathCount {
        requested: 5,
        maximum: 3,
    };
    let candidate = restrict_with_hints(&original, &[hint], false, &mut canonical).unwrap();
    assert_eq!(native_path_count(&candidate.policy), 3);
    assert_eq!(candidate.policy.denied_paths, [r"C:\work\secret"]);
    assert_eq!(
        candidate.policy.enumerate_paths,
        original.policy.enumerate_paths
    );
    assert_eq!(
        rejection(
            &original,
            &[RestrictionHint::ReducePathCount {
                requested: 5,
                maximum: 2
            }],
            false,
            &mut canonical,
        ),
        "the path limit cannot be met by exact deduplication; MXC will not discard distinct grants or exceptions"
    );
    assert_eq!(
        rejection(
            &original,
            &[RestrictionHint::ReducePathCount {
                requested: 4,
                maximum: 3
            }],
            false,
            &mut canonical,
        ),
        "the native path count disagrees with the submitted request"
    );
}

#[test]
fn restriction_rejects_contradictory_and_unmatched_constraints() {
    let original = request(ContainerPolicy {
        readwrite_paths: vec![r"C:\work".into()],
        ..Default::default()
    });
    assert_eq!(
        rejection(
            &original,
            &[
                restrict(r"C:\work", RW, RO),
                restrict(r"C:\work", RW, NO_ACCESS)
            ],
            false,
            &mut canonical,
        ),
        "the native details contain contradictory constraints"
    );
    assert_eq!(
        rejection(
            &original,
            &[restrict(r"C:\work", RO, NO_ACCESS)],
            false,
            &mut canonical
        ),
        "the native filesystem witness disagrees with the submitted request"
    );
    assert_eq!(
        rejection(&original, &[remove("unknown")], false, &mut canonical),
        "the forbidden capability does not match the submitted request"
    );
}
