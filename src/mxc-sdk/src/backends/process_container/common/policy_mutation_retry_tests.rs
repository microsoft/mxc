// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use super::*;
use crate::mxc_common::models::{
    CaptureDenialsConfig, NetworkEgressPolicy, NetworkIngressPolicy, ProxyAddress, ProxyConfig,
};
use crate::process_security_environment_spec::process_security_environment_layout as psec;

const UPDATE_WARNING_PREFIX: &str = "Sandbox configuration updated due to IT policy: ";

fn request() -> ExecutionRequest {
    ExecutionRequest {
        script_code: "cmd /c exit 0".into(),
        policy_mutation_enabled: true,
        policy: ContainerPolicy {
            capabilities: vec!["registryRead".into(), "registryWrite".into()],
            ..Default::default()
        },
        ..Default::default()
    }
}

fn remove(capability: &str) -> CreationError {
    CreationError::test_policy_refusal(vec![MutationHint::RemoveCapability(capability.into())])
}

fn prepare(request: &ExecutionRequest) -> Result<PreparedPolicy, ScriptResponse> {
    let version =
        if !request.policy.enumerate_paths.is_empty() || !request.policy.denied_paths.is_empty() {
            SecurityEnvironmentVersion::V1_1
        } else {
            SecurityEnvironmentVersion::V1_0
        };
    let capture_network_decisions = request.policy.capture_denials.is_some();
    Ok(PreparedPolicy {
        specification: crate::process_container_common::base_container_helpers::
            build_psec_v1_security_environment_spec(
                request,
                version,
                capture_network_decisions,
            ),
        capture_network_decisions,
        version,
    })
}

fn learn_read(
    request: &ExecutionRequest,
    cache: &mut cache::Cache,
) -> (NegotiatedEnvironment<()>, usize) {
    let mut calls = 0;
    let result = negotiate_with_cache(
        request,
        cache,
        Vec::new(),
        prepare,
        |_, policy| {
            calls += 1;
            if policy
                .capabilities
                .iter()
                .any(|value| value == "registryRead")
            {
                Err(remove("registryRead"))
            } else {
                Ok(())
            }
        },
        |_| Ok(()),
    )
    .unwrap();
    (result, calls)
}

#[test]
fn mutation_cache_reuses_successful_repairs_but_always_calls_native_creation() {
    let original = request();
    let before = serde_json::to_string(&original).unwrap();
    let mut cache = cache::Cache::default();
    let (first, first_calls) = learn_read(&original, &mut cache);
    assert_eq!(first_calls, 2);
    assert_eq!(
        first.warnings,
        [format!(
            "{UPDATE_WARNING_PREFIX}processContainer.capabilities (effective request): \
             [\"registryRead\",\"registryWrite\"] -> [\"registryWrite\"]"
        )]
    );
    let mut next = original.clone();
    next.container_id = "another-container".into();
    next.script_code = "different workload".into();
    next.env = Some(vec!["OTHER=value".into()]);
    let (result, calls) = learn_read(&next, &mut cache);
    assert_eq!(calls, 1);
    assert_eq!(result.request.script_code, next.script_code);
    assert_eq!(result.request.env, next.env);
    assert!(result.warnings.is_empty());
    assert_eq!(result.request.policy.capabilities, ["registryWrite"]);
    assert_eq!(serde_json::to_string(&original).unwrap(), before);
    assert_eq!(learn_read(&original, &mut cache::Cache::default()).1, 2);
    next.policy.readonly_paths.push(r"C:\other".into());
    let (unrelated, unrelated_calls) = learn_read(&next, &mut cache);
    assert_eq!(
        unrelated_calls, 1,
        "an unrelated grant must not invalidate a remembered capability restriction"
    );
    assert!(unrelated.warnings.is_empty());
    assert_eq!(unrelated.request.policy.readonly_paths, [r"C:\other"]);
}

#[test]
fn mutation_cache_commits_only_success_and_never_relaxes_remembered_restrictions() {
    let original = request();
    let mut cache = cache::Cache::default();
    learn_read(&original, &mut cache);
    assert!(negotiate_with_cache::<()>(
        &original,
        &mut cache,
        Vec::new(),
        prepare,
        |_, _| Err(remove("registryWrite")),
        |_| Ok(()),
    )
    .is_err());
    assert_eq!(
        learn_read(&original, &mut cache)
            .0
            .request
            .policy
            .capabilities,
        ["registryWrite"]
    );
    let mut calls = 0;
    let tightened = negotiate_with_cache(
        &original,
        &mut cache,
        Vec::new(),
        prepare,
        |_, policy| {
            calls += 1;
            if policy.capabilities.is_empty() {
                Ok(())
            } else {
                Err(remove("registryWrite"))
            }
        },
        |_| Ok(()),
    )
    .unwrap();
    assert_eq!(calls, 2);
    assert_eq!(
        tightened.warnings,
        [format!(
            "{UPDATE_WARNING_PREFIX}processContainer.capabilities (effective request): \
             [\"registryWrite\"] -> []"
        )],
        "only the newly required correction should be reported"
    );
    let mut calls = 0;
    let reused = negotiate_with_cache(
        &original,
        &mut cache,
        Vec::new(),
        prepare,
        |_, policy| {
            calls += 1;
            assert!(
                policy.capabilities.is_empty(),
                "a relaxed ceiling does not restore grants"
            );
            Ok(())
        },
        |_| Ok(()),
    )
    .unwrap();
    assert_eq!(calls, 1);
    assert!(reused.warnings.is_empty());
}

#[test]
fn mutation_cache_revalidates_serviceability_and_prepare_failures() {
    let original = request();
    let mut cache = cache::Cache::default();
    learn_read(&original, &mut cache);
    let error = negotiate_with_cache::<()>(
        &original,
        &mut cache,
        Vec::new(),
        |request| {
            assert!(request
                .policy
                .capabilities
                .iter()
                .any(|capability| capability == "registryRead"));
            prepare(request)
        },
        |_, _| panic!("invalid remembered policy must not be created"),
        |_| Err(ScriptResponse::rejected("native support changed")),
    )
    .unwrap_err();
    assert!(error.error_message.contains("native support changed"));
    assert!(error.error_message.contains("remembered restrictions"));
    assert!(!error.error_message.contains(UPDATE_WARNING_PREFIX));
    assert!(!error
        .error_message
        .contains("Attempted creation-policy changes"));
    let error = negotiate_with_cache::<()>(
        &original,
        &mut cache,
        Vec::new(),
        |request| {
            if request
                .policy
                .capabilities
                .iter()
                .any(|capability| capability == "registryRead")
            {
                prepare(request)
            } else {
                Err(ScriptResponse::rejected("cannot prepare"))
            }
        },
        |_, _| panic!("preparation failed"),
        |_| Ok(()),
    )
    .unwrap_err();
    assert!(error.error_message.contains("cannot prepare"));
    assert!(!error.error_message.contains(UPDATE_WARNING_PREFIX));
    assert!(!error
        .error_message
        .contains("Attempted creation-policy changes"));
}

#[test]
fn mutation_cache_desktop_deny_retry_preserves_submitted_enumeration_paths() {
    let desktop = r"C:\Users\AdminUser\Desktop";
    let denied = r"C:\Users\AdminUser\Desktop\denied";
    let mut original = request();
    original.policy.readwrite_paths = vec![desktop.into()];
    original.policy.enumerate_paths = vec![r"C:\Users\AdminUser".into(), r"C:\bootstrap".into()];
    let mut cache = cache::Cache::default();
    for expected in [2, 1] {
        let mut calls = 0;
        let result = negotiate_with_cache(
            &original,
            &mut cache,
            Vec::new(),
            prepare,
            |prepared, policy| {
                calls += 1;
                let spec =
                    psec::root_as_process_security_environment(&prepared.specification).unwrap();
                assert_eq!(
                    spec.fs_enumerate().unwrap().iter().collect::<Vec<_>>(),
                    [r"C:\Users\AdminUser", r"C:\bootstrap"],
                );
                assert_eq!(
                    spec.fs_read_write().unwrap().iter().collect::<Vec<_>>(),
                    [desktop]
                );
                if policy
                    .denied_paths
                    .iter()
                    .any(|path| path.eq_ignore_ascii_case(denied))
                {
                    assert!(spec
                        .fs_deny()
                        .unwrap()
                        .iter()
                        .any(|path| path.eq_ignore_ascii_case(denied)));
                    Ok(())
                } else {
                    Err(CreationError::test_policy_refusal(vec![
                        MutationHint::RestrictPath {
                            path: denied.into(),
                            requested: 2,
                            maximum: 0,
                        },
                    ]))
                }
            },
            |_| Ok(()),
        )
        .unwrap();
        assert_eq!(calls, expected);
        assert_eq!(result.warnings.len(), usize::from(expected == 2));
        assert_eq!(result.request.policy.denied_paths, [denied]);
        assert_eq!(
            result.request.policy.enumerate_paths,
            original.policy.enumerate_paths
        );
    }
}

#[test]
fn mutation_cache_preserves_fresh_ca_grants_and_proxy_endpoints_while_reusing_a_path_ceiling() {
    let desktop = r"C:\Users\AdminUser\Desktop";
    let denied = r"C:\Users\AdminUser\Desktop\denied";
    let mut cache = cache::Cache::default();
    for index in 0..3 {
        let mut original = request();
        original.policy.readwrite_paths = vec![desktop.into()];
        original.policy.readonly_paths = vec![format!(
            r"C:\Users\AdminUser\AppData\Local\Temp\copilot-credential-ca-{index}.pem"
        )];
        original.policy.network_proxy = ProxyConfig {
            address: Some(ProxyAddress::new("127.0.0.1".into(), 8000 + index)),
        };
        original.policy.network_ingress = Some(NetworkIngressPolicy::default());
        original.policy.capture_denials = (index % 2 == 0).then(CaptureDenialsConfig::default);
        let mut calls = 0;
        let result = negotiate_with_cache(
            &original,
            &mut cache,
            Vec::new(),
            prepare,
            |_, policy| {
                calls += 1;
                if policy
                    .denied_paths
                    .iter()
                    .any(|path| path.eq_ignore_ascii_case(denied))
                {
                    Ok(())
                } else {
                    Err(CreationError::test_policy_refusal(vec![
                        MutationHint::RestrictPath {
                            path: denied.into(),
                            requested: 2,
                            maximum: 0,
                        },
                    ]))
                }
            },
            |_| Ok(()),
        )
        .unwrap();
        assert_eq!(calls, if index == 0 { 2 } else { 1 });
        let mut expected = original.policy.clone();
        expected.denied_paths.push(denied.into());
        assert_eq!(
            serde_json::to_value(&result.request.policy).unwrap(),
            serde_json::to_value(&expected).unwrap(),
            "cache reuse must change only the narrowing edit, never current unrelated fields"
        );
        assert_eq!(
            result
                .request
                .policy
                .network_proxy
                .address
                .as_ref()
                .unwrap()
                .port,
            8000 + index,
        );
        if index > 0 {
            assert!(result.warnings.is_empty());
        } else {
            assert!(result.warnings[0].starts_with(UPDATE_WARNING_PREFIX));
        }
    }
}

#[test]
fn mutation_cache_revalidates_current_access_and_does_not_reapply_an_existing_restriction() {
    let desktop = r"C:\Users\AdminUser\Desktop";
    let denied = r"C:\Users\AdminUser\Desktop\denied";
    let mut original = request();
    original.policy.readwrite_paths = vec![desktop.into()];
    let mut cache = cache::Cache::default();
    negotiate_with_cache(
        &original,
        &mut cache,
        Vec::new(),
        prepare,
        |_, policy| {
            if policy.denied_paths.is_empty() {
                Err(CreationError::test_policy_refusal(vec![
                    MutationHint::RestrictPath {
                        path: denied.into(),
                        requested: 2,
                        maximum: 0,
                    },
                ]))
            } else {
                Ok(())
            }
        },
        |_| Ok(()),
    )
    .unwrap();
    original.policy.readwrite_paths.clear();
    original.policy.readonly_paths = vec![desktop.into()];
    let mut calls = 0;
    let result = negotiate_with_cache(
        &original,
        &mut cache,
        Vec::new(),
        prepare,
        |_, policy| {
            calls += 1;
            assert_eq!(policy.readonly_paths, [desktop]);
            assert_eq!(policy.denied_paths, [denied]);
            Ok(())
        },
        |_| Ok(()),
    )
    .unwrap();
    assert_eq!(calls, 1);
    assert!(result.warnings.is_empty());

    original.policy.denied_paths = vec![denied.into()];
    let mut unchanged_calls = 0;
    let unchanged = negotiate_with_cache(
        &original,
        &mut cache,
        Vec::new(),
        prepare,
        |_, policy| {
            unchanged_calls += 1;
            assert_eq!(policy.readonly_paths, [desktop]);
            assert_eq!(policy.denied_paths, [denied]);
            Ok(())
        },
        |_| Ok(()),
    )
    .unwrap();
    assert_eq!(unchanged_calls, 1);
    assert!(unchanged.warnings.is_empty());
}

#[test]
fn mutation_cache_reuses_proxy_removal_and_capture_omission_in_the_native_form() {
    let mut original = request();
    original.policy.network_proxy = ProxyConfig {
        address: Some(ProxyAddress::new("127.0.0.1".into(), 8080)),
    };
    original.policy.runtime_network_proxy_specified = true;
    original.policy.network_egress = Some(NetworkEgressPolicy::default());
    original.policy.network_ingress = Some(NetworkIngressPolicy {
        default: NetworkAction::Allow,
        host_loopback: NetworkAction::Allow,
    });
    original.policy.capture_denials = Some(CaptureDenialsConfig::default());
    let mut cache = cache::Cache::default();
    let mut first = true;
    negotiate_with_cache(
        &original,
        &mut cache,
        Vec::new(),
        prepare,
        |_, _| {
            if std::mem::take(&mut first) {
                Err(remove("privateNetworkClientServer"))
            } else {
                Ok(())
            }
        },
        |_| Ok(()),
    )
    .unwrap();
    let mut calls = 0;
    negotiate_with_cache(
        &original,
        &mut cache,
        Vec::new(),
        prepare,
        |prepared, policy| {
            calls += 1;
            assert_eq!(prepared.version, SecurityEnvironmentVersion::V1_0);
            assert!(!prepared.capture_network_decisions);
            assert!(!policy.network_proxy.is_enabled());
            assert!(policy.capture_denials.is_none());
            let spec = psec::root_as_process_security_environment(&prepared.specification).unwrap();
            assert!(spec.network_policy().unwrap().proxy().is_none());
            Ok(())
        },
        |_| Ok(()),
    )
    .unwrap();
    assert_eq!(calls, 1);
}

#[test]
fn mutation_cache_reports_a_stricter_path_ceiling_once_then_reuses_it_silently() {
    let path = r"C:\Users\AdminUser\Desktop\project";
    let mut original = request();
    original.policy.readwrite_paths = vec![path.into()];
    let mut cache = cache::Cache::default();
    for (index, maximum) in [1, 0, 0].into_iter().enumerate() {
        let mut calls = 0;
        let result = negotiate_with_cache(
            &original,
            &mut cache,
            Vec::new(),
            prepare,
            |prepared, policy| {
                calls += 1;
                let spec =
                    psec::root_as_process_security_environment(&prepared.specification).unwrap();
                let requested = access_at(policy, path);
                if requested > maximum {
                    return Err(CreationError::test_policy_refusal(vec![
                        MutationHint::RestrictPath {
                            path: path.into(),
                            requested,
                            maximum,
                        },
                    ]));
                }
                assert_eq!(requested, maximum);
                assert!(spec.fs_read_write().is_none());
                if maximum == 1 {
                    assert_eq!(
                        spec.fs_read_only().unwrap().iter().collect::<Vec<_>>(),
                        [path]
                    );
                } else {
                    assert_eq!(spec.fs_deny().unwrap().iter().collect::<Vec<_>>(), [path]);
                }
                Ok(())
            },
            |_| Ok(()),
        )
        .unwrap();
        assert_eq!(calls, if index < 2 { 2 } else { 1 });
        if index < 2 {
            assert_eq!(result.warnings.len(), 2);
            assert!(result
                .warnings
                .iter()
                .all(|warning| warning.starts_with(UPDATE_WARNING_PREFIX)));
            if index == 1 {
                assert!(result
                    .warnings
                    .iter()
                    .all(|warning| !warning.contains("filesystem.readwritePaths")));
            }
        } else {
            assert!(result.warnings.is_empty());
        }
        assert_eq!(access_at(&original.policy, path), 2);
    }
}

#[test]
fn mutation_cache_serializes_learning_without_owning_environment_lifetimes() {
    use std::sync::{
        atomic::{AtomicUsize, Ordering},
        Barrier, Mutex,
    };
    let original = request();
    let cache = Mutex::new(cache::Cache::default());
    let calls = AtomicUsize::new(0);
    let notifications = AtomicUsize::new(0);
    let all_created = Barrier::new(4);
    std::thread::scope(|scope| {
        for _ in 0..4 {
            let original = &original;
            let cache = &cache;
            let calls = &calls;
            let notifications = &notifications;
            let all_created = &all_created;
            scope.spawn(move || {
                let result = {
                    let mut warnings = Vec::new();
                    let mut cache = cache::lock(cache, &mut warnings);
                    negotiate_with_cache(
                        original,
                        &mut cache,
                        warnings,
                        prepare,
                        |_, policy| {
                            calls.fetch_add(1, Ordering::SeqCst);
                            if policy
                                .capabilities
                                .iter()
                                .any(|value| value == "registryRead")
                            {
                                Err(remove("registryRead"))
                            } else {
                                Ok(())
                            }
                        },
                        |_| Ok(()),
                    )
                    .unwrap()
                };
                all_created.wait();
                assert_eq!(result.request.policy.capabilities, ["registryWrite"]);
                notifications.fetch_add(result.warnings.len(), Ordering::SeqCst);
            });
        }
    });
    assert_eq!(calls.load(Ordering::SeqCst), 5);
    assert_eq!(notifications.load(Ordering::SeqCst), 1);
}
