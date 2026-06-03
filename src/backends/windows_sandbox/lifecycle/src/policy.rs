// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Translate an [`ExecutionRequest`]'s filesystem and network policy into the
//! concrete primitives the transient one-shot Windows Sandbox backend can
//! enforce, rejecting anything it cannot express.
//!
//! Windows Sandbox shares **nothing** from the host by default, so the
//! filesystem model is additive: `readwrite`/`readonly` paths become extra
//! `<MappedFolder>` entries (read-write / read-only respectively), mapped at
//! the same absolute path inside the guest for host parity. `deniedPaths`
//! describe host paths the contained code must *not* reach; because the host
//! shares nothing by default, a denied path that lies outside every mapped
//! share is already satisfied (no-op). A denied path that is equal to, or
//! nested inside, a mapped share is a contradiction the backend cannot honor
//! (Windows Sandbox has no per-path Deny primitive), so it is rejected.
//!
//! Network model: the WSB **guest agent** already enforces network isolation
//! unconditionally — once the host connects, `guest::firewall::lockdown` sets a
//! default-deny-outbound (and -inbound) Windows Firewall policy, and the guest
//! is a pure listener (the host always reconnects inbound). So a `Block`
//! default network policy (also the schema default) is honored natively with
//! no host-side action. `Allow` cannot be granted without a guest-side change,
//! so it is rejected for now. Selective host filtering
//! (`allowedHosts`/`blockedHosts`) and an explicit proxy are likewise rejected
//! — the backend has no DNS-aware filtering primitive.

use wxc_common::models::{ExecutionRequest, NetworkPolicy};

use crate::error::OneShotError;
use crate::vm::MappedFolder;

/// The enforceable shape of a request's policy for one disposable run.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct WsbPolicyPlan {
    /// Extra host folders to expose inside the guest (beyond the fixed
    /// guest/rendezvous/python mappings).
    pub(crate) mapped_folders: Vec<MappedFolder>,
}

/// Validate the request's policy and produce a [`WsbPolicyPlan`], or a
/// [`OneShotError::Policy`] describing the first unenforceable element.
///
/// This performs only validation and read-only filesystem probing — it has no
/// side effects, so a rejection leaves the host untouched.
pub(crate) fn plan_policy(request: &ExecutionRequest) -> Result<WsbPolicyPlan, OneShotError> {
    validate_network(request)?;
    let mapped_folders = plan_filesystem(request)?;

    Ok(WsbPolicyPlan { mapped_folders })
}

/// Validate the network portion of the policy. `Block` (the schema default) is
/// honored natively by the guest agent's firewall lockdown, so it needs no
/// host-side action. Everything else the backend cannot express is rejected.
fn validate_network(request: &ExecutionRequest) -> Result<(), OneShotError> {
    let policy = &request.policy;

    if !policy.allowed_hosts.is_empty() || !policy.blocked_hosts.is_empty() {
        return Err(OneShotError::Policy(
            "per-host network filtering (allowedHosts/blockedHosts) is not supported by the \
             Windows Sandbox backend; the guest agent enforces all-or-nothing network isolation"
                .to_string(),
        ));
    }
    if policy.network_proxy.is_enabled() {
        return Err(OneShotError::Policy(
            "a network proxy is not supported by the Windows Sandbox backend".to_string(),
        ));
    }

    match policy.default_network_policy {
        // Honored natively: the guest agent locks the firewall down to
        // default-deny-outbound once the host connects.
        NetworkPolicy::Block => Ok(()),
        // The guest agent unconditionally blocks egress, so outbound network
        // access cannot be granted without a guest-side change.
        NetworkPolicy::Allow => Err(OneShotError::Policy(
            "outbound network access (network policy 'allow') is not supported by the Windows \
             Sandbox backend; the guest agent enforces network isolation"
                .to_string(),
        )),
    }
}

/// A mapped root in normalized form: the cleaned absolute string used for the
/// `.wsb` plus its lowercased path components for containment comparisons.
struct MappedRoot {
    display: String,
    components: Vec<String>,
    read_only: bool,
}

/// Resolve `readwrite`/`readonly` paths into mapped folders and validate
/// `deniedPaths` against them.
fn plan_filesystem(request: &ExecutionRequest) -> Result<Vec<MappedFolder>, OneShotError> {
    let policy = &request.policy;
    let mut roots: Vec<MappedRoot> = Vec::new();

    for path in &policy.readwrite_paths {
        add_mapped_root(&mut roots, path, false)?;
    }
    for path in &policy.readonly_paths {
        add_mapped_root(&mut roots, path, true)?;
    }

    reject_denied_inside_shares(&policy.denied_paths, &roots)?;

    Ok(roots
        .into_iter()
        .map(|root| MappedFolder {
            host: root.display.clone(),
            sandbox: root.display,
            read_only: root.read_only,
        })
        .collect())
}

/// Canonicalize `raw`, ensure it is an existing directory, and add it to
/// `roots` — rejecting missing paths, files, conflicting read-only flags for
/// the same path, and overlapping (nested) mapped roots.
fn add_mapped_root(
    roots: &mut Vec<MappedRoot>,
    raw: &str,
    read_only: bool,
) -> Result<(), OneShotError> {
    let canonical = std::fs::canonicalize(raw).map_err(|e| {
        OneShotError::Policy(format!(
            "mapped path {raw:?} does not exist or is inaccessible (Windows Sandbox cannot map a \
             missing host folder): {e}"
        ))
    })?;

    let is_dir = canonical.is_dir();
    let display = strip_verbatim_prefix(&canonical.to_string_lossy());
    if !is_dir {
        return Err(OneShotError::Policy(format!(
            "mapped path {raw:?} is a file; Windows Sandbox can only map directories. Map its \
             parent directory instead."
        )));
    }

    let components = path_components(&display);

    for existing in roots.iter() {
        if existing.components == components {
            if existing.read_only != read_only {
                return Err(OneShotError::Policy(format!(
                    "path {display:?} is listed as both read-write and read-only"
                )));
            }
            // Identical duplicate with the same access — collapse silently.
            return Ok(());
        }
        if is_descendant(&components, &existing.components)
            || is_descendant(&existing.components, &components)
        {
            return Err(OneShotError::Policy(format!(
                "mapped path {display:?} overlaps another mapped path {:?}; Windows Sandbox \
                 rejects nested mapped folders",
                existing.display
            )));
        }
    }

    roots.push(MappedRoot {
        display,
        components,
        read_only,
    });
    Ok(())
}

/// Reject any denied path that is equal to, or nested inside, a mapped share —
/// Windows Sandbox has no per-path Deny primitive, so the contradiction cannot
/// be honored. Denied paths outside every share are no-ops (the host shares
/// nothing by default) and are silently accepted.
fn reject_denied_inside_shares(
    denied_paths: &[String],
    roots: &[MappedRoot],
) -> Result<(), OneShotError> {
    for denied in denied_paths {
        // A denied path may not exist on the host, so normalize lexically
        // (no filesystem access). This shares the residual symlink/junction
        // gap noted in the module docs.
        let denied_components = path_components(&strip_verbatim_prefix(denied));
        if denied_components.is_empty() {
            continue;
        }
        for root in roots {
            if denied_components == root.components {
                return Err(OneShotError::Policy(format!(
                    "denied path {denied:?} is the same as mapped share {:?}; the Windows Sandbox \
                     backend cannot map a folder and deny it at the same time",
                    root.display
                )));
            }
            if is_descendant(&denied_components, &root.components) {
                return Err(OneShotError::Policy(format!(
                    "denied path {denied:?} lies inside mapped share {:?}; the Windows Sandbox \
                     backend cannot carve a denied subtree out of a mapped folder",
                    root.display
                )));
            }
        }
    }
    Ok(())
}

/// Strip a `\\?\` or `\\?\UNC\` verbatim prefix from a Windows path string.
/// `std::fs::canonicalize` returns verbatim paths, which Windows Sandbox does
/// not accept in a `.wsb`.
fn strip_verbatim_prefix(path: &str) -> String {
    if let Some(rest) = path.strip_prefix(r"\\?\UNC\") {
        format!(r"\\{rest}")
    } else if let Some(rest) = path.strip_prefix(r"\\?\") {
        rest.to_string()
    } else {
        path.to_string()
    }
}

/// Split a path into lowercased, normalized components for case-insensitive
/// comparison. `.` segments are dropped and `..` pops the previous component.
/// Drive/separator forms are unified by splitting on both `\` and `/`.
fn path_components(path: &str) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    for raw in path.split(['\\', '/']) {
        match raw {
            "" | "." => {}
            ".." => {
                out.pop();
            }
            seg => out.push(seg.to_ascii_lowercase()),
        }
    }
    out
}

/// True when `child` is strictly nested inside `ancestor` (component-wise
/// prefix, longer than the ancestor). Component-wise comparison avoids the
/// `C:\foo` vs `C:\foobar` false positive a string-prefix test would hit.
fn is_descendant(child: &[String], ancestor: &[String]) -> bool {
    child.len() > ancestor.len() && child.starts_with(ancestor)
}

#[cfg(test)]
mod tests {
    use super::*;
    use wxc_common::models::{ContainerPolicy, ProxyAddress, ProxyConfig};

    fn request_with(policy: ContainerPolicy) -> ExecutionRequest {
        ExecutionRequest {
            policy,
            ..Default::default()
        }
    }

    fn assert_policy_err_contains(err: OneShotError, expected: &str) {
        match err {
            OneShotError::Policy(msg) => {
                assert!(msg.contains(expected), "expected {expected:?} in {msg:?}")
            }
            other => panic!("expected Policy variant, got {other:?}"),
        }
    }

    // ===== network =====

    #[test]
    fn default_policy_blocks_network_and_maps_nothing() {
        // Schema default is Block, which is honored natively (guest enforces).
        let plan = plan_policy(&ExecutionRequest::default()).unwrap();
        assert!(plan.mapped_folders.is_empty());
    }

    #[test]
    fn allow_network_rejected() {
        let err = plan_policy(&request_with(ContainerPolicy {
            default_network_policy: NetworkPolicy::Allow,
            ..Default::default()
        }))
        .unwrap_err();
        assert_policy_err_contains(err, "outbound network access");
    }

    #[test]
    fn allowed_hosts_rejected() {
        let err = plan_policy(&request_with(ContainerPolicy {
            allowed_hosts: vec!["example.com".to_string()],
            ..Default::default()
        }))
        .unwrap_err();
        assert_policy_err_contains(err, "per-host network filtering");
    }

    #[test]
    fn blocked_hosts_rejected() {
        let err = plan_policy(&request_with(ContainerPolicy {
            blocked_hosts: vec!["evil.com".to_string()],
            ..Default::default()
        }))
        .unwrap_err();
        assert_policy_err_contains(err, "per-host network filtering");
    }

    #[test]
    fn proxy_rejected() {
        let err = plan_policy(&request_with(ContainerPolicy {
            network_proxy: ProxyConfig {
                address: Some(ProxyAddress::new("127.0.0.1".to_string(), 8080)),
                builtin_test_server: false,
            },
            ..Default::default()
        }))
        .unwrap_err();
        assert_policy_err_contains(err, "proxy");
    }

    // ===== filesystem =====

    #[test]
    fn readwrite_and_readonly_paths_become_mapped_folders() {
        let rw = tempfile::tempdir().unwrap();
        let ro = tempfile::tempdir().unwrap();
        let plan = plan_policy(&request_with(ContainerPolicy {
            readwrite_paths: vec![rw.path().to_string_lossy().into_owned()],
            readonly_paths: vec![ro.path().to_string_lossy().into_owned()],
            ..Default::default()
        }))
        .unwrap();
        assert_eq!(plan.mapped_folders.len(), 2);
        let rw_folder = plan.mapped_folders.iter().find(|f| !f.read_only).unwrap();
        let ro_folder = plan.mapped_folders.iter().find(|f| f.read_only).unwrap();
        // Host parity: sandbox path equals host path.
        assert_eq!(rw_folder.host, rw_folder.sandbox);
        assert_eq!(ro_folder.host, ro_folder.sandbox);
        // No verbatim prefix leaks into the .wsb value.
        assert!(!rw_folder.host.starts_with(r"\\?\"));
    }

    #[test]
    fn missing_path_rejected() {
        let err = plan_policy(&request_with(ContainerPolicy {
            readonly_paths: vec![r"C:\definitely\not\here\xyzzy".to_string()],
            ..Default::default()
        }))
        .unwrap_err();
        assert_policy_err_contains(err, "does not exist");
    }

    #[test]
    fn file_path_rejected() {
        let dir = tempfile::tempdir().unwrap();
        let file = dir.path().join("a.txt");
        std::fs::write(&file, b"x").unwrap();
        let err = plan_policy(&request_with(ContainerPolicy {
            readonly_paths: vec![file.to_string_lossy().into_owned()],
            ..Default::default()
        }))
        .unwrap_err();
        assert_policy_err_contains(err, "is a file");
    }

    #[test]
    fn conflicting_readonly_flags_rejected() {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().to_string_lossy().into_owned();
        let err = plan_policy(&request_with(ContainerPolicy {
            readwrite_paths: vec![p.clone()],
            readonly_paths: vec![p],
            ..Default::default()
        }))
        .unwrap_err();
        assert_policy_err_contains(err, "both read-write and read-only");
    }

    #[test]
    fn duplicate_same_access_collapses() {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().to_string_lossy().into_owned();
        let plan = plan_policy(&request_with(ContainerPolicy {
            readwrite_paths: vec![p.clone(), p],
            ..Default::default()
        }))
        .unwrap();
        assert_eq!(plan.mapped_folders.len(), 1);
    }

    #[test]
    fn nested_mapped_paths_rejected() {
        let parent = tempfile::tempdir().unwrap();
        let child = parent.path().join("child");
        std::fs::create_dir(&child).unwrap();
        let err = plan_policy(&request_with(ContainerPolicy {
            readwrite_paths: vec![parent.path().to_string_lossy().into_owned()],
            readonly_paths: vec![child.to_string_lossy().into_owned()],
            ..Default::default()
        }))
        .unwrap_err();
        assert_policy_err_contains(err, "overlaps");
    }

    // ===== denied paths =====

    #[test]
    fn denied_outside_shares_is_noop() {
        let dir = tempfile::tempdir().unwrap();
        let plan = plan_policy(&request_with(ContainerPolicy {
            readwrite_paths: vec![dir.path().to_string_lossy().into_owned()],
            denied_paths: vec![r"C:\some\unrelated\secret".to_string()],
            ..Default::default()
        }))
        .unwrap();
        assert_eq!(plan.mapped_folders.len(), 1);
    }

    #[test]
    fn denied_equal_to_mapped_share_rejected() {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().to_string_lossy().into_owned();
        let err = plan_policy(&request_with(ContainerPolicy {
            readwrite_paths: vec![p.clone()],
            denied_paths: vec![p],
            ..Default::default()
        }))
        .unwrap_err();
        assert_policy_err_contains(err, "same as mapped share");
    }

    #[test]
    fn denied_inside_mapped_share_rejected() {
        let dir = tempfile::tempdir().unwrap();
        let inside = format!("{}\\secret", dir.path().to_string_lossy());
        let err = plan_policy(&request_with(ContainerPolicy {
            readwrite_paths: vec![dir.path().to_string_lossy().into_owned()],
            denied_paths: vec![inside],
            ..Default::default()
        }))
        .unwrap_err();
        assert_policy_err_contains(err, "inside mapped share");
    }

    // ===== component helpers =====

    #[test]
    fn path_components_are_case_insensitive_and_normalized() {
        assert_eq!(
            path_components(r"C:\Foo\Bar"),
            path_components(r"c:/foo/bar/")
        );
        assert_eq!(
            path_components(r"C:\foo\.\bar"),
            path_components(r"C:\foo\bar")
        );
        assert_eq!(
            path_components(r"C:\foo\baz\..\bar"),
            path_components(r"C:\foo\bar")
        );
    }

    #[test]
    fn is_descendant_avoids_prefix_false_positive() {
        let foobar = path_components(r"C:\foobar");
        let foo = path_components(r"C:\foo");
        assert!(!is_descendant(&foobar, &foo));
        let foo_child = path_components(r"C:\foo\child");
        assert!(is_descendant(&foo_child, &foo));
        // Equal is not a descendant.
        assert!(!is_descendant(&foo, &foo));
    }

    #[test]
    fn strip_verbatim_prefix_handles_drive_and_unc() {
        assert_eq!(strip_verbatim_prefix(r"\\?\C:\foo"), r"C:\foo");
        assert_eq!(
            strip_verbatim_prefix(r"\\?\UNC\server\share"),
            r"\\server\share"
        );
        assert_eq!(strip_verbatim_prefix(r"C:\foo"), r"C:\foo");
    }
}
