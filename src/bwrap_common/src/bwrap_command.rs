// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Builds the `bwrap` CLI argument vector from an [`ExecutionRequest`].
//!
//! This module is platform-agnostic: it only produces a `Vec<String>` of
//! arguments without spawning any processes, so it compiles and can be
//! unit-tested on every host (Windows, macOS, Linux).

use wxc_common::models::{ExecutionRequest, NetworkPolicy, ProxyAddress};

/// Env var keys that the proxy block manages. Listed here so we can strip
/// any conflicting entries the caller supplied via `request.env` (callers
/// must not be able to defeat the cooperative proxy by injecting their own
/// proxy env vars).
const PROXY_ENV_KEYS: &[&str] = &[
    "HTTP_PROXY",
    "HTTPS_PROXY",
    "http_proxy",
    "https_proxy",
    "NO_PROXY",
    "no_proxy",
];

/// Build the complete argument list for `bwrap` from the given request.
///
/// The returned vector does **not** include the `bwrap` binary name itself —
/// callers pass it to `Command::new("bwrap").args(&args)`.
///
/// `proxy_address` is the loopback address of the network proxy launched by
/// the Bubblewrap runner (if the request has `network.proxy` configured).
/// When `Some`, the builder:
/// - drops `--unshare-net` (the sandbox needs to reach the loopback proxy on
///   the host's network namespace),
/// - strips any caller-supplied `HTTP_PROXY` / `HTTPS_PROXY` / `NO_PROXY`
///   entries from `request.env`,
/// - emits `--setenv` for those keys pointing at the proxy URL.
pub fn build_args(request: &ExecutionRequest, proxy_address: Option<&ProxyAddress>) -> Vec<String> {
    // -- Namespace isolation (all unshared by default) ---------------------
    let mut args = vec![
        "--unshare-user",
        "--unshare-pid",
        "--unshare-ipc",
        "--unshare-uts",
    ]
    .into_iter()
    .map(String::from)
    .collect::<Vec<_>>();

    // Network: use --unshare-net for full block when no per-host rules are
    // configured AND no proxy is active. When allowedHosts / blockedHosts
    // are present the runner leaves the network namespace shared and
    // applies iptables rules separately. When a network proxy is active we
    // also keep the host network namespace so the sandbox can reach the
    // loopback proxy.
    let has_host_rules =
        !request.policy.allowed_hosts.is_empty() || !request.policy.blocked_hosts.is_empty();
    let full_block = request.policy.default_network_policy == NetworkPolicy::Block
        && !has_host_rules
        && proxy_address.is_none();
    if full_block {
        args.push("--unshare-net".into());
    }

    // -- Base filesystem ---------------------------------------------------
    // bwrap applies mounts in order; later mounts at the same path shadow
    // earlier ones. We therefore lay down the base + standard virtual
    // filesystems first, then apply user-supplied policy mounts last so they
    // always win, including when policy paths overlap a standard mount such
    // as `/tmp` (e.g. `readwritePaths: ["/tmp/workspace"]`).
    args.extend(["--ro-bind".into(), "/".into(), "/".into()]);

    // Standard virtual filesystems (applied before policy mounts so policy
    // paths under /dev, /proc, or /tmp survive).
    args.extend(["--dev".into(), "/dev".into()]);
    args.extend(["--proc".into(), "/proc".into()]);
    args.extend(["--tmpfs".into(), "/tmp".into()]);

    // Read-write paths (override the base ro-bind and any standard mount
    // they overlap).
    for path in &request.policy.readwrite_paths {
        args.extend(["--bind".into(), path.clone(), path.clone()]);
    }

    // Read-only paths (already covered by the base ro-bind, but listed
    // explicitly so the intent is clear and they override any rw parent).
    for path in &request.policy.readonly_paths {
        args.extend(["--ro-bind".into(), path.clone(), path.clone()]);
    }

    // Denied paths: mask with an empty tmpfs so contents are invisible.
    for path in &request.policy.denied_paths {
        args.extend(["--tmpfs".into(), path.clone()]);
    }

    // -- Working directory -------------------------------------------------
    if !request.working_directory.is_empty() {
        args.extend(["--chdir".into(), request.working_directory.clone()]);
    }

    // -- Environment -------------------------------------------------------
    // Clear the inherited environment, then set only the vars from the
    // request so the sandbox has a minimal, predictable environment.
    args.push("--clearenv".into());
    for env_str in &request.env {
        if let Some((key, value)) = env_str.split_once('=') {
            // When the proxy is active, drop any caller-supplied proxy env
            // entries so they cannot override the values we set below.
            if proxy_address.is_some() && PROXY_ENV_KEYS.contains(&key) {
                continue;
            }
            args.extend(["--setenv".into(), key.into(), value.into()]);
        }
    }

    // -- Network proxy env vars -------------------------------------------
    // Cooperative env-var proxying: well-behaved tools (curl, requests,
    // etc.) honor these and route through the proxy where allow / block
    // enforcement happens. Tools that bypass these variables (raw sockets)
    // are NOT enforced -- this is a documented limitation of the
    // unprivileged proxy model.
    //
    // We deliberately do NOT set NO_PROXY here. Bubblewrap with a proxy
    // keeps the host network namespace shared, so without a NO_PROXY entry
    // a cooperating client doing `CONNECT 127.0.0.1:5432` (e.g. local
    // Postgres) still goes via the proxy, where the configured
    // allowed/blocked-hosts policy applies. Exempting loopback via
    // NO_PROXY would silently bypass that filtering for host-loopback
    // destinations.
    if let Some(addr) = proxy_address {
        let url = addr.to_url();
        for key in ["HTTP_PROXY", "HTTPS_PROXY", "http_proxy", "https_proxy"] {
            args.extend(["--setenv".into(), key.into(), url.clone()]);
        }
    }

    // -- Command -----------------------------------------------------------
    args.push("--".into());
    args.push("sh".into());
    args.push("-c".into());
    args.push(request.script_code.clone());

    args
}

#[cfg(test)]
mod tests {
    use super::*;
    use wxc_common::models::{ExecutionRequest, NetworkPolicy, ProxyAddress};

    fn base_request() -> ExecutionRequest {
        ExecutionRequest {
            script_code: "echo hello".into(),
            working_directory: "/home/user".into(),
            ..Default::default()
        }
    }

    #[test]
    fn basic_args_contain_namespace_flags() {
        let args = build_args(&base_request(), None);
        assert!(args.contains(&"--unshare-user".to_string()));
        assert!(args.contains(&"--unshare-pid".to_string()));
        assert!(args.contains(&"--unshare-ipc".to_string()));
        assert!(args.contains(&"--unshare-uts".to_string()));
    }

    #[test]
    fn network_block_adds_unshare_net() {
        let mut r = base_request();
        r.policy.default_network_policy = NetworkPolicy::Block;
        let args = build_args(&r, None);
        assert!(args.contains(&"--unshare-net".to_string()));
    }

    #[test]
    fn network_allow_omits_unshare_net() {
        let mut r = base_request();
        r.policy.default_network_policy = NetworkPolicy::Allow;
        let args = build_args(&r, None);
        assert!(!args.contains(&"--unshare-net".to_string()));
    }

    #[test]
    fn network_block_with_host_rules_omits_unshare_net() {
        let mut r = base_request();
        r.policy.default_network_policy = NetworkPolicy::Block;
        r.policy.allowed_hosts = vec!["example.com".into()];
        let args = build_args(&r, None);
        assert!(
            !args.contains(&"--unshare-net".to_string()),
            "should omit --unshare-net when host rules require iptables"
        );
    }

    #[test]
    fn filesystem_policy_produces_correct_mounts() {
        let mut r = base_request();
        r.policy.readwrite_paths = vec!["/workspace".into()];
        r.policy.readonly_paths = vec!["/data".into()];
        r.policy.denied_paths = vec!["/secrets".into()];
        let args = build_args(&r, None);

        // rw
        let rw_pos = args.iter().position(|a| a == "--bind").unwrap();
        assert_eq!(args[rw_pos + 1], "/workspace");
        assert_eq!(args[rw_pos + 2], "/workspace");

        // ro
        let ro_positions: Vec<_> = args
            .iter()
            .enumerate()
            .filter(|(_, a)| *a == "--ro-bind")
            .map(|(i, _)| i)
            .collect();
        // First --ro-bind is the base "/" mount, second is "/data"
        assert!(ro_positions.len() >= 2);
        let data_pos = *ro_positions.last().unwrap();
        assert_eq!(args[data_pos + 1], "/data");

        // denied
        let tmpfs_positions: Vec<_> = args
            .iter()
            .enumerate()
            .filter(|(_, a)| *a == "--tmpfs")
            .collect();
        let secrets_mount = tmpfs_positions
            .iter()
            .find(|(i, _)| args[i + 1] == "/secrets");
        assert!(
            secrets_mount.is_some(),
            "denied path should be tmpfs-masked"
        );
    }

    #[test]
    fn environment_variables_are_set() {
        let mut r = base_request();
        r.env = vec!["FOO=bar".into(), "PATH=/usr/bin".into()];
        let args = build_args(&r, None);
        assert!(args.contains(&"--clearenv".to_string()));
        let foo_pos = args.iter().position(|a| a == "FOO").unwrap();
        assert_eq!(args[foo_pos - 1], "--setenv");
        assert_eq!(args[foo_pos + 1], "bar");
    }

    #[test]
    fn working_directory_is_set() {
        let args = build_args(&base_request(), None);
        let chdir_pos = args.iter().position(|a| a == "--chdir").unwrap();
        assert_eq!(args[chdir_pos + 1], "/home/user");
    }

    #[test]
    fn command_is_last() {
        let args = build_args(&base_request(), None);
        let sep = args.iter().position(|a| a == "--").unwrap();
        assert_eq!(args[sep + 1], "sh");
        assert_eq!(args[sep + 2], "-c");
        assert_eq!(args[sep + 3], "echo hello");
    }

    #[test]
    fn empty_working_directory_omits_chdir() {
        let mut r = base_request();
        r.working_directory = String::new();
        let args = build_args(&r, None);
        assert!(!args.contains(&"--chdir".to_string()));
    }

    /// Regression test for policy-mount-shadowing bug:
    /// the hard-coded `--tmpfs /tmp` must NOT shadow user policy mounts
    /// whose paths fall under `/tmp`. With the original ordering the
    /// standard `/tmp` tmpfs was applied AFTER policy mounts and wiped them
    /// out. The fix is to lay standard mounts down first so user policy
    /// mounts always come after and win.
    #[test]
    fn policy_mounts_under_tmp_are_not_shadowed_by_standard_tmpfs() {
        let mut r = base_request();
        r.policy.readwrite_paths = vec!["/tmp/workspace".into()];
        r.policy.readonly_paths = vec!["/tmp/data".into()];
        r.policy.denied_paths = vec!["/tmp/secrets".into()];
        let args = build_args(&r, None);

        // Locate the position of the standard --tmpfs /tmp mount.
        let tmpfs_tmp_pos = args
            .windows(2)
            .position(|w| w[0] == "--tmpfs" && w[1] == "/tmp")
            .expect("standard --tmpfs /tmp must be present");

        // Helper: find the position of an "--<op> /tmp/<x>" mount, asserting
        // it comes AFTER the standard /tmp tmpfs so it actually applies.
        let assert_after = |op: &str, target: &str| {
            let pos = args
                .windows(2)
                .position(|w| w[0] == op && w[1] == target)
                .unwrap_or_else(|| panic!("missing {} {}", op, target));
            assert!(
                pos > tmpfs_tmp_pos,
                "{} {} (pos {}) must come after --tmpfs /tmp (pos {}) \
                     or it will be shadowed",
                op,
                target,
                pos,
                tmpfs_tmp_pos
            );
        };

        assert_after("--bind", "/tmp/workspace");
        assert_after("--ro-bind", "/tmp/data");
        assert_after("--tmpfs", "/tmp/secrets");
    }

    // ------- Network proxy env-var injection tests ----------------------

    #[test]
    fn proxy_active_omits_unshare_net_even_when_default_blocks() {
        let mut r = base_request();
        r.policy.default_network_policy = NetworkPolicy::Block;
        let addr = ProxyAddress::new("127.0.0.1".into(), 12345);
        let args = build_args(&r, Some(&addr));
        assert!(
            !args.contains(&"--unshare-net".to_string()),
            "proxy active must keep host netns so loopback proxy is reachable"
        );
    }

    #[test]
    fn proxy_active_injects_env_vars() {
        let r = base_request();
        let addr = ProxyAddress::new("127.0.0.1".into(), 7777);
        let args = build_args(&r, Some(&addr));

        // Each HTTP/HTTPS proxy key must be set via --setenv.
        for key in &["HTTP_PROXY", "HTTPS_PROXY", "http_proxy", "https_proxy"] {
            let pos = args
                .iter()
                .position(|a| a == *key)
                .unwrap_or_else(|| panic!("missing --setenv {} in {:?}", key, args));
            assert_eq!(args[pos - 1], "--setenv");
        }

        // Value points at the loopback proxy URL.
        let http_pos = args.iter().position(|a| a == "HTTP_PROXY").unwrap();
        assert_eq!(args[http_pos + 1], "http://127.0.0.1:7777");
    }

    #[test]
    fn proxy_active_does_not_exempt_loopback_via_no_proxy() {
        // Setting NO_PROXY=localhost,127.0.0.1 would let cooperating HTTP
        // clients bypass the proxy for host-loopback destinations.
        // Bubblewrap+proxy keeps the host netns shared, so that bypass
        // would silently defeat allowedHosts/blockedHosts for loopback.
        let r = base_request();
        let addr = ProxyAddress::new("127.0.0.1".into(), 7777);
        let args = build_args(&r, Some(&addr));

        assert!(
            !args.iter().any(|a| a == "NO_PROXY" || a == "no_proxy"),
            "proxy mode must not emit NO_PROXY/no_proxy --setenv pairs: {:?}",
            args,
        );
    }

    #[test]
    fn proxy_active_strips_caller_supplied_proxy_env() {
        let mut r = base_request();
        r.env = vec![
            "FOO=bar".into(),
            "HTTP_PROXY=http://attacker.example:9999".into(),
            "https_proxy=http://attacker.example:9999".into(),
            "PATH=/usr/bin".into(),
        ];
        let addr = ProxyAddress::new("127.0.0.1".into(), 9000);
        let args = build_args(&r, Some(&addr));

        // Caller-supplied proxy values must NOT appear.
        assert!(
            !args.iter().any(|a| a == "http://attacker.example:9999"),
            "caller-supplied proxy URL must be stripped"
        );

        // The legitimate (non-proxy) env vars are preserved.
        assert!(args.iter().any(|a| a == "FOO"));
        assert!(args.iter().any(|a| a == "PATH"));

        // The proxy URL is the one we set, not the attacker's.
        let http_pos = args.iter().position(|a| a == "HTTP_PROXY").unwrap();
        assert_eq!(args[http_pos + 1], "http://127.0.0.1:9000");
    }

    #[test]
    fn proxy_inactive_leaves_caller_supplied_proxy_env_intact() {
        // When the runner has not configured a proxy, the builder must NOT
        // strip env vars whose keys happen to match PROXY_ENV_KEYS -- those
        // are just regular env vars set by the caller for some other reason.
        let mut r = base_request();
        r.env = vec!["HTTP_PROXY=http://caller.example:8080".into()];
        let args = build_args(&r, None);

        let pos = args.iter().position(|a| a == "HTTP_PROXY").unwrap();
        assert_eq!(args[pos + 1], "http://caller.example:8080");
    }
}
