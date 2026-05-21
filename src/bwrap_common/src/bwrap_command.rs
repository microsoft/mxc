// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Builds the `bwrap` CLI argument vector from a [`CodexRequest`].
//!
//! This module is platform-agnostic: it only produces a `Vec<String>` of
//! arguments without spawning any processes, so it compiles and can be
//! unit-tested on every host (Windows, macOS, Linux).

use wxc_common::models::{CodexRequest, NetworkPolicy};

/// Build the complete argument list for `bwrap` from the given request.
///
/// The returned vector does **not** include the `bwrap` binary name itself —
/// callers pass it to `Command::new("bwrap").args(&args)`.
pub fn build_args(request: &CodexRequest) -> Vec<String> {
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
    // configured. When allowedHosts / blockedHosts are present the runner
    // leaves the network namespace shared and applies iptables rules
    // separately (handled by the runner, not the command builder).
    let has_host_rules =
        !request.policy.allowed_hosts.is_empty() || !request.policy.blocked_hosts.is_empty();
    let full_block =
        request.policy.default_network_policy == NetworkPolicy::Block && !has_host_rules;
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
            args.extend(["--setenv".into(), key.into(), value.into()]);
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
    use wxc_common::models::{CodexRequest, NetworkPolicy};

    fn base_request() -> CodexRequest {
        CodexRequest {
            script_code: "echo hello".into(),
            working_directory: "/home/user".into(),
            ..Default::default()
        }
    }

    #[test]
    fn basic_args_contain_namespace_flags() {
        let args = build_args(&base_request());
        assert!(args.contains(&"--unshare-user".to_string()));
        assert!(args.contains(&"--unshare-pid".to_string()));
        assert!(args.contains(&"--unshare-ipc".to_string()));
        assert!(args.contains(&"--unshare-uts".to_string()));
    }

    #[test]
    fn network_block_adds_unshare_net() {
        let mut r = base_request();
        r.policy.default_network_policy = NetworkPolicy::Block;
        let args = build_args(&r);
        assert!(args.contains(&"--unshare-net".to_string()));
    }

    #[test]
    fn network_allow_omits_unshare_net() {
        let mut r = base_request();
        r.policy.default_network_policy = NetworkPolicy::Allow;
        let args = build_args(&r);
        assert!(!args.contains(&"--unshare-net".to_string()));
    }

    #[test]
    fn network_block_with_host_rules_omits_unshare_net() {
        let mut r = base_request();
        r.policy.default_network_policy = NetworkPolicy::Block;
        r.policy.allowed_hosts = vec!["example.com".into()];
        let args = build_args(&r);
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
        let args = build_args(&r);

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
        let args = build_args(&r);
        assert!(args.contains(&"--clearenv".to_string()));
        let foo_pos = args.iter().position(|a| a == "FOO").unwrap();
        assert_eq!(args[foo_pos - 1], "--setenv");
        assert_eq!(args[foo_pos + 1], "bar");
    }

    #[test]
    fn working_directory_is_set() {
        let args = build_args(&base_request());
        let chdir_pos = args.iter().position(|a| a == "--chdir").unwrap();
        assert_eq!(args[chdir_pos + 1], "/home/user");
    }

    #[test]
    fn command_is_last() {
        let args = build_args(&base_request());
        let sep = args.iter().position(|a| a == "--").unwrap();
        assert_eq!(args[sep + 1], "sh");
        assert_eq!(args[sep + 2], "-c");
        assert_eq!(args[sep + 3], "echo hello");
    }

    #[test]
    fn empty_working_directory_omits_chdir() {
        let mut r = base_request();
        r.working_directory = String::new();
        let args = build_args(&r);
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
        let args = build_args(&r);

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
}
