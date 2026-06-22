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

/// Read-only host paths bind-mounted into every Bubblewrap sandbox as the
/// deny-by-default baseline. Mirrors the seatbelt backend's
/// `SYSTEM_READ_ALLOW` (`src/backends/seatbelt/common/src/profile_builder.rs`):
/// just enough of the host for a shell, the dynamic linker, libc, and
/// system tools to work. Everything else — including the caller's `$HOME`,
/// `/root`, `/opt`, `/var`, `/sys`, `/mnt`, `/media`, and the rest of
/// `/run` — is invisible until the caller opts in via `readonlyPaths` /
/// `readwritePaths`.
///
/// Notes:
/// - Missing paths are silently skipped because the runner emits these
///   via `--ro-bind-try` (e.g. `/lib32` does not exist on x86_64-only
///   systems; `/run/systemd/resolve` does not exist on hosts without
///   systemd-resolved).
/// - On merged-usr distros (modern Debian, Ubuntu, Fedora, Arch) the
///   top-level `/bin`, `/sbin`, `/lib*` entries are symlinks pointing
///   under `/usr`. `bwrap` follows the source-side symlink, so the
///   bind-mount still succeeds and the sandbox sees `/bin/sh` etc.
/// - We deliberately do NOT bind `/usr` wholesale: that would expose
///   `/usr/local`, which contains locally-installed (and sometimes
///   user-managed) software. Callers who need `/usr/local` must list it
///   explicitly in `readonlyPaths`.
/// - We deliberately do NOT bind `/run` wholesale: `/run/user/<uid>`
///   holds the caller's D-Bus session socket, keyring sockets, and
///   ssh-agent socket. We only bind the well-known DNS stub-resolver
///   directories so name resolution still works when `/etc/resolv.conf`
///   is a symlink (the default on systemd-resolved hosts).
/// - To keep DNS working when `/etc/resolv.conf` points *outside* those
///   dirs, we also synthesise a `/var/run -> /run` compat symlink (for
///   `/var/run/...`-routed targets — older RHEL/CentOS-era and some
///   container images) and `--ro-bind-try` `/mnt/wsl/resolv.conf` (for
///   WSL). Neither exposes host `/var` or `/mnt` contents — only the
///   resolver path itself.
/// - `/etc` is bound whole because cherry-picking files (`passwd`,
///   `nsswitch.conf`, `ssl/`, `ld.so.conf*`, …) is fragile and breaks
///   tools that read other config files. Files with sensitive contents
///   (`/etc/shadow`, `/etc/sudoers`, `/etc/ssh/ssh_host_*_key`) are mode
///   `0400` / `0640` root and remain unreadable to a non-root caller —
///   user-namespace UID mapping does not bypass kernel DAC.
const BASELINE_RO_BIND_PATHS: &[&str] = &[
    // Top-level executable / library dirs (symlinks under /usr on
    // merged-usr distros, real directories on Alpine and older Debian).
    "/bin",
    "/sbin",
    "/lib",
    "/lib32",
    "/lib64",
    "/libx32",
    // /usr subpaths — aligned with seatbelt's baseline, intentionally
    // excluding /usr/local.
    "/usr/bin",
    "/usr/sbin",
    "/usr/lib",
    "/usr/lib32",
    "/usr/lib64",
    "/usr/libexec",
    "/usr/share",
    // System configuration (ld.so config, certs, resolv.conf, hosts,
    // passwd, group, machine-id, …). See module-level note on DAC.
    "/etc",
    // DNS stub-resolver directories. /etc/resolv.conf is usually a
    // symlink into one of these on modern Linux distros (systemd-resolved
    // / NetworkManager / resolvconf). We bind the narrow subdirectories
    // rather than all of /run to avoid exposing /run/user/<uid>.
    "/run/systemd/resolve",
    "/run/NetworkManager",
    "/run/resolvconf",
    // WSL generates its resolv.conf here and points /etc/resolv.conf at
    // it. Bind just this single file (not /mnt) so DNS works under WSL
    // without exposing the Windows drive mounts. Skipped on non-WSL hosts
    // because the baseline is emitted via `--ro-bind-try`.
    "/mnt/wsl/resolv.conf",
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

    // -- Base filesystem (deny-by-default; see `BASELINE_RO_BIND_PATHS`) ---
    // bwrap applies mounts in order; later mounts at the same path shadow
    // earlier ones. We therefore lay the baseline + standard virtual
    // filesystems down first, then apply user-supplied policy mounts last
    // so they always win when paths overlap (e.g. `readwritePaths:
    // ["/tmp/workspace"]` must beat the standard `--tmpfs /tmp`).
    for path in BASELINE_RO_BIND_PATHS {
        args.extend(["--ro-bind-try".into(), (*path).into(), (*path).into()]);
    }

    // Recreate the standard `/var/run -> /run` compatibility symlink. Some
    // distros (older RHEL/CentOS-era, some container images) write
    // `/etc/resolv.conf` as a symlink routed through `/var/run/...` (e.g.
    // `/var/run/NetworkManager/resolv.conf`). We never mount `/var`, so that
    // intermediate path would dangle inside the sandbox and DNS would
    // silently fail. The symlink rescues the whole `/var/run/...` family and
    // pulls no host `/var` contents in (bwrap synthesises an empty `/var`).
    args.extend(["--symlink".into(), "/run".into(), "/var/run".into()]);

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

        // ro — baseline paths are emitted via --ro-bind-try, so a bare
        // --ro-bind must correspond to the user's readonlyPaths entry.
        args.windows(3)
            .position(|w| w[0] == "--ro-bind" && w[1] == "/data" && w[2] == "/data")
            .expect("readonly policy path /data should produce a --ro-bind mount");

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

    // ------- Deny-by-default baseline filesystem tests ------------------

    /// Regression test for the original `--ro-bind / /` baseline. The
    /// builder must NOT bind-mount the entire host root, because that
    /// exposed `$HOME` and other confidential dirs by default. Mirrors
    /// the seatbelt backend's `(deny default)` posture.
    #[test]
    fn baseline_does_not_bind_mount_host_root() {
        let args = build_args(&base_request(), None);
        let root_bind = args
            .windows(3)
            .any(|w| (w[0] == "--ro-bind" || w[0] == "--bind") && w[1] == "/" && w[2] == "/");
        assert!(
            !root_bind,
            "baseline must not bind-mount host / into the sandbox; got: {:?}",
            args
        );
    }

    /// The minimum baseline allowlist required for a shell + dynamic
    /// linker + libc to function inside the sandbox. Emitted via
    /// `--ro-bind-try` so missing paths are silently skipped on distros
    /// where they don't exist (e.g. `/lib32` on x86_64-only systems).
    #[test]
    fn baseline_emits_required_ro_bind_try_paths() {
        let args = build_args(&base_request(), None);
        let required = [
            "/bin",
            "/sbin",
            "/lib",
            "/lib64",
            "/usr/bin",
            "/usr/lib",
            "/usr/share",
            "/etc",
        ];
        for path in required {
            let found = args
                .windows(3)
                .any(|w| w[0] == "--ro-bind-try" && w[1] == path && w[2] == path);
            assert!(
                found,
                "baseline must emit `--ro-bind-try {} {}` so sandboxed processes \
                 can find sh / libc / system config",
                path, path
            );
        }
    }

    /// The baseline must NOT include `/usr` wholesale because that would
    /// expose `/usr/local` (locally-installed software, sometimes
    /// user-managed). Seatbelt's `SYSTEM_READ_ALLOW` does not include
    /// `/usr/local` either — match that posture.
    #[test]
    fn baseline_does_not_expose_usr_local() {
        let args = build_args(&base_request(), None);
        // No `--ro-bind /usr /usr` and no `--ro-bind-try /usr /usr`.
        let usr_whole = args
            .windows(3)
            .any(|w| matches!(w[0].as_str(), "--ro-bind" | "--ro-bind-try") && w[1] == "/usr");
        assert!(
            !usr_whole,
            "baseline must bind /usr subpaths individually so /usr/local is \
             not implicitly exposed; got: {:?}",
            args
        );
        // And no explicit /usr/local mount either. Restrict the scan to
        // mount-argument windows so a script body that merely mentions
        // `/usr/local` cannot trigger a false positive.
        let usr_local = args.windows(3).any(|w| {
            matches!(w[0].as_str(), "--bind" | "--ro-bind" | "--ro-bind-try")
                && w[1] == "/usr/local"
        });
        assert!(!usr_local, "baseline must not expose /usr/local by default");
    }

    /// The baseline must keep confidential host locations out of the
    /// sandbox. Callers who legitimately need any of these can opt in
    /// via `readonlyPaths`.
    #[test]
    fn baseline_excludes_confidential_paths() {
        let args = build_args(&base_request(), None);
        for forbidden in [
            "/home",
            "/root",
            "/opt",
            "/srv",
            "/var",
            "/sys",
            "/run/user",
            "/run/dbus",
        ] {
            let exposed = args.windows(2).any(|w| {
                matches!(w[0].as_str(), "--bind" | "--ro-bind" | "--ro-bind-try")
                    && w[1] == forbidden
            });
            assert!(
                !exposed,
                "baseline must not bind-mount {} — that would re-expose \
                 confidential host state",
                forbidden
            );
        }
    }

    /// DNS stub-resolver dirs must be in the baseline so `/etc/resolv.conf`
    /// symlinks resolve when the caller has network access. Emitted via
    /// `--ro-bind-try` so hosts without systemd-resolved / NetworkManager /
    /// resolvconf still build a valid argument vector.
    #[test]
    fn baseline_includes_dns_stub_resolver_dirs() {
        let args = build_args(&base_request(), None);
        for path in [
            "/run/systemd/resolve",
            "/run/NetworkManager",
            "/run/resolvconf",
        ] {
            let found = args
                .windows(3)
                .any(|w| w[0] == "--ro-bind-try" && w[1] == path && w[2] == path);
            assert!(
                found,
                "baseline must emit `--ro-bind-try {} {}` so DNS works when \
                 /etc/resolv.conf is a symlink",
                path, path
            );
        }
    }

    /// Regression test for the `/etc/resolv.conf -> /var/run/.../resolv.conf`
    /// symlink case (older RHEL/CentOS-era, some container images). We never
    /// mount `/var`, so without a `/var/run -> /run` compat symlink the
    /// target dangles and DNS silently breaks. Assert the symlink is emitted
    /// so `/var/run/NetworkManager/resolv.conf` resolves into the bound
    /// `/run/NetworkManager`.
    #[test]
    fn baseline_recreates_var_run_compat_symlink() {
        let args = build_args(&base_request(), None);
        let found = args
            .windows(3)
            .any(|w| w[0] == "--symlink" && w[1] == "/run" && w[2] == "/var/run");
        assert!(
            found,
            "baseline must emit `--symlink /run /var/run` so /etc/resolv.conf \
             symlinks routed through /var/run/... resolve; got: {:?}",
            args
        );
        // The compat symlink must not drag a host /var bind in with it.
        let var_bound = args.windows(2).any(|w| {
            matches!(w[0].as_str(), "--bind" | "--ro-bind" | "--ro-bind-try") && w[1] == "/var"
        });
        assert!(!var_bound, "compat symlink must not bind host /var");
    }

    /// Regression test for WSL, where `/etc/resolv.conf` points at
    /// `/mnt/wsl/resolv.conf`. We bind that single file (via `--ro-bind-try`,
    /// so it is skipped on non-WSL hosts) without exposing the rest of
    /// `/mnt`.
    #[test]
    fn baseline_includes_wsl_resolv_conf() {
        let args = build_args(&base_request(), None);
        let found = args.windows(3).any(|w| {
            w[0] == "--ro-bind-try"
                && w[1] == "/mnt/wsl/resolv.conf"
                && w[2] == "/mnt/wsl/resolv.conf"
        });
        assert!(
            found,
            "baseline must emit `--ro-bind-try /mnt/wsl/resolv.conf ...` so DNS \
             works under WSL; got: {:?}",
            args
        );
        // Only the single resolv.conf file — never /mnt or /mnt/wsl wholesale.
        let mnt_whole = args.windows(2).any(|w| {
            matches!(w[0].as_str(), "--bind" | "--ro-bind" | "--ro-bind-try")
                && (w[1] == "/mnt" || w[1] == "/mnt/wsl")
        });
        assert!(
            !mnt_whole,
            "baseline must not expose /mnt or /mnt/wsl wholesale"
        );
    }

    /// Baseline mounts must come before policy mounts so the user's
    /// `readwritePaths` / `readonlyPaths` / `deniedPaths` always win on
    /// conflict (same shadowing rule as the existing `/tmp` regression
    /// test, applied here to the baseline).
    #[test]
    fn baseline_mounts_precede_policy_mounts() {
        let mut r = base_request();
        r.policy.readwrite_paths = vec!["/etc/policy-writable".into()];
        let args = build_args(&r, None);

        let baseline_etc = args
            .windows(3)
            .position(|w| w[0] == "--ro-bind-try" && w[1] == "/etc" && w[2] == "/etc")
            .expect("baseline /etc bind missing");
        let policy_bind = args
            .windows(3)
            .position(|w| w[0] == "--bind" && w[1] == "/etc/policy-writable")
            .expect("policy bind missing");

        assert!(
            policy_bind > baseline_etc,
            "policy mount at /etc/policy-writable (pos {}) must come after \
             baseline /etc bind (pos {}) so the policy mount wins",
            policy_bind,
            baseline_etc
        );
    }
}
