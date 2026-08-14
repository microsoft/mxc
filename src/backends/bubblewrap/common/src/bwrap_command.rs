// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Builds the `bwrap` CLI argument vector from an [`ExecutionRequest`].
//!
//! This module is platform-agnostic: it only produces a `Vec<String>` of
//! arguments without spawning any processes, so it compiles and can be
//! unit-tested on every host (Windows, macOS, Linux).

use std::collections::HashSet;

use wxc_common::filesystem_resolve::FsIntent;
use wxc_common::models::{ExecutionRequest, NetworkEnforcementMode, NetworkPolicy, ProxyAddress};
use wxc_common::proxy_env::{is_managed_proxy_key, PROXY_SET_KEYS};

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

/// The networking behavior Bubblewrap applies for one execution.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ResolvedNetworkMode {
    /// A private network namespace with no external connectivity.
    Isolated,
    /// The host network namespace without MXC firewall filtering.
    Shared,
    /// Pre-0.8 cooperative proxy routing in the host network namespace.
    LegacyProxy,
    /// The host network namespace with per-destination iptables filtering.
    FirewallFiltered,
    /// Cooperative proxy routing inside a slirp-backed private namespace.
    /// Later work adds proxy-only egress enforcement.
    ProxyOnly,
}

/// Whether this schema opts into the 0.8 private proxy-network contract.
fn uses_private_proxy_network(request: &ExecutionRequest) -> bool {
    let mut components = request.schema_version.split('.');
    let major = components
        .next()
        .and_then(|value| value.parse::<u64>().ok());
    let minor = components
        .next()
        .and_then(|value| value.parse::<u64>().ok());
    matches!((major, minor), (Some(major), Some(minor)) if major > 0 || minor >= 8)
}

impl ResolvedNetworkMode {
    /// Classify the internal request using the proxy's resolved runtime state.
    pub(crate) fn from_request(request: &ExecutionRequest, proxy_active: bool) -> Self {
        if proxy_active {
            return if uses_private_proxy_network(request) {
                Self::ProxyOnly
            } else {
                Self::LegacyProxy
            };
        }

        let uses_firewall = matches!(
            request.policy.network_enforcement_mode,
            NetworkEnforcementMode::Firewall | NetworkEnforcementMode::Both
        );
        let has_host_rules =
            !request.policy.allowed_hosts.is_empty() || !request.policy.blocked_hosts.is_empty();

        if uses_firewall && has_host_rules {
            Self::FirewallFiltered
        } else if request.policy.default_network_policy == NetworkPolicy::Block && !has_host_rules {
            Self::Isolated
        } else {
            Self::Shared
        }
    }

    /// Whether current behavior gives the sandbox a private network namespace.
    pub(crate) fn uses_private_netns(self) -> bool {
        matches!(self, Self::Isolated | Self::ProxyOnly)
    }

    /// Whether the runner supplies a pre-created user namespace to Bubblewrap.
    pub(crate) fn uses_external_userns(self) -> bool {
        matches!(self, Self::ProxyOnly)
    }

    /// Whether current behavior installs iptables filtering rules.
    #[cfg(any(target_os = "linux", test))]
    pub(crate) fn requires_iptables(self) -> bool {
        matches!(self, Self::FirewallFiltered)
    }
}

/// Describe a `network.allowLocalNetwork` setting Bubblewrap cannot honor, or
/// `None` when the sandbox's namespace already matches the request.
///
/// `allowLocalNetwork` governs whether the sandboxed process may bind/listen on
/// local IPs and accept **inbound** connections (it says nothing about outbound
/// reachability of local addresses — that is `defaultPolicy`/`allowedHosts`).
/// Bubblewrap has no inbound-only primitive: the sandbox either gets a private
/// network namespace or shares the host's, and neither can be narrowed further.
/// Unprivileged bwrap has no veth to scope iptables to, and seccomp cannot
/// dereference the `sockaddr` passed to `bind`, so an AF_INET-only filter is not
/// expressible. The namespace choice therefore decides the outcome, and this
/// returns the mismatch so the runner can say so out loud rather than dropping
/// the field silently.
///
/// The private-namespace arm satisfies `false` only at the sandbox boundary:
/// bwrap brings `lo` up inside the new namespace, so sandbox processes can still
/// bind and connect to each other over their own loopback. That stays inside the
/// caller's trust boundary — those processes already share pipes, files and the
/// mount namespace — so it is not warned about.
pub fn local_network_diagnostic(
    request: &ExecutionRequest,
    proxy_address: Option<&ProxyAddress>,
) -> Option<&'static str> {
    let network_mode = ResolvedNetworkMode::from_request(request, proxy_address.is_some());
    local_network_diagnostic_for_mode(request, network_mode)
}

/// Describe an inbound-policy mismatch using a previously resolved mode.
pub(crate) fn local_network_diagnostic_for_mode(
    request: &ExecutionRequest,
    network_mode: ResolvedNetworkMode,
) -> Option<&'static str> {
    match (
        request.policy.allow_local_network,
        network_mode.uses_private_netns(),
    ) {
        (false, false) => Some(
            "WARNING: Bubblewrap: network.allowLocalNetwork=false is not enforced while the \
             sandbox shares the host network namespace (defaultPolicy='allow'). \
             The sandboxed process can still bind, listen and accept on host-local addresses. For \
             an unreachable sandbox use defaultPolicy='block' with no proxy, which applies \
             --unshare-net.",
        ),
        (true, true) => Some(
            "WARNING: Bubblewrap: network.allowLocalNetwork=true is confined to the sandbox's own \
             network namespace. Isolated and proxy modes apply --unshare-net, so a listener inside \
             the sandbox is reachable only from within it, never from the host. Use \
             defaultPolicy='allow' without a proxy to share the host network namespace.",
        ),
        _ => None,
    }
}

/// Build the complete `bwrap` argument list, masking **every** denied path as a
/// directory (`--tmpfs`).
///
/// This is the pure, classification-free entry point: it performs no filesystem
/// I/O and so stays unit-testable on every host. Unit tests and any caller that
/// has not stat'd the denied paths use it. The Bubblewrap runner uses
/// [`build_args_classified`] instead. See
/// docs/bwrap-support/bubblewrap-backend.md for how denied paths are masked.
pub fn build_args(request: &ExecutionRequest, proxy_address: Option<&ProxyAddress>) -> Vec<String> {
    build_args_classified(request, proxy_address, &HashSet::new())
}

/// Build the complete argument list for `bwrap` from the given request.
///
/// The returned vector does **not** include the `bwrap` binary name itself —
/// callers pass it to `Command::new("bwrap").args(&args)`.
///
/// `proxy_address` is the proxy endpoint visible from the sandbox (if the
/// request has `network.proxy` configured).
/// When `Some`, the builder:
/// - emits `--unshare-net` and expects the runner to provide `--userns FD`
///   plus slirp-backed connectivity,
/// - strips any caller-supplied `HTTP_PROXY` / `HTTPS_PROXY` / `ALL_PROXY` /
///   `FTP_PROXY` / `NO_PROXY` entries from `request.env`,
/// - emits `--setenv` for the proxy keys (all but `NO_PROXY`) pointing at the
///   proxy URL.
///
/// `denied_files` is the set of `deniedPaths` entries the runner classified as
/// files (built by `symlink_metadata`-probing each denied path, so this function
/// performs no filesystem I/O and stays unit-testable on every host). See
/// docs/bwrap-support/bubblewrap-backend.md for how denied paths are masked.
pub fn build_args_classified(
    request: &ExecutionRequest,
    proxy_address: Option<&ProxyAddress>,
    denied_files: &HashSet<String>,
) -> Vec<String> {
    let network_mode = ResolvedNetworkMode::from_request(request, proxy_address.is_some());
    build_args_classified_with_mode(request, proxy_address, denied_files, network_mode)
}

/// Build Bubblewrap arguments using a previously resolved network mode.
pub(crate) fn build_args_classified_with_mode(
    request: &ExecutionRequest,
    proxy_address: Option<&ProxyAddress>,
    denied_files: &HashSet<String>,
    network_mode: ResolvedNetworkMode,
) -> Vec<String> {
    // -- Namespace isolation (all unshared by default) ---------------------
    let mut args = Vec::new();
    if !network_mode.uses_external_userns() {
        args.push("--unshare-user".into());
    }
    args.extend(
        ["--unshare-pid", "--unshare-ipc", "--unshare-uts"]
            .into_iter()
            .map(String::from),
    );

    // Network: full-block and proxy modes use a private namespace. Proxy mode
    // receives rootless connectivity from the runner's slirp supervisor.
    // Per-host firewall mode continues to share the host namespace.
    if network_mode.uses_private_netns() {
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

    // Policy mounts, emitted in most-specific-path-wins order so a deeper path
    // always overrides a shallower ancestor with a different intent regardless
    // of which policy list it came from (e.g. `readwritePaths: ["/data/secrets"]`
    // must survive `deniedPaths: ["/data"]`). bwrap applies mounts in order and
    // the last at a path wins, so walking the specificity-ordered list last —
    // after the baseline + virtual filesystems above — gives the intended
    // precedence. `resolve_mount_order` assumes object normalization already ran
    // (it does, in the runner before `build_args`), so exact same-path conflicts
    // are already collapsed to the strictest intent.
    for mount in wxc_common::filesystem_resolve::resolve_mount_order(&request.policy) {
        match mount.intent {
            // Read-write: override the base ro-bind and any standard mount.
            FsIntent::ReadWrite => {
                args.extend(["--bind".into(), mount.path.clone(), mount.path.clone()]);
            }
            // Read-only: already covered by the base ro-bind, but listed
            // explicitly so the intent is clear and it overrides any rw parent.
            FsIntent::ReadOnly => {
                args.extend(["--ro-bind".into(), mount.path.clone(), mount.path.clone()]);
            }
            FsIntent::Denied => {
                if denied_files.contains(&mount.path) {
                    args.extend(["--ro-bind".into(), "/dev/null".into(), mount.path.clone()]);
                } else {
                    args.extend(["--tmpfs".into(), mount.path.clone()]);
                }
            }
        }
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
            if proxy_address.is_some() && is_managed_proxy_key(key) {
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
    // We deliberately do NOT set NO_PROXY here. Exempting any destination
    // would let cooperating clients bypass the configured proxy policy.
    if let Some(addr) = proxy_address {
        let url = addr.to_url();
        for key in PROXY_SET_KEYS {
            args.extend(["--setenv".into(), (*key).into(), url.clone()]);
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

    struct NetworkPlanCase {
        name: &'static str,
        default_policy: NetworkPolicy,
        enforcement_mode: NetworkEnforcementMode,
        allowed_hosts: &'static [&'static str],
        blocked_hosts: &'static [&'static str],
        proxy_active: bool,
        expected: ResolvedNetworkMode,
    }

    #[test]
    fn classifies_current_network_policy_modes() {
        let cases = [
            NetworkPlanCase {
                name: "default block is isolated",
                default_policy: NetworkPolicy::Block,
                enforcement_mode: NetworkEnforcementMode::Capabilities,
                allowed_hosts: &[],
                blocked_hosts: &[],
                proxy_active: false,
                expected: ResolvedNetworkMode::Isolated,
            },
            NetworkPlanCase {
                name: "default allow is shared",
                default_policy: NetworkPolicy::Allow,
                enforcement_mode: NetworkEnforcementMode::Capabilities,
                allowed_hosts: &[],
                blocked_hosts: &[],
                proxy_active: false,
                expected: ResolvedNetworkMode::Shared,
            },
            NetworkPlanCase {
                name: "firewall allow rules require filtering",
                default_policy: NetworkPolicy::Block,
                enforcement_mode: NetworkEnforcementMode::Firewall,
                allowed_hosts: &["example.com"],
                blocked_hosts: &[],
                proxy_active: false,
                expected: ResolvedNetworkMode::FirewallFiltered,
            },
            NetworkPlanCase {
                name: "combined enforcement block rules require filtering",
                default_policy: NetworkPolicy::Allow,
                enforcement_mode: NetworkEnforcementMode::Both,
                allowed_hosts: &[],
                blocked_hosts: &["example.com"],
                proxy_active: false,
                expected: ResolvedNetworkMode::FirewallFiltered,
            },
            NetworkPlanCase {
                name: "capabilities mode with host rules stays shared",
                default_policy: NetworkPolicy::Block,
                enforcement_mode: NetworkEnforcementMode::Capabilities,
                allowed_hosts: &["example.com"],
                blocked_hosts: &[],
                proxy_active: false,
                expected: ResolvedNetworkMode::Shared,
            },
            NetworkPlanCase {
                name: "proxy takes precedence over isolation",
                default_policy: NetworkPolicy::Block,
                enforcement_mode: NetworkEnforcementMode::Capabilities,
                allowed_hosts: &[],
                blocked_hosts: &[],
                proxy_active: true,
                expected: ResolvedNetworkMode::ProxyOnly,
            },
            NetworkPlanCase {
                name: "proxy takes precedence over firewall filtering",
                default_policy: NetworkPolicy::Allow,
                enforcement_mode: NetworkEnforcementMode::Firewall,
                allowed_hosts: &[],
                blocked_hosts: &["example.com"],
                proxy_active: true,
                expected: ResolvedNetworkMode::ProxyOnly,
            },
        ];

        for case in cases {
            let mut request = ExecutionRequest {
                schema_version: "0.8.0-alpha".into(),
                ..Default::default()
            };
            request.policy.default_network_policy = case.default_policy;
            request.policy.network_enforcement_mode = case.enforcement_mode;
            request.policy.allowed_hosts = case
                .allowed_hosts
                .iter()
                .map(|host| (*host).into())
                .collect();
            request.policy.blocked_hosts = case
                .blocked_hosts
                .iter()
                .map(|host| (*host).into())
                .collect();

            let actual = ResolvedNetworkMode::from_request(&request, case.proxy_active);
            assert_eq!(actual, case.expected, "{}", case.name);
        }
    }

    #[test]
    fn resolved_network_mode_capabilities_match_current_behavior() {
        assert!(ResolvedNetworkMode::Isolated.uses_private_netns());
        assert!(ResolvedNetworkMode::ProxyOnly.uses_private_netns());
        assert!(ResolvedNetworkMode::ProxyOnly.uses_external_userns());
        assert!(!ResolvedNetworkMode::Isolated.uses_external_userns());
        assert!(!ResolvedNetworkMode::LegacyProxy.uses_private_netns());
        assert!(ResolvedNetworkMode::FirewallFiltered.requires_iptables());
        assert!(!ResolvedNetworkMode::Shared.requires_iptables());
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

    // ------- allowLocalNetwork diagnostic tests -------------------------

    #[test]
    fn local_network_denied_under_private_netns_is_not_warned() {
        // Default policy (block, no host lists, no proxy) applies
        // --unshare-net: nothing outside can reach in, so allowLocalNetwork=false
        // is satisfied at the sandbox boundary and needs no warning.
        let r = base_request();
        assert!(!r.policy.allow_local_network);
        assert!(local_network_diagnostic(&r, None).is_none());
    }

    #[test]
    fn local_network_denied_on_shared_netns_warns() {
        let mut r = base_request();
        r.policy.default_network_policy = NetworkPolicy::Allow;
        let msg = local_network_diagnostic(&r, None).expect("shared netns cannot honor the deny");
        assert!(msg.contains("allowLocalNetwork=false"));
    }

    #[test]
    fn local_network_denied_with_host_rules_warns() {
        let mut r = base_request();
        r.policy.blocked_hosts = vec!["evil.example.com".into()];
        assert!(local_network_diagnostic(&r, None).is_some());
    }

    #[test]
    fn local_network_denied_with_legacy_proxy_warns() {
        let r = base_request();
        let addr = ProxyAddress::new("127.0.0.1".into(), 8080);
        assert!(local_network_diagnostic(&r, Some(&addr)).is_some());
    }

    #[test]
    fn local_network_denied_with_0_8_proxy_is_not_warned() {
        let mut r = base_request();
        r.schema_version = "0.8.0-alpha".into();
        let addr = ProxyAddress::new("127.0.0.1".into(), 8080);
        assert!(local_network_diagnostic(&r, Some(&addr)).is_none());
    }

    #[test]
    fn local_network_allowed_under_private_netns_warns() {
        let mut r = base_request();
        r.policy.allow_local_network = true;
        let msg = local_network_diagnostic(&r, None).expect("--unshare-net isolates the listener");
        assert!(msg.contains("allowLocalNetwork=true"));
    }

    #[test]
    fn local_network_allowed_on_shared_netns_is_honored() {
        let mut r = base_request();
        r.policy.allow_local_network = true;
        r.policy.default_network_policy = NetworkPolicy::Allow;
        assert!(local_network_diagnostic(&r, None).is_none());
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

    /// Helper: index of the `op` mount whose **destination** path is `path`.
    /// `--tmpfs` emits `op DEST` (one path); `--bind`/`--ro-bind` emit
    /// `op SRC DEST`, so the destination is the second path. Matching the
    /// destination (rather than the arg immediately after the op) keeps this
    /// correct even if the backend ever emits `SRC != DEST`. Searches from the
    /// end so a policy mount is matched rather than a same-named baseline entry.
    fn policy_mount_pos(args: &[String], op: &str, path: &str) -> usize {
        let dest_offset = if op == "--tmpfs" { 1 } else { 2 };
        (0..args.len())
            .rev()
            .find(|&i| args[i] == op && args.get(i + dest_offset).map(String::as_str) == Some(path))
            .unwrap_or_else(|| panic!("expected `{op} ... {path}` in args: {args:?}"))
    }

    /// A deep denied path must be emitted AFTER a shallower read-write ancestor
    /// so the mask wins on the subtree (most-specific-path-wins).
    #[test]
    fn deep_denied_child_masks_rw_parent() {
        let mut r = base_request();
        r.policy.readwrite_paths = vec!["/data".into()];
        r.policy.denied_paths = vec!["/data/secrets".into()];
        let args = build_args(&r, None);

        let parent = policy_mount_pos(&args, "--bind", "/data");
        let child = policy_mount_pos(&args, "--tmpfs", "/data/secrets");
        assert!(
            child > parent,
            "denied /data/secrets (pos {child}) must come after rw /data (pos {parent}) \
             so it masks the subtree: {args:?}"
        );
    }

    /// Regression for the previously-broken case: a deep read-write path under a
    /// shallower denied parent must be emitted AFTER the parent tmpfs so the deep
    /// bind is not shadowed by the mask (most-specific-path-wins).
    #[test]
    fn deep_rw_child_survives_denied_parent() {
        let mut r = base_request();
        r.policy.readwrite_paths = vec!["/data/secrets".into()];
        r.policy.denied_paths = vec!["/data".into()];
        let args = build_args(&r, None);

        let parent = policy_mount_pos(&args, "--tmpfs", "/data");
        let child = policy_mount_pos(&args, "--bind", "/data/secrets");
        assert!(
            child > parent,
            "rw /data/secrets (pos {child}) must come after denied /data (pos {parent}) \
             so the deep bind is not shadowed by the mask: {args:?}"
        );
    }

    /// A denied path classified as a **directory** (not in `denied_files`) is
    /// masked with an empty `--tmpfs`, matching the default `build_args`.
    #[test]
    fn denied_directory_is_masked_with_tmpfs() {
        let mut r = base_request();
        r.policy.denied_paths = vec!["/secrets".into()];
        let denied_files = HashSet::new();
        let args = build_args_classified(&r, None, &denied_files);

        // tmpfs at /secrets, and no ro-bind of /dev/null onto it.
        policy_mount_pos(&args, "--tmpfs", "/secrets");
        assert!(
            args.windows(3)
                .all(|w| !(w[0] == "--ro-bind" && w[1] == "/dev/null" && w[2] == "/secrets")),
            "a directory denied path must not be masked with /dev/null: {args:?}"
        );
    }

    /// A denied path classified as a **file** (present in `denied_files`) is
    /// masked with `--ro-bind /dev/null`, not `--tmpfs` (which would replace the
    /// file with an empty directory).
    #[test]
    fn denied_file_is_masked_with_dev_null() {
        let mut r = base_request();
        r.policy.denied_paths = vec!["/etc/shadow".into()];
        let denied_files = HashSet::from(["/etc/shadow".to_string()]);
        let args = build_args_classified(&r, None, &denied_files);

        // `--ro-bind /dev/null /etc/shadow` present ...
        let pos = args
            .windows(3)
            .position(|w| w[0] == "--ro-bind" && w[1] == "/dev/null" && w[2] == "/etc/shadow");
        assert!(
            pos.is_some(),
            "a file denied path must be masked with `--ro-bind /dev/null`: {args:?}"
        );
        // ... and it is NOT tmpfs-masked.
        assert!(
            args.windows(2)
                .all(|w| !(w[0] == "--tmpfs" && w[1] == "/etc/shadow")),
            "a file denied path must not be tmpfs-masked: {args:?}"
        );
    }

    /// Classification is per-path: in one policy a denied file and a denied
    /// directory get their respective masks, and the specificity ordering is
    /// still honored (deep file mask emitted after its shallower rw ancestor).
    #[test]
    fn mixed_denied_file_and_dir_masks_each_correctly() {
        let mut r = base_request();
        r.policy.readwrite_paths = vec!["/data".into()];
        r.policy.denied_paths = vec!["/data/secret.txt".into(), "/cache".into()];
        let denied_files = HashSet::from(["/data/secret.txt".to_string()]);
        let args = build_args_classified(&r, None, &denied_files);

        // File → /dev/null, after the rw /data parent.
        let parent = policy_mount_pos(&args, "--bind", "/data");
        let file_mask = policy_mount_pos(&args, "--ro-bind", "/data/secret.txt");
        assert!(
            file_mask > parent,
            "deep denied file mask (pos {file_mask}) must come after rw /data (pos {parent}): {args:?}"
        );
        assert_eq!(args[file_mask + 1], "/dev/null");

        // Dir → tmpfs.
        policy_mount_pos(&args, "--tmpfs", "/cache");
    }

    /// Regression for review comment: a denied **directory** and a denied
    /// **file nested inside it** must each get the correct primitive AND be
    /// ordered parent-first, so the deeper `/dev/null` file mask lands inside
    /// the shallower tmpfs (most-specific-path-wins) rather than being shadowed
    /// by it. Mirrors the empirically-verified E2E behaviour.
    #[test]
    fn nested_denied_dir_and_child_file_mask_each_correctly() {
        let mut r = base_request();
        r.policy.denied_paths = vec!["/data/secret".into(), "/data/secret/key".into()];
        // Only the nested path is a file; the parent is a directory (tmpfs).
        let denied_files = HashSet::from(["/data/secret/key".to_string()]);
        let args = build_args_classified(&r, None, &denied_files);

        // Parent dir → tmpfs; child file → /dev/null.
        let parent = policy_mount_pos(&args, "--tmpfs", "/data/secret");
        let child = policy_mount_pos(&args, "--ro-bind", "/data/secret/key");
        assert_eq!(
            args[child + 1],
            "/dev/null",
            "nested denied file must be masked with /dev/null: {args:?}"
        );
        assert!(
            child > parent,
            "child file mask (pos {child}) must come after parent tmpfs (pos {parent}) \
             so it lands inside the masked subtree: {args:?}"
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
    fn proxy_active_uses_private_network_and_external_user_namespace() {
        let mut r = base_request();
        r.schema_version = "0.8.0-alpha".into();
        r.policy.default_network_policy = NetworkPolicy::Block;
        let addr = ProxyAddress::new("127.0.0.1".into(), 12345);
        let args = build_args(&r, Some(&addr));
        assert!(
            args.contains(&"--unshare-net".to_string()),
            "proxy mode must use a private network namespace"
        );
        assert!(
            !args.contains(&"--unshare-user".to_string()),
            "the runner supplies proxy mode's pre-created user namespace"
        );
    }

    #[test]
    fn pre_0_8_proxy_keeps_existing_shared_network_behavior() {
        for version in ["", "0.6.0-alpha", "0.7.0-alpha"] {
            let mut request = base_request();
            request.schema_version = version.into();
            let address = ProxyAddress::new("127.0.0.1".into(), 12345);
            let args = build_args(&request, Some(&address));

            assert!(
                args.contains(&"--unshare-user".to_string()),
                "{version:?} should retain Bubblewrap's existing user namespace setup"
            );
            assert!(
                !args.contains(&"--unshare-net".to_string()),
                "{version:?} should retain shared-network proxy behavior"
            );
        }
    }

    #[test]
    fn proxy_active_injects_env_vars() {
        let r = base_request();
        let addr = ProxyAddress::new("127.0.0.1".into(), 7777);
        let args = build_args(&r, Some(&addr));

        // Each proxy key must be set via --setenv.
        for key in &[
            "HTTP_PROXY",
            "HTTPS_PROXY",
            "ALL_PROXY",
            "http_proxy",
            "https_proxy",
            "all_proxy",
        ] {
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
        // Any bypass would silently defeat allowedHosts/blockedHosts.
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
            "ALL_PROXY=http://attacker.example:9999".into(),
            "FTP_PROXY=http://attacker.example:9999".into(),
            "ftp_proxy=http://attacker.example:9999".into(),
            "NO_PROXY=*".into(),
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

        // FTP variables point at the configured proxy rather than a
        // caller-controlled alternative.
        for key in ["FTP_PROXY", "ftp_proxy"] {
            let pos = args
                .iter()
                .position(|arg| arg == key)
                .unwrap_or_else(|| panic!("missing --setenv {key} in {args:?}"));
            assert_eq!(args[pos + 1], "http://127.0.0.1:9000");
        }

        // Bypass variables remain absent after clearing the caller's
        // environment.
        for key in ["NO_PROXY", "no_proxy"] {
            assert!(
                !args.iter().any(|arg| arg == key),
                "proxy mode must not emit caller-controlled {key}: {args:?}"
            );
        }
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
