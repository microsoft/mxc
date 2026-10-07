// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Builds the `bwrap` CLI argument vector from an [`ExecutionRequest`].
//!
//! This module is platform-agnostic: it only produces a `Vec<String>` of
//! arguments without spawning any processes, so it compiles and can be
//! unit-tested on every host (Windows, macOS, Linux).

use std::collections::HashSet;

use crate::mxc_common::filesystem_resolve::FsIntent;
use crate::mxc_common::models::{ExecutionRequest, NetworkAction, ProxyAddress};
use crate::mxc_common::proxy_env::{is_managed_proxy_key, PROXY_SET_KEYS};

/// The fixed prefix of the command bwrap is asked to run.
///
/// `build_args` appends this last, so its position identifies where the
/// options end -- unlike a bare `--` token, which a caller-supplied
/// environment value can also be. Shared so the two cannot drift apart.
pub(crate) const COMMAND_TAIL: [&str; 3] = ["--", "sh", "-c"];

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
    /// Directional iptables filtering inside a slirp-backed private namespace.
    FirewallEnforced,
    /// Cooperative proxy routing inside a slirp-backed private namespace, with
    /// egress closed to everything but the proxy.
    ProxyOnly,
}

impl ResolvedNetworkMode {
    /// Classify the internal request using the proxy's resolved runtime state.
    pub(crate) fn from_request(request: &ExecutionRequest, proxy_active: bool) -> Self {
        if proxy_active {
            return Self::ProxyOnly;
        }

        // An absent egress section is the supported deny default. Only a
        // ruleless deny can omit slirp and the namespace-local firewall.
        let egress = request.policy.network_egress.as_ref();
        if egress.is_none_or(|egress| {
            egress.default == NetworkAction::Deny
                && egress.allow.is_empty()
                && egress.deny.is_empty()
        }) {
            Self::Isolated
        } else {
            Self::FirewallEnforced
        }
    }

    /// Whether the runner supplies a pre-created user namespace to Bubblewrap.
    pub(crate) fn uses_external_userns(self) -> bool {
        matches!(self, Self::ProxyOnly | Self::FirewallEnforced)
    }
}

/// Refuse an inbound posture Bubblewrap cannot honor.
///
/// The backend declares `INGRESS_DEFAULT` and `HOST_LOOPBACK` in
/// [`network_policy_support`], which tells shared validation it understands
/// those fields — not that it can satisfy both of their values. Shared
/// validation therefore stops checking them and these rejections become the
/// only thing standing between an unsupported value and a silent drop, so they
/// ship in the same change as the declaration.
///
pub fn directional_network_rejection(request: &ExecutionRequest) -> Option<&'static str> {
    let egress = request.policy.network_egress.as_ref();
    let ingress = request.policy.network_ingress.as_ref();
    if egress.is_none() && ingress.is_none() {
        return None;
    }

    if let Some(ingress) = ingress {
        if ingress.default == NetworkAction::Allow {
            return Some(BWRAP_INGRESS_DEFAULT_ALLOW);
        }
        if ingress.host_loopback == NetworkAction::Allow {
            return Some(BWRAP_HOST_LOOPBACK_ALLOW);
        }
    }

    None
}

/// Rejection text for an inbound-accepting directional posture.
pub const BWRAP_INGRESS_DEFAULT_ALLOW: &str =
    "Bubblewrap: network.ingress.default='allow' is not supported. The sandbox runs in a \
     private network namespace reached through slirp, which has no route in until a host \
     port is forwarded to it, and the schema carries no port list to forward. A listener \
     inside the sandbox is reachable from the sandbox only. Use \
     network.ingress.default='deny'.";

/// Rejection text for an inbound-accepting host-loopback posture.
pub const BWRAP_HOST_LOOPBACK_ALLOW: &str =
    "Bubblewrap: network.ingress.hostLoopback='allow' is not supported. The sandbox's \
     loopback belongs to its own network namespace and is not the host's, so the host \
     cannot dial a sandbox listener and nothing bridges the two. Use \
     network.ingress.hostLoopback='deny'.";

/// Rejection text for a proxy combined with direct egress.
#[cfg(any(target_os = "linux", test))]
pub(crate) const BWRAP_PROXY_DIRECTIONAL_EGRESS: &str =
    "Bubblewrap: runtimeConfig.networkProxy cannot be combined with direct network.egress rules \
     or default='allow'. \
     A proxy resolves to proxy-only egress, whose chain opens the proxy endpoint alone and \
     never reads network.egress, so the rules would be dropped in silence. Use \
     network.egress.default='deny' with no allow/deny rules (the proxy-only posture), or \
     remove runtimeConfig.networkProxy and express the policy with network.egress.";

/// Reject direct egress that proxy-only routing would otherwise discard.
#[cfg(any(target_os = "linux", test))]
pub(crate) fn proxy_with_egress_rejection(request: &ExecutionRequest) -> Option<&'static str> {
    let proxy = &request.policy.network_proxy;
    if !proxy.is_enabled() {
        return None;
    }

    request
        .policy
        .network_egress
        .as_ref()
        .is_some_and(|egress| {
            egress.default != NetworkAction::Deny
                || !egress.allow.is_empty()
                || !egress.deny.is_empty()
        })
        .then_some(BWRAP_PROXY_DIRECTIONAL_EGRESS)
}

/// `PATH` for the sandboxed child, from schema 0.9.
///
/// `--clearenv` leaves the child with no `PATH`, so resolution fell through to
/// the shell's compiled-in default. That value varies: it matches this one on
/// Debian and Ubuntu, so nothing changes there, but on RHEL it omitted the
/// `sbin` directories. Setting it explicitly removes the dependency.
const DEFAULT_PATH: &str = "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin";

/// `TERM` for the sandboxed child. Curses-based tools error out when it is
/// unset; it does not make a tool believe it has a terminal, which is `isatty`.
const DEFAULT_TERM: &str = "xterm-256color";

/// The directory the child is actually started in, if any.
///
/// [`build_args_classified_with_mode`] emits `--chdir` for exactly this value
/// and [`default_env`] points `HOME` at it, so the two cannot name different
/// directories — a relative `--chdir` would otherwise resolve against whatever
/// cwd bwrap carried into the namespace, leaving `HOME` naming a different
/// directory than the one the child landed in. Normalizing against the sandbox
/// root is what makes them agree for every supported contract.
///
/// A policy grant is deliberately *not* consulted: bwrap enters one only when
/// `process.cwd` names it, so treating it as the start directory would put
/// `HOME` somewhere the child never went.
fn start_directory(request: &ExecutionRequest) -> Option<String> {
    Some(request.working_directory.as_str())
        .filter(|dir| !dir.is_empty())
        .map(crate::mxc_common::models::sandbox_absolute_path)
}

/// The default environment: `PATH`, `TERM`, and — when one resolves — `HOME`.
///
/// `HOME` names the directory the child actually runs in, so it is a path the
/// sandbox can reach rather than the launching user's real home, which the
/// bind-mount policy would not have made visible. With no start directory it
/// is left unset: policy mounts are emitted after `--tmpfs /tmp` and therefore
/// win, so a `/tmp` fallback could be the host's shared directory rather than
/// a private one.
fn default_env(request: &ExecutionRequest) -> Vec<(String, String)> {
    let mut entries = vec![("PATH".to_string(), DEFAULT_PATH.to_string())];

    if let Some(home) = start_directory(request) {
        entries.push(("HOME".to_string(), home));
    }

    entries.push(("TERM".to_string(), DEFAULT_TERM.to_string()));
    entries
}

/// The entries the child should get, as `KEY=VALUE` strings.
///
/// The state dispatch and overlay merge are shared; see
/// [`crate::mxc_common::default_env::resolve_env`]. Explicit replacement entries
/// are passed through untouched.
fn resolved_env(request: &ExecutionRequest) -> Vec<String> {
    crate::mxc_common::default_env::resolve_env(request, || default_env(request))
}

/// Build the complete `bwrap` argument list, masking **every** denied path as a
/// directory (`--tmpfs`).
///
/// This is the pure, classification-free entry point: it performs no filesystem
/// I/O and so stays unit-testable on every host. Unit tests and any caller that
/// has not stat'd the denied paths use it. The Bubblewrap runner uses
/// [`build_args_classified`] instead. See
/// docs/backends/bwrap/bubblewrap-backend.md for how denied paths are masked.
pub fn build_args(request: &ExecutionRequest, proxy_address: Option<&ProxyAddress>) -> Vec<String> {
    build_args_classified(request, proxy_address, &HashSet::new())
}

/// Build the complete argument list for `bwrap` from the given request.
///
/// The returned vector does **not** include the `bwrap` binary name itself —
/// callers pass it to `Command::new("bwrap").args(&args)`.
///
/// `proxy_address` is the sandbox-visible runtime proxy endpoint, if configured.
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
/// docs/backends/bwrap/bubblewrap-backend.md for how denied paths are masked.
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
    // SECURITY: proxy mode joins the supervisor's user namespace rather than
    // unsharing, leaving that descriptor open in the workload. It is inert only
    // because bwrap empties the capability sets before exec — asserted by
    // run_bwrap_network_proxy_test.sh, explained in
    // docs/backends/bwrap/bubblewrap-backend.md.
    args.extend(
        ["--unshare-pid", "--unshare-ipc", "--unshare-uts"]
            .into_iter()
            .map(String::from),
    );

    // `--unshare-pid` alone does not make killing our `bwrap` handle tear the
    // sandbox down: bwrap forks, so pid 1 of the new namespace is that child,
    // not the process we spawned. Without this flag a backgrounded descendant
    // outlives a timeout kill and keeps running after `run_teardown()` has
    // removed the network enforcement it was sandboxed by.
    args.push("--die-with-parent".into());

    // Every supported mode has a private namespace; slirp provides connectivity
    // only after its firewall is installed.
    args.push("--unshare-net".into());

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
    for mount in crate::mxc_common::filesystem_resolve::resolve_mount_order(&request.policy) {
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
    if let Some(dir) = start_directory(request) {
        args.extend(["--chdir".into(), dir]);
    }

    // -- Environment -------------------------------------------------------
    // Clear the inherited environment, then set only the vars from the
    // request so the sandbox has a minimal, predictable environment.
    args.push("--clearenv".into());
    for env_str in resolved_env(request) {
        // An entry with no `=` names no variable, so it is dropped here too.
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
    // Cooperating tools route through the externally managed proxy; raw
    // sockets cannot bypass the namespace-local default-DROP chain.
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
    args.extend(COMMAND_TAIL.iter().map(|arg| arg.to_string()));
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

    /// `process.env` resolution, which schema 0.9 gave a default block.
    mod env {
        use super::*;
        fn request() -> ExecutionRequest {
            ExecutionRequest::default()
        }

        fn value<'a>(entries: &'a [String], key: &str) -> Option<&'a str> {
            entries
                .iter()
                .find_map(|kv| kv.strip_prefix(&format!("{key}=")))
        }

        /// A direct typed SDK request that named no contract takes the current
        /// behavior.
        #[test]
        fn a_direct_sdk_request_gets_the_default_block() {
            let r = ExecutionRequest::default();
            assert_eq!(value(&resolved_env(&r), "PATH"), Some(DEFAULT_PATH));
        }

        #[test]
        fn an_omitted_env_gets_the_default_block() {
            let mut r = request();
            r.env = None;
            r.working_directory = "/workspace".into();
            let entries = resolved_env(&r);
            assert_eq!(value(&entries, "PATH"), Some(DEFAULT_PATH));
            assert_eq!(value(&entries, "HOME"), Some("/workspace"));
            assert_eq!(value(&entries, "TERM"), Some(DEFAULT_TERM));
        }

        #[test]
        fn the_default_path_covers_sbin() {
            // The RHEL failure this default exists to prevent.
            for dir in ["/usr/sbin", "/sbin", "/usr/bin", "/bin"] {
                assert!(
                    DEFAULT_PATH.split(':').any(|entry| entry == dir),
                    "{dir} must be on the default PATH"
                );
            }
        }

        #[test]
        fn an_explicitly_empty_env_stays_empty() {
            let mut r = request();
            r.env = Some(vec![]);
            assert!(resolved_env(&r).is_empty());
        }

        #[test]
        fn a_supplied_env_is_used_verbatim() {
            let mut r = request();
            r.env = Some(vec!["FOO=bar".into()]);
            assert_eq!(resolved_env(&r), vec!["FOO=bar".to_string()]);
        }

        #[test]
        fn inherit_default_env_layers_over_the_default_block() {
            let mut r = request();
            r.env = Some(vec!["FOO=bar".into(), "PATH=/only/mine".into()]);
            r.inherit_default_env = true;
            let entries = resolved_env(&r);

            assert_eq!(value(&entries, "FOO"), Some("bar"));
            assert_eq!(value(&entries, "TERM"), Some(DEFAULT_TERM));
            // Replaced, not appended: --setenv twice for one name is
            // order-dependent.
            assert_eq!(value(&entries, "PATH"), Some("/only/mine"));
            assert_eq!(
                entries.iter().filter(|kv| kv.starts_with("PATH=")).count(),
                1
            );
        }

        #[test]
        fn home_follows_the_directory_the_child_starts_in() {
            let mut r = request();
            r.env = None;
            r.working_directory = "/workspace".into();
            assert_eq!(value(&resolved_env(&r), "HOME"), Some("/workspace"));
        }

        #[test]

        fn a_caller_entry_without_a_value_reaches_no_setenv() {
            for inherit in [false, true] {
                let mut r = base_request();
                r.env = Some(vec!["FEATURE_FLAG".into(), "FOO=bar".into()]);
                r.inherit_default_env = inherit;
                let args = build_args(&r, None);

                assert!(
                    !args.iter().any(|a| a == "FEATURE_FLAG"),
                    "a valueless entry must not be set (inherit {inherit}): {args:?}"
                );
                assert!(
                    args.windows(3)
                        .any(|w| w[0] == "--setenv" && w[1] == "FOO" && w[2] == "bar"),
                    "the well-formed entry must survive (inherit {inherit}): {args:?}"
                );
            }
        }

        /// A policy grant is not a working directory: bwrap emits `--chdir`
        /// only for `process.cwd`, so a granted directory the child never
        /// enters must not become its `HOME`.
        #[test]
        fn a_policy_grant_alone_does_not_become_home() {
            let mut r = request();
            r.env = None;
            r.working_directory = String::new();
            // A real directory, so the shared resolver's `is_dir` probe would
            // accept it if `HOME` consulted the policy.
            r.policy.readwrite_paths = vec![std::env::temp_dir().display().to_string()];

            assert_eq!(value(&resolved_env(&r), "HOME"), None);
            let args = build_args(&r, None);
            assert!(
                !args.iter().any(|a| a == "--chdir"),
                "a policy grant must not chdir the child: {args:?}"
            );
        }

        /// `HOME` and `--chdir` come from one resolution, so they cannot name
        /// different directories.
        #[test]
        fn home_and_chdir_agree() {
            for cwd in ["", "/workspace", "work", "./work", "a/../b", "/x/../y/./z"] {
                let mut r = request();
                r.env = None;
                r.working_directory = cwd.into();
                let args = build_args(&r, None);

                let chdir = args
                    .windows(2)
                    .find(|w| w[0] == "--chdir")
                    .map(|w| w[1].clone());
                let home = value(&resolved_env(&r), "HOME").map(str::to_string);
                assert_eq!(
                    home, chdir,
                    "HOME must name the directory the child starts in (cwd {cwd:?})"
                );
            }
        }

        #[test]
        fn a_relative_start_directory_is_anchored_to_the_sandbox_root() {
            for (cwd, expected) in [
                ("work", "/work"),
                ("./work", "/work"),
                ("a/../b", "/b"),
                ("/x/../y/./z", "/y/z"),
            ] {
                let mut r = request();
                r.env = None;
                r.working_directory = cwd.into();
                assert_eq!(value(&resolved_env(&r), "HOME"), Some(expected));
            }
        }

        #[test]
        fn the_default_block_reaches_the_argument_list() {
            let mut r = base_request();
            r.env = None;
            let args = build_args(&r, None);

            let pos = args
                .windows(3)
                .position(|w| w[0] == "--setenv" && w[1] == "PATH" && w[2] == DEFAULT_PATH);
            assert!(pos.is_some(), "PATH must be set via --setenv: {args:?}");
            let clearenv = args.iter().position(|a| a == "--clearenv").unwrap();
            assert!(
                pos.unwrap() > clearenv,
                "--setenv must follow --clearenv, else it is wiped"
            );
        }
    }

    #[test]
    fn an_omitted_network_policy_is_isolated() {
        let request = ExecutionRequest { ..base_request() };
        assert_eq!(
            ResolvedNetworkMode::from_request(&request, false),
            ResolvedNetworkMode::Isolated
        );
    }

    #[test]
    fn basic_args_contain_namespace_flags() {
        let args = build_args(&base_request(), None);
        assert!(args.contains(&"--unshare-user".to_string()));
        assert!(args.contains(&"--unshare-pid".to_string()));
        assert!(args.contains(&"--unshare-ipc".to_string()));
        assert!(args.contains(&"--unshare-uts".to_string()));
    }

    /// Dropping this flag silently reintroduces a real leak: a backgrounded
    /// descendant survives the timeout kill and keeps running after teardown
    /// has removed its network enforcement.
    #[test]
    fn basic_args_request_die_with_parent() {
        let args = build_args(&base_request(), None);
        assert!(args.contains(&"--die-with-parent".to_string()));
    }

    /// A directional egress policy must land on the one mode whose chains the
    /// sandbox actually traverses.
    ///
    #[test]
    fn a_directional_rule_selects_the_namespace_whose_chain_is_programmed() {
        let request = directional_egress_request(NetworkAction::Deny, true);
        assert_eq!(
            ResolvedNetworkMode::from_request(&request, false),
            ResolvedNetworkMode::FirewallEnforced
        );
    }

    /// A ruleless directional policy still gets a namespace that honors the
    /// inbound posture. Only a bare deny degenerates to `--unshare-net`, where
    /// the absence of connectivity denies inbound for free; a bare allow keeps
    /// the private namespace and expresses itself as an accept-all chain,
    /// because the host namespace could not deny inbound at all.
    #[test]
    fn a_ruleless_directional_policy_still_honors_the_inbound_posture() {
        let denied = directional_egress_request(NetworkAction::Deny, false);
        assert_eq!(
            ResolvedNetworkMode::from_request(&denied, false),
            ResolvedNetworkMode::Isolated
        );

        let allowed = directional_egress_request(NetworkAction::Allow, false);
        let mode = ResolvedNetworkMode::from_request(&allowed, false);
        assert_eq!(mode, ResolvedNetworkMode::FirewallEnforced);
        assert!(build_args(&allowed, None).contains(&"--unshare-net".to_string()));
    }

    /// Neither default nor rules may share the host namespace.
    #[test]
    fn no_directional_posture_shares_the_host_namespace() {
        for default in [NetworkAction::Allow, NetworkAction::Deny] {
            for with_rule in [false, true] {
                let request = directional_egress_request(default, with_rule);
                assert!(
                    build_args(&request, None).contains(&"--unshare-net".to_string()),
                    "default={default:?} with_rule={with_rule} omitted --unshare-net"
                );
            }
        }
    }

    /// A proxy run is classified by the proxy arm before the directional one,
    /// so a directional section must not divert it out of `ProxyOnly` — that
    /// mode derives its chain from the resolved proxy endpoint.
    #[test]
    fn a_directional_section_does_not_divert_a_proxy_run() {
        let mut request = directional_egress_request(NetworkAction::Deny, false);
        request.policy.network_proxy.address = Some(ProxyAddress::new("127.0.0.1".into(), 3128));
        assert_eq!(
            ResolvedNetworkMode::from_request(&request, true),
            ResolvedNetworkMode::ProxyOnly
        );
    }

    /// An ingress-only request retains isolation with implicit egress deny.
    #[test]
    fn an_ingress_only_directional_request_still_gets_a_private_namespace() {
        use crate::mxc_common::models::NetworkIngressPolicy;

        let mut request = base_request();
        request.policy.network_ingress = Some(NetworkIngressPolicy::default());
        let mode = ResolvedNetworkMode::from_request(&request, false);
        assert_eq!(mode, ResolvedNetworkMode::Isolated);
        assert!(build_args(&request, None).contains(&"--unshare-net".to_string()));
    }

    /// Build a supported egress request.
    fn directional_egress_request(default: NetworkAction, with_rule: bool) -> ExecutionRequest {
        use crate::mxc_common::models::{NetworkEgressPolicy, NetworkRule};

        let mut request = base_request();
        request.policy.network_egress = Some(NetworkEgressPolicy {
            default,
            allow: if with_rule {
                vec![NetworkRule::default()]
            } else {
                Vec::new()
            },
            deny: Vec::new(),
        });
        request
    }

    /// Build a directional request carrying both sections.
    fn directional_request(
        ingress_default: NetworkAction,
        host_loopback: NetworkAction,
    ) -> ExecutionRequest {
        use crate::mxc_common::models::{NetworkEgressPolicy, NetworkIngressPolicy};

        let mut request = base_request();
        request.policy.network_egress = Some(NetworkEgressPolicy::default());
        request.policy.network_ingress = Some(NetworkIngressPolicy {
            default: ingress_default,
            host_loopback,
        });
        request
    }

    /// Slirp has no route into the namespace and the schema carries no port
    /// list to forward one, so an inbound-accepting posture cannot be honored.
    #[test]
    fn an_inbound_accepting_directional_posture_is_refused() {
        let request = directional_request(NetworkAction::Allow, NetworkAction::Deny);
        assert_eq!(
            directional_network_rejection(&request),
            Some(BWRAP_INGRESS_DEFAULT_ALLOW)
        );
    }

    /// The sandbox's loopback is its own namespace's, not the host's.
    #[test]
    fn a_host_loopback_accepting_posture_is_refused() {
        let request = directional_request(NetworkAction::Deny, NetworkAction::Allow);
        assert_eq!(
            directional_network_rejection(&request),
            Some(BWRAP_HOST_LOOPBACK_ALLOW)
        );
    }

    /// Positive control: the honorable posture must pass, or the gate above is
    /// just refusing every directional config.
    #[test]
    fn a_fully_denied_directional_posture_is_accepted() {
        let request = directional_request(NetworkAction::Deny, NetworkAction::Deny);
        assert_eq!(directional_network_rejection(&request), None);
    }

    #[test]
    fn only_external_runtime_proxies_are_accepted() {
        let mut request = directional_egress_request(NetworkAction::Deny, false);
        request.policy.network_proxy.address = Some(ProxyAddress::new("127.0.0.1".into(), 3128));
        assert!(proxy_with_egress_rejection(&request).is_none());
        request.policy.network_egress = Some(crate::mxc_common::models::NetworkEgressPolicy {
            default: NetworkAction::Allow,
            ..Default::default()
        });
        assert_eq!(
            proxy_with_egress_rejection(&request),
            Some(BWRAP_PROXY_DIRECTIONAL_EGRESS)
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
        r.env = Some(vec!["FOO=bar".into(), "PATH=/usr/bin".into()]);
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
        let r = base_request();
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
        // Any bypass would silently defeat externally managed proxy policy.
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
        r.env = Some(vec![
            "FOO=bar".into(),
            "HTTP_PROXY=http://attacker.example:9999".into(),
            "https_proxy=http://attacker.example:9999".into(),
            "ALL_PROXY=http://attacker.example:9999".into(),
            "FTP_PROXY=http://attacker.example:9999".into(),
            "ftp_proxy=http://attacker.example:9999".into(),
            "NO_PROXY=*".into(),
            "PATH=/usr/bin".into(),
        ]);
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
        r.env = Some(vec!["HTTP_PROXY=http://caller.example:8080".into()]);
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
