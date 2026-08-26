// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Builds the `bwrap` CLI argument vector from an [`ExecutionRequest`].
//!
//! This module is platform-agnostic: it only produces a `Vec<String>` of
//! arguments without spawning any processes, so it compiles and can be
//! unit-tested on every host (Windows, macOS, Linux).

use std::collections::HashSet;

use wxc_common::filesystem_resolve::FsIntent;
use wxc_common::models::{
    ContainerPolicy, ExecutionRequest, NetworkAction, NetworkEnforcementMode, NetworkPolicy,
    ProxyAddress,
};
use wxc_common::proxy_env::{is_managed_proxy_key, PROXY_SET_KEYS};

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
    /// The host network namespace without MXC firewall filtering.
    Shared,
    /// Pre-0.8 cooperative proxy routing in the host network namespace.
    LegacyProxy,
    /// The host network namespace with per-destination iptables filtering.
    ///
    /// Pre-0.8 only. The rules land on the *host* chain, which the sandbox
    /// never traverses, so this filters nothing; it is retained unchanged
    /// because pre-0.8 callers already run under it.
    FirewallFiltered,
    /// Per-destination iptables filtering inside a slirp-backed private
    /// namespace, with no proxy. 0.8+ only.
    FirewallEnforced,
    /// Cooperative proxy routing inside a slirp-backed private namespace, with
    /// egress closed to everything but the proxy.
    ProxyOnly,
}

/// Whether a schema version opts into the 0.8 network contract, under which a
/// network element Bubblewrap cannot enforce is a hard error rather than a
/// warning.
///
/// An absent version stays lenient: the parser accepts it, and programmatic
/// callers who never set one are the pre-0.8 population. A malformed non-empty
/// version is treated as strict instead of lenient -- the parser would reject
/// it outright, so the only way one reaches here is a hand-built
/// `ExecutionRequest` that skipped the parser, and a typo like `"0.8"` must not
/// silently buy pre-0.8 leniency.
pub fn schema_enforces_network_strictly(version: &str) -> bool {
    if version.is_empty() {
        return false;
    }
    semver::Version::parse(version)
        .map(|parsed| (parsed.major, parsed.minor) >= (0, 8))
        .unwrap_or(true)
}

/// Whether this schema opts into the 0.8 private network-namespace contract.
///
/// Gates both the proxy path (`LegacyProxy` → `ProxyOnly`) and the firewall
/// path (`FirewallFiltered` → `FirewallEnforced`). Everything the private
/// namespace brings — slirp, in-namespace rules, IP/CIDR-only rule addresses —
/// is a behavior change for callers already running on 0.6/0.7, so it is
/// introduced on the dev line rather than retrofitted.
fn uses_private_network_contract(request: &ExecutionRequest) -> bool {
    schema_enforces_network_strictly(&request.schema_version)
}

/// Whether the policy carries the 0.8 directional shape.
///
/// Either section is enough: the parser fills both together, but checking only
/// one would route an ingress-only policy into the legacy path, where its
/// directional intent is silently discarded. Shared by every site that splits
/// directional from legacy so the fail-closed reading cannot drift apart.
///
/// Distinct from `wxc_common::validator::directional_posture_supplied`, which
/// also folds in `network_mode_specified` and the proxy; the two are not
/// interchangeable.
pub(crate) fn is_directional(policy: &ContainerPolicy) -> bool {
    policy.network_egress.is_some() || policy.network_ingress.is_some()
}

impl ResolvedNetworkMode {
    /// Classify the internal request using the proxy's resolved runtime state.
    pub(crate) fn from_request(request: &ExecutionRequest, proxy_active: bool) -> Self {
        if proxy_active {
            return if uses_private_network_contract(request) {
                Self::ProxyOnly
            } else {
                Self::LegacyProxy
            };
        }

        // The directional 0.8 posture is authoritative when present: the parser
        // fills these sections only on that path and leaves every legacy field
        // at its default, so classifying from the legacy fields below would
        // read a policy that never said either as `Isolated` and take the
        // sandbox offline with the requested rules programmed nowhere.
        //
        // Either section makes it directional (see `is_directional`); a missing
        // egress defaults to deny, failing closed.
        //
        // Directional never selects `Shared`: the host namespace has no inbound
        // primitive, and `network_ingress` has no `_specified` twin, so a
        // defaulted `ingress.default='deny'` is indistinguishable from one the
        // caller wrote and could not be refused without refusing every
        // "allow all outbound" policy with it. The private namespace honors
        // both directions, so an open egress posture becomes an accept-all
        // chain rather than an unfiltered namespace.
        if is_directional(&request.policy) {
            // Off the 0.8 contract there is no private namespace to program.
            // Report the unfiltered truth and let `validate` refuse it rather
            // than pretending the posture was applied.
            if !uses_private_network_contract(request) {
                return Self::Shared;
            }
            let egress = request.policy.network_egress.clone().unwrap_or_default();
            // A bare deny is `--unshare-net`: cheaper than slirp plus a
            // deny-all chain, identical in effect, and inbound is denied by
            // the absence of connectivity rather than by a rule.
            let ruleless = egress.allow.is_empty() && egress.deny.is_empty();
            return if ruleless && egress.default == NetworkAction::Deny {
                Self::Isolated
            } else {
                Self::FirewallEnforced
            };
        }

        let uses_firewall = matches!(
            request.policy.network_enforcement_mode,
            NetworkEnforcementMode::Firewall | NetworkEnforcementMode::Both
        );
        let has_host_rules =
            !request.policy.allowed_hosts.is_empty() || !request.policy.blocked_hosts.is_empty();

        if uses_firewall && has_host_rules {
            if uses_private_network_contract(request) {
                Self::FirewallEnforced
            } else {
                Self::FirewallFiltered
            }
        } else if request.policy.default_network_policy == NetworkPolicy::Block && !has_host_rules {
            Self::Isolated
        } else {
            Self::Shared
        }
    }

    /// Whether current behavior gives the sandbox a private network namespace.
    pub(crate) fn uses_private_netns(self) -> bool {
        matches!(
            self,
            Self::Isolated | Self::ProxyOnly | Self::FirewallEnforced
        )
    }

    /// Whether the runner supplies a pre-created user namespace to Bubblewrap.
    pub(crate) fn uses_external_userns(self) -> bool {
        matches!(self, Self::ProxyOnly | Self::FirewallEnforced)
    }

    /// Whether the mode uses the host-side firewall manager.
    ///
    /// False for `ProxyOnly` and `FirewallEnforced`, which are *not*
    /// iptables-free: they program rules directly into the sandbox's own
    /// network namespace from the supervisor (see `proxy_network`) rather than
    /// going through the host manager.
    #[cfg(any(target_os = "linux", test))]
    pub(crate) fn requires_host_firewall_manager(self) -> bool {
        matches!(self, Self::FirewallFiltered)
    }

    /// Whether this mode actually applies the policy's host lists.
    ///
    /// `FirewallEnforced` filters by address in the sandbox's own namespace.
    /// `ProxyOnly` closes egress to everything but the proxy endpoint, so the
    /// lists are enforced at the proxy — true only for the builtin proxy; an
    /// external one is refused by [`external_proxy_host_rules_rejection`].
    /// Every other mode leaves the lists unapplied.
    pub(crate) fn enforces_host_rules(self) -> bool {
        matches!(self, Self::FirewallEnforced | Self::ProxyOnly)
    }
}

/// Whether this schema opts into rejecting network elements Bubblewrap cannot
/// honor. Pre-0.8 callers keep the warning, so existing configs still run.
fn rejects_unhonorable_network(request: &ExecutionRequest) -> bool {
    schema_enforces_network_strictly(&request.schema_version)
}

/// Rejection text for host lists no mechanism will enforce, on schema 0.8+.
///
/// Owned here rather than in the parser: this is a statement about what
/// Bubblewrap can enforce, so it belongs with the backend that enforces it.
pub const BWRAP_UNENFORCED_HOST_RULES: &str =
    "Bubblewrap: network.allowedHosts and network.blockedHosts require an enforcement \
     mechanism. With enforcementMode='capabilities' (the default) and no network.proxy, \
     nothing applies them: the host lists suppress the --unshare-net full block, so the \
     sandbox shares the host network namespace with no filtering at all. Set \
     network.enforcementMode to 'firewall' to filter by address inside the sandbox's own \
     network namespace, set network.proxy to enforce host filtering at the proxy layer, or \
     drop the host lists to get the namespace-level block that defaultPolicy='block' applies \
     on its own.";

/// Rejection text for `allowLocalNetwork=false` under a shared namespace.
pub const BWRAP_LOCAL_NETWORK_SHARED_NS: &str =
    "Bubblewrap: network.allowLocalNetwork=false is not enforced while the \
     sandbox shares the host network namespace (defaultPolicy='allow'). \
     The sandboxed process can still bind, listen and accept on host-local addresses. For \
     an unreachable sandbox use defaultPolicy='block' with no host rules and no proxy, \
     which applies --unshare-net; to keep the shared namespace, acknowledge the exposure \
     with allowLocalNetwork=true.";

/// Rejection text for `allowLocalNetwork=true` under a private namespace.
pub const BWRAP_LOCAL_NETWORK_PRIVATE_NS: &str =
    "Bubblewrap: network.allowLocalNetwork=true is confined to the sandbox's own \
     network namespace. Isolated, proxy and firewall modes apply --unshare-net, so a \
     listener inside the sandbox is reachable only from within it, never from the host. \
     Use defaultPolicy='allow' with no host rules and no proxy to share the host network \
     namespace.";

/// Refuse a directional 0.8 posture Bubblewrap cannot honor.
///
/// The backend declares `INGRESS_DEFAULT` and `HOST_LOOPBACK` in
/// [`network_policy_support`], which tells shared validation it understands
/// those fields — not that it can satisfy both of their values. Shared
/// validation therefore stops checking them and these rejections become the
/// only thing standing between an unsupported value and a silent drop, so they
/// ship in the same change as the declaration.
///
/// Deliberately *not* schema-gated. The pre-0.8 warning path exists for configs
/// that predate a rule; a directional section is a 0.8 construct, so seeing one
/// on an older schema is a caller error rather than a legacy config to carry
/// forward — and the mode resolver reports `Shared` for it, meaning nothing
/// would be programmed.
pub fn directional_network_rejection(request: &ExecutionRequest) -> Option<&'static str> {
    let egress = request.policy.network_egress.as_ref();
    let ingress = request.policy.network_ingress.as_ref();
    if egress.is_none() && ingress.is_none() {
        return None;
    }

    if !rejects_unhonorable_network(request) {
        return Some(BWRAP_DIRECTIONAL_PRE_0_8);
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

/// Rejection text for a directional section on a pre-0.8 schema.
pub const BWRAP_DIRECTIONAL_PRE_0_8: &str =
    "Bubblewrap: network.egress/network.ingress require schema 0.8.0-alpha or later. \
     Earlier schemas run the sandbox in the host network namespace, where the \
     directional posture would be accepted and then never programmed. Raise the \
     config's version field, or express the policy with defaultPolicy, \
     allowedHosts and blockedHosts.";

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

/// Reject host lists that no mechanism will apply, on schema 0.8+.
///
/// Host lists suppress the `Isolated` mode, so a mode that does not apply them
/// leaves the sandbox on the host namespace unfiltered. This is the only layer
/// that checks it: the parser validates structure, and every caller — CLI,
/// SDK, FFI, or a Rust caller handing `mxc_engine` a hand-built
/// `ExecutionRequest` — reaches a runner, while only JSON configs reach the
/// parser.
pub fn unenforced_host_rules_rejection(request: &ExecutionRequest) -> Option<&'static str> {
    if !rejects_unhonorable_network(request) {
        return None;
    }
    let has_host_rules =
        !request.policy.allowed_hosts.is_empty() || !request.policy.blocked_hosts.is_empty();
    let mode =
        ResolvedNetworkMode::from_request(request, request.policy.network_proxy.is_enabled());

    (has_host_rules && !mode.enforces_host_rules()).then_some(BWRAP_UNENFORCED_HOST_RULES)
}

/// Rejection text for an external proxy combined with host lists.
///
/// Duplicated (verbatim) from the parser's pre-existing check of the same
/// combination. The parser keeps its copy for JSON configs; this one covers
/// callers who hand a runner an `ExecutionRequest` directly.
pub const BWRAP_EXTERNAL_PROXY_HOST_RULES: &str =
    "Bubblewrap: an external network.proxy (url/localhost) cannot be combined with \
     allowedHosts, blockedHosts, or defaultPolicy='block'. The external proxy is expected to \
     enforce its own host policy; MXC does not forward host lists to it. Use \
     'network.proxy.builtinTestServer: true' (testing only) for MXC-enforced host filtering, \
     or remove the host policy.";

/// Rejection text for a proxy combined with a directional egress rule set.
///
/// Distinct from [`BWRAP_EXTERNAL_PROXY_HOST_RULES`] because the two describe
/// different mistakes: that one names the legacy host-list fields, none of
/// which a directional caller has set. A caller told to remove `allowedHosts`
/// when they wrote `network.egress` would have nothing to act on.
pub const BWRAP_PROXY_DIRECTIONAL_EGRESS: &str =
    "Bubblewrap: network.proxy cannot be combined with a directional network.egress rule set. \
     A proxy resolves to proxy-only egress, whose chain opens the proxy endpoint alone and \
     never reads network.egress, so the rules would be dropped in silence. Use \
     network.egress.default='deny' with no allow/deny rules (the proxy-only posture), or \
     remove network.proxy and express the policy with network.egress.";

/// Validate-time twin of the parser's external-proxy host-list rejection.
///
/// MXC applies the host lists itself only for the builtin test proxy; an
/// operator-supplied proxy is never handed them, so accepting the combination
/// would drop the requested policy silently. Not schema-gated, matching the
/// parser.
pub fn external_proxy_host_rules_rejection(request: &ExecutionRequest) -> Option<&'static str> {
    let proxy = &request.policy.network_proxy;
    if !proxy.is_enabled() {
        return None;
    }

    // Checked ahead of the builtin exemption because it binds to *every*
    // enabled proxy. Both proxy flavors resolve to `ResolvedNetworkMode::
    // ProxyOnly`, whose chain comes from `EgressPlan::for_proxy` and never
    // reads `network_egress` -- so a directional rule set is dropped in
    // silence either way. The exemption below is about host *lists*, which
    // MXC does apply itself for the builtin proxy; nothing applies directional
    // rules under a proxy, so the exemption must not extend to them.
    //
    // JSON configs cannot reach this (the parser constrains the same posture),
    // which leaves programmatic callers: precisely who this twin exists for.
    let directional_conflicts = request
        .policy
        .network_egress
        .as_ref()
        .is_some_and(|egress| {
            egress.default != NetworkAction::Deny
                || !egress.allow.is_empty()
                || !egress.deny.is_empty()
        });
    if directional_conflicts {
        return Some(BWRAP_PROXY_DIRECTIONAL_EGRESS);
    }

    if proxy.builtin_test_server {
        return None;
    }
    let has_host_rules =
        !request.policy.allowed_hosts.is_empty() || !request.policy.blocked_hosts.is_empty();
    // `default_network_policy` is a legacy-shape field: the directional path
    // never writes it, so it sits at its `Block` default whether or not the
    // caller said anything about egress. Reading it as a caller statement
    // would refuse every directional runtime proxy -- the one posture the
    // parser already constrains to `egress.default='deny'` with no direct
    // rules, which *is* proxy-only egress and carries no host lists that could
    // be silently dropped.
    let legacy_shape = !is_directional(&request.policy);
    let conflicts = has_host_rules
        || (legacy_shape && request.policy.default_network_policy == NetworkPolicy::Block);

    conflicts.then_some(BWRAP_EXTERNAL_PROXY_HOST_RULES)
}

/// Validate-time twin of [`local_network_diagnostic`]: the same mismatch, but
/// only for schemas that reject it rather than warn.
///
/// Keys off proxy *enablement* rather than a resolved address because
/// `builtinTestServer` has no address until the proxy starts, which is after
/// validation.
///
/// Rejects on the value, not on whether the caller wrote the field. `false` is
/// the schema default *and* a deny, so an omitted `allowLocalNetwork` still
/// asks for inbound denial. Callers wanting the shared namespace acknowledge
/// the exposure with `allowLocalNetwork=true`. The warning path keeps the
/// looser check: it only logs.
pub fn local_network_rejection(request: &ExecutionRequest) -> Option<&'static str> {
    if !rejects_unhonorable_network(request) {
        return None;
    }
    let mode =
        ResolvedNetworkMode::from_request(request, request.policy.network_proxy.is_enabled());
    local_network_diagnostic_for_mode(request, mode)
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
///
/// The text carries no severity prefix so it can serve both the pre-0.8
/// warning and the 0.8+ rejection; callers add "WARNING: " when logging.
pub(crate) fn local_network_diagnostic_for_mode(
    request: &ExecutionRequest,
    network_mode: ResolvedNetworkMode,
) -> Option<&'static str> {
    match (
        request.policy.allow_local_network,
        network_mode.uses_private_netns(),
    ) {
        (false, false) => Some(BWRAP_LOCAL_NETWORK_SHARED_NS),
        (true, true) => Some(BWRAP_LOCAL_NETWORK_PRIVATE_NS),
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
    // SECURITY: proxy mode joins the supervisor's user namespace rather than
    // unsharing, leaving that descriptor open in the workload. It is inert only
    // because bwrap empties the capability sets before exec — asserted by
    // run_bwrap_network_proxy_test.sh, explained in
    // docs/bwrap-support/bubblewrap-backend.md.
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
    args.extend(COMMAND_TAIL.iter().map(|arg| arg.to_string()));
    args.push(request.script_code.clone());

    args
}

#[cfg(test)]
mod tests {
    use super::*;
    use wxc_common::models::ContainerPolicy;

    fn base_request() -> ExecutionRequest {
        ExecutionRequest {
            script_code: "echo hello".into(),
            working_directory: "/home/user".into(),
            ..Default::default()
        }
    }

    #[test]
    fn the_schema_gate_selects_the_private_namespace_only_from_0_8_onward() {
        // The gate decides whether a proxy run gets the 0.8 private namespace
        // or keeps the legacy shared-host-network behavior GHCP depends on, so
        // its boundaries are pinned explicitly.
        let cases = [
            ("0.6.0-alpha", ResolvedNetworkMode::LegacyProxy),
            ("0.7.0-alpha", ResolvedNetworkMode::LegacyProxy),
            ("0.7.99", ResolvedNetworkMode::LegacyProxy),
            ("0.8.0", ResolvedNetworkMode::ProxyOnly),
            ("0.8.0-alpha", ResolvedNetworkMode::ProxyOnly),
            ("0.8.0-beta", ResolvedNetworkMode::ProxyOnly),
            ("0.9.0", ResolvedNetworkMode::ProxyOnly),
            ("0.10.0", ResolvedNetworkMode::ProxyOnly),
            ("1.0.0", ResolvedNetworkMode::ProxyOnly),
            ("2.1.0", ResolvedNetworkMode::ProxyOnly),
            // An absent version stays legacy: programmatic callers who never
            // set one are the pre-0.8 population. Anything non-empty but
            // unparsable cannot have come from the parser (it validates the
            // version first), so it is a hand-built request whose typo must not
            // buy pre-0.8 leniency -- it resolves strictly, matching
            // `schema_enforces_network_strictly`, which the rejection gates
            // share.
            ("", ResolvedNetworkMode::LegacyProxy),
            ("0.8", ResolvedNetworkMode::ProxyOnly),
            ("0", ResolvedNetworkMode::ProxyOnly),
            ("0.8-beta", ResolvedNetworkMode::ProxyOnly),
            ("v0.8.0", ResolvedNetworkMode::ProxyOnly),
            ("not-a-version", ResolvedNetworkMode::ProxyOnly),
        ];

        for (version, expected) in cases {
            let request = ExecutionRequest {
                schema_version: version.into(),
                ..base_request()
            };
            assert_eq!(
                ResolvedNetworkMode::from_request(&request, true),
                expected,
                "schema version {version:?} resolved to the wrong network mode"
            );
        }
    }

    #[test]
    fn the_schema_gate_selects_in_netns_firewall_rules_only_from_0_8_onward() {
        // The same gate governs the firewall path. Pre-0.8 callers keep
        // FirewallFiltered — which filters nothing, because its rules land on
        // a host chain the sandbox never traverses — because that is the
        // behavior they already run under; only 0.8+ opts into rules that
        // actually apply, and into the IP/CIDR-only rule addresses that come
        // with them.
        let cases = [
            ("0.6.0-alpha", ResolvedNetworkMode::FirewallFiltered),
            ("0.7.0-alpha", ResolvedNetworkMode::FirewallFiltered),
            ("0.7.99", ResolvedNetworkMode::FirewallFiltered),
            ("0.8.0-alpha", ResolvedNetworkMode::FirewallEnforced),
            ("0.9.0", ResolvedNetworkMode::FirewallEnforced),
            ("1.0.0", ResolvedNetworkMode::FirewallEnforced),
            // Absent stays legacy; a non-empty unparsable version resolves
            // strictly, for the same reason it does on the proxy path.
            ("", ResolvedNetworkMode::FirewallFiltered),
            ("not-a-version", ResolvedNetworkMode::FirewallEnforced),
        ];

        for (version, expected) in cases {
            let request = ExecutionRequest {
                schema_version: version.into(),
                policy: ContainerPolicy {
                    network_enforcement_mode: NetworkEnforcementMode::Firewall,
                    allowed_hosts: vec!["203.0.113.7".into()],
                    ..Default::default()
                },
                ..base_request()
            };
            assert_eq!(
                ResolvedNetworkMode::from_request(&request, false),
                expected,
                "schema version {version:?} resolved to the wrong firewall mode"
            );
        }
    }

    #[test]
    fn the_schema_gate_does_not_apply_when_no_proxy_is_active() {
        // Without an active proxy the version is irrelevant — a 0.8 request
        // still classifies on policy alone (default policy is block, so this
        // lands on the plain isolated namespace, not the proxy one).
        let request = ExecutionRequest {
            schema_version: "0.8.0".into(),
            ..base_request()
        };
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

    struct NetworkPlanCase {
        name: &'static str,
        schema_version: &'static str,
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
                schema_version: "0.8.0-alpha",
                default_policy: NetworkPolicy::Block,
                enforcement_mode: NetworkEnforcementMode::Capabilities,
                allowed_hosts: &[],
                blocked_hosts: &[],
                proxy_active: false,
                expected: ResolvedNetworkMode::Isolated,
            },
            NetworkPlanCase {
                name: "default allow is shared",
                schema_version: "0.8.0-alpha",
                default_policy: NetworkPolicy::Allow,
                enforcement_mode: NetworkEnforcementMode::Capabilities,
                allowed_hosts: &[],
                blocked_hosts: &[],
                proxy_active: false,
                expected: ResolvedNetworkMode::Shared,
            },
            NetworkPlanCase {
                name: "firewall allow rules are enforced in-namespace at 0.8",
                schema_version: "0.8.0-alpha",
                default_policy: NetworkPolicy::Block,
                enforcement_mode: NetworkEnforcementMode::Firewall,
                allowed_hosts: &["203.0.113.7"],
                blocked_hosts: &[],
                proxy_active: false,
                expected: ResolvedNetworkMode::FirewallEnforced,
            },
            NetworkPlanCase {
                name: "firewall allow rules keep the legacy host chain pre-0.8",
                schema_version: "0.7.0-alpha",
                default_policy: NetworkPolicy::Block,
                enforcement_mode: NetworkEnforcementMode::Firewall,
                allowed_hosts: &["example.com"],
                blocked_hosts: &[],
                proxy_active: false,
                expected: ResolvedNetworkMode::FirewallFiltered,
            },
            NetworkPlanCase {
                name: "combined enforcement block rules are enforced at 0.8",
                schema_version: "0.8.0-alpha",
                default_policy: NetworkPolicy::Allow,
                enforcement_mode: NetworkEnforcementMode::Both,
                allowed_hosts: &[],
                blocked_hosts: &["198.51.100.9"],
                proxy_active: false,
                expected: ResolvedNetworkMode::FirewallEnforced,
            },
            NetworkPlanCase {
                name: "combined enforcement block rules keep the host chain pre-0.8",
                schema_version: "0.6.0-alpha",
                default_policy: NetworkPolicy::Allow,
                enforcement_mode: NetworkEnforcementMode::Both,
                allowed_hosts: &[],
                blocked_hosts: &["example.com"],
                proxy_active: false,
                expected: ResolvedNetworkMode::FirewallFiltered,
            },
            NetworkPlanCase {
                name: "capabilities mode with host rules stays shared",
                schema_version: "0.8.0-alpha",
                default_policy: NetworkPolicy::Block,
                enforcement_mode: NetworkEnforcementMode::Capabilities,
                allowed_hosts: &["example.com"],
                blocked_hosts: &[],
                proxy_active: false,
                expected: ResolvedNetworkMode::Shared,
            },
            NetworkPlanCase {
                name: "proxy takes precedence over isolation",
                schema_version: "0.8.0-alpha",
                default_policy: NetworkPolicy::Block,
                enforcement_mode: NetworkEnforcementMode::Capabilities,
                allowed_hosts: &[],
                blocked_hosts: &[],
                proxy_active: true,
                expected: ResolvedNetworkMode::ProxyOnly,
            },
            NetworkPlanCase {
                name: "proxy takes precedence over firewall filtering",
                schema_version: "0.8.0-alpha",
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
                schema_version: case.schema_version.into(),
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
        assert!(ResolvedNetworkMode::FirewallFiltered.requires_host_firewall_manager());
        assert!(!ResolvedNetworkMode::Shared.requires_host_firewall_manager());
        // ProxyOnly enforces via in-netns rules, not the host manager.
        assert!(!ResolvedNetworkMode::ProxyOnly.requires_host_firewall_manager());
        // FirewallEnforced is the same shape as ProxyOnly minus the proxy: its
        // rules are programmed from inside the sandbox's own namespace, which
        // is the whole reason it filters where FirewallFiltered does not.
        assert!(ResolvedNetworkMode::FirewallEnforced.uses_private_netns());
        assert!(ResolvedNetworkMode::FirewallEnforced.uses_external_userns());
        assert!(!ResolvedNetworkMode::FirewallEnforced.requires_host_firewall_manager());
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

    // ------- allowLocalNetwork rejection (schema 0.8+) ------------------

    #[test]
    fn local_network_mismatch_is_not_rejected_before_0_8() {
        // A 0.7 proxy config shares the host netns and leaves allowLocalNetwork
        // at its default false. That combination must keep warning rather than
        // start failing, or every existing 0.6/0.7 proxy caller breaks.
        let mut r = base_request();
        r.schema_version = "0.7.0-alpha".into();
        r.policy.network_proxy.address = Some(ProxyAddress::new("127.0.0.1".into(), 8080));
        assert!(local_network_diagnostic(&r, r.policy.network_proxy.address.as_ref()).is_some());
        assert!(local_network_rejection(&r).is_none());
    }

    #[test]
    fn local_network_mismatch_is_rejected_at_0_8() {
        let mut r = base_request();
        r.schema_version = "0.8.0-alpha".into();
        r.policy.default_network_policy = NetworkPolicy::Allow;
        let msg = local_network_rejection(&r).expect("shared netns cannot honor the deny");
        assert!(msg.contains("allowLocalNetwork=false"));
        // The text is reused verbatim as an error, so it must carry no severity.
        assert!(!msg.contains("WARNING"));
    }

    #[test]
    fn an_omitted_local_network_is_rejected_like_an_explicit_deny_at_0_8() {
        // `false` is the schema default *and* a deny, so silence still asks for
        // inbound denial.
        let mut r = base_request();
        r.schema_version = "0.8.0-alpha".into();
        r.policy.default_network_policy = NetworkPolicy::Allow;
        assert!(!r.policy.allow_local_network, "default is the deny posture");
        let msg = local_network_rejection(&r).expect("an omitted deny is still a deny");
        assert!(msg.contains("allowLocalNetwork=false"));
        // Actionable only if it names the acknowledgment.
        assert!(msg.contains("allowLocalNetwork=true"));
    }

    #[test]
    fn acknowledged_local_network_exposure_is_accepted_at_0_8() {
        // The escape hatch from the rejection above.
        let mut r = base_request();
        r.schema_version = "0.8.0-alpha".into();
        r.policy.default_network_policy = NetworkPolicy::Allow;
        r.policy.allow_local_network = true;
        assert!(local_network_rejection(&r).is_none());
    }

    #[test]
    fn honored_local_network_is_not_rejected_at_0_8() {
        // block + no host rules + no proxy is a private netns, which satisfies
        // allowLocalNetwork=false; nothing to reject.
        let mut r = base_request();
        r.schema_version = "0.8.0-alpha".into();
        assert!(local_network_rejection(&r).is_none());
    }

    #[test]
    fn builtin_test_server_counts_as_an_active_proxy_when_rejecting() {
        // builtinTestServer has no address until the proxy starts, which is
        // after validation, so the rejection keys off enablement instead.
        // defaultPolicy='allow' would be a shared namespace on its own, so the
        // rejection fires only if the proxy is recognized without an address.
        let mut r = base_request();
        r.schema_version = "0.8.0-alpha".into();
        r.policy.default_network_policy = NetworkPolicy::Allow;
        r.policy.allow_local_network = true;
        assert!(local_network_rejection(&r).is_none());

        r.policy.network_proxy.builtin_test_server = true;
        assert!(r.policy.network_proxy.address.is_none());
        assert!(local_network_rejection(&r).is_some());
    }

    /// Without this twin a programmatic caller would sail past the parser's
    /// rejection and have the host policy dropped on the floor.
    #[test]
    fn external_proxy_with_host_rules_is_rejected() {
        let mut r = base_request();
        r.schema_version = "0.8.0-alpha".into();
        r.policy.default_network_policy = NetworkPolicy::Allow;
        r.policy.network_proxy.address = Some(ProxyAddress::new("proxy.example.com".into(), 3128));
        assert!(external_proxy_host_rules_rejection(&r).is_none());

        r.policy.allowed_hosts = vec!["10.0.0.1".into()];
        let msg = external_proxy_host_rules_rejection(&r).expect("lists are never forwarded");
        assert!(msg.contains("external network.proxy"));

        r.policy.allowed_hosts.clear();
        r.policy.blocked_hosts = vec!["10.0.0.1".into()];
        assert!(external_proxy_host_rules_rejection(&r).is_some());

        r.policy.blocked_hosts.clear();
        r.policy.default_network_policy = NetworkPolicy::Block;
        assert!(external_proxy_host_rules_rejection(&r).is_some());
    }

    /// The builtin test proxy *is* handed the lists, so it must stay accepted.
    #[test]
    fn builtin_test_server_with_host_rules_is_not_rejected() {
        let mut r = base_request();
        r.schema_version = "0.8.0-alpha".into();
        r.policy.network_proxy.builtin_test_server = true;
        r.policy.allowed_hosts = vec!["10.0.0.1".into()];
        assert!(external_proxy_host_rules_rejection(&r).is_none());
    }

    /// A directional runtime proxy must not trip the legacy host-list guard.
    ///
    /// `default_network_policy` is a legacy-shape field the directional path
    /// never writes, so it sits at its `Block` default. Reading it as if the
    /// caller had asked for `defaultPolicy='block'` refused *every* directional
    /// runtime proxy -- which made `RUNTIME_PROXY` declarable but unusable,
    /// since the parser requires exactly `egress.default='deny'` with no direct
    /// rules for that field. The guard must still fire on the legacy shape, and
    /// still fire on real host lists in either shape, so all three are pinned
    /// here.
    #[test]
    fn a_directional_runtime_proxy_is_not_refused_by_the_legacy_host_list_guard() {
        use wxc_common::models::{NetworkEgressPolicy, NetworkRule};

        let mut r = base_request();
        r.schema_version = "0.8.0-alpha".into();
        r.policy.network_proxy.address = Some(ProxyAddress::new("127.0.0.1".into(), 3128));

        // Legacy shape, defaulted `Block`: still refused, as before.
        r.policy.default_network_policy = NetworkPolicy::Block;
        assert!(
            external_proxy_host_rules_rejection(&r).is_some(),
            "the legacy shape must keep its refusal"
        );

        // Directional shape: the same defaulted `Block` is not a caller
        // statement, so it must no longer refuse.
        r.policy.network_egress = Some(NetworkEgressPolicy {
            default: NetworkAction::Deny,
            ..Default::default()
        });
        assert!(
            external_proxy_host_rules_rejection(&r).is_none(),
            "a directional proxy-only posture carries no host lists to drop"
        );

        // An ingress-only directional request is directional too: keying the
        // legacy discriminator on `egress` alone read the defaulted `Block` as
        // a caller statement and refused it.
        r.policy.network_egress = None;
        r.policy.network_ingress = Some(wxc_common::models::NetworkIngressPolicy::default());
        assert!(
            external_proxy_host_rules_rejection(&r).is_none(),
            "an absent egress section is not a legacy `defaultPolicy='block'`"
        );
        r.policy.network_ingress = None;
        r.policy.network_egress = Some(NetworkEgressPolicy {
            default: NetworkAction::Deny,
            ..Default::default()
        });

        // Real host lists are still refused even on the directional shape --
        // the parser forbids the mix, so this only reaches a programmatic
        // caller, which is exactly who this twin exists for.
        r.policy.allowed_hosts = vec!["10.0.0.1".into()];
        assert!(
            external_proxy_host_rules_rejection(&r).is_some(),
            "host lists are never forwarded to an external proxy"
        );
        r.policy.allowed_hosts.clear();

        // Directional egress that is *not* the proxy-only posture must fail
        // closed. `ProxyOnly` builds its chain from `EgressPlan::for_proxy` and
        // never reads `network_egress`, so accepting these would drop the
        // requested rules in silence -- the same class of bug the host-list
        // half of this guard prevents.
        for unhonorable in [
            NetworkEgressPolicy {
                default: NetworkAction::Allow,
                ..Default::default()
            },
            NetworkEgressPolicy {
                default: NetworkAction::Deny,
                allow: vec![NetworkRule::default()],
                ..Default::default()
            },
            NetworkEgressPolicy {
                default: NetworkAction::Deny,
                deny: vec![NetworkRule::default()],
                ..Default::default()
            },
        ] {
            r.policy.network_egress = Some(unhonorable.clone());
            assert_eq!(
                external_proxy_host_rules_rejection(&r),
                Some(BWRAP_PROXY_DIRECTIONAL_EGRESS),
                "a directional rule set combined with a proxy would be dropped in silence"
            );

            // The builtin proxy takes the same chain from `for_proxy`, so the
            // exemption it enjoys for host *lists* -- which MXC applies itself
            // -- must not extend to directional rules, which nothing applies.
            let mut builtin = r.clone();
            builtin.policy.network_proxy.address = None;
            builtin.policy.network_proxy.builtin_test_server = true;
            assert_eq!(
                external_proxy_host_rules_rejection(&builtin),
                Some(BWRAP_PROXY_DIRECTIONAL_EGRESS),
                "the builtin proxy drops directional rules just as silently"
            );
        }

        // The builtin proxy keeps its host-list exemption: that is the whole
        // point of the flag, and narrowing it would be a behavior change.
        r.policy.network_egress = Some(NetworkEgressPolicy {
            default: NetworkAction::Deny,
            ..Default::default()
        });
        r.policy.network_proxy.address = None;
        r.policy.network_proxy.builtin_test_server = true;
        r.policy.allowed_hosts = vec!["10.0.0.1".into()];
        assert!(
            external_proxy_host_rules_rejection(&r).is_none(),
            "MXC enforces host lists itself for the builtin proxy"
        );
    }

    /// A directional egress policy must land on the one mode whose chains the
    /// sandbox actually traverses.
    ///
    /// This is the invariant that was broken: `ResolvedNetworkMode` classified
    /// from the legacy fields alone, which the directional parse path leaves at
    /// their defaults, so a rule-bearing policy resolved to `Isolated` and the
    /// runner — which builds the egress chain only under `FirewallEnforced`
    /// (bwrap_runner.rs) — never programmed the rules at all. Unit tests on
    /// `EgressPlan` cannot see this: they call the plan directly and so skip
    /// the gate that decides whether it is ever called.
    #[test]
    fn a_directional_rule_selects_the_namespace_whose_chain_is_programmed() {
        let request = directional_egress_request("0.8.0-alpha", NetworkAction::Deny, true);
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
        let denied = directional_egress_request("0.8.0-alpha", NetworkAction::Deny, false);
        assert_eq!(
            ResolvedNetworkMode::from_request(&denied, false),
            ResolvedNetworkMode::Isolated
        );

        let allowed = directional_egress_request("0.8.0-alpha", NetworkAction::Allow, false);
        let mode = ResolvedNetworkMode::from_request(&allowed, false);
        assert_eq!(mode, ResolvedNetworkMode::FirewallEnforced);
        assert!(mode.uses_private_netns());
    }

    /// No directional posture may share the host network namespace under the
    /// 0.8 contract: there is no inbound primitive there, and a defaulted
    /// `ingress.default='deny'` is indistinguishable from a written one, so
    /// `Shared` would silently drop the inbound half of the policy.
    #[test]
    fn no_directional_posture_shares_the_host_namespace() {
        for default in [NetworkAction::Allow, NetworkAction::Deny] {
            for with_rule in [false, true] {
                let request = directional_egress_request("0.8.0-alpha", default, with_rule);
                let mode = ResolvedNetworkMode::from_request(&request, false);
                assert!(
                    mode.uses_private_netns(),
                    "default={default:?} with_rule={with_rule} resolved to {mode:?}"
                );
            }
        }
    }

    /// Off the 0.8 contract there is no namespace to program, so the mode
    /// reports the unfiltered truth instead of claiming a filtering it cannot
    /// perform. `validate` refuses the combination; this pins that the mode
    /// never silently promotes a pre-0.8 request into the private namespace.
    #[test]
    fn a_directional_rule_off_the_0_8_contract_is_not_claimed_as_filtered() {
        let request = directional_egress_request("0.7.0-alpha", NetworkAction::Deny, true);
        let mode = ResolvedNetworkMode::from_request(&request, false);
        assert_eq!(mode, ResolvedNetworkMode::Shared);
        assert!(!mode.uses_private_netns());
    }

    /// A proxy run is classified by the proxy arm before the directional one,
    /// so a directional section must not divert it out of `ProxyOnly` — that
    /// mode derives its chain from the resolved proxy endpoint.
    #[test]
    fn a_directional_section_does_not_divert_a_proxy_run() {
        let mut request = directional_egress_request("0.8.0-alpha", NetworkAction::Deny, true);
        request.policy.network_proxy.builtin_test_server = true;
        assert_eq!(
            ResolvedNetworkMode::from_request(&request, true),
            ResolvedNetworkMode::ProxyOnly
        );
    }

    /// An ingress-only directional request must not fall to the legacy arm.
    ///
    /// It did: keying on `network_egress` alone sent it there, where a leftover
    /// `defaultPolicy='allow'` resolved to `Shared` -- the host namespace, with
    /// no chain at all -- silently discarding both the ingress denial and the
    /// host-loopback drop.
    #[test]
    fn an_ingress_only_directional_request_still_gets_a_private_namespace() {
        use wxc_common::models::{NetworkIngressPolicy, NetworkPolicy};

        let mut request = base_request();
        request.schema_version = "0.8.0-alpha".into();
        request.policy.network_ingress = Some(NetworkIngressPolicy::default());
        request.policy.default_network_policy = NetworkPolicy::Allow;

        let mode = ResolvedNetworkMode::from_request(&request, false);
        assert_ne!(
            mode,
            ResolvedNetworkMode::Shared,
            "the host namespace programs no chain, so the deny posture would be lost"
        );
        assert!(mode.uses_private_netns(), "{mode:?}");
    }

    /// The predicate is now shared by three call sites, so pin it directly:
    /// a per-site test would let one drift without failing the others.
    #[test]
    fn either_directional_section_alone_marks_the_policy_directional() {
        use wxc_common::models::{NetworkEgressPolicy, NetworkIngressPolicy};

        let cases = [
            (None, None, false),
            (Some(NetworkEgressPolicy::default()), None, true),
            (None, Some(NetworkIngressPolicy::default()), true),
            (
                Some(NetworkEgressPolicy::default()),
                Some(NetworkIngressPolicy::default()),
                true,
            ),
        ];

        for (egress, ingress, expected) in cases {
            let policy = ContainerPolicy {
                network_egress: egress.clone(),
                network_ingress: ingress.clone(),
                ..Default::default()
            };
            assert_eq!(
                is_directional(&policy),
                expected,
                "egress={:?} ingress={:?}",
                egress.is_some(),
                ingress.is_some()
            );
        }
    }

    /// Build a directional request: no legacy network field is touched, which
    /// is exactly what the parser produces on that path.
    fn directional_egress_request(
        schema: &str,
        default: NetworkAction,
        with_rule: bool,
    ) -> ExecutionRequest {
        use wxc_common::models::{NetworkEgressPolicy, NetworkRule};

        let mut request = base_request();
        request.schema_version = schema.into();
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
        schema: &str,
        ingress_default: NetworkAction,
        host_loopback: NetworkAction,
    ) -> ExecutionRequest {
        use wxc_common::models::{NetworkEgressPolicy, NetworkIngressPolicy};

        let mut request = base_request();
        request.schema_version = schema.into();
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
        let request = directional_request("0.8.0-alpha", NetworkAction::Allow, NetworkAction::Deny);
        assert_eq!(
            directional_network_rejection(&request),
            Some(BWRAP_INGRESS_DEFAULT_ALLOW)
        );
    }

    /// The sandbox's loopback is its own namespace's, not the host's.
    #[test]
    fn a_host_loopback_accepting_posture_is_refused() {
        let request = directional_request("0.8.0-alpha", NetworkAction::Deny, NetworkAction::Allow);
        assert_eq!(
            directional_network_rejection(&request),
            Some(BWRAP_HOST_LOOPBACK_ALLOW)
        );
    }

    /// A directional section is a 0.8 construct. On an earlier schema the mode
    /// resolver reports `Shared`, so accepting it would program nothing --
    /// hence a rejection that is deliberately not schema-gated.
    #[test]
    fn a_directional_section_before_0_8_is_refused() {
        for schema in ["", "0.6.0-alpha", "0.7.0-alpha"] {
            let request = directional_request(schema, NetworkAction::Deny, NetworkAction::Deny);
            assert_eq!(
                directional_network_rejection(&request),
                Some(BWRAP_DIRECTIONAL_PRE_0_8),
                "schema={schema}"
            );
        }
    }

    /// Positive control: the honorable posture must pass, or the gate above is
    /// just refusing every directional config.
    #[test]
    fn a_fully_denied_directional_posture_is_accepted() {
        let request = directional_request("0.8.0-alpha", NetworkAction::Deny, NetworkAction::Deny);
        assert_eq!(directional_network_rejection(&request), None);
    }

    /// The gate must not fire on the legacy shape, which has no directional
    /// sections at all -- that path is what GHCP runs on.
    #[test]
    fn a_legacy_request_is_untouched_by_the_directional_gate() {
        let mut request = base_request();
        request.schema_version = "0.8.0-alpha".into();
        request.policy.default_network_policy = NetworkPolicy::Allow;
        request.policy.allowed_hosts = vec!["10.0.0.1".into()];
        assert_eq!(directional_network_rejection(&request), None);
    }

    // The predicate gates whether an unenforceable network element is a hard
    // error or a warning, so a regression in it changes security behavior
    // silently. Pinned directly rather than only through the call sites.
    #[test]
    fn strict_network_enforcement_starts_at_0_8() {
        assert!(!schema_enforces_network_strictly("0.7.9"));
        assert!(!schema_enforces_network_strictly("0.7.0-alpha"));
        assert!(schema_enforces_network_strictly("0.8.0-alpha"));
        assert!(schema_enforces_network_strictly("0.8.0"));
        assert!(schema_enforces_network_strictly("0.9.0"));
    }

    #[test]
    fn strict_network_enforcement_holds_past_1_0() {
        // A tuple compare, so a major bump must not wrap back to lenient.
        assert!(schema_enforces_network_strictly("1.0.0"));
        assert!(schema_enforces_network_strictly("2.3.4"));
    }

    #[test]
    fn a_pre_release_label_does_not_lower_the_version() {
        // semver orders 0.8.0-alpha *below* 0.8.0; comparing (major, minor)
        // sidesteps that, which is the whole reason for the tuple.
        assert!(
            semver::Version::parse("0.8.0-alpha").unwrap()
                < semver::Version::parse("0.8.0").unwrap()
        );
        assert!(schema_enforces_network_strictly("0.8.0-alpha"));
    }

    #[test]
    fn an_absent_version_is_lenient_but_a_malformed_one_is_not() {
        // Absent is the pre-0.8 programmatic caller: the parser accepts it, so
        // it keeps its behavior. Malformed cannot come from the parser at all
        // (it rejects these), so it is a hand-built request whose typo must not
        // buy leniency.
        assert!(!schema_enforces_network_strictly(""));
        assert!(schema_enforces_network_strictly("x"));
        assert!(schema_enforces_network_strictly("0.8"));
        assert!(schema_enforces_network_strictly("0.7"));
    }

    /// `ResolvedNetworkMode` is now the only implementation of the namespace
    /// choice — the parser's re-derived twin is gone — so the mode matrix is
    /// pinned against explicit expectations rather than against a second copy
    /// that could drift with it.
    #[test]
    fn the_resolved_mode_matches_the_namespace_it_claims_across_the_matrix() {
        for schema in ["", "0.7.0-alpha", "0.8.0-alpha"] {
            let strict = schema == "0.8.0-alpha";
            for proxy in [false, true] {
                for mode in [
                    NetworkEnforcementMode::Capabilities,
                    NetworkEnforcementMode::Firewall,
                    NetworkEnforcementMode::Both,
                ] {
                    for policy in [NetworkPolicy::Allow, NetworkPolicy::Block] {
                        for hosts in [false, true] {
                            let mut r = base_request();
                            r.schema_version = schema.into();
                            r.policy.network_proxy.builtin_test_server = proxy;
                            r.policy.network_enforcement_mode = mode.clone();
                            r.policy.default_network_policy = policy.clone();
                            r.policy.allowed_hosts = if hosts {
                                vec!["10.0.0.1".into()]
                            } else {
                                vec![]
                            };

                            // Private namespaces: proxy-only and firewall-
                            // enforced are both 0.8-only, so either shape is
                            // private exactly when the schema is strict. Plus
                            // Isolated, the only pre-0.8 mode that unshares.
                            let uses_firewall = matches!(
                                mode,
                                NetworkEnforcementMode::Firewall | NetworkEnforcementMode::Both
                            );
                            let expected = if proxy || (uses_firewall && hosts) {
                                strict
                            } else {
                                policy == NetworkPolicy::Block && !hosts
                            };

                            let resolved = ResolvedNetworkMode::from_request(&r, proxy);
                            assert_eq!(
                                resolved.uses_private_netns(),
                                expected,
                                "schema={schema} proxy={proxy} mode={mode:?} \
                                 policy={policy:?} hosts={hosts}"
                            );
                        }
                    }
                }
            }
        }
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
