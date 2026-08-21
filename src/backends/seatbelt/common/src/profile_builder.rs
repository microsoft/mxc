// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Pure builder that converts an [`ExecutionRequest`] into a TinyScheme sandbox
//! profile string suitable for `/usr/bin/sandbox-exec -p <profile>`.
//!
//! This module is platform-agnostic — it is just string generation — so it
//! is unit-tested on every host (Windows / Linux / macOS) in CI.
//!
//! # Profile shape
//!
//! The generated profile follows a deny-by-default baseline with explicit
//! allow rules layered on top, then explicit deny rules at the end so that
//! `deniedPaths` overrides any broader `readonly`/`readwrite` allow:
//!
//! ```text
//! (version 1)
//! (deny default)
//! ;; baseline allow rules required for any process to start ...
//! ;; policy-derived allow rules (filesystem readonly/readwrite, network) ...
//! ;; policy-derived deny rules (deniedPaths) ...
//! ```
//!
//! Apple's Seatbelt sandbox evaluates rules with last-match-wins semantics (within a given
//! operation), so trailing deny rules take precedence over earlier allow
//! rules — the behavior callers expect from MXC's `denied_paths`.

use std::fmt::Write as _;

use wxc_common::filesystem_resolve::{resolve_path_plan, FsIntent};
use wxc_common::models::{
    ClipboardPolicy, ContainerPolicy, ExecutionRequest, NetworkAction, NetworkPolicy, ProxyAddress,
};

/// Build a complete Seatbelt sandbox profile, scoping cooperative proxy
/// reachability to the resolved address supplied by the runner.
///
/// `pub` (not `pub(crate)`) so it stays a reachable API root: `profile_builder`
/// is compiled and unit-tested on every host, but its only in-crate caller
/// (`seatbelt_runner`) is `cfg(target_os = "macos")`, so on other targets a
/// narrower visibility would make the whole profile-building chain dead code.
pub fn build_profile_with_proxy(
    request: &ExecutionRequest,
    proxy_address: Option<&ProxyAddress>,
) -> Result<String, String> {
    if let Some(override_profile) = request
        .seatbelt
        .as_ref()
        .and_then(|c| c.profile_override.as_ref())
    {
        return Ok(override_profile.clone());
    }

    let mut out = String::with_capacity(2048);

    // Header — Apple's Seatbelt requires `(version 1)` and we baseline with deny-default.
    out.push_str("(version 1)\n");
    out.push_str("(deny default)\n");

    // Minimum allow rules so a child process can actually run. These are
    // the same things Apple's own built-in profiles (e.g. no-internet)
    // include: dyld + system libraries, mach-lookup of the basic agents,
    // sysctl reads, and signaling processes in the same sandbox.
    out.push_str(BASELINE_ALLOW);

    // Filesystem — read-only system paths every process needs.
    out.push_str(SYSTEM_READ_ALLOW);

    // Pseudo-terminal access — when the executor binary runs under a pty
    // the sandboxed shell inherits that TTY, so it sees a real terminal
    // and calls `isatty()` / `tcgetattr()` / `ttyname()` against it.
    // Without these rules, those calls fail with EPERM because the
    // kernel calls block on the secondary fd.
    out.push_str(TTY_ALLOW);

    // Policy-derived allow rules.
    let resolved = ResolvedPaths::from_policy(&request.policy)?;
    write_filesystem_allow(&mut out, &resolved);
    write_network_rules(&mut out, request, proxy_address);
    write_nested_pty_rules(&mut out, request);
    write_keychain_rules(&mut out, request)?;
    write_extra_seatbelt_rules(&mut out, request);
    write_ui_rules(&mut out, request);

    // Policy-derived deny rules go LAST so they win on conflict.
    write_filesystem_deny(&mut out, &resolved);

    Ok(out)
}

/// Baseline allow rules required for any sandboxed process to start.
const BASELINE_ALLOW: &str = "\
;; --- baseline (required for any process to start) ---
(allow process-fork)
(allow process-exec)
(allow signal (target same-sandbox))
(allow sysctl-read)
(allow file-read-metadata)
(allow mach-lookup
    (global-name \"com.apple.system.notification_center\")
    (global-name \"com.apple.system.logger\")
    (global-name \"com.apple.distributed_notifications@Uv3\")
    (global-name \"com.apple.CoreServices.coreservicesd\")
    (global-name \"com.apple.FSEvents\"))
";

/// Read-only access to system paths required by virtually every binary
/// (dynamic linker, system libraries, time-zone data, etc.).
const SYSTEM_READ_ALLOW: &str = "\
;; --- read-only access to system locations ---
;; `/` itself must be readable as data so the shell / loader can resolve
;; path lookups; without this the kernel kills the child during exec.
(allow file-read-data (literal \"/\"))
(allow file-read*
    (subpath \"/bin\")
    (subpath \"/sbin\")
    (subpath \"/usr/bin\")
    (subpath \"/usr/sbin\")
    (subpath \"/usr/lib\")
    (subpath \"/usr/libexec\")
    (subpath \"/usr/share\")
    (subpath \"/System\")
    (subpath \"/Library\")
    (subpath \"/private/var/db/timezone\")
    (subpath \"/private/var/db/dyld\")
    (subpath \"/private/var/select\")
    (subpath \"/private/etc\"))
;; Standard bit-bucket / entropy devices — read+write because shell
;; redirections (`>/dev/null`, `</dev/urandom`) need both directions.
;; Writes to /dev/null and /dev/zero are discarded; /dev/random and
;; /dev/urandom write to the entropy pool, which is harmless.
(allow file-read* file-write*
    (literal \"/dev/null\")
    (literal \"/dev/zero\")
    (literal \"/dev/random\")
    (literal \"/dev/urandom\"))
";

/// Pseudo-terminal device access required by the inner shell when the
/// runner attaches it to a pty. The secondary fd we hand the child as
/// stdin/stdout/stderr lives at `/dev/ttysNNN`, and the shell calls
/// `isatty()` (→ `tcgetattr` → ioctl) plus `ttyname()` against it. We
/// also need read access to `/dev/tty` because most shells re-open it
/// at startup, and read access to `/dev/fd` for the `/dev/stdout` etc.
/// indirection some tools use.
const TTY_ALLOW: &str = "\
;; --- pseudo-terminal access (inherited TTY when run under a pty) ---
(allow file-read* file-write* file-ioctl
    (literal \"/dev/tty\")
    (regex #\"^/dev/ttys[0-9]+$\"))
(allow file-read* (subpath \"/dev/fd\"))
";

/// The policy path lists resolved into the form Seatbelt matches, with the
/// most-restrictive-wins precedence (`deny` > `readonly` > `readwrite`)
/// re-applied.
///
/// The shared parser applies that precedence to the *raw* strings, which is not
/// enough once paths are resolved: two spellings of the same path
/// (`readonlyPaths: ["/private/tmp/x"]` and `readwritePaths: ["/tmp/x"]`)
/// differ as strings, so both survive the parser, then resolve to the same
/// filter here. Seatbelt is last-match-wins and the read-write rule is emitted
/// after the read-only one, so without this the *weaker* grant would win and
/// silently make a read-only path writable.
struct ResolvedPaths {
    readonly: Vec<String>,
    readwrite: Vec<String>,
    denied: Vec<String>,
}

impl ResolvedPaths {
    fn from_policy(policy: &ContainerPolicy) -> Result<Self, String> {
        let denied = resolve_all(&policy.denied_paths)?;
        let readonly = resolve_all(&policy.readonly_paths)?;
        let mut readwrite = resolve_all(&policy.readwrite_paths)?;

        // `denied` is emitted last and would override either allow anyway, but
        // dropping the path keeps the emitted profile an honest description of
        // the effective policy.
        let mut readonly: Vec<String> = readonly;
        readonly.retain(|p| !denied.contains(p));
        readwrite.retain(|p| !denied.contains(p) && !readonly.contains(p));

        Ok(Self {
            readonly,
            readwrite,
            denied,
        })
    }
}

fn resolve_all(paths: &[String]) -> Result<Vec<String>, String> {
    paths.iter().map(|p| resolve_policy_path(p)).collect()
}

fn write_filesystem_allow(out: &mut String, paths: &ResolvedPaths) {
    if paths.readonly.is_empty() && paths.readwrite.is_empty() {
        return;
    }

    // Emit shallow-to-deep, one rule per path, using the same ordering the
    // Linux backends apply (`wxc_common::filesystem_resolve`). Seatbelt is
    // last-match-wins between rules that carry a filter, so ordering by depth
    // makes the *deepest* intent win at every path — a `readonlyPaths` entry
    // nested inside a broader `readwritePaths` subtree stays read-only rather
    // than inheriting the parent's write grant. `deniedPaths` is deliberately
    // not part of this plan: it is emitted last so it outranks these filtered
    // allows regardless of depth.
    out.push_str(";; --- policy.readonlyPaths / policy.readwritePaths (shallow-to-deep) ---\n");
    for mount in resolve_path_plan(&paths.readwrite, &paths.readonly, &[]) {
        let subpath = [mount.path.clone()];
        match mount.intent {
            FsIntent::ReadWrite => {
                // `network-bind` / `network-outbound` under a *path* filter
                // match only AF_UNIX sockets — Seatbelt matches IP sockets with
                // `(local ip)` / `(remote ip)` — so this widens nothing on the
                // IP side. Both halves are needed: Node toolchains (tsx, vite,
                // esbuild, jest) bind an IPC pipe and then connect to it.
                write_path_rule(
                    out,
                    "allow file-read* file-write* network-bind network-outbound",
                    &subpath,
                );
            }
            FsIntent::ReadOnly => {
                write_path_rule(out, "allow file-read*", &subpath);
                // The read allow names only `file-read*`, so it says nothing
                // about write or socket ops and cannot displace a shallower
                // read-write grant — the removal has to be explicit.
                //
                // This deny survives the unfiltered `(allow network-outbound)`
                // that `write_network_rules` emits below under
                // `defaultPolicy: "allow"`: last-match-wins applies between
                // rules that carry a filter, and an unfiltered rule does not
                // override a path-filtered one. Pinned by
                // `readonly_socket_strip_survives_a_default_allow_outbound`.
                write_path_rule(
                    out,
                    "deny file-write* network-bind network-outbound",
                    &subpath,
                );
            }
            FsIntent::Denied => unreachable!("denied paths are not part of this plan"),
        }
    }
}

fn write_filesystem_deny(out: &mut String, paths: &ResolvedPaths) {
    if !paths.denied.is_empty() {
        // `network-outbound` is denied here for two reasons. A denied path can
        // sit inside a broader `readwritePaths` subtree, whose allow covers it;
        // and `write_outbound_allow_rules` emits an *unfiltered* `(allow
        // network-outbound)` under `defaultPolicy: "allow"` and the
        // remote-proxy fallback. Either would otherwise let the sandbox
        // `connect()` to a UNIX socket inside a denied subtree and talk to
        // whatever listens there. A Docker / ssh-agent / gpg-agent socket is a
        // control plane, so that would be an escape.
        out.push_str(";; --- policy.deniedPaths (override broader allow rules) ---\n");
        write_path_rule(
            out,
            "deny file-read* file-write* network-bind network-outbound",
            &paths.denied,
        );
    }
}

/// Emit a single `(<ops> (subpath …)…)` rule over already-resolved paths.
fn write_path_rule(out: &mut String, ops: &str, paths: &[String]) {
    let _ = writeln!(out, "({ops}");
    for p in paths {
        let _ = writeln!(out, "    (subpath {})", quote_scheme(p));
    }
    out.push_str(")\n");
}

fn write_network_rules(
    out: &mut String,
    request: &ExecutionRequest,
    proxy_address: Option<&ProxyAddress>,
) {
    let policy = &request.policy;
    let allow_outbound = effective_egress_allow(policy);
    let has_allowed_hosts = !policy.allowed_hosts.is_empty();

    // blocked_hosts is rejected at the runner level before reaching the
    // profile builder, so it isn't handled here.
    match (allow_outbound, has_allowed_hosts) {
        (false, false) => {
            // Pure deny — implicit from `(deny default)`.
            out.push_str(";; --- network: default-deny (no allow-network rules emitted) ---\n");
            if let Some(address) = proxy_address {
                write_proxy_reachability_rules(out, address);
            }
        }
        (false, true) => {
            // An allowlist under a deny default must never *widen* the posture
            // to allow-all: that would be the inverse of the requested policy.
            // `config_parser` rejects this combination outright unless the
            // MXC-run builtin test proxy is in play, in which case the proxy
            // itself enforces the host list and the profile's job is just to
            // keep the deny baseline plus port-scoped proxy reachability, so
            // the proxy is the only egress path.
            out.push_str(";; --- network: default-deny; allowedHosts enforced by the proxy, not\n");
            out.push_str(";;     the profile (Seatbelt cannot filter by host) ---\n");
            if let Some(address) = proxy_address {
                write_proxy_reachability_rules(out, address);
            }
        }
        (true, false) => {
            out.push_str(";; --- network: outbound allowed (any host) ---\n");
            write_outbound_allow_rules(out);
        }
        (true, true) => {
            // Seatbelt only accepts `*` or `localhost` in `(remote ...)` filters —
            // per-hostname filtering isn't possible. The default is already
            // allow-all here, so the allowlist is a no-op superset rather than a
            // weakening, and allow-all remains the honest rendering.
            out.push_str(
                ";; --- network: allowedHosts requested but Seatbelt cannot filter by host;\n",
            );
            out.push_str(";;     default is already allow, so all outbound stays allowed ---\n");
            write_outbound_allow_rules(out);
        }
    }

    write_local_network_rules(out, effective_allow_local_network(policy));
}

/// Resolves the effective outbound-allow posture, preferring the schema-0.8
/// directional `network.egress.default` when present (the domain's legacy
/// `default_network_policy` field stays at its `Block` default under the
/// directional shape — see `network_parser::apply_directional_network`) and
/// falling back to the legacy field otherwise.
fn effective_egress_allow(policy: &ContainerPolicy) -> bool {
    match policy.network_egress.as_ref() {
        Some(egress) => egress.default == NetworkAction::Allow,
        None => matches!(policy.default_network_policy, NetworkPolicy::Allow),
    }
}

/// Resolves the effective `allowLocalNetwork` posture. Seatbelt maps
/// `network.ingress.default` (not `hostLoopback`, which `validate()` requires
/// to match `default` — Seatbelt has no independent host-loopback posture) to
/// its existing `(allow network-inbound (local ip))` rule.
fn effective_allow_local_network(policy: &ContainerPolicy) -> bool {
    match policy.network_ingress.as_ref() {
        Some(ingress) => ingress.default == NetworkAction::Allow,
        None => policy.allow_local_network,
    }
}

fn write_outbound_allow_rules(out: &mut String) {
    out.push_str("(allow network-outbound)\n");
    out.push_str("(allow network-bind (local ip))\n");
    out.push_str("(allow system-socket)\n");
}

/// Emit the minimal outbound rules that let a sandboxed process reach the
/// resolved cooperative proxy while the default outbound policy stays deny.
///
/// For a loopback proxy — the common `localhost` / `builtinTestServer` case —
/// this scopes outbound to the proxy's exact `localhost:<port>`, so raw-socket
/// clients that ignore `HTTP_PROXY` can reach neither the wider network nor
/// other host-local services — only the proxy itself (a tighter guarantee than
/// Bubblewrap, which shares the host netns). For a remote proxy Seatbelt cannot
/// filter by DNS name, so we fall back to allowing all outbound as a
/// best-effort; the proxy itself enforces host policy for cooperating clients.
/// Because that fallback would silently weaken a `defaultPolicy: "block"` for
/// raw-socket clients, `config_parser` rejects remote-proxy + default-deny up
/// front, so under deny this function only ever sees loopback proxies in
/// practice (the remote arm remains as defense-in-depth).
fn write_proxy_reachability_rules(out: &mut String, proxy_address: &ProxyAddress) {
    if matches!(proxy_address.host(), "127.0.0.1" | "::1" | "localhost") {
        let _ = writeln!(
            out,
            ";; --- network: proxy configured — allow reaching the loopback proxy on port {} ---",
            proxy_address.port()
        );
        let _ = writeln!(
            out,
            "(allow network-outbound (remote ip \"localhost:{}\"))",
            proxy_address.port()
        );
    } else {
        out.push_str(
            ";; --- network: remote proxy configured but Seatbelt cannot filter by host;\n",
        );
        out.push_str(";;     allowing all outbound as best-effort (proxy enforces policy) ---\n");
        write_outbound_allow_rules(out);
    }
}

/// Emit the `network-inbound` rule that lets the sandboxed process accept
/// incoming connections on its own listeners. Required for `server.listen()`
/// on macOS — the `network-bind` rule alone is not enough; the kernel rejects
/// `listen()` with EPERM without `network-inbound`. Scoped to `(local ip)` so
/// it only covers IP sockets, never UNIX-domain or Mach sockets.
fn write_local_network_rules(out: &mut String, allow_local_network: bool) {
    if !allow_local_network {
        return;
    }
    out.push_str(";; --- network: allowLocalNetwork — accept inbound on local IPs ---\n");
    out.push_str("(allow network-inbound (local ip))\n");
}

fn write_ui_rules(out: &mut String, request: &ExecutionRequest) {
    let ui = &request.policy.ui;
    let gui_access = request.seatbelt.as_ref().is_some_and(|c| c.gui_access);

    // The baseline profile uses `(deny default)`, so services are blocked
    // unless explicitly allowed. When UI is enabled, we allow the mach
    // services that gate window creation and launch services. When UI is
    // disabled we omit those allows (and add explicit denies for clarity).
    if !ui.disable {
        out.push_str(";; --- ui enabled: allow WindowServer + LaunchServices ---\n");
        out.push_str("(allow mach-lookup\n");
        out.push_str("    (global-name \"com.apple.windowserver.active\")\n");
        out.push_str("    (global-name \"com.apple.windowserver.session\")\n");
        out.push_str("    (global-name \"com.apple.coreservices.launchservicesd\"))\n");

        if gui_access {
            // GUI apps need a broad set of Mach services to draw windows —
            // WindowServer, CoreAnimation, fonts, Dock, accessibility,
            // preferences, and many XPC helpers that vary across macOS
            // versions. Rather than maintaining a fragile allowlist, we
            // permit all mach-lookup when guiAccess is on. Filesystem and
            // network policies still apply.
            out.push_str(";; --- guiAccess: allow all Mach IPC for GUI applications ---\n");
            out.push_str("(allow mach-lookup)\n");
            // GUI apps must register their own Mach services (XPC listeners)
            // to receive callbacks from WindowServer and other system agents.
            out.push_str("(allow mach-register)\n");

            // IOKit user-client access for GPU / Metal rendering
            out.push_str(";; --- guiAccess: allow IOKit for GPU rendering ---\n");
            out.push_str("(allow iokit-open)\n");

            // Needed for app temp files, caches, GPU shader caches
            out.push_str(";; --- guiAccess: allow writing to per-user temp/cache ---\n");
            out.push_str("(allow file-read* file-write*\n");
            out.push_str("    (subpath \"/private/tmp\")\n");
            out.push_str("    (subpath \"/private/var/folders\"))\n");

            // Pseudo-TTY support — Terminal.app and other GUI apps that
            // spawn shell sessions need to open, grant, and use PTY devices.
            out.push_str(";; --- guiAccess: allow pseudo-TTY for shell sessions ---\n");
            out.push_str("(allow pseudo-tty)\n");
            out.push_str("(allow file-read* file-write* file-ioctl\n");
            out.push_str("    (regex #\"/dev/ttys[0-9]+\")\n");
            out.push_str("    (regex #\"/dev/ptmx\"))\n");

            // POSIX shared memory and IPC — required by Terminal.app and
            // other apps that use notification center or shared memory.
            out.push_str(";; --- guiAccess: allow POSIX IPC for GUI apps ---\n");
            out.push_str("(allow ipc-posix-shm-read-data ipc-posix-shm-write-data ipc-posix-shm-write-create)\n");
        }
    } else {
        out.push_str(";; --- ui.disable: deny WindowServer + related ---\n");
        out.push_str("(deny mach-lookup\n");
        out.push_str("    (global-name \"com.apple.windowserver.active\")\n");
        out.push_str("    (global-name \"com.apple.windowserver.session\")\n");
        out.push_str("    (global-name \"com.apple.coreservices.launchservicesd\"))\n");
    }

    // Clipboard: allow pasteboard mach service when clipboard is read,
    // write, or all. The explicit deny when clipboard=none is redundant
    // with `(deny default)` but documents intent.
    let clipboard_allowed = !matches!(ui.clipboard, ClipboardPolicy::None);
    if clipboard_allowed {
        out.push_str(";; --- clipboard enabled: allow pasteboard ---\n");
        out.push_str("(allow mach-lookup (global-name \"com.apple.pasteboard.1\"))\n");
    } else {
        out.push_str(";; --- ui.clipboard=none: deny pasteboard ---\n");
        out.push_str("(deny mach-lookup (global-name \"com.apple.pasteboard.1\"))\n");
    }

    if !ui.injection {
        out.push_str(";; --- ui.injection=false: deny HID iokit access ---\n");
        out.push_str("(deny iokit-open (iokit-user-client-class \"IOHIDLibUserClient\"))\n");
    }
}

/// Emit rules so the inner process can call `posix_openpt()` and allocate
/// its own pty. Skipped when `gui_access` (with UI enabled) already emits
/// a strict superset.
fn write_nested_pty_rules(out: &mut String, request: &ExecutionRequest) {
    let sb = request.seatbelt.as_ref();
    let enabled = sb.is_none_or(|c| c.nested_pty);
    let gui_block_emitted = sb.is_some_and(|c| c.gui_access) && !request.policy.ui.disable;
    if !enabled || gui_block_emitted {
        return;
    }
    out.push_str(";; --- nestedPty: allow inner process to allocate its own pty ---\n");
    out.push_str("(allow pseudo-tty)\n");
    // /dev/ptmx is the primary multiplexer; opening it is what posix_openpt
    // does under the hood. The TTY_ALLOW baseline already grants access to
    // /dev/ttysNNN (the secondary side).
    out.push_str("(allow file-read* file-write* file-ioctl\n");
    out.push_str("    (literal \"/dev/ptmx\"))\n");
}

/// Emit rules so `Security.framework` / `keytar` can reach `securityd`
/// and read/write the user's Keychain. Off by default — opt in via
/// `seatbelt.keychainAccess: true`.
///
/// Real-world Keychain access fans out across several daemons. At
/// minimum we need:
///
/// * `securityd` / `SecurityServer` — the actual Keychain server.
/// * `trustd` / `ocspd` — TLS trust evaluation; without them every
///   handshake logs "failed to copy trust settings".
/// * `cfprefsd.daemon` — `Security.framework` reads preferences for
///   trust settings, ACL prompts, etc.
/// * `xpcd` + `lsd.*` — XPC bootstrapper and LaunchServices, used to
///   resolve helper bundles when the keychain is unlocked.
///
/// On the filesystem side, the user's keychain DB lives under
/// `~/Library/Keychains` (read+write — keytar creates new entries),
/// `/private/var/db/mds` is Spotlight/MDS metadata that
/// `Security.framework` consults (read-only), and per-user XPC caches
/// live under `/private/var/folders` (read+write). The system keychain
/// stores under `/Library/Keychains` and `/System/Library/Keychains`
/// are already covered by the baseline `/Library` and `/System`
/// read-only allows, so we don't re-add them here.
fn write_keychain_rules(out: &mut String, request: &ExecutionRequest) -> Result<(), String> {
    let enabled = request.seatbelt.as_ref().is_some_and(|c| c.keychain_access);
    if !enabled {
        return Ok(());
    }
    // Seatbelt only applies on macOS. On other hosts the option is a
    // no-op so workspace clippy / cross-platform tests don't have to
    // care about `$HOME` (Windows CI doesn't set it).
    if !cfg!(target_os = "macos") {
        return Ok(());
    }

    out.push_str(";; --- keychainAccess: Mach IPC for Keychain (securityd, prefs, XPC, LS) ---\n");
    out.push_str("(allow mach-lookup\n");
    out.push_str("    (global-name \"com.apple.SecurityServer\")\n");
    out.push_str("    (global-name \"com.apple.securityd\")\n");
    // trustd handles SecTrustSettingsCopyTrustSettings; without it Security
    // logs "failed to copy trust settings of system certificate-N" for every
    // cert in the system root store on every TLS handshake.
    out.push_str("    (global-name \"com.apple.trustd\")\n");
    out.push_str("    (global-name \"com.apple.trustd.agent\")\n");
    out.push_str("    (global-name \"com.apple.ocspd\")\n");
    out.push_str("    (global-name \"com.apple.cfprefsd.daemon\")\n");
    out.push_str("    (global-name \"com.apple.cfprefsd.agent\")\n");
    out.push_str("    (global-name \"com.apple.xpcd\")\n");
    // Seatbelt has no glob in (global-name); use regex for the lsd.* family
    // (lsd.modifydb, lsd.mapdb, lsd.openurl, …). Anchored to
    // `com.apple.lsd.` so we don't accidentally match unrelated services.
    out.push_str("    (global-name-regex #\"^com\\.apple\\.lsd\\.\"))\n");

    out.push_str(";; --- keychainAccess: MDS keychain metadata + trustd protected store ---\n");
    out.push_str("(allow file-read*\n");
    // trustd's protected store of trust settings + revocation data.
    out.push_str("    (subpath \"/private/var/protected/trustd\")\n");
    out.push_str("    (subpath \"/private/var/db/mds\"))\n");

    let home = std::env::var("HOME").map_err(|_| {
        "HOME environment variable not set; cannot expand '~/Library/Keychains' for keychainAccess"
            .to_string()
    })?;
    let user_keychains = format!("{home}/Library/Keychains");
    out.push_str(";; --- keychainAccess: user keychain DB + XPC/folder caches (read+write) ---\n");
    out.push_str("(allow file-read* file-write*\n");
    let _ = writeln!(out, "    (subpath {})", quote_scheme(&user_keychains));
    out.push_str("    (subpath \"/private/var/folders\"))\n");
    Ok(())
}

/// Emit caller-provided `extraMachLookups` rules: additional Mach service
/// global-names the inner process may resolve. No-op when the list is empty.
fn write_extra_seatbelt_rules(out: &mut String, request: &ExecutionRequest) {
    let Some(sb) = request.seatbelt.as_ref() else {
        return;
    };
    if sb.extra_mach_lookups.is_empty() {
        return;
    }

    out.push_str(";; --- extraMachLookups: caller-provided Mach services ---\n");
    out.push_str("(allow mach-lookup\n");
    for name in &sb.extra_mach_lookups {
        let _ = writeln!(out, "    (global-name {})", quote_scheme(name));
    }
    out.push_str(")\n");
}

/// Resolve a caller-supplied policy path into the form Seatbelt matches:
/// expand a leading `~`, normalize redundant lexical segments, then rewrite the
/// symlinked macOS root directories.
///
/// All three steps are required. See [`expand_tilde`], [`normalize_lexical`]
/// and [`resolve_macos_root_symlinks`].
pub(crate) fn resolve_policy_path(path: &str) -> Result<String, String> {
    let expanded = expand_tilde(path)?;
    Ok(resolve_macos_root_symlinks(&normalize_lexical(&expanded)?))
}

/// Collapse the lexical spellings of a path that leave a Seatbelt rule dead:
/// repeated separators (`//tmp`), `.` segments (`/./tmp`), and a trailing `/`.
///
/// The kernel canonicalizes an accessed path before matching it against a
/// profile filter, but it does not canonicalize the filter, so `(subpath
/// "//tmp/secret")` never matches anything. For `deniedPaths` that fails
/// **open**, so these spellings have to be folded away rather than passed
/// through.
///
/// A `..` segment is rejected instead of being resolved. macOS resolves `..`
/// *physically* — after following symlinks — so resolving it lexically can move
/// the rule somewhere else entirely: `/tmp/..` is `/private`, not `/`. Silently
/// widening an allow rule to `/` would be worse than the dead rule, and leaving
/// it in place keeps the deny fail-open, so an unresolvable path is a config
/// error the caller must fix by passing the resolved path.
fn normalize_lexical(path: &str) -> Result<String, String> {
    if path.split('/').any(|seg| seg == "..") {
        return Err(format!(
            "Filesystem path '{path}' contains a '..' segment. macOS resolves '..' after \
             following symlinks, so the generated sandbox rule could not be matched \
             reliably; specify the fully resolved path instead."
        ));
    }

    let joined = path
        .split('/')
        .filter(|seg| !seg.is_empty() && *seg != ".")
        .collect::<Vec<_>>()
        .join("/");

    Ok(if path.starts_with('/') {
        format!("/{joined}")
    } else {
        joined
    })
}

/// The macOS root directories that are symlinks, and their targets.
///
/// `/etc`, `/tmp`, and `/var` point into `/private`; `/home` points at the
/// data volume. `/Users` is deliberately absent — it is a *firmlink*, not a
/// symlink, so `/Users/...` is already the canonical path the kernel matches.
const MACOS_SYMLINKED_ROOTS: [(&str, &str); 4] = [
    ("/etc", "/private/etc"),
    ("/tmp", "/private/tmp"),
    ("/var", "/private/var"),
    ("/home", "/System/Volumes/Data/home"),
];

/// Rewrite a leading symlinked macOS root directory to its real target.
///
/// The kernel resolves a path fully before matching it against a profile's
/// `subpath` / `literal` filters, so a rule written against the unresolved
/// path is dead: `(subpath "/tmp/work")` never matches, because the kernel
/// only ever sees `/private/tmp/work`. That silently voided every policy path
/// under these roots — including the automatic `$TMPDIR` grant, which resolves
/// to `/var/folders/...` on macOS.
///
/// Only a whole leading path segment is rewritten, so `/variable` is left
/// alone. Paths already written against the real target pass through
/// unchanged, because none of the targets is itself under a symlinked root.
fn resolve_macos_root_symlinks(path: &str) -> String {
    for (root, target) in MACOS_SYMLINKED_ROOTS {
        let Some(rest) = path.strip_prefix(root) else {
            continue;
        };
        if rest.is_empty() || rest.starts_with('/') {
            return format!("{target}{rest}");
        }
    }
    path.to_string()
}

/// Expand a leading `~` or `~/` to the current user's home directory.
/// Returns an error if `HOME` is not set and the path requires expansion.
pub(crate) fn expand_tilde(path: &str) -> Result<String, String> {
    if path == "~" || path.starts_with("~/") {
        let home = std::env::var("HOME").map_err(|_| {
            format!("HOME environment variable not set; cannot expand '{path}' in seatbelt profile")
        })?;
        if path == "~" {
            Ok(home)
        } else {
            Ok(format!("{home}/{}", &path[2..]))
        }
    } else {
        Ok(path.to_string())
    }
}

/// Quote a string for use as a TinyScheme string literal, escaping
/// embedded backslashes and double-quotes.
fn quote_scheme(s: &str) -> String {
    let mut q = String::with_capacity(s.len() + 2);
    q.push('"');
    q.push_str(&escape_for_quotes(s));
    q.push('"');
    q
}

fn escape_for_quotes(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '\\' => out.push_str("\\\\"),
            '"' => out.push_str("\\\""),
            other => out.push(other),
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use wxc_common::models::{SeatbeltConfig, UiPolicy};

    fn build_profile(request: &ExecutionRequest) -> Result<String, String> {
        build_profile_with_proxy(request, request.policy.network_proxy.address.as_ref())
    }

    fn req() -> ExecutionRequest {
        ExecutionRequest {
            script_code: "echo hi".to_string(),
            ..Default::default()
        }
    }

    #[test]
    fn baseline_profile_has_deny_default_and_baseline_allows() {
        let p = build_profile(&req()).unwrap();
        assert!(p.contains("(version 1)"));
        assert!(p.contains("(deny default)"));
        assert!(p.contains("(allow process-fork)"));
        assert!(p.contains("(allow process-exec)"));
        assert!(p.contains("(allow signal (target same-sandbox))"));
        assert!(p.contains("/usr/lib"));
        assert!(p.contains("/System"));
        assert!(p.contains("(subpath \"/bin\")"));
        assert!(p.contains("(subpath \"/usr/bin\")"));
        assert!(p.contains("(allow file-read-data (literal \"/\"))"));
    }

    #[test]
    fn readonly_paths_emit_subpath_allows() {
        let mut r = req();
        r.policy.readonly_paths = vec!["/opt/tools".into(), "/var/data".into()];
        let p = build_profile(&r).unwrap();
        assert!(p.contains("policy.readonlyPaths"));
        assert!(p.contains("(allow file-read*"));
        assert!(p.contains("(subpath \"/opt/tools\")"));
        assert!(p.contains("(subpath \"/private/var/data\")"));
        assert!(!p.contains("file-write* (subpath \"/opt/tools\")"));
    }

    #[test]
    fn readwrite_paths_emit_read_and_write_allows() {
        let mut r = req();
        r.policy.readwrite_paths = vec!["/tmp/output".into()];
        let p = build_profile(&r).unwrap();
        assert!(p.contains("(allow file-read* file-write*"));
        assert!(p.contains("(subpath \"/private/tmp/output\")"));
    }

    #[test]
    fn denied_paths_appear_after_allows_to_override() {
        let mut r = req();
        r.policy.readwrite_paths = vec!["/tmp".into()];
        r.policy.denied_paths = vec!["/tmp/secret".into()];
        let p = build_profile(&r).unwrap();
        let allow_idx = p.find("(allow file-read* file-write*").unwrap();
        let deny_idx = p.find("(deny file-read* file-write*").unwrap();
        assert!(
            deny_idx > allow_idx,
            "deny rules must come after allow rules so they win on last-match"
        );
        assert!(p.contains("(subpath \"/private/tmp/secret\")"));
    }

    #[test]
    fn default_deny_network_emits_no_allow_network() {
        let mut r = req();
        // Default policy is Allow per NetworkPolicy::default(); flip it.
        r.policy.default_network_policy = NetworkPolicy::Block;
        let p = build_profile(&r).unwrap();
        assert!(!p.contains("(allow network-outbound"));
        assert!(p.contains("network: default-deny"));
    }

    #[test]
    fn block_with_allowed_hosts_never_widens_to_allow_all() {
        // `allowedHosts` under a deny default must not flip the profile to
        // allow-all outbound — that would be the inverse of the requested
        // policy. `config_parser` rejects this combination unless the builtin
        // test proxy enforces the list, so the profile keeps its deny baseline.
        let mut r = req();
        r.policy.default_network_policy = NetworkPolicy::Block;
        r.policy.allowed_hosts = vec!["api.github.com".into(), "registry.npmjs.org".into()];
        let p = build_profile(&r).unwrap();
        assert!(!p.contains("(allow network-outbound)"));
        assert!(p.contains("enforced by the proxy"));
        // Should NOT have per-host remote rules.
        assert!(!p.contains("(remote"));
    }

    #[test]
    fn block_with_allowed_hosts_and_proxy_keeps_deny_plus_proxy_reachability() {
        // The builtin-test-proxy case: the proxy filters the host list, so the
        // profile must stay deny-all except port-scoped proxy reachability.
        let mut r = req();
        r.policy.default_network_policy = NetworkPolicy::Block;
        r.policy.allowed_hosts = vec!["api.github.com".into()];
        let address = ProxyAddress::new("127.0.0.1".into(), 8080);
        let p = build_profile_with_proxy(&r, Some(&address)).unwrap();
        assert!(!p.contains("(allow network-outbound)"));
        assert!(p.contains("8080"));
    }

    #[test]
    fn allow_outbound_no_hosts_emits_open_network_outbound() {
        let mut r = req();
        r.policy.default_network_policy = NetworkPolicy::Allow;
        let p = build_profile(&r).unwrap();
        assert!(p.contains("(allow network-outbound)"));
    }

    #[test]
    fn allow_outbound_with_hosts_emits_per_host_remote_rules() {
        let mut r = req();
        r.policy.default_network_policy = NetworkPolicy::Allow;
        r.policy.allowed_hosts = vec!["api.github.com".into(), "1.2.3.4".into()];
        let p = build_profile(&r).unwrap();
        assert!(p.contains("Seatbelt cannot filter by host"));
        assert!(p.contains("(allow network-outbound)"));
        assert!(!p.contains("(remote"));
    }

    #[test]
    fn blocked_hosts_not_emitted_in_profile() {
        // blocked_hosts is rejected at the runner level, but verify the
        // profile builder doesn't crash if called with them anyway.
        let mut r = req();
        r.policy.default_network_policy = NetworkPolicy::Allow;
        r.policy.blocked_hosts = vec!["evil.example.com".into()];
        let p = build_profile(&r).unwrap();
        assert!(!p.contains("(deny network-outbound"));
    }

    #[test]
    fn loopback_proxy_under_default_deny_scopes_outbound_to_proxy_port() {
        // A cooperative loopback proxy must be reachable even though outbound
        // is default-deny — but only the proxy's exact port, not all of
        // loopback and not the whole network.
        let mut r = req();
        r.policy.default_network_policy = NetworkPolicy::Block;
        let addr = ProxyAddress::new("127.0.0.1".into(), 8080);
        let p = build_profile_with_proxy(&r, Some(&addr)).unwrap();
        assert!(p.contains("(allow network-outbound (remote ip \"localhost:8080\"))"));
        // Must NOT open outbound to all loopback ports or the whole network.
        assert!(!p.contains("localhost:*"));
        assert!(!p.contains("(allow network-outbound)\n"));
    }

    #[test]
    fn builtin_test_proxy_under_default_deny_scopes_outbound_to_proxy_port() {
        // builtinTestServer binds a loopback port at runtime; the runner passes
        // that *resolved* address here, so the rule is scoped to the real port
        // just like an explicit loopback proxy.
        let mut r = req();
        r.policy.default_network_policy = NetworkPolicy::Block;
        let addr = ProxyAddress::new("127.0.0.1".into(), 54321);
        let p = build_profile_with_proxy(&r, Some(&addr)).unwrap();
        assert!(p.contains("(allow network-outbound (remote ip \"localhost:54321\"))"));
        assert!(!p.contains("localhost:*"));
        assert!(!p.contains("(allow network-outbound)\n"));
    }

    #[test]
    fn remote_proxy_under_default_deny_allows_all_outbound_best_effort() {
        // Seatbelt cannot filter a remote proxy by DNS name, so reachability
        // degrades to allow-all outbound (the proxy enforces host policy).
        // NOTE: config_parser now rejects remote-proxy + defaultPolicy='block'
        // for Seatbelt, so this combination is unreachable via real config; this
        // test pins the profile-builder's defense-in-depth behavior if reached.
        let mut r = req();
        r.policy.default_network_policy = NetworkPolicy::Block;
        let addr = ProxyAddress::from_url(
            "http://proxy.example.com:8080",
            "proxy.example.com".into(),
            8080,
        );
        let p = build_profile_with_proxy(&r, Some(&addr)).unwrap();
        assert!(p.contains("remote proxy configured"));
        assert!(p.contains("(allow network-outbound)\n"));
        assert!(!p.contains("localhost:"));
    }

    #[test]
    fn proxy_under_default_allow_does_not_add_scoped_rule() {
        // When outbound is already open (defaultPolicy allow), the proxy
        // reachability rule is redundant and must not be emitted.
        let mut r = req();
        r.policy.default_network_policy = NetworkPolicy::Allow;
        let addr = ProxyAddress::new("127.0.0.1".into(), 8080);
        let p = build_profile_with_proxy(&r, Some(&addr)).unwrap();
        assert!(p.contains("(allow network-outbound)\n"));
        assert!(!p.contains("localhost:"));
    }

    #[test]
    fn build_profile_wrapper_scopes_static_localhost_proxy() {
        // The convenience `build_profile` wrapper must honor a statically
        // configured proxy address (localhost:<port>), scoping the reachability
        // rule to that exact port under default-deny — not silently dropping it.
        let mut r = req();
        r.policy.default_network_policy = NetworkPolicy::Block;
        r.policy.network_proxy = wxc_common::models::ProxyConfig {
            address: Some(ProxyAddress::new("127.0.0.1".into(), 9091)),
            builtin_test_server: false,
        };
        let p = build_profile(&r).unwrap();
        assert!(p.contains("(allow network-outbound (remote ip \"localhost:9091\"))"));
        assert!(!p.contains("localhost:*"));
    }

    #[test]
    fn allow_local_network_emits_inbound_rule() {
        // server.listen() on macOS is governed by `network-inbound`, not
        // `network-bind` — with only `network-bind (local ip)` the bind()
        // succeeds and the kernel then rejects listen() with EPERM.
        let mut r = req();
        r.policy.default_network_policy = NetworkPolicy::Allow;
        r.policy.allow_local_network = true;
        let p = build_profile(&r).unwrap();
        assert!(p.contains("(allow network-inbound (local ip))"));
        assert!(p.contains("allowLocalNetwork"));
    }

    #[test]
    fn allow_local_network_default_omits_inbound_rule() {
        // Default (allow_local_network=false) must not emit any inbound rule.
        let mut r = req();
        r.policy.default_network_policy = NetworkPolicy::Allow;
        let p = build_profile(&r).unwrap();
        assert!(!p.contains("network-inbound"));
    }

    #[test]
    fn allow_local_network_works_with_default_deny_outbound() {
        // allow_local_network is independent of outbound: a process can be
        // a pure server (no client traffic) and still accept local inbound.
        let mut r = req();
        r.policy.default_network_policy = NetworkPolicy::Block;
        r.policy.allow_local_network = true;
        let p = build_profile(&r).unwrap();
        assert!(p.contains("(allow network-inbound (local ip))"));
        assert!(!p.contains("(allow network-outbound)"));
    }

    #[test]
    fn directional_egress_deny_emits_no_allow_network() {
        // Schema-0.8 directional shape: network_egress.default is consulted
        // instead of the legacy default_network_policy field (which stays at
        // its Block default under this shape and must not be read directly).
        let mut r = req();
        r.policy.default_network_policy = NetworkPolicy::Allow; // must be ignored
        r.policy.network_egress = Some(wxc_common::models::NetworkEgressPolicy {
            default: NetworkAction::Deny,
            ..Default::default()
        });
        let p = build_profile(&r).unwrap();
        assert!(!p.contains("(allow network-outbound"));
        assert!(p.contains("network: default-deny"));
    }

    #[test]
    fn directional_egress_allow_emits_open_network_outbound() {
        let mut r = req();
        r.policy.network_egress = Some(wxc_common::models::NetworkEgressPolicy {
            default: NetworkAction::Allow,
            ..Default::default()
        });
        let p = build_profile(&r).unwrap();
        assert!(p.contains("(allow network-outbound)"));
    }

    #[test]
    fn directional_ingress_default_allow_emits_inbound_rule() {
        // Seatbelt maps ingress.default (not hostLoopback) to the existing
        // allowLocalNetwork behavior — see network_parser and validate().
        let mut r = req();
        r.policy.allow_local_network = false; // must be ignored
        r.policy.network_ingress = Some(wxc_common::models::NetworkIngressPolicy {
            default: NetworkAction::Allow,
            host_loopback: NetworkAction::Allow,
        });
        let p = build_profile(&r).unwrap();
        assert!(p.contains("(allow network-inbound (local ip))"));
    }

    #[test]
    fn directional_ingress_default_deny_omits_inbound_rule() {
        let mut r = req();
        r.policy.allow_local_network = true; // must be ignored
        r.policy.network_ingress = Some(wxc_common::models::NetworkIngressPolicy {
            default: NetworkAction::Deny,
            host_loopback: NetworkAction::Deny,
        });
        let p = build_profile(&r).unwrap();
        assert!(!p.contains("network-inbound"));
    }

    #[test]
    fn directional_deny_with_loopback_proxy_scopes_outbound_to_proxy_port() {
        // Same proxy-reachability behavior as the legacy shape must be
        // preserved when the directional shape selects deny + loopback proxy
        // (the only combination the GA schema allows with a runtime proxy).
        let mut r = req();
        r.policy.network_egress = Some(wxc_common::models::NetworkEgressPolicy {
            default: NetworkAction::Deny,
            ..Default::default()
        });
        let addr = ProxyAddress::new("127.0.0.1".into(), 56159);
        let p = build_profile_with_proxy(&r, Some(&addr)).unwrap();
        assert!(p.contains("(allow network-outbound (remote ip \"localhost:56159\"))"));
        assert!(!p.contains("(allow network-outbound)\n"));
    }

    #[test]
    fn ui_disabled_blocks_windowserver() {
        let r = req();
        // Default UiPolicy has disable=true.
        assert!(r.policy.ui.disable);
        let p = build_profile(&r).unwrap();
        assert!(p.contains("(deny mach-lookup"));
        assert!(p.contains("com.apple.windowserver.active"));
    }

    #[test]
    fn ui_enabled_allows_windowserver_and_clipboard() {
        let mut r = req();
        r.policy.ui = UiPolicy {
            disable: false,
            clipboard: ClipboardPolicy::All,
            injection: true,
        };
        let p = build_profile(&r).unwrap();
        // UI enabled → allow WindowServer
        assert!(p.contains("(allow mach-lookup"));
        assert!(p.contains("com.apple.windowserver.active"));
        // Clipboard=all → allow pasteboard
        assert!(p.contains("com.apple.pasteboard.1"));
        assert!(!p.contains("IOHIDLibUserClient"));
    }

    #[test]
    fn clipboard_none_blocks_pasteboard() {
        let r = req();
        // Default clipboard is None.
        let p = build_profile(&r).unwrap();
        assert!(p.contains("com.apple.pasteboard.1"));
    }

    #[test]
    fn injection_false_blocks_hid_iokit() {
        let r = req();
        let p = build_profile(&r).unwrap();
        assert!(p.contains("IOHIDLibUserClient"));
    }

    #[test]
    fn profile_override_takes_precedence() {
        let mut r = req();
        r.policy.readonly_paths = vec!["/should/be/ignored".into()];
        r.seatbelt = Some(SeatbeltConfig {
            profile_override: Some("(version 1)(allow default)".into()),
            gui_access: false,
            ..Default::default()
        });
        let p = build_profile(&r).unwrap();
        assert_eq!(p, "(version 1)(allow default)");
    }

    #[test]
    fn paths_with_quotes_and_backslashes_are_escaped() {
        let mut r = req();
        // Hypothetical adversarial input — we never want a path to break out
        // of the quoted string and inject Scheme.
        r.policy.readonly_paths = vec!["/tmp/a\"b\\c".into()];
        let p = build_profile(&r).unwrap();
        assert!(p.contains("(subpath \"/private/tmp/a\\\"b\\\\c\")"));
    }

    const FS_SECTION: &str =
        ";; --- policy.readonlyPaths / policy.readwritePaths (shallow-to-deep) ---";
    const RO_STRIP: &str = "(deny file-write* network-bind network-outbound\n";

    /// The policy-derived filesystem section, excluding the always-emitted
    /// baseline rules that also start with `(allow file-read*`.
    fn fs_section(profile: &str) -> &str {
        profile
            .find(FS_SECTION)
            .map(|i| &profile[i..])
            .unwrap_or("")
    }
    const RW_RULE: &str = "(allow file-read* file-write* network-bind network-outbound\n";
    const DENY_RULE: &str = "(deny file-read* file-write* network-bind network-outbound\n";

    #[test]
    fn readwrite_paths_emit_unix_socket_ops() {
        let mut r = req();
        r.policy.readwrite_paths = vec!["/tmp/output".into()];
        let p = build_profile(&r).unwrap();
        let idx = p.find(RW_RULE).expect("readwrite rule");
        assert!(p[idx..].contains("(subpath \"/private/tmp/output\")"));
    }

    #[test]
    fn readwrite_unix_socket_ops_are_independent_of_network_policy() {
        // AF_UNIX bind/connect follow the filesystem policy, so a default-deny
        // network policy with allowLocalNetwork off must still permit them.
        let mut r = req();
        r.policy.readwrite_paths = vec!["/tmp/output".into()];
        r.policy.default_network_policy = NetworkPolicy::Block;
        r.policy.allow_local_network = false;
        let p = build_profile(&r).unwrap();
        assert!(p.contains(RW_RULE));
        assert!(!p.contains("network-inbound"));
        assert!(!p.contains("(allow network-outbound)"));
    }

    #[test]
    fn denied_paths_deny_outbound_under_default_allow() {
        // `defaultPolicy: allow` emits a bare `(allow network-outbound)`, which
        // on its own grants AF_UNIX `connect()`. A denied subtree must still
        // deny it. Position relative to that unfiltered allow is deliberately
        // not asserted: an unfiltered rule cannot override a path-filtered one
        // in either direction, so pinning the order would encode a constraint
        // that does not exist. The orderings that *do* matter — deny after the
        // filtered read-write allows — are covered by
        // `denied_paths_appear_after_allows_to_override` and
        // `denied_paths_deny_unix_socket_ops_after_allows`.
        let mut r = req();
        r.policy.default_network_policy = NetworkPolicy::Allow;
        r.policy.denied_paths = vec!["/tmp/secret".into()];
        let p = build_profile(&r).unwrap();
        let deny_idx = p.find(DENY_RULE).expect("deny must cover network-outbound");
        assert!(p[deny_idx..].contains("(subpath \"/private/tmp/secret\")"));
    }

    #[test]
    fn readonly_paths_do_not_get_unix_socket_ops() {
        let mut r = req();
        r.policy.readonly_paths = vec!["/tmp/input".into()];
        let p = build_profile(&r).unwrap();
        assert!(!p.contains(RW_RULE));
        // The only socket mention for a read-only path is the explicit removal.
        assert!(!p.contains("allow network-bind"));
        assert!(fs_section(&p).contains(RO_STRIP));
    }

    #[test]
    fn denied_paths_deny_unix_socket_ops_after_allows() {
        let mut r = req();
        r.policy.readwrite_paths = vec!["/tmp".into()];
        r.policy.denied_paths = vec!["/tmp/secret".into()];
        let p = build_profile(&r).unwrap();
        let deny_idx = p.find(DENY_RULE).expect("deny must cover socket ops");
        let allow_idx = p.find(RW_RULE).expect("allow rule");
        assert!(
            deny_idx > allow_idx,
            "deny must follow allow so last-match-wins re-denies the socket path"
        );
        assert!(p[deny_idx..].contains("(subpath \"/private/tmp/secret\")"));
    }

    #[test]
    fn lexical_spellings_normalize_to_the_same_rule() {
        // Each of these accesses `/private/tmp/secret` at the kernel level, so
        // each must produce the same filter — otherwise a deny written with a
        // redundant spelling is dead and fails open.
        for spelling in [
            "/tmp/secret",
            "//tmp/secret",
            "/./tmp/secret",
            "/tmp//secret",
            "/tmp/./secret/",
            "///tmp/secret//",
        ] {
            assert_eq!(
                resolve_policy_path(spelling).unwrap(),
                "/private/tmp/secret",
                "spelling {spelling} must normalize"
            );
        }
    }

    #[test]
    fn lexical_normalization_is_idempotent_and_preserves_root() {
        assert_eq!(resolve_policy_path("/").unwrap(), "/");
        assert_eq!(resolve_policy_path("//").unwrap(), "/");
        let once = resolve_policy_path("//tmp/./secret/").unwrap();
        assert_eq!(resolve_policy_path(&once).unwrap(), once);
    }

    #[test]
    fn parent_segments_are_rejected_rather_than_resolved() {
        // `/tmp/..` is `/private` on macOS, not `/`, so resolving lexically
        // would silently widen an allow and leave a deny dead.
        for path in ["/private/var/../tmp", "/tmp/..", "/..", "/a/b/../c"] {
            let err = resolve_policy_path(path).unwrap_err();
            assert!(err.contains(".."), "{path} must be rejected, got {err}");
        }
        // A path merely *containing* dots in a segment name is fine.
        assert_eq!(
            resolve_policy_path("/tmp/..secret").unwrap(),
            "/private/tmp/..secret"
        );
    }

    #[test]
    fn denied_path_with_redundant_spelling_still_denies() {
        let mut r = req();
        r.policy.readwrite_paths = vec!["/tmp".into()];
        r.policy.denied_paths = vec!["//tmp/./secret/".into()];
        let p = build_profile(&r).unwrap();
        let deny_idx = p.find(DENY_RULE).expect("deny rule");
        assert!(p[deny_idx..].contains("(subpath \"/private/tmp/secret\")"));
    }

    #[test]
    fn nested_readonly_keeps_write_away_from_broader_readwrite() {
        // `/tmp` resolves to `/private/tmp`, which is an ancestor of the
        // read-only entry. The read-only `allow` names only `file-read*`, so
        // it says nothing about write or socket ops and cannot displace the
        // broader grant on its own — hence the explicit removal, emitted
        // *after* the read-write allow.
        let mut r = req();
        r.policy.readwrite_paths = vec!["/tmp".into()];
        r.policy.readonly_paths = vec!["/private/tmp/secret".into()];
        let p = build_profile(&r).unwrap();

        let rw_idx = p.find(RW_RULE).expect("readwrite rule");
        let strip_idx = p.find(RO_STRIP).expect("read-only must strip write");
        assert!(
            strip_idx > rw_idx,
            "deepest intent must be emitted last, profile:\n{p}"
        );
        assert!(p[strip_idx..].contains("(subpath \"/private/tmp/secret\")"));
    }

    #[test]
    fn nested_readwrite_still_wins_inside_broader_readonly() {
        // The mirror case: the deeper read-write entry must survive, otherwise
        // depth ordering would have simply inverted the bug.
        let mut r = req();
        r.policy.readonly_paths = vec!["/tmp".into()];
        r.policy.readwrite_paths = vec!["/private/tmp/build".into()];
        let p = build_profile(&r).unwrap();

        let strip_idx = p.find(RO_STRIP).expect("read-only strip");
        let rw_idx = p.find(RW_RULE).expect("readwrite rule");
        assert!(
            rw_idx > strip_idx,
            "deeper readwrite must win, profile:\n{p}"
        );
        assert!(p[rw_idx..].contains("(subpath \"/private/tmp/build\")"));
    }

    #[test]
    fn readonly_socket_strip_survives_a_default_allow_outbound() {
        // `defaultPolicy: "allow"` emits an unfiltered `(allow
        // network-outbound)`. The read-only strip still governs AF_UNIX
        // `connect()` under that subtree, because an unfiltered rule does not
        // override a path-filtered one. Verified end-to-end against
        // `mxc-exec-mac` with a listener created outside the sandbox: this
        // policy denies `connect()` with EPERM, while the same policy with the
        // path moved to `readwrite_paths` connects.
        //
        // Emission order relative to the unfiltered allow is deliberately not
        // asserted — it has no bearing on the outcome.
        let mut r = req();
        r.policy.default_network_policy = NetworkPolicy::Allow;
        r.policy.readonly_paths = vec!["/tmp/ro".into()];
        let p = build_profile(&r).unwrap();

        let strip_idx = p.find(RO_STRIP).expect("read-only strip");
        assert!(p[strip_idx..].contains("(subpath \"/private/tmp/ro\")"));
    }

    #[test]
    fn readonly_wins_over_readwrite_for_aliased_spellings() {
        // The parser's most-restrictive-wins pass compares raw strings, so
        // these two spellings both survive it and only collide once resolved.
        // Seatbelt is last-match-wins and readwrite is emitted second, so
        // without resolved-path precedence the read-only intent would be lost.
        let mut r = req();
        r.policy.readonly_paths = vec!["/private/tmp/x".into()];
        r.policy.readwrite_paths = vec!["/tmp/x".into()];
        let p = build_profile(&r).unwrap();

        assert!(fs_section(&p).contains("(subpath \"/private/tmp/x\")"));
        assert!(
            !p.contains(RW_RULE),
            "aliased readwrite entry must be dropped, profile was:\n{p}"
        );
    }

    #[test]
    fn denied_wins_over_aliased_readonly_and_readwrite() {
        let mut r = req();
        r.policy.denied_paths = vec!["/private/tmp/x".into()];
        r.policy.readonly_paths = vec!["/tmp/x".into()];
        r.policy.readwrite_paths = vec!["//tmp/./x".into()];
        let p = build_profile(&r).unwrap();

        assert!(!p.contains(FS_SECTION), "profile:\n{p}");
        assert!(!p.contains(RW_RULE), "profile:\n{p}");
        let deny_idx = p.find(DENY_RULE).expect("deny rule");
        assert!(p[deny_idx..].contains("(subpath \"/private/tmp/x\")"));
    }

    #[test]
    fn distinct_paths_survive_resolved_precedence() {
        let mut r = req();
        r.policy.readonly_paths = vec!["/tmp/ro".into()];
        r.policy.readwrite_paths = vec!["/tmp/rw".into()];
        let p = build_profile(&r).unwrap();

        assert!(fs_section(&p).contains("(subpath \"/private/tmp/ro\")"));
        let rw_idx = p.find(RW_RULE).expect("readwrite rule");
        assert!(p[rw_idx..].contains("(subpath \"/private/tmp/rw\")"));
    }

    #[test]
    fn macos_root_symlinks_are_resolved() {
        assert_eq!(resolve_macos_root_symlinks("/tmp"), "/private/tmp");
        assert_eq!(resolve_macos_root_symlinks("/var"), "/private/var");
        assert_eq!(resolve_macos_root_symlinks("/etc"), "/private/etc");
        assert_eq!(
            resolve_macos_root_symlinks("/var/folders/qj/T"),
            "/private/var/folders/qj/T"
        );
        assert_eq!(
            resolve_macos_root_symlinks("/home/me"),
            "/System/Volumes/Data/home/me"
        );
    }

    #[test]
    fn macos_root_resolution_only_matches_whole_segments() {
        // A prefix that merely starts with the same letters is not a match.
        assert_eq!(resolve_macos_root_symlinks("/variable"), "/variable");
        assert_eq!(resolve_macos_root_symlinks("/tmpfs/x"), "/tmpfs/x");
        assert_eq!(resolve_macos_root_symlinks("/etcd"), "/etcd");
        assert_eq!(resolve_macos_root_symlinks("/homebrew"), "/homebrew");
        // Already-resolved and unrelated paths pass through untouched.
        assert_eq!(
            resolve_macos_root_symlinks("/private/tmp/x"),
            "/private/tmp/x"
        );
        assert_eq!(resolve_macos_root_symlinks("/Users/me/w"), "/Users/me/w");
        assert_eq!(resolve_macos_root_symlinks(""), "");
    }

    #[test]
    fn macos_root_resolution_is_idempotent() {
        // Re-resolving a resolved path must be a no-op — no target is itself
        // under a symlinked root.
        for (_, target) in MACOS_SYMLINKED_ROOTS {
            assert_eq!(resolve_macos_root_symlinks(target), target);
        }
    }

    #[test]
    fn empty_policy_still_compiles_to_valid_profile() {
        let r = req();
        let p = build_profile(&r).unwrap();
        // Profile must always start with `(version 1)` and contain `(deny default)`.
        assert!(p.starts_with("(version 1)"));
        assert!(p.contains("(deny default)"));
        // No empty `(allow file-read*\n)` block — that would be invalid Scheme.
        assert!(!p.contains("(allow file-read*\n)\n"));
    }

    #[test]
    fn gui_access_adds_mach_services_for_gui_apps() {
        let mut r = req();
        r.policy.ui = UiPolicy {
            disable: false,
            clipboard: ClipboardPolicy::None,
            injection: true,
        };
        r.seatbelt = Some(SeatbeltConfig {
            profile_override: None,
            gui_access: true,
            ..Default::default()
        });
        let p = build_profile(&r).unwrap();
        // Wildcard mach-lookup and mach-register for GUI apps
        assert!(
            p.contains("(allow mach-lookup)"),
            "missing wildcard mach-lookup"
        );
        assert!(p.contains("(allow mach-register)"), "missing mach-register");
        // IOKit for GPU
        assert!(p.contains("(allow iokit-open)"), "missing iokit-open");
        // Temp/cache write access
        assert!(p.contains("/private/tmp"), "missing /private/tmp");
        assert!(
            p.contains("/private/var/folders"),
            "missing /private/var/folders"
        );
    }

    #[test]
    fn gui_access_false_omits_gui_services() {
        let mut r = req();
        r.policy.ui = UiPolicy {
            disable: false,
            clipboard: ClipboardPolicy::None,
            injection: true,
        };
        r.seatbelt = Some(SeatbeltConfig {
            profile_override: None,
            gui_access: false,
            // Pin nested_pty off so this test stays focused on
            // gui_access semantics (otherwise it emits iokit-open).
            nested_pty: false,
            ..Default::default()
        });
        let p = build_profile(&r).unwrap();
        // Basic UI services should be present
        assert!(p.contains("com.apple.windowserver.active"));
        // GUI-specific wildcard should NOT be present
        assert!(!p.contains("(allow mach-lookup)\n"));
        assert!(!p.contains("(allow iokit-open)"));
    }

    #[test]
    fn gui_access_requires_ui_enabled() {
        let mut r = req();
        // ui.disable = true (default) but gui_access = true
        r.seatbelt = Some(SeatbeltConfig {
            profile_override: None,
            gui_access: true,
            // Pin nested_pty off so this test isolates the
            // gui_access + ui.disable interaction.
            nested_pty: false,
            ..Default::default()
        });
        let p = build_profile(&r).unwrap();
        // Should NOT emit GUI services when UI is disabled
        assert!(!p.contains("com.apple.CARenderServer"));
        assert!(!p.contains("(allow iokit-open)"));
        // Should have the deny block instead
        assert!(p.contains("ui.disable: deny WindowServer"));
    }

    #[test]
    fn nested_pty_default_on_emits_pty_rules() {
        // When seatbelt is absent the builder should still
        // emit nested_pty rules — that's the documented default behavior.
        let r = req();
        assert!(r.seatbelt.is_none());
        let p = build_profile(&r).unwrap();
        assert!(p.contains("nestedPty"), "nestedPty comment missing");
        assert!(p.contains("(allow pseudo-tty)"));
        assert!(p.contains("(literal \"/dev/ptmx\")"));
    }

    #[test]
    fn nested_pty_explicit_true_emits_pty_rules() {
        let mut r = req();
        r.seatbelt = Some(SeatbeltConfig {
            nested_pty: true,
            ..Default::default()
        });
        let p = build_profile(&r).unwrap();
        assert!(p.contains("(allow pseudo-tty)"));
        assert!(p.contains("(literal \"/dev/ptmx\")"));
    }

    #[test]
    fn nested_pty_false_omits_pty_rules() {
        let mut r = req();
        r.seatbelt = Some(SeatbeltConfig {
            nested_pty: false,
            ..Default::default()
        });
        let p = build_profile(&r).unwrap();
        assert!(!p.contains("nestedPty"));
        assert!(!p.contains("/dev/ptmx"));
        // pseudo-tty allow should also not be present.
        assert!(!p.contains("(allow pseudo-tty)"));
    }

    #[test]
    fn nested_pty_skipped_when_gui_block_emitted() {
        // gui_access + ui enabled emits a strict superset of nested_pty
        // rules. Verify we don't double-emit.
        let mut r = req();
        r.policy.ui = UiPolicy {
            disable: false,
            clipboard: ClipboardPolicy::None,
            injection: true,
        };
        r.seatbelt = Some(SeatbeltConfig {
            gui_access: true,
            nested_pty: true,
            ..Default::default()
        });
        let p = build_profile(&r).unwrap();
        // No nestedPty comment block — gui_access block carries the rules.
        assert!(!p.contains("nestedPty"));
        // GUI block's broader rules should still be there.
        assert!(p.contains("(allow iokit-open)"));
        assert!(p.contains("(allow pseudo-tty)"));
    }

    #[test]
    fn nested_pty_emits_when_gui_access_set_but_ui_disabled() {
        // gui_access=true with ui.disable=true means write_ui_rules
        // suppresses the GUI block — so nested_pty must NOT skip itself.
        let mut r = req();
        assert!(
            r.policy.ui.disable,
            "default ui.disable expected to be true"
        );
        r.seatbelt = Some(SeatbeltConfig {
            gui_access: true,
            nested_pty: true,
            ..Default::default()
        });
        let p = build_profile(&r).unwrap();
        assert!(p.contains("nestedPty"));
        assert!(p.contains("(allow pseudo-tty)"));
        assert!(p.contains("/dev/ptmx"));
    }

    #[test]
    fn keychain_access_default_off_omits_security_services() {
        let r = req();
        let p = build_profile(&r).unwrap();
        assert!(!p.contains("keychainAccess"));
        assert!(!p.contains("com.apple.SecurityServer"));
        assert!(!p.contains("com.apple.securityd"));
        assert!(!p.contains("com.apple.cfprefsd.daemon"));
        assert!(!p.contains("com.apple.lsd"));
        assert!(!p.contains("/Library/Keychains"));
        assert!(!p.contains("/private/var/db/mds"));
    }

    // Keychain rules expand `~/Library/Keychains` from $HOME at build
    // time, so the tests that exercise `keychain_access: true` are gated
    // to macOS (the only OS where this code path is actually used and
    // where $HOME is reliably set in CI).
    #[cfg(target_os = "macos")]
    #[test]
    fn keychain_access_true_allows_securityd_mach_services() {
        let mut r = req();
        r.seatbelt = Some(SeatbeltConfig {
            keychain_access: true,
            ..Default::default()
        });
        let p = build_profile(&r).unwrap();
        assert!(p.contains("keychainAccess"));
        // Mach surface
        assert!(p.contains("com.apple.SecurityServer"));
        assert!(p.contains("com.apple.securityd"));
        assert!(p.contains("com.apple.cfprefsd.daemon"));
        assert!(p.contains("com.apple.xpcd"));
        assert!(p.contains("(global-name-regex #\"^com\\.apple\\.lsd\\.\")"));
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn keychain_access_true_allows_filesystem_paths() {
        let mut r = req();
        r.seatbelt = Some(SeatbeltConfig {
            keychain_access: true,
            ..Default::default()
        });
        let p = build_profile(&r).unwrap();
        // /Library/Keychains and /System/Library/Keychains are read via
        // the baseline /Library and /System read-only allows; we don't
        // re-emit them here.
        assert!(p.contains("(subpath \"/private/var/db/mds\")"));
        // Read+write surfaces
        let home = std::env::var("HOME").expect("HOME must be set in test env");
        let user_keychains = format!("{home}/Library/Keychains");
        assert!(
            p.contains(&format!("(subpath \"{user_keychains}\")")),
            "missing user keychain subpath"
        );
        assert!(p.contains("(subpath \"/private/var/folders\")"));
    }

    #[test]
    fn extra_mach_lookups_emits_grouped_allow_form() {
        let mut r = req();
        r.seatbelt = Some(SeatbeltConfig {
            extra_mach_lookups: vec![
                "com.apple.example.one".to_string(),
                "com.apple.example.two".to_string(),
            ],
            ..Default::default()
        });
        let p = build_profile(&r).unwrap();
        assert!(p.contains(";; --- extraMachLookups"));
        assert!(p.contains("(allow mach-lookup\n    (global-name \"com.apple.example.one\")\n    (global-name \"com.apple.example.two\")\n)"));
    }

    #[test]
    fn extra_mach_lookups_omitted_when_empty() {
        let mut r = req();
        r.seatbelt = Some(SeatbeltConfig::default());
        let p = build_profile(&r).unwrap();
        assert!(!p.contains("extraMachLookups"));
    }

    #[test]
    fn extra_mach_lookups_escape_embedded_quotes() {
        let mut r = req();
        r.seatbelt = Some(SeatbeltConfig {
            extra_mach_lookups: vec!["weird\"name".to_string()],
            ..Default::default()
        });
        let p = build_profile(&r).unwrap();
        assert!(p.contains("(global-name \"weird\\\"name\")"));
    }
}
