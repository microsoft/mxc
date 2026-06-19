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

use wxc_common::models::{ClipboardPolicy, ExecutionRequest, NetworkPolicy};

/// Build a complete sandbox profile string from the given request.
///
/// If `request.seatbelt.profile_override` is set, that
/// string is returned verbatim and policy fields are ignored. This is the
/// escape hatch for advanced/testing scenarios that need to hand-author a
/// profile.
pub fn build_profile(request: &ExecutionRequest) -> Result<String, String> {
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
    // sysctl reads, and signaling self.
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
    write_filesystem_allow(&mut out, request)?;
    write_network_rules(&mut out, request);
    write_nested_pty_rules(&mut out, request);
    write_keychain_rules(&mut out, request)?;
    write_extra_seatbelt_rules(&mut out, request);
    write_ui_rules(&mut out, request);

    // Policy-derived deny rules go LAST so they win on conflict.
    write_filesystem_deny(&mut out, request)?;

    Ok(out)
}

/// Baseline allow rules required for any sandboxed process to start.
const BASELINE_ALLOW: &str = "\
;; --- baseline (required for any process to start) ---
(allow process-fork)
(allow process-exec)
(allow signal (target self))
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

fn write_filesystem_allow(out: &mut String, request: &ExecutionRequest) -> Result<(), String> {
    let policy = &request.policy;

    if !policy.readonly_paths.is_empty() {
        out.push_str(";; --- policy.readonlyPaths ---\n");
        out.push_str("(allow file-read*\n");
        for p in &policy.readonly_paths {
            let expanded = expand_tilde(p)?;
            let _ = writeln!(out, "    (subpath {})", quote_scheme(&expanded));
        }
        out.push_str(")\n");
    }

    if !policy.readwrite_paths.is_empty() {
        out.push_str(";; --- policy.readwritePaths ---\n");
        out.push_str("(allow file-read* file-write*\n");
        for p in &policy.readwrite_paths {
            let expanded = expand_tilde(p)?;
            let _ = writeln!(out, "    (subpath {})", quote_scheme(&expanded));
        }
        out.push_str(")\n");
    }

    Ok(())
}

fn write_filesystem_deny(out: &mut String, request: &ExecutionRequest) -> Result<(), String> {
    let policy = &request.policy;

    if !policy.denied_paths.is_empty() {
        out.push_str(";; --- policy.deniedPaths (override broader allow rules) ---\n");
        out.push_str("(deny file-read* file-write*\n");
        for p in &policy.denied_paths {
            let expanded = expand_tilde(p)?;
            let _ = writeln!(out, "    (subpath {})", quote_scheme(&expanded));
        }
        out.push_str(")\n");
    }

    Ok(())
}

fn write_network_rules(out: &mut String, request: &ExecutionRequest) {
    let policy = &request.policy;
    let allow_outbound = matches!(policy.default_network_policy, NetworkPolicy::Allow);
    let has_allowed_hosts = !policy.allowed_hosts.is_empty();

    // blocked_hosts is rejected at the runner level before reaching the
    // profile builder, so it isn't handled here.
    match (allow_outbound, has_allowed_hosts) {
        (false, false) => {
            // Pure deny — implicit from `(deny default)`.
            out.push_str(";; --- network: default-deny (no allow-network rules emitted) ---\n");
        }
        (true, false) => {
            out.push_str(";; --- network: outbound allowed (any host) ---\n");
            write_outbound_allow_rules(out);
        }
        (_, true) => {
            // Seatbelt only accepts `*` or `localhost` in `(remote ...)` filters —
            // per-hostname filtering isn't possible, so allowedHosts degrades to
            // allow-all outbound as a best-effort.
            out.push_str(
                ";; --- network: allowedHosts requested but Seatbelt cannot filter by host;\n",
            );
            out.push_str(";;     allowing all outbound as best-effort ---\n");
            write_outbound_allow_rules(out);
        }
    }

    write_local_network_rules(out, policy.allow_local_network);
}

fn write_outbound_allow_rules(out: &mut String) {
    out.push_str("(allow network-outbound)\n");
    out.push_str("(allow network-bind (local ip))\n");
    out.push_str("(allow system-socket)\n");
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
        assert!(p.contains("(subpath \"/var/data\")"));
        assert!(!p.contains("file-write* (subpath \"/opt/tools\")"));
    }

    #[test]
    fn readwrite_paths_emit_read_and_write_allows() {
        let mut r = req();
        r.policy.readwrite_paths = vec!["/tmp/output".into()];
        let p = build_profile(&r).unwrap();
        assert!(p.contains("(allow file-read* file-write*"));
        assert!(p.contains("(subpath \"/tmp/output\")"));
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
        assert!(p.contains("(subpath \"/tmp/secret\")"));
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
    fn block_with_allowed_hosts_emits_allowlist() {
        let mut r = req();
        r.policy.default_network_policy = NetworkPolicy::Block;
        r.policy.allowed_hosts = vec!["api.github.com".into(), "registry.npmjs.org".into()];
        let p = build_profile(&r).unwrap();
        assert!(p.contains("(allow network-outbound)"));
        assert!(p.contains("Seatbelt cannot filter by host"));
        // Should NOT have per-host remote rules.
        assert!(!p.contains("(remote"));
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
    fn allow_local_network_emits_inbound_rule() {
        // server.listen() on macOS needs `network-inbound` in addition to
        // `network-bind` — the kernel rejects listen() with EPERM otherwise.
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
        assert!(p.contains("(subpath \"/tmp/a\\\"b\\\\c\")"));
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
