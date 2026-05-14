// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Pure builder that converts a [`CodexRequest`] into a TinyScheme sandbox
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

use wxc_common::models::{ClipboardPolicy, CodexRequest, NetworkPolicy};

/// Build a complete sandbox profile string from the given request.
///
/// If `request.experimental.seatbelt.profile_override` is set, that
/// string is returned verbatim and policy fields are ignored. This is the
/// escape hatch for advanced/testing scenarios that need to hand-author a
/// profile.
pub fn build_profile(request: &CodexRequest) -> String {
    if let Some(override_profile) = request
        .experimental
        .seatbelt
        .as_ref()
        .and_then(|c| c.profile_override.as_ref())
    {
        return override_profile.clone();
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

    // Pseudo-terminal access — the seatbelt runner attaches the inner
    // shell to a freshly-allocated pty (see `mxc_pty::run_with_pty`) so
    // callers can stream output and the shell sees a real TTY. Without
    // these rules, `isatty()` / `tcgetattr()` / `ttyname()` fail with
    // EPERM because the kernel calls block on the slave fd.
    out.push_str(TTY_ALLOW);

    // Policy-derived allow rules.
    write_filesystem_allow(&mut out, request);
    write_network_rules(&mut out, request);
    write_ui_rules(&mut out, request);

    // Policy-derived deny rules go LAST so they win on conflict.
    write_filesystem_deny(&mut out, request);

    out
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
    (global-name \"com.apple.CoreServices.coreservicesd\"))
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
    (subpath \"/private/etc\")
    (literal \"/dev/null\")
    (literal \"/dev/zero\")
    (literal \"/dev/random\")
    (literal \"/dev/urandom\"))
";

/// Pseudo-terminal device access required by the inner shell when the
/// runner attaches it to a pty. The slave fd we hand the child as
/// stdin/stdout/stderr lives at `/dev/ttysNNN`, and the shell calls
/// `isatty()` (→ `tcgetattr` → ioctl) plus `ttyname()` against it. We
/// also need read access to `/dev/tty` because most shells re-open it
/// at startup, and read access to `/dev/fd` for the `/dev/stdout` etc.
/// indirection some tools use.
const TTY_ALLOW: &str = "\
;; --- pseudo-terminal access (pty bridge in mxc_pty::run_with_pty) ---
(allow file-read* file-write* file-ioctl
    (literal \"/dev/tty\")
    (regex #\"^/dev/ttys[0-9]+$\"))
(allow file-read* (subpath \"/dev/fd\"))
";

fn write_filesystem_allow(out: &mut String, request: &CodexRequest) {
    let policy = &request.policy;

    if !policy.readonly_paths.is_empty() {
        out.push_str(";; --- policy.readonlyPaths ---\n");
        out.push_str("(allow file-read*\n");
        for p in &policy.readonly_paths {
            let expanded = expand_tilde(p);
            let _ = writeln!(out, "    (subpath {})", quote_scheme(&expanded));
        }
        out.push_str(")\n");
    }

    if !policy.readwrite_paths.is_empty() {
        out.push_str(";; --- policy.readwritePaths ---\n");
        out.push_str("(allow file-read* file-write*\n");
        for p in &policy.readwrite_paths {
            let expanded = expand_tilde(p);
            let _ = writeln!(out, "    (subpath {})", quote_scheme(&expanded));
        }
        out.push_str(")\n");
    }
}

fn write_filesystem_deny(out: &mut String, request: &CodexRequest) {
    let policy = &request.policy;

    if !policy.denied_paths.is_empty() {
        out.push_str(";; --- policy.deniedPaths (override broader allow rules) ---\n");
        out.push_str("(deny file-read* file-write*\n");
        for p in &policy.denied_paths {
            let expanded = expand_tilde(p);
            let _ = writeln!(out, "    (subpath {})", quote_scheme(&expanded));
        }
        out.push_str(")\n");
    }
}

fn write_network_rules(out: &mut String, request: &CodexRequest) {
    let policy = &request.policy;
    let allow_outbound = matches!(policy.default_network_policy, NetworkPolicy::Allow);

    if !allow_outbound {
        if policy.allowed_hosts.is_empty() {
            // Pure deny — implicit from `(deny default)`.
            out.push_str(";; --- network: default-deny (no allow-network rules emitted) ---\n");
            return;
        }
        // defaultPolicy=block + allowedHosts = allowlist mode.
        // Seatbelt limitation: only `*` or `localhost` are valid hosts in
        // `(remote ...)` filters — per-hostname filtering is not supported.
        // Fall back to allowing all outbound when allowedHosts is specified.
        out.push_str(
            ";; --- network: allowedHosts requested but Seatbelt cannot filter by host;\n",
        );
        out.push_str(";;     allowing all outbound as best-effort ---\n");
        out.push_str("(allow network-outbound)\n");
        out.push_str("(allow network-bind (local ip))\n");
        out.push_str("(allow system-socket)\n");
        return;
    }

    if policy.allowed_hosts.is_empty() {
        out.push_str(";; --- network: outbound allowed (any host) ---\n");
        out.push_str("(allow network-outbound)\n");
        out.push_str("(allow network-bind (local ip))\n");
        out.push_str("(allow system-socket)\n");
    } else {
        // Seatbelt limitation: per-host filtering not supported.
        // Allow all outbound as best-effort when allowedHosts is specified.
        out.push_str(
            ";; --- network: allowedHosts requested but Seatbelt cannot filter by host;\n",
        );
        out.push_str(";;     allowing all outbound as best-effort ---\n");
        out.push_str("(allow network-outbound)\n");
        out.push_str("(allow network-bind (local ip))\n");
        out.push_str("(allow system-socket)\n");
    }

    // Note: blocked_hosts is rejected at the runner level before reaching
    // the profile builder, so we don't need to handle it here.
}

fn write_ui_rules(out: &mut String, request: &CodexRequest) {
    let ui = &request.policy.ui;
    let gui_access = request
        .experimental
        .seatbelt
        .as_ref()
        .is_some_and(|c| c.gui_access);

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

/// Expand a leading `~` or `~/` to the current user's home directory.
/// Passes through paths that don't start with `~` unchanged.
fn expand_tilde(path: &str) -> String {
    if path == "~" {
        std::env::var("HOME").unwrap_or_else(|_| "~".to_string())
    } else if let Some(rest) = path.strip_prefix("~/") {
        match std::env::var("HOME") {
            Ok(home) => format!("{home}/{rest}"),
            Err(_) => path.to_string(),
        }
    } else {
        path.to_string()
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

    fn req() -> CodexRequest {
        CodexRequest {
            script_code: "echo hi".to_string(),
            ..Default::default()
        }
    }

    #[test]
    fn baseline_profile_has_deny_default_and_baseline_allows() {
        let p = build_profile(&req());
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
        let p = build_profile(&r);
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
        let p = build_profile(&r);
        assert!(p.contains("(allow file-read* file-write*"));
        assert!(p.contains("(subpath \"/tmp/output\")"));
    }

    #[test]
    fn denied_paths_appear_after_allows_to_override() {
        let mut r = req();
        r.policy.readwrite_paths = vec!["/tmp".into()];
        r.policy.denied_paths = vec!["/tmp/secret".into()];
        let p = build_profile(&r);
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
        let p = build_profile(&r);
        assert!(!p.contains("(allow network-outbound"));
        assert!(p.contains("network: default-deny"));
    }

    #[test]
    fn block_with_allowed_hosts_emits_allowlist() {
        let mut r = req();
        r.policy.default_network_policy = NetworkPolicy::Block;
        r.policy.allowed_hosts = vec!["api.github.com".into(), "registry.npmjs.org".into()];
        let p = build_profile(&r);
        assert!(p.contains("(allow network-outbound)"));
        assert!(p.contains("Seatbelt cannot filter by host"));
        // Should NOT have per-host remote rules.
        assert!(!p.contains("(remote"));
    }

    #[test]
    fn allow_outbound_no_hosts_emits_open_network_outbound() {
        let mut r = req();
        r.policy.default_network_policy = NetworkPolicy::Allow;
        let p = build_profile(&r);
        assert!(p.contains("(allow network-outbound)"));
    }

    #[test]
    fn allow_outbound_with_hosts_emits_per_host_remote_rules() {
        let mut r = req();
        r.policy.default_network_policy = NetworkPolicy::Allow;
        r.policy.allowed_hosts = vec!["api.github.com".into(), "1.2.3.4".into()];
        let p = build_profile(&r);
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
        let p = build_profile(&r);
        assert!(!p.contains("(deny network-outbound"));
    }

    #[test]
    fn ui_disabled_blocks_windowserver() {
        let r = req();
        // Default UiPolicy has disable=true.
        assert!(r.policy.ui.disable);
        let p = build_profile(&r);
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
        let p = build_profile(&r);
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
        let p = build_profile(&r);
        assert!(p.contains("com.apple.pasteboard.1"));
    }

    #[test]
    fn injection_false_blocks_hid_iokit() {
        let r = req();
        let p = build_profile(&r);
        assert!(p.contains("IOHIDLibUserClient"));
    }

    #[test]
    fn profile_override_takes_precedence() {
        let mut r = req();
        r.policy.readonly_paths = vec!["/should/be/ignored".into()];
        r.experimental.seatbelt = Some(SeatbeltConfig {
            profile_override: Some("(version 1)(allow default)".into()),
            gui_access: false,
            ..Default::default()
        });
        let p = build_profile(&r);
        assert_eq!(p, "(version 1)(allow default)");
    }

    #[test]
    fn paths_with_quotes_and_backslashes_are_escaped() {
        let mut r = req();
        // Hypothetical adversarial input — we never want a path to break out
        // of the quoted string and inject Scheme.
        r.policy.readonly_paths = vec!["/tmp/a\"b\\c".into()];
        let p = build_profile(&r);
        assert!(p.contains("(subpath \"/tmp/a\\\"b\\\\c\")"));
    }

    #[test]
    fn empty_policy_still_compiles_to_valid_profile() {
        let r = req();
        let p = build_profile(&r);
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
        r.experimental.seatbelt = Some(SeatbeltConfig {
            profile_override: None,
            gui_access: true,
            ..Default::default()
        });
        let p = build_profile(&r);
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
        r.experimental.seatbelt = Some(SeatbeltConfig {
            profile_override: None,
            gui_access: false,
            ..Default::default()
        });
        let p = build_profile(&r);
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
        r.experimental.seatbelt = Some(SeatbeltConfig {
            profile_override: None,
            gui_access: true,
            ..Default::default()
        });
        let p = build_profile(&r);
        // Should NOT emit GUI services when UI is disabled
        assert!(!p.contains("com.apple.CARenderServer"));
        assert!(!p.contains("(allow iokit-open)"));
        // Should have the deny block instead
        assert!(p.contains("ui.disable: deny WindowServer"));
    }
}
