// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Cooperative HTTP/HTTPS proxy env-var handling shared by the Linux
//! (Bubblewrap) and WSLc backends.
//!
//! When a backend cannot install a netfilter drop-floor (WSLc has no
//! iptables in its kernel; Bubblewrap deliberately skips iptables while a
//! proxy is active), per-host network policy is enforced *cooperatively*:
//! the sandboxed process is handed `HTTP_PROXY` / `HTTPS_PROXY` env vars and
//! cooperating clients (curl, requests, apt, …) route through the proxy.
//!
//! Two hygiene rules make this robust:
//! 1. **Scrub** every caller-supplied proxy env var ([`PROXY_ENV_KEYS`]) so a
//!    workload cannot pre-disable the proxy via its own `HTTP_PROXY` (or a
//!    `NO_PROXY` exemption). This only sanitizes the *initial* env; the model
//!    is cooperative, so a workload can still mutate its own env at runtime.
//! 2. **Set** the HTTP/HTTPS/ALL proxy keys ([`PROXY_SET_KEYS`]) to the
//!    configured URL — never `NO_PROXY` (a host exemption list, not a target).
//!
//! `NO_PROXY` is kept out of [`PROXY_SET_KEYS`] and handled per-backend:
//! - Bubblewrap uses `--clearenv` + `PROXY_SET_KEYS`, so it never emits
//!   `NO_PROXY` (a stray exemption would bypass the proxy's host filtering).
//! - WSLc ([`apply_cooperative_proxy_env`]) *merges* over the image's baked-in
//!   `ENV`, so an image `NO_PROXY=*` could survive. To neutralize it, WSLc
//!   sets `NO_PROXY`/`no_proxy` ([`PROXY_NEUTRALIZE_KEYS`]) to the *empty*
//!   string rather than omitting them.
//!
//! Functions here operate on `"KEY=VALUE"` strings, so they are
//! platform-agnostic and unit-testable on every host.

use crate::models::ProxyConfig;

/// Proxy-related env var keys that are *scrubbed* from caller-supplied env so
/// a sandboxed process cannot override or disable the cooperative proxy.
pub const PROXY_ENV_KEYS: &[&str] = &[
    "HTTP_PROXY",
    "HTTPS_PROXY",
    "ALL_PROXY",
    "FTP_PROXY",
    "http_proxy",
    "https_proxy",
    "all_proxy",
    "NO_PROXY",
    "no_proxy",
];

/// Proxy env var keys that are actively *set* to the configured proxy URL.
///
/// The HTTP/HTTPS/ALL keys (upper- and lower-case) are set. `NO_PROXY` is
/// deliberately omitted (it is a host-exemption list, not a proxy target; see
/// module docs and [`PROXY_NEUTRALIZE_KEYS`]).
pub const PROXY_SET_KEYS: &[&str] = &[
    "HTTP_PROXY",
    "HTTPS_PROXY",
    "ALL_PROXY",
    "http_proxy",
    "https_proxy",
    "all_proxy",
];

/// Proxy env var keys that [`apply_cooperative_proxy_env`] sets to the *empty
/// string* to neutralize any inherited (e.g. image-baked) value. Forcing
/// `NO_PROXY` empty exempts nothing, so all cooperating traffic still routes
/// through the proxy. (Bubblewrap uses `--clearenv` and does not use these.)
pub const PROXY_NEUTRALIZE_KEYS: &[&str] = &["NO_PROXY", "no_proxy"];

/// Returns the key portion of a `"KEY=VALUE"` env entry (the whole string if
/// there is no `=`).
fn env_key(entry: &str) -> &str {
    entry.split_once('=').map(|(k, _)| k).unwrap_or(entry)
}

/// Returns `true` if `key` is one of the proxy env vars this module manages
/// (and therefore must be stripped from caller-supplied env when a
/// cooperative proxy is active).
///
/// Matched case-insensitively: clients (Python `urllib`, curl, …) lower-case
/// these names, so `No_Proxy` must be scrubbed just like `NO_PROXY`.
pub fn is_managed_proxy_key(key: &str) -> bool {
    PROXY_ENV_KEYS.iter().any(|k| k.eq_ignore_ascii_case(key))
}

/// Redact any `user:pass@` userinfo from a proxy URL so it is safe to log.
pub fn redact_proxy_url(url: &str) -> String {
    let Some((scheme, rest)) = url.split_once("://") else {
        return url.to_string();
    };
    let auth_end = rest.find(['/', '?', '#']).unwrap_or(rest.len());
    let (authority, tail) = rest.split_at(auth_end);
    match authority.rsplit_once('@') {
        Some((_userinfo, host)) => format!("{scheme}://***@{host}{tail}"),
        None => url.to_string(),
    }
}

/// Build the effective environment for a sandbox whose egress is routed
/// through a cooperative proxy at `proxy_url`.
///
/// Every managed proxy key ([`PROXY_ENV_KEYS`]) is removed from `caller_env`,
/// then each key in [`PROXY_SET_KEYS`] is appended pointing at `proxy_url`,
/// and each key in [`PROXY_NEUTRALIZE_KEYS`] (`NO_PROXY`/`no_proxy`) is
/// appended set to the *empty* string — so an inherited or image-baked
/// exemption cannot disable the proxy. All non-proxy entries are preserved in
/// their original order.
///
/// `caller_env` entries are `"KEY=VALUE"` strings; the returned vector uses
/// the same encoding.
pub fn apply_cooperative_proxy_env(caller_env: &[String], proxy_url: &str) -> Vec<String> {
    let mut effective: Vec<String> = caller_env
        .iter()
        .filter(|entry| !is_managed_proxy_key(env_key(entry)))
        .cloned()
        .collect();

    for key in PROXY_SET_KEYS {
        effective.push(format!("{key}={proxy_url}"));
    }

    // Neutralize any inherited NO_PROXY: WSLc merges over the image's ENV, so
    // an image `NO_PROXY=*` would otherwise disable the proxy. Empty exempts
    // nothing.
    for key in PROXY_NEUTRALIZE_KEYS {
        effective.push(format!("{key}="));
    }

    effective
}

/// Scrub proxy env vars from `env` in place, then point them at `proxy` when it
/// carries an address.
///
/// This is the LXC entry point; it delegates to [`apply_cooperative_proxy_env`]
/// so LXC scrubs and sets exactly the same key set as Bubblewrap and WSLc
/// rather than maintaining a parallel list that can drift.
///
/// `env` uses the `ExecutionRequest::env` representation: `KEY=VALUE` strings.
/// Entries without `=` are treated as a bare key, so a valueless `HTTP_PROXY`
/// is still scrubbed.
///
/// Returns `true` when the caller should force a clean environment even if the
/// resulting vector is empty (for example, because every entry was scrubbed).
pub fn apply_proxy_env(env: &mut Vec<String>, proxy: &ProxyConfig) -> bool {
    if let Some(address) = &proxy.address {
        *env = apply_cooperative_proxy_env(env, &address.to_url());
        return true;
    }

    // Proxy disabled: still strip inherited proxy vars so a caller cannot point
    // the sandbox at an egress path the policy never authorized.
    // Always return true so the caller emits --clear-env even when the input
    // was empty — an empty env must still prevent lxc-attach from inheriting
    // the full MXC host process environment (including proxy vars and tokens).
    env.retain(|entry| !is_managed_proxy_key(env_key(entry)));
    true
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::ProxyAddress;

    #[test]
    fn sets_all_http_https_proxy_keys_to_url() {
        let env = apply_cooperative_proxy_env(&[], "http://127.0.0.1:8080");
        for key in PROXY_SET_KEYS {
            assert!(
                env.contains(&format!("{key}=http://127.0.0.1:8080")),
                "missing {key}: {env:?}"
            );
        }
    }

    #[test]
    fn sets_no_proxy_empty() {
        // NO_PROXY / no_proxy are forced to the empty string (never a value),
        // so an inherited or image-baked exemption cannot disable the proxy.
        let env = apply_cooperative_proxy_env(&[], "http://127.0.0.1:8080");
        for key in PROXY_NEUTRALIZE_KEYS {
            assert!(
                env.contains(&format!("{key}=")),
                "expected empty {key}: {env:?}"
            );
        }
        // ...and never carries a non-empty value.
        assert!(
            !env.iter().any(|e| {
                let (k, v) = e.split_once('=').unwrap_or((e.as_str(), ""));
                k.eq_ignore_ascii_case("no_proxy") && !v.is_empty()
            }),
            "NO_PROXY must be empty: {env:?}"
        );
    }

    #[test]
    fn strips_caller_supplied_proxy_env() {
        let caller = vec![
            "FOO=bar".to_string(),
            "HTTP_PROXY=http://attacker.example:9999".to_string(),
            "https_proxy=http://attacker.example:9999".to_string(),
            "NO_PROXY=example.com".to_string(),
            "PATH=/usr/bin".to_string(),
        ];
        let env = apply_cooperative_proxy_env(&caller, "http://127.0.0.1:9000");

        // Non-proxy entries preserved.
        assert!(env.contains(&"FOO=bar".to_string()));
        assert!(env.contains(&"PATH=/usr/bin".to_string()));

        // Proxy points at the configured URL, not the attacker's.
        assert!(env.contains(&"HTTP_PROXY=http://127.0.0.1:9000".to_string()));
        // The attacker's values are gone.
        assert!(!env.iter().any(|e| e.contains("attacker.example")));
        // Caller NO_PROXY was scrubbed; only the empty neutralizer remains.
        assert!(env.contains(&"NO_PROXY=".to_string()));
        assert!(!env.iter().any(|e| e == "NO_PROXY=example.com"));
    }

    #[test]
    fn preserves_order_of_non_proxy_entries() {
        let caller = vec!["A=1".to_string(), "B=2".to_string(), "C=3".to_string()];
        let env = apply_cooperative_proxy_env(&caller, "http://127.0.0.1:1");
        assert_eq!(env[0], "A=1");
        assert_eq!(env[1], "B=2");
        assert_eq!(env[2], "C=3");
    }

    #[test]
    fn entry_without_equals_is_treated_as_key() {
        // A bare "HTTP_PROXY" (no value) is still a managed key and stripped.
        let caller = vec!["HTTP_PROXY".to_string(), "KEEP=1".to_string()];
        let env = apply_cooperative_proxy_env(&caller, "http://127.0.0.1:2");
        assert!(env.contains(&"KEEP=1".to_string()));
        assert_eq!(
            env.iter().filter(|e| *e == "HTTP_PROXY").count(),
            0,
            "bare managed key must be stripped: {env:?}"
        );
    }

    #[test]
    fn strips_mixed_case_proxy_keys() {
        // Clients lower-case these names, so a mixed-case spelling must not
        // survive the scrub and defeat the cooperative proxy.
        let caller = vec![
            "No_Proxy=*".to_string(),
            "HtTp_PrOxY=http://attacker.example:9999".to_string(),
            "KEEP=1".to_string(),
        ];
        let env = apply_cooperative_proxy_env(&caller, "http://127.0.0.1:9000");
        assert!(env.contains(&"KEEP=1".to_string()));
        assert!(!env.iter().any(|e| e.contains("attacker.example")));
        // The mixed-case No_Proxy=* was scrubbed; only an empty neutralizer
        // (never the `*` value) survives.
        assert!(
            !env.iter().any(|e| {
                let (k, v) = e.split_once('=').unwrap_or((e.as_str(), ""));
                k.eq_ignore_ascii_case("no_proxy") && !v.is_empty()
            }),
            "No_Proxy value must not survive: {env:?}"
        );
    }

    #[test]
    fn neutralizes_image_baked_no_proxy() {
        // WSLc merges this env over the image's ENV (process env wins per key),
        // so we must emit an explicit empty NO_PROXY/no_proxy to override an
        // image `ENV NO_PROXY=*`.
        let env = apply_cooperative_proxy_env(&[], "http://127.0.0.1:8888");
        assert!(
            env.contains(&"NO_PROXY=".to_string()),
            "empty NO_PROXY override missing: {env:?}"
        );
        assert!(
            env.contains(&"no_proxy=".to_string()),
            "empty no_proxy override missing: {env:?}"
        );
        // Neither override may carry a value (which would re-add an exemption).
        assert!(!env.iter().any(|e| e == "NO_PROXY=*" || e == "no_proxy=*"));
    }

    #[test]
    fn redacts_userinfo_in_proxy_url() {
        assert_eq!(
            redact_proxy_url("http://user:pass@proxy.example:8080"),
            "http://***@proxy.example:8080"
        );
        // No userinfo -> unchanged.
        assert_eq!(
            redact_proxy_url("http://proxy.example:8080"),
            "http://proxy.example:8080"
        );
        // '@' only in the path must not trigger redaction.
        assert_eq!(
            redact_proxy_url("http://proxy.example:8080/a@b"),
            "http://proxy.example:8080/a@b"
        );
    }

    #[test]
    fn apply_proxy_env_removes_all_managed_proxy_vars() {
        let mut env = vec![
            "HTTP_PROXY=old".to_string(),
            "HTTPS_PROXY=old".to_string(),
            "ALL_PROXY=old".to_string(),
            "FTP_PROXY=old".to_string(),
            "NO_PROXY=old".to_string(),
            "http_proxy=old".to_string(),
            "https_proxy=old".to_string(),
            "all_proxy=old".to_string(),
            "ftp_proxy=old".to_string(),
            "no_proxy=old".to_string(),
            "PATH=/usr/bin".to_string(),
            "MALFORMED".to_string(),
        ];

        let force_clear = apply_proxy_env(&mut env, &ProxyConfig::default());

        assert!(force_clear);
        assert_eq!(env, vec!["PATH=/usr/bin", "MALFORMED"]);
    }

    #[test]
    fn apply_proxy_env_sets_configured_proxy_when_enabled() {
        let mut env = vec![
            "HTTP_PROXY=http://old.example:1".to_string(),
            "FOO=bar".to_string(),
        ];
        let proxy = ProxyConfig {
            address: Some(ProxyAddress::new("127.0.0.1".to_string(), 8080)),
            builtin_test_server: false,
        };

        let force_clear = apply_proxy_env(&mut env, &proxy);

        assert!(force_clear);
        assert_eq!(env[0], "FOO=bar");
        for key in ["HTTP_PROXY", "HTTPS_PROXY", "http_proxy", "https_proxy"] {
            assert!(
                env.iter()
                    .any(|entry| entry == &format!("{key}=http://127.0.0.1:8080")),
                "missing {key} in {env:?}"
            );
        }
        assert!(!env.iter().any(|entry| entry.contains("old.example")));
    }

    #[test]
    fn apply_proxy_env_neutralizes_inherited_no_proxy() {
        // Shares `apply_cooperative_proxy_env`, so an inherited `NO_PROXY=*`
        // cannot survive as an exemption that steers traffic around the proxy.
        let mut env = vec!["NO_PROXY=*".to_string()];
        let proxy = ProxyConfig {
            address: Some(ProxyAddress::new("10.0.0.5".to_string(), 3128)),
            builtin_test_server: false,
        };

        apply_proxy_env(&mut env, &proxy);

        assert!(env.contains(&"NO_PROXY=".to_string()));
        assert!(!env.iter().any(|entry| entry == "NO_PROXY=*"));
    }

    #[test]
    fn apply_proxy_env_disabled_clears_proxy_vars_without_setting_any() {
        let mut env = vec![
            "HTTP_PROXY=http://old.example:1".to_string(),
            "https_proxy=http://old.example:2".to_string(),
        ];

        let force_clear = apply_proxy_env(&mut env, &ProxyConfig::default());

        assert!(force_clear);
        assert!(env.is_empty());
    }

    #[test]
    fn apply_proxy_env_disabled_always_forces_clear_even_without_proxy_vars() {
        // Previously asserted !force_clear, which was wrong and masked the leak.
        // The fix makes apply_proxy_env return true unconditionally in the
        // proxy-disabled branch so --clear-env is always emitted.  Non-proxy
        // vars (PATH) must survive the scrub unchanged.
        // Safe to assert true here: with a non-empty env the !env.is_empty()
        // arm of build_attach_args already triggered --clear-env before the fix,
        // so the produced argv is byte-identical for this input.  The bool only
        // changed observable attach-args behavior for the empty-env case.
        let mut env = vec!["PATH=/usr/bin".to_string()];

        let force_clear = apply_proxy_env(&mut env, &ProxyConfig::default());

        assert!(force_clear);
        assert_eq!(env, vec!["PATH=/usr/bin"]);
    }
}
