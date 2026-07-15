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
//!    workload cannot defeat the cooperative proxy by injecting its own
//!    `HTTP_PROXY` (or clearing it via `NO_PROXY`).
//! 2. **Set** only the HTTP/HTTPS proxy keys ([`PROXY_SET_KEYS`]) to the
//!    configured proxy URL.
//!
//! `NO_PROXY` is intentionally *not* set: exempting loopback/other hosts
//! would silently bypass the proxy's host filtering.
//!
//! The functions here operate purely on `"KEY=VALUE"` strings so they are
//! platform-agnostic and unit-testable on every host.

/// Proxy-related env var keys that are *scrubbed* from caller-supplied env so
/// a sandboxed process cannot override or disable the cooperative proxy.
pub const PROXY_ENV_KEYS: &[&str] = &[
    "HTTP_PROXY",
    "HTTPS_PROXY",
    "http_proxy",
    "https_proxy",
    "NO_PROXY",
    "no_proxy",
];

/// Proxy env var keys that are actively *set* to the configured proxy URL.
///
/// Only the HTTP/HTTPS keys (upper- and lower-case) are set. `NO_PROXY` is
/// deliberately omitted (see module docs).
pub const PROXY_SET_KEYS: &[&str] = &["HTTP_PROXY", "HTTPS_PROXY", "http_proxy", "https_proxy"];

/// Returns the key portion of a `"KEY=VALUE"` env entry (the whole string if
/// there is no `=`).
fn env_key(entry: &str) -> &str {
    entry.split_once('=').map(|(k, _)| k).unwrap_or(entry)
}

/// Returns `true` if `key` is one of the proxy env vars this module manages
/// (and therefore must be stripped from caller-supplied env when a
/// cooperative proxy is active).
pub fn is_managed_proxy_key(key: &str) -> bool {
    PROXY_ENV_KEYS.contains(&key)
}

/// Build the effective environment for a sandbox whose egress is routed
/// through a cooperative proxy at `proxy_url`.
///
/// Every managed proxy key ([`PROXY_ENV_KEYS`]) is removed from `caller_env`,
/// then each key in [`PROXY_SET_KEYS`] is appended pointing at `proxy_url`.
/// All non-proxy entries are preserved in their original order.
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

    effective
}

#[cfg(test)]
mod tests {
    use super::*;

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
    fn does_not_set_no_proxy() {
        let env = apply_cooperative_proxy_env(&[], "http://127.0.0.1:8080");
        assert!(
            !env.iter()
                .any(|e| env_key(e) == "NO_PROXY" || env_key(e) == "no_proxy"),
            "NO_PROXY must not be set: {env:?}"
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
        // Caller NO_PROXY was scrubbed and not re-added.
        assert!(!env.iter().any(|e| env_key(e) == "NO_PROXY"));
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
}
