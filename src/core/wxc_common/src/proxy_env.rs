// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Helpers for applying network proxy policy to process environment vectors.

use crate::models::ProxyConfig;

const PROXY_ENV_KEYS: &[&str] = &[
    "HTTP_PROXY",
    "HTTPS_PROXY",
    "ALL_PROXY",
    "FTP_PROXY",
    "NO_PROXY",
    "http_proxy",
    "https_proxy",
    "all_proxy",
    "ftp_proxy",
    "no_proxy",
];

/// Scrub proxy-related variables from `env`, then set the configured HTTP(S)
/// proxy variables when `proxy` has an address.
///
/// `env` uses the `ExecutionRequest::env` representation: `KEY=VALUE` strings.
/// Malformed entries without `=` are preserved because they are ignored by the
/// backend-specific command builders anyway.
///
/// Returns `true` when the caller should force a clean environment even if the
/// resulting vector is empty (for example, because every entry was scrubbed).
pub fn apply_proxy_env(env: &mut Vec<String>, proxy: &ProxyConfig) -> bool {
    let original_len = env.len();
    env.retain(|entry| {
        entry
            .split_once('=')
            .is_none_or(|(key, _)| !PROXY_ENV_KEYS.contains(&key))
    });

    let scrubbed_any = env.len() != original_len;

    if let Some(address) = &proxy.address {
        let url = address.to_url();
        for key in ["HTTP_PROXY", "HTTPS_PROXY", "http_proxy", "https_proxy"] {
            env.push(format!("{key}={url}"));
        }
        true
    } else {
        scrubbed_any
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::{ProxyAddress, ProxyConfig};

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
    fn apply_proxy_env_disabled_no_proxy_vars_does_not_force_clear() {
        let mut env = vec!["PATH=/usr/bin".to_string()];

        let force_clear = apply_proxy_env(&mut env, &ProxyConfig::default());

        assert!(!force_clear);
        assert_eq!(env, vec!["PATH=/usr/bin"]);
    }
}
