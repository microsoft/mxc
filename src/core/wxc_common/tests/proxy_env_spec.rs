//! Black-box contract tests for `wxc_common::proxy_env`.
//!
//! These tests are derived from the documented contract of the public API, not
//! from its implementation. Each test names the client whose observable
//! behavior it protects, in the sense of Khorikov's "observable behavior is
//! relative to a named client and its goals":
//!
//! (a) LXC backend (PLANNED integration, not yet wired) -- will call
//!     `apply_proxy_env` and use the returned bool to decide whether to pass
//!     `--clear-env` to `lxc-attach`. Today `attach_run` derives `--clear-env`
//!     solely from `env` being non-empty (`lxc_bindings.rs:90`). The empty-env
//!     case is where the helper contract and current behavior diverge:
//!     `apply_proxy_env` returns `true` even for an empty env so the host
//!     environment cannot leak, whereas current code emits no `--clear-env`
//!     then. Wiring this in must update `lxc_bindings.rs` and the test at
//!     `lxc_bindings.rs:743` that pins the current empty-env rule. These tests
//!     validate the helper contract, not existing LXC behavior.
//! (b) Bubblewrap backend -- calls `is_managed_proxy_key`, iterates
//!     `PROXY_SET_KEYS`.
//! (c) WSLc backend -- calls `apply_cooperative_proxy_env`, merges the result
//!     over an image's baked-in `ENV`.
//! (d) Security review -- a sandboxed workload must not disable or redirect the
//!     proxy via its own env, and logs must not leak proxy credentials.

use wxc_common::models::{ProxyAddress, ProxyConfig};
use wxc_common::proxy_env::{
    apply_cooperative_proxy_env, apply_proxy_env, is_managed_proxy_key, proxy_url_has_credentials,
    redact_proxy_url, PROXY_ENV_KEYS, PROXY_NEUTRALIZE_KEYS, PROXY_SET_KEYS,
};

const PROXY_URL: &str = "http://127.0.0.1:8080";

// Split a `KEY=VALUE` entry into its key. An entry with no `=` is a bare key.
fn key_of(entry: &str) -> &str {
    match entry.split_once('=') {
        Some((key, _)) => key,
        None => entry,
    }
}

// First value for `key` (case-sensitive on the key) in a `KEY=VALUE` list.
fn value_for<'a>(env: &'a [String], key: &str) -> Option<&'a str> {
    env.iter().find_map(|entry| {
        let (k, v) = entry.split_once('=')?;
        (k == key).then_some(v)
    })
}

// Every entry whose key is NOT managed, in original order.
fn non_proxy_entries(env: &[String]) -> Vec<&String> {
    env.iter()
        .filter(|e| !is_managed_proxy_key(key_of(e)))
        .collect()
}

// ---------------------------------------------------------------------------
// is_managed_proxy_key
// ---------------------------------------------------------------------------

// Protects client (b) and (d): the scrub decision runs through this predicate,
// so every managed family in every spelling must match. If a spelling stopped
// matching, a sandboxed workload could smuggle that variable past the scrubber.
#[test]
fn is_managed_proxy_key_matches_every_managed_family() {
    assert!(is_managed_proxy_key("HTTP_PROXY"));
    assert!(is_managed_proxy_key("HTTPS_PROXY"));
    assert!(is_managed_proxy_key("ALL_PROXY"));
    assert!(is_managed_proxy_key("FTP_PROXY"));
    assert!(is_managed_proxy_key("NO_PROXY"));
}

// Protects client (b) and (d): the contract states matching is case-insensitive
// because clients (Python urllib, curl) lower-case these names. If matching
// regressed to case-sensitive, `No_Proxy` from a workload would survive.
#[test]
fn is_managed_proxy_key_is_case_insensitive() {
    assert!(is_managed_proxy_key("http_proxy"));
    assert!(is_managed_proxy_key("no_proxy"));
    assert!(is_managed_proxy_key("No_Proxy"));
    assert!(is_managed_proxy_key("hTtP_pRoXy"));
    assert!(is_managed_proxy_key("all_proxy"));
    assert!(is_managed_proxy_key("ftp_proxy"));
}

// Protects client (b): over-scrubbing would silently delete a workload's
// legitimate environment. Names that merely resemble a proxy key, or embed one
// as a substring, must NOT be treated as managed.
#[test]
fn is_managed_proxy_key_rejects_non_proxy_names() {
    assert!(!is_managed_proxy_key("PROXY"));
    assert!(!is_managed_proxy_key("HTTP_PROXYY"));
    assert!(!is_managed_proxy_key("XHTTP_PROXY"));
    assert!(!is_managed_proxy_key("HTTP_PROXY_EXTRA"));
    assert!(!is_managed_proxy_key("PATH"));
    assert!(!is_managed_proxy_key(""));
}

// ---------------------------------------------------------------------------
// The key-set constants
// ---------------------------------------------------------------------------

// Protects client (b) and (d): the contract says NO_PROXY is deliberately
// omitted from the actively-set keys (it is a host-exemption list, not a proxy
// target). Setting NO_PROXY to a proxy URL would be nonsensical and could open
// an exemption.
#[test]
fn proxy_set_keys_never_include_no_proxy() {
    assert!(!PROXY_SET_KEYS
        .iter()
        .any(|k| k.eq_ignore_ascii_case("NO_PROXY")));
}

// Protects client (b): every key the module actively sets must also be a key it
// scrubs first. A set key that is not managed would be appended on top of a
// caller-supplied value instead of replacing it.
#[test]
fn every_set_key_is_managed() {
    assert!(PROXY_SET_KEYS.iter().all(|k| is_managed_proxy_key(k)));
}

// Protects client (d): every neutralized key must be a managed key, and the
// neutralize set is exactly the NO_PROXY family. If HTTP_PROXY leaked into the
// neutralize set the proxy target would be blanked and egress would break.
#[test]
fn neutralize_keys_are_exactly_the_no_proxy_family() {
    assert!(PROXY_NEUTRALIZE_KEYS
        .iter()
        .all(|k| is_managed_proxy_key(k)));
    assert!(PROXY_NEUTRALIZE_KEYS
        .iter()
        .all(|k| k.eq_ignore_ascii_case("NO_PROXY")));
    assert!(PROXY_NEUTRALIZE_KEYS.contains(&"NO_PROXY"));
    assert!(PROXY_NEUTRALIZE_KEYS.contains(&"no_proxy"));
}

// Protects client (b) and (d): every managed family appears in the scrub list
// in BOTH spellings -- upper-case and lower-case -- and every entry in the list
// is itself a key the module recognizes as managed (no stray or unmanaged
// entry). The contract keeps the lower-case duplicates so a consumer that does
// a case-sensitive `contains` over the slice (clients like Python urllib and
// curl lower-case these names) still sees the whole set; if a lower-case
// spelling went missing, such a consumer would fail to scrub that family.
#[test]
fn proxy_env_keys_contain_both_spellings_of_every_family_and_only_managed_entries() {
    for family in [
        "HTTP_PROXY",
        "HTTPS_PROXY",
        "ALL_PROXY",
        "FTP_PROXY",
        "NO_PROXY",
    ] {
        assert!(PROXY_ENV_KEYS.contains(&family));
        assert!(PROXY_ENV_KEYS.contains(&family.to_ascii_lowercase().as_str()));
    }
    assert!(PROXY_ENV_KEYS.iter().all(|k| is_managed_proxy_key(k)));
}

// Protects client (b), (c), and (d): every key the module actively sets or
// neutralizes must also appear in the scrub list, so a consumer that scrubs by
// iterating PROXY_ENV_KEYS removes everything the module will re-add. If a set
// key were missing from the scrub list, a caller-supplied value could shadow
// the one the module appends.
#[test]
fn every_set_and_neutralize_key_is_in_the_scrub_list() {
    assert!(PROXY_SET_KEYS.iter().all(|k| PROXY_ENV_KEYS.contains(k)));
    assert!(PROXY_NEUTRALIZE_KEYS
        .iter()
        .all(|k| PROXY_ENV_KEYS.contains(k)));
}

// ---------------------------------------------------------------------------
// apply_cooperative_proxy_env -- scrubbing
// ---------------------------------------------------------------------------

// Protects client (d): a sandboxed workload cannot pre-set a proxy variable to
// escape the cooperative proxy. Every managed key the caller supplies -- in any
// case, and the FTP family that is scrubbed but never re-set -- is gone or
// replaced; the workload's `evil` target never survives.
#[test]
fn cooperative_env_scrubs_all_caller_supplied_proxy_keys() {
    let caller = vec![
        "HTTP_PROXY=http://evil:1".to_string(),
        "https_proxy=http://evil:1".to_string(),
        "ALL_PROXY=http://evil:1".to_string(),
        "FTP_PROXY=http://evil:1".to_string(),
        "No_Proxy=internal.example.com".to_string(),
    ];

    let result = apply_cooperative_proxy_env(&caller, PROXY_URL);

    assert!(!result.iter().any(|e| e.contains("evil")));
    assert!(!result.iter().any(|e| e.contains("internal.example.com")));
    assert!(!result
        .iter()
        .any(|e| key_of(e).eq_ignore_ascii_case("FTP_PROXY")));
}

// Protects client (d): duplicate and mixed-case proxy keys are an obvious
// evasion attempt. Neither the second copy nor an unusual casing survives with
// the workload's value.
#[test]
fn cooperative_env_scrubs_duplicate_and_mixed_case_proxy_keys() {
    let caller = vec![
        "HTTP_PROXY=http://evil:1".to_string(),
        "HtTp_PrOxY=http://evil:2".to_string(),
        "http_proxy=http://evil:3".to_string(),
    ];

    let result = apply_cooperative_proxy_env(&caller, PROXY_URL);

    assert!(!result.iter().any(|e| e.contains("evil")));
    assert_eq!(value_for(&result, "HTTP_PROXY"), Some(PROXY_URL));
    assert_eq!(value_for(&result, "http_proxy"), Some(PROXY_URL));
}

// ---------------------------------------------------------------------------
// apply_cooperative_proxy_env -- setting and neutralizing
// ---------------------------------------------------------------------------

// Protects client (c): WSLc merges this result over an image's baked-in ENV,
// so each set key must point at the real proxy for cooperating traffic to be
// routed. Every PROXY_SET_KEYS entry is present and points at proxy_url.
#[test]
fn cooperative_env_sets_every_set_key_to_the_proxy_url() {
    let result = apply_cooperative_proxy_env(&[], PROXY_URL);

    assert!(PROXY_SET_KEYS
        .iter()
        .all(|k| value_for(&result, k) == Some(PROXY_URL)));
}

// Protects client (d): the contract neutralizes the NO_PROXY family to the
// empty string so an inherited or image-baked exemption cannot disable the
// proxy. Each neutralize key is present and set to empty -- not absent, not a
// host list.
#[test]
fn cooperative_env_neutralizes_no_proxy_family_to_empty() {
    let caller = vec!["NO_PROXY=*".to_string(), "no_proxy=*.internal".to_string()];

    let result = apply_cooperative_proxy_env(&caller, PROXY_URL);

    assert!(PROXY_NEUTRALIZE_KEYS
        .iter()
        .all(|k| value_for(&result, k) == Some("")));
}

// Protects client (d): a workload that sets NO_PROXY=* is trying to exempt all
// hosts from the proxy. NO_PROXY must never be pointed at the proxy URL, and
// its blanket-exemption value must not survive.
#[test]
fn cooperative_env_never_points_no_proxy_at_the_proxy_url() {
    let caller = vec!["NO_PROXY=*".to_string()];

    let result = apply_cooperative_proxy_env(&caller, PROXY_URL);

    assert_ne!(value_for(&result, "NO_PROXY"), Some(PROXY_URL));
    assert_eq!(value_for(&result, "NO_PROXY"), Some(""));
    assert!(!result.iter().any(|e| e == "NO_PROXY=*"));
}

// ---------------------------------------------------------------------------
// apply_cooperative_proxy_env -- order preservation
// ---------------------------------------------------------------------------

// Protects client (c): WSLc relies on non-proxy entries surviving unchanged so
// the merge over the image ENV is predictable. Every non-proxy entry is
// preserved verbatim and in its original relative order.
#[test]
fn cooperative_env_preserves_non_proxy_entries_in_order() {
    let caller = vec![
        "PATH=/usr/bin:/bin".to_string(),
        "HTTP_PROXY=http://evil:1".to_string(),
        "HOME=/root".to_string(),
        "LANG=C.UTF-8".to_string(),
    ];

    let result = apply_cooperative_proxy_env(&caller, PROXY_URL);

    let preserved = non_proxy_entries(&result);
    assert_eq!(
        preserved,
        vec![
            &"PATH=/usr/bin:/bin".to_string(),
            &"HOME=/root".to_string(),
            &"LANG=C.UTF-8".to_string(),
        ]
    );
}

// Protects client (c): the contract appends the managed keys after scrubbing,
// so when WSLc treats later entries as winning duplicates the proxy keys win.
// Every non-proxy entry precedes every managed entry in the result.
#[test]
fn cooperative_env_appends_managed_keys_after_non_proxy_entries() {
    let caller = vec![
        "PATH=/usr/bin".to_string(),
        "HTTP_PROXY=http://evil:1".to_string(),
        "HOME=/root".to_string(),
    ];

    let result = apply_cooperative_proxy_env(&caller, PROXY_URL);

    let last_non_proxy = result
        .iter()
        .rposition(|e| !is_managed_proxy_key(key_of(e)))
        .unwrap();
    let first_managed = result
        .iter()
        .position(|e| is_managed_proxy_key(key_of(e)))
        .unwrap();
    assert!(last_non_proxy < first_managed);
}

// ---------------------------------------------------------------------------
// apply_proxy_env -- LXC entry point
// ---------------------------------------------------------------------------

// Protects client (a): when the proxy carries an address, LXC needs the env
// pointed at it and NO_PROXY neutralized. The keys are set to the proxy's URL
// and the return is true so LXC emits --clear-env.
#[test]
fn apply_proxy_env_enabled_sets_keys_and_returns_true() {
    let proxy = ProxyConfig {
        address: Some(ProxyAddress::new("127.0.0.1".to_string(), 8080)),
        builtin_test_server: false,
    };
    let expected_url = proxy.address.as_ref().unwrap().to_url();
    let mut env = vec![
        "PATH=/usr/bin".to_string(),
        "HTTP_PROXY=http://evil:1".to_string(),
    ];

    let force_clean = apply_proxy_env(&mut env, &proxy);

    assert!(force_clean);
    assert!(!env.iter().any(|e| e.contains("evil")));
    assert!(PROXY_SET_KEYS
        .iter()
        .all(|k| value_for(&env, k) == Some(expected_url.as_str())));
    assert!(PROXY_NEUTRALIZE_KEYS
        .iter()
        .all(|k| value_for(&env, k) == Some("")));
}

// Protects client (a) and (d): the contract says a valueless entry with no `=`
// is treated as a bare key and still scrubbed. A workload passing a bare
// `HTTP_PROXY` (which inherits the host value) must not slip through.
#[test]
fn apply_proxy_env_scrubs_bare_valueless_proxy_key() {
    let proxy = ProxyConfig {
        address: Some(ProxyAddress::new("127.0.0.1".to_string(), 8080)),
        builtin_test_server: false,
    };
    let mut env = vec!["HTTP_PROXY".to_string(), "PATH=/usr/bin".to_string()];

    let force_clean = apply_proxy_env(&mut env, &proxy);

    assert!(force_clean);
    assert!(!env.iter().any(|e| e == "HTTP_PROXY"));
    assert_eq!(value_for(&env, "PATH"), Some("/usr/bin"));
}

// Protects client (a) and (d): even with no proxy configured, LXC must still
// force a clean environment so lxc-attach cannot inherit the MXC host process
// env (which carries proxy vars and credentials). Caller proxy keys are
// scrubbed and the return is still true.
#[test]
fn apply_proxy_env_disabled_still_scrubs_and_returns_true() {
    let proxy = ProxyConfig::default();
    let mut env = vec![
        "PATH=/usr/bin".to_string(),
        "HTTP_PROXY=http://host-proxy:9".to_string(),
        "NO_PROXY=internal".to_string(),
    ];

    let force_clean = apply_proxy_env(&mut env, &proxy);

    assert!(force_clean);
    assert!(!env.iter().any(|e| e.contains("host-proxy")));
    assert!(!env.iter().any(|e| e.contains("internal")));
    assert_eq!(value_for(&env, "PATH"), Some("/usr/bin"));
}

// Protects client (a): the return contract is "always true, including when env
// ends up empty" -- the empty vector still tells LXC to emit --clear-env so an
// empty env does not silently inherit the host environment.
#[test]
fn apply_proxy_env_returns_true_for_empty_env() {
    let proxy = ProxyConfig::default();
    let mut env: Vec<String> = Vec::new();

    let force_clean = apply_proxy_env(&mut env, &proxy);

    assert!(force_clean);
}

// ---------------------------------------------------------------------------
// redact_proxy_url
// ---------------------------------------------------------------------------

// Protects client (d): logs must not leak proxy credentials. When userinfo is
// present the password must not appear in the redacted string, while the host
// is retained so the log is still useful.
#[test]
fn redact_proxy_url_removes_userinfo_credentials() {
    let redacted = redact_proxy_url("http://alice:hunter2@proxy.example.com:8080");

    assert!(!redacted.contains("hunter2"));
    assert!(!redacted.contains("alice:hunter2"));
    assert!(redacted.contains("proxy.example.com"));
}

// Protects client (d): a URL with no userinfo has nothing to redact and must be
// returned unchanged, so redaction does not corrupt an ordinary proxy URL.
#[test]
fn redact_proxy_url_leaves_url_without_userinfo_unchanged() {
    let input = "http://127.0.0.1:8080";

    let redacted = redact_proxy_url(input);

    assert_eq!(redacted, input);
}

// Protects client (d): a naive split on '@' would corrupt a URL whose only '@'
// is in the path. Such a URL has no userinfo, so it must be returned intact.
#[test]
fn redact_proxy_url_ignores_at_sign_in_path() {
    let input = "http://127.0.0.1:8080/path@segment";

    let redacted = redact_proxy_url(input);

    assert_eq!(redacted, input);
}

// proxy_url_has_credentials
// -------------------------
// Protects client (d): this predicate is what a backend consults before it
// puts a proxy URL somewhere the URL cannot be taken back out of -- process
// argv, in the LXC case.  A false negative is a leaked password, so each shape
// below is asserted directly rather than inferred from the redaction helper.

// The shape the guard exists for: userinfo carrying a password.
#[test]
fn a_url_with_user_and_password_carries_credentials() {
    assert!(proxy_url_has_credentials(
        "http://alice:hunter2@proxy.example.com:8080"
    ));
}

// A bare username is still userinfo.  It names a principal, and the guard's
// contract is about userinfo, not about whether a password happens to follow.
#[test]
fn a_url_with_a_bare_username_carries_credentials() {
    assert!(proxy_url_has_credentials(
        "http://alice@proxy.example.com:8080"
    ));
}

// The complement, and the anti-vacuity partner for every assertion above: an
// ordinary proxy URL must pass, or the guard would refuse all proxies and the
// positive cases would prove nothing.
#[test]
fn an_ordinary_proxy_url_carries_no_credentials() {
    assert!(!proxy_url_has_credentials("http://127.0.0.1:8080"));
    assert!(!proxy_url_has_credentials(
        "https://proxy.example.com:3128/"
    ));
}

// A naive `contains('@')` would report credentials for a URL whose only '@' is
// in the path, refusing a legitimate proxy.
#[test]
fn an_at_sign_in_the_path_is_not_credentials() {
    assert!(!proxy_url_has_credentials(
        "http://127.0.0.1:8080/path@segment"
    ));
    assert!(!proxy_url_has_credentials("http://127.0.0.1:8080/?q=a@b"));
    assert!(!proxy_url_has_credentials("http://127.0.0.1:8080/#a@b"));
}

// The case that rules out defining this predicate as "redaction changes the
// string": userinfo that is already the redaction marker redacts to itself, so
// a comparison-based implementation reports a credential-bearing URL as clean.
#[test]
fn userinfo_that_looks_like_the_redaction_marker_still_carries_credentials() {
    let url = "http://***@proxy.example.com:8080";

    assert_eq!(
        redact_proxy_url(url),
        url,
        "precondition: redaction leaves this URL unchanged"
    );
    assert!(
        proxy_url_has_credentials(url),
        "the predicate must not be defined as `redact_proxy_url(url) != url`"
    );
}

// A string with no scheme separator has no authority to parse, so there is no
// userinfo to find and the guard must not refuse it on a spurious match.
#[test]
fn a_url_without_a_scheme_carries_no_credentials() {
    assert!(!proxy_url_has_credentials("proxy.example.com:8080"));
    assert!(!proxy_url_has_credentials("not-a-url@at-all"));
}
