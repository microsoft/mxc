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

use url::Url;
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

// Parseability is not safety.  Nothing downstream re-parses the value:
// `ProxyAddress::from_url` stores it verbatim, `to_url` returns it verbatim,
// and it lands in `lxc-attach` argv as written -- so a string with no scheme
// separator still carries whatever userinfo it appears to.
//
// The decisive shape is a bearer token used as the sole userinfo --
// `token@proxy.example.com` has no colon and no scheme, so a predicate that
// gives up without a scheme reports a live secret as clean.  Every
// password-bearing form does contain a colon, which is what makes a
// colon-driven predicate look safe.
//
// A port colon is not a scheme separator either, and the guard must not fire
// on one.  Both halves are asserted here.
#[test]
fn a_port_colon_is_not_userinfo_but_a_schemeless_token_is() {
    assert!(
        !proxy_url_has_credentials("proxy.example.com:8080"),
        "a port colon must not be mistaken for userinfo"
    );
    assert!(
        !proxy_url_has_credentials("not-a-url-at-all"),
        "a schemeless string with no `@` carries nothing"
    );
    assert!(
        proxy_url_has_credentials("not-a-url@at-all"),
        "an `@` ahead of the path is userinfo even with no scheme to anchor it"
    );
}

// Protects client (d): a proxy URL is redacted on the *failure* path, where it
// may not be a well-formed absolute URL.  `url::Url::parse` accepts
// `alice:hunter2@example.com` as scheme `alice`, so a redactor that gives up
// without `://` hands the password straight to the scheme diagnostic.
#[test]
fn redact_proxy_url_removes_userinfo_from_a_scheme_opaque_url() {
    let redacted = redact_proxy_url("alice:hunter2@proxy.example.com");

    assert!(
        !redacted.contains("hunter2"),
        "password survived: {redacted}"
    );
    assert!(
        redacted.contains("proxy.example.com"),
        "the host must survive so the error still diagnoses anything: {redacted}"
    );
}

// The complement: a string with no userinfo and no `://` must come back intact,
// or the redactor would corrupt ordinary diagnostics.
#[test]
fn redact_proxy_url_leaves_a_scheme_opaque_url_without_userinfo_alone() {
    let input = "socks5:proxy.example.com";

    assert_eq!(redact_proxy_url(input), input);
}

// `url::Url::parse` accepts `scheme:rest`, `ProxyAddress::from_url` is public
// and stores whatever string it is handed, and `to_url` returns it verbatim --
// so this shape reaches `--set-var` in `lxc-attach` argv, and argv is
// world-readable through /proc/<pid>/cmdline.  Redaction and the guard share
// one parse, so neither can treat this form as credential-free while the
// other hides it.
#[test]
fn a_scheme_opaque_url_with_userinfo_carries_credentials() {
    assert!(
        proxy_url_has_credentials("http:alice:hunter2@proxy.example.com"),
        "the opaque scheme:rest form hides userinfo from a `://`-only parser"
    );
}

#[test]
fn a_scheme_opaque_url_with_a_bare_username_carries_credentials() {
    assert!(
        proxy_url_has_credentials("http:alice@proxy.example.com"),
        "userinfo without a password is still userinfo"
    );
}

// The complement, so the fix cannot be "return true more often".  A port colon
// must not be mistaken for the opaque scheme separator.
#[test]
fn a_scheme_opaque_url_without_userinfo_carries_no_credentials() {
    assert!(
        !proxy_url_has_credentials("socks5:proxy.example.com"),
        "an opaque URL with no `@` carries nothing"
    );
    assert!(
        !proxy_url_has_credentials("proxy.example.com:8080"),
        "a port colon is not userinfo"
    );
}

// An `@` after the path delimiter belongs to the path, in the opaque form just
// as in the absolute one.
#[test]
fn an_at_sign_in_the_path_of_an_opaque_url_is_not_userinfo() {
    assert!(
        !proxy_url_has_credentials("http:proxy.example.com/a@b"),
        "an `@` after the path delimiter is not userinfo"
    );
}

// A value with no scheme at all reaches no legitimate proxy path, but the guard
// is the last line before argv, so it fails closed rather than reasoning about
// where a malformed value ends up.
#[test]
fn a_schemeless_value_with_userinfo_fails_closed() {
    assert!(
        proxy_url_has_credentials("alice@proxy.example.com"),
        "a schemeless value carrying userinfo must not be reported as clean"
    );
}

// The two functions must agree about what an authority is.  Disagreeing about
// it is the whole defect: redaction handled the opaque form while the guard
// called the same string clean.
#[test]
fn redaction_and_the_credential_guard_agree_on_every_shape() {
    let bearing = [
        "http://alice:hunter2@proxy.example.com:8080",
        "http:alice:hunter2@proxy.example.com",
        "https://alice@proxy.example.com",
        "http:alice@proxy.example.com",
    ];
    for url in bearing {
        assert!(
            proxy_url_has_credentials(url),
            "guard reported no credentials for {url}"
        );
        assert_ne!(
            redact_proxy_url(url),
            url,
            "redaction left {url} unchanged while the guard flagged it"
        );
        assert!(
            !redact_proxy_url(url).contains("hunter2"),
            "password survived redaction of {url}"
        );
    }

    let clean = [
        "http://proxy.example.com:8080",
        "socks5:proxy.example.com",
        "http://proxy.example.com/a@b",
    ];
    for url in clean {
        assert!(
            !proxy_url_has_credentials(url),
            "guard invented credentials in {url}"
        );
        assert_eq!(
            redact_proxy_url(url),
            url,
            "redaction altered the credential-free {url}"
        );
    }
}

// A *special* scheme (http, https, and the rest of the WHATWG set) treats one
// slash exactly as it treats two, so this is the credentialed URL
// `http://alice:hunter2@proxy.example.com:3128/` however plainly it reads as a
// path. Anchoring the authority on `://` skipped straight past it.
#[test]
fn a_single_slash_after_the_scheme_still_introduces_an_authority() {
    let url = "http:/alice:hunter2@proxy.example.com:3128";

    assert!(
        proxy_url_has_credentials(url),
        "the one-slash form carries credentials"
    );
    assert!(
        !redact_proxy_url(url).contains("hunter2"),
        "password survived redaction of {url}"
    );
}

#[test]
fn any_run_of_slashes_after_the_scheme_introduces_an_authority() {
    for url in [
        "http:///alice:hunter2@proxy.example.com",
        "http:////alice:hunter2@proxy.example.com",
    ] {
        assert!(proxy_url_has_credentials(url), "{url} carries credentials");
        assert!(
            !redact_proxy_url(url).contains("hunter2"),
            "password survived redaction of {url}"
        );
    }
}

// The redaction has to reassemble the URL in the form it arrived in, or the
// message names a URL the operator never wrote.
#[test]
fn redaction_preserves_the_separator_it_was_given() {
    assert_eq!(
        redact_proxy_url("http://alice:hunter2@proxy.example.com"),
        "http://***@proxy.example.com"
    );
    assert_eq!(
        redact_proxy_url("http:/alice:hunter2@proxy.example.com"),
        "http:/***@proxy.example.com"
    );
    assert_eq!(
        redact_proxy_url("http:alice:hunter2@proxy.example.com"),
        "http:***@proxy.example.com"
    );
}

// A bearer token used as sole userinfo has no colon and so no scheme to anchor
// on. The guard already refused it, but redaction returned it unchanged -- so
// the rejection message printed the very secret it was refusing.
#[test]
fn a_schemeless_value_with_userinfo_is_redacted_as_well_as_refused() {
    let url = "token@proxy.example.com";

    assert!(proxy_url_has_credentials(url), "{url} carries a credential");
    assert_eq!(redact_proxy_url(url), "***@proxy.example.com");
}

// Empty userinfo names no user and no password. Refusing it would reject a
// configuration that leaks nothing, and redacting it would invent a secret.
//
// Only `""` and `":"` are empty. `"::"` is not: the *first* colon separates the
// username from the password, so the second one is the password's own value.
// Measured against the parser, `http://::@host` yields `password = Some("%3A")`
// while `http://:@host` yields `None`, which is where the boundary sits.
#[test]
fn empty_userinfo_is_not_a_credential() {
    for url in [
        "http://@proxy.example.com:3128",
        "http://:@proxy.example.com:3128",
    ] {
        assert!(
            !proxy_url_has_credentials(url),
            "{url} names neither a user nor a password"
        );
        assert_eq!(redact_proxy_url(url), url, "nothing to redact in {url}");
    }
}

// The boundary case that the all-colons rule got wrong. A password made of
// colons carries little, but the guard's whole job is to agree with the parser
// about what the userinfo is, and disagreeing here is how it disagreed
// everywhere else.
#[test]
fn a_second_colon_in_the_userinfo_is_a_password_not_emptiness() {
    for url in [
        "http://::@proxy.example.com:3128",
        "http://:::@proxy.example.com:3128",
    ] {
        let parsed = Url::parse(url).expect("corpus entry should parse");
        assert!(
            parsed.password().is_some(),
            "the parser should see a password in {url}"
        );
        assert!(
            proxy_url_has_credentials(url),
            "{url} carries a password the guard missed"
        );
        assert!(
            !redact_proxy_url(url).contains("::@"),
            "the userinfo survived redaction in {url}"
        );
    }
}

// The omitted half is the dangerous half to get wrong: a password with no
// username is still a password, and a username with no password is how a
// bearer token is passed.
#[test]
fn a_single_userinfo_component_is_a_credential() {
    for url in [
        "http://:hunter2@proxy.example.com",
        "http://token@proxy.example.com",
    ] {
        assert!(proxy_url_has_credentials(url), "{url} carries a credential");
        assert_ne!(
            redact_proxy_url(url),
            url,
            "redaction left {url} unchanged while the guard flagged it"
        );
    }
}

// The two functions are only safe while they cannot disagree, and the pairs
// below are exactly the shapes on which they historically did.
#[test]
fn the_guard_and_the_redaction_never_disagree_on_the_shapes_that_broke_them() {
    let shapes = [
        "http://alice:hunter2@proxy.example.com",
        "http:alice:hunter2@proxy.example.com",
        "http:/alice:hunter2@proxy.example.com",
        "token@proxy.example.com",
        "alice@proxy.example.com:3128",
        ":hunter2@proxy.example.com:3128",
        "http://@proxy.example.com",
        "http://:@proxy.example.com",
        "http://proxy.example.com:8080",
        "proxy.example.com:8080",
        "http://proxy.example.com/a@b",
        "socks5:proxy.example.com",
    ];

    for url in shapes {
        let flagged = proxy_url_has_credentials(url);
        let redacted = redact_proxy_url(url) != url;
        assert_eq!(
            flagged, redacted,
            "guard said {flagged} and redaction said {redacted} for {url}"
        );
    }
}

// A colon is not proof of a scheme. When it separates a port instead, taking
// every character before it as the scheme would read the authority of
// `alice@proxy.example.com:3128` as the bare port `3128`, which carries no
// `@` -- leaving the username neither flagged nor hidden while it still
// reaches `lxc-attach` argv.
#[test]
fn a_schemeless_host_and_port_still_shows_its_userinfo() {
    assert!(
        proxy_url_has_credentials("alice@proxy.example.com:3128"),
        "a username before a host:port is a credential"
    );
    assert_eq!(
        redact_proxy_url("alice@proxy.example.com:3128"),
        "***@proxy.example.com:3128",
        "the username must not survive redaction"
    );
}

#[test]
fn a_schemeless_password_before_a_port_is_a_credential() {
    assert!(proxy_url_has_credentials(":hunter2@proxy.example.com:3128"));
    assert!(
        !redact_proxy_url(":hunter2@proxy.example.com:3128").contains("hunter2"),
        "the password must not survive redaction"
    );
}

// The prefix of a bare `host:port` does satisfy the scheme grammar, and that
// has to stay harmless: it leaves the port as the authority, which carries no
// credential either way. This is the invariant the fix above could have broken.
#[test]
fn a_bare_host_and_port_is_still_not_a_credential() {
    assert!(!proxy_url_has_credentials("proxy.example.com:8080"));
    assert_eq!(
        redact_proxy_url("proxy.example.com:8080"),
        "proxy.example.com:8080"
    );
}

// A prefix that fails the grammar for a reason other than `@` must not start
// being treated as an authority in a way that invents a credential.
#[test]
fn a_prefix_that_is_not_a_scheme_does_not_invent_a_credential() {
    for url in [
        "1http://proxy.example.com",
        "pro xy:8080",
        ":3128",
        "proxy_host:8080",
    ] {
        assert!(
            !proxy_url_has_credentials(url),
            "{url} names no user and no password"
        );
    }
}

// `url::Url::parse` follows WHATWG and ignores leading and trailing C0
// controls and spaces, and strips tab, newline, and carriage return from
// anywhere in the value -- but `ProxyAddress::from_url` stores the string it
// was given. A guard that reads the raw bytes therefore judges a different
// URL from the one the rest of the system acts on.
#[test]
fn whitespace_around_a_credentialed_url_does_not_hide_it() {
    for (name, url) in [
        (
            "leading space",
            " http://alice:hunter2@proxy.example.com:3128",
        ),
        (
            "leading tab",
            "\thttp://alice:hunter2@proxy.example.com:3128",
        ),
        (
            "leading newline",
            "\nhttp://alice:hunter2@proxy.example.com:3128",
        ),
        (
            "leading crlf",
            "\r\nhttp://alice:hunter2@proxy.example.com:3128",
        ),
        (
            "trailing space",
            "http://alice:hunter2@proxy.example.com:3128 ",
        ),
        (
            "interior tab",
            "ht\ttp://alice:hunter2@proxy.example.com:3128",
        ),
    ] {
        assert!(
            proxy_url_has_credentials(url),
            "{name}: the credential is still there once the parser is done with it"
        );
        assert!(
            !redact_proxy_url(url).contains("hunter2"),
            "{name}: redaction left the password in place"
        );
    }
}

// Whitespace must not invent a credential either.
#[test]
fn whitespace_around_a_clean_url_stays_clean() {
    for url in [
        " http://proxy.example.com:3128",
        "http://proxy.example.com:3128\n",
        "\tproxy.example.com:8080",
    ] {
        assert!(
            !proxy_url_has_credentials(url),
            "{url:?} names no user and no password"
        );
    }
}

// The guard exists to agree with the parser that actually consumes this URL.
// Every bypass has one shape -- the guard reads one string and `lxc-attach`
// receives another -- so the assertion is differential:
// wherever `url::Url::parse` finds userinfo, the guard must find it too, and
// wherever the parser finds none, the guard must not invent one. `url` is the
// crate `ProxyAddress` itself parses with, so it is the oracle rather than a
// second opinion.
//
// The corpus is *generated* rather than listed. A hand-written list has to
// name every shape in advance, and the easily-missed ones are real: the
// backslash authority introducer, and `::@`, where the second colon is a
// password rather than more emptiness. Crossing the dimensions instead makes
// coverage a property of the dimensions, so a gap has to be a missing
// *dimension* rather than a missing example.
fn differential_corpus() -> Vec<String> {
    let schemes = [
        "http",
        "https",
        "HTTP",
        "ftp",
        "ws",
        "socks5",
        "weird-scheme",
    ];
    let separators = ["://", ":/", ":", ":\\/", ":/\\", ":\\\\", "//"];
    let userinfos = [
        "",
        "@",
        ":@",
        "::@",
        ":::@",
        "alice@",
        ":hunter2@",
        "alice:hunter2@",
        "alice:@",
        "***@",
        "a%40b:c@",
        "alice:hun%20ter2@",
    ];
    let hosts = ["10.0.3.1:3128", "proxy.example.com", "[::1]:3128"];
    let tails = ["", "/path", "/p@th", "?q=a@b", "#f@g"];
    let paddings = ["", " ", "\t", "\n", "\r"];

    let mut corpus = Vec::new();
    for scheme in schemes {
        for separator in separators {
            for userinfo in userinfos {
                for host in hosts {
                    for tail in tails {
                        let body = format!("{scheme}{separator}{userinfo}{host}{tail}");
                        for padding in paddings {
                            corpus.push(format!("{padding}{body}"));
                            corpus.push(format!("{body}{padding}"));
                        }
                    }
                }
            }
        }
    }
    corpus
}

#[test]
fn the_guard_agrees_with_the_parser_that_will_actually_read_the_url() {
    let mut missed = Vec::new();
    let mut invented = Vec::new();
    let mut compared = 0usize;

    for raw in differential_corpus() {
        // The parser is only an oracle for inputs it accepts. Where it refuses
        // outright, nothing reaches `lxc-attach` and there is no credential to
        // leak, so it has no verdict to compare against.
        let Ok(parsed) = Url::parse(&raw) else {
            continue;
        };
        compared += 1;

        let parser_sees = !parsed.username().is_empty() || parsed.password().is_some();
        let guard_sees = proxy_url_has_credentials(&raw);

        if parser_sees && !guard_sees {
            missed.push(format!(
                "  MISSED: parser found user={:?} pass={:?}, guard found none, in bytes {:?}",
                parsed.username(),
                parsed.password(),
                raw.as_bytes()
            ));
        }

        // Over-reporting and under-reporting do not cost the same, so they are
        // not held to the same standard. A miss puts a password into argv and
        // into the error text meant to hide it. An over-report rejects a
        // config -- bad, since the caller destroys the container, but not a
        // disclosure. So the guard is allowed to fire on any string carrying an
        // `@`, since that is the only character that can introduce userinfo and
        // its presence makes suspicion defensible. What the guard may never do
        // is claim a credential in a string with no `@` anywhere, which would
        // be an invention rather than caution.
        if !parser_sees && guard_sees && !raw.contains('@') {
            invented.push(format!(
                "  INVENTED: guard claimed a credential with no `@` anywhere, in bytes {:?}",
                raw.as_bytes()
            ));
        }
    }

    assert!(
        compared > 500,
        "the corpus degenerated: only {compared} inputs parsed"
    );
    assert!(
        missed.is_empty() && invented.is_empty(),
        "the guard disagreed with the parser on {} of {compared} parseable inputs:\n{}\n{}",
        missed.len() + invented.len(),
        missed.join("\n"),
        invented.join("\n")
    );
}

// The fifth bypass, and the second one a differential test caught rather than
// a guess. WHATWG treats a backslash as a slash for the special schemes, so
// `http:\/alice:hunter2@host` introduces an authority exactly as `http://`
// does. Counting only forward slashes left the authority as the single
// character `\`, which carries no `@`, so the guard reported no credentials
// and the redaction returned the password verbatim.
#[test]
fn a_backslash_introduces_an_authority_for_the_special_schemes() {
    let bypasses = [
        "http:\\/alice:hunter2@10.0.3.1:3128",
        "http:/\\alice:hunter2@10.0.3.1:3128",
        "http:\\\\alice:hunter2@10.0.3.1:3128",
        "https:\\/alice:hunter2@10.0.3.1:3128",
        "HTTP:\\/alice:hunter2@10.0.3.1:3128",
    ];

    for url in bypasses {
        assert!(
            proxy_url_has_credentials(url),
            "a backslash hid the credentials in {:?} (bytes {:?})",
            url,
            url.as_bytes()
        );
        assert!(
            !redact_proxy_url(url).contains("hunter2"),
            "the redaction returned the password for {url:?}"
        );
    }
}

// The equivalence belongs to the special schemes only, which is what keeps the
// guard from rejecting proxies that leak nothing. A backslash after a
// non-special scheme is an opaque path to the parser, not an authority.
#[test]
fn a_backslash_still_ends_an_authority_it_does_not_only_begin_one() {
    // The authority ends at the backslash, so the `@` belongs to the path and
    // names no credential -- exactly as the parser reads it.
    assert!(!proxy_url_has_credentials(
        "http://10.0.3.1:3128\\path@notuserinfo"
    ));
    assert_eq!(
        redact_proxy_url("http://10.0.3.1:3128\\path@notuserinfo"),
        "http://10.0.3.1:3128\\path@notuserinfo"
    );
}

// The backslash equivalence is applied to every scheme, not only the special
// ones, and that is a deliberate divergence from the parser.  The parser reads
// `socks5:\/alice:hunter2@host` as an opaque path -- measured directly, it
// reports `cannot_be_a_base = true`, an empty username, and no host -- so by
// its rules there is no credential.  But the password is still sitting in the
// string, and that string reaches argv and the failure diagnostic.  The two
// ways of being wrong do not cost the same: over-reporting rejects a config,
// under-reporting publishes a password.  So the guard is allowed to be more
// suspicious than the parser here, and the redactor has to strip it.
#[test]
fn a_backslash_does_not_hide_a_credential_behind_an_unusual_scheme() {
    let opaque = "socks5:\\/alice:hunter2@10.0.3.1:1080";

    let parsed = Url::parse(opaque).expect("the parser accepts it as an opaque path");
    assert!(
        parsed.username().is_empty() && parsed.password().is_none(),
        "the parser is supposed to see no userinfo here -- that is the whole point"
    );

    assert!(
        proxy_url_has_credentials(opaque),
        "the password is in the string and reaches argv, so the guard must fire"
    );
    let redacted = redact_proxy_url(opaque);
    assert!(
        !redacted.contains("hunter2"),
        "password survived redaction: {redacted}"
    );
    assert!(
        redacted.contains("10.0.3.1"),
        "the host must survive so the error still diagnoses something: {redacted}"
    );

    // The ordinary `//` form of the same scheme is an authority by anyone's
    // reading, and it carries a credential too.
    assert!(proxy_url_has_credentials(
        "socks5://alice:hunter2@10.0.3.1:1080"
    ));
}
