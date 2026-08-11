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
use std::borrow::Cow;

/// Proxy-related env var keys that are *scrubbed* from caller-supplied env so
/// a sandboxed process cannot override or disable the cooperative proxy.
///
/// Both spellings of every family are listed. Matching goes through
/// [`is_managed_proxy_key`], which is case-insensitive, so the lower-case
/// entries are redundant for that path; they are kept so a consumer that
/// iterates or does a case-sensitive `contains` over this slice still sees the
/// whole set.
pub const PROXY_ENV_KEYS: &[&str] = &[
    "HTTP_PROXY",
    "HTTPS_PROXY",
    "ALL_PROXY",
    "FTP_PROXY",
    "http_proxy",
    "https_proxy",
    "all_proxy",
    "ftp_proxy",
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
///
/// Handles the malformed input a diagnostic actually sees: a proxy URL is
/// redacted on the failure path, where it may not be a well-formed absolute
/// URL. `scheme:opaque` is redacted too, since `url::Url::parse` accepts it and
/// the resulting error message would otherwise carry the password.
///
/// When the value carries a credential the *normalized* form is returned, not
/// the original, so the whitespace a URL parser ignores cannot be used to smuggle
/// the secret through the redaction. When it carries none the input is returned
/// untouched.
pub fn redact_proxy_url(url: &str) -> String {
    let normalized = normalize_as_the_url_parser_does(url);
    let parts = split_proxy_authority(&normalized);
    match credential_userinfo(parts.authority) {
        Some((_userinfo, host)) => format!(
            "{}{}***@{}{}",
            parts.scheme, parts.separator, host, parts.tail
        ),
        None => url.to_string(),
    }
}

/// Drop the characters `url::Url::parse` ignores, so this module judges the
/// same URL the rest of the system acts on.
///
/// WHATWG strips leading and trailing C0 controls and spaces, and removes tab,
/// newline, and carriage return from anywhere in the input. `ProxyAddress::from_url`
/// stores the string it was given and `to_url` returns it verbatim, so without
/// this the guard read one URL while `lxc-attach` received another:
/// `" http://alice:hunter2@host"` has no recognizable scheme once the leading
/// space is counted, so the authority stopped at the first `/` of `//` and the
/// `@` after it was never seen. The guard reported no credentials and redaction
/// returned the password verbatim.
fn normalize_as_the_url_parser_does(url: &str) -> Cow<'_, str> {
    let is_trimmed = |c: char| c <= ' ';
    if url.contains(['\t', '\n', '\r']) {
        Cow::Owned(
            url.chars()
                .filter(|c| !matches!(c, '\t' | '\n' | '\r'))
                .collect::<String>()
                .trim_matches(is_trimmed)
                .to_string(),
        )
    } else {
        Cow::Borrowed(url.trim_matches(is_trimmed))
    }
}

/// The pieces of a proxy URL that userinfo handling needs.
struct ProxyAuthority<'a> {
    scheme: &'a str,
    /// Whichever separator followed the scheme -- `:`, `://`, or the `:/` that
    /// a special scheme also accepts -- so a redaction can be reassembled in
    /// the same form it arrived in.
    separator: &'a str,
    /// Everything between the separator and the first path, query, or fragment
    /// delimiter. An `@` after that point belongs to the path, not to userinfo.
    authority: &'a str,
    tail: &'a str,
}

/// Split `url` into scheme, separator, authority, and tail.
///
/// Every form is recognized deliberately, because [`ProxyAddress::from_url`]
/// stores whatever string it is given and [`ProxyAddress::to_url`] returns it
/// verbatim, so anything that parses somewhere downstream reaches the same
/// places a well-formed URL does.
///
/// * `scheme://authority` -- the ordinary form.
/// * `scheme:authority` -- `url::Url::parse` accepts the opaque form, and
///   `alice:hunter2@example.com` parses with scheme `alice`.
/// * `scheme:/authority` -- for a *special* scheme (`http`, `https`, and the
///   rest of the WHATWG set) one slash introduces an authority exactly as two
///   do, so `http:/alice:hunter2@example.com` is the credentialed URL
///   `http://alice:hunter2@example.com/`. Any run of leading slashes is
///   therefore part of the separator rather than the start of a path.
/// * no scheme at all -- the whole value is treated as an authority. Nothing
///   downstream should accept it as a proxy URL, but the point here is not to
///   decide that; it is that a bearer token used as sole userinfo,
///   `token@proxy.example.com`, carries no colon and would otherwise be both
///   unflagged and unredacted.
///
/// A colon alone does not make a scheme: the prefix has to satisfy
/// [`is_uri_scheme`], or the colon is a port separator and the whole value is
/// the authority. `alice@proxy.example.com:3128` is that case.
///
/// This is the single parse shared by [`redact_proxy_url`] and
/// [`proxy_url_has_credentials`]. They previously had one each, which is how
/// they came to disagree: redaction handled the opaque form while the guard
/// reported it as carrying no credentials. It is total rather than fallible
/// for the same reason -- an input only one of them could parse is an input
/// they can differ on.
fn split_proxy_authority(url: &str) -> ProxyAuthority<'_> {
    let (scheme, after_scheme) = match url.find(':') {
        Some(colon) if is_uri_scheme(&url[..colon]) => url.split_at(colon),
        _ => (&url[..0], url),
    };
    let slashes = after_scheme
        .strip_prefix(':')
        .map(|rest| 1 + (rest.len() - rest.trim_start_matches('/').len()))
        .unwrap_or(0);
    let (separator, rest) = after_scheme.split_at(slashes);
    let auth_end = rest.find(['/', '?', '#']).unwrap_or(rest.len());
    let (authority, tail) = rest.split_at(auth_end);
    ProxyAuthority {
        scheme,
        separator,
        authority,
        tail,
    }
}

/// Whether `candidate` satisfies the RFC 3986 scheme grammar,
/// `ALPHA *( ALPHA / DIGIT / "+" / "-" / "." )`.
///
/// Everything before the first colon used to be taken for a scheme on sight,
/// which is wrong whenever the colon is a *port* separator instead. In
/// `alice@proxy.example.com:3128` that read the scheme as
/// `alice@proxy.example.com` and the authority as `3128`; an authority of
/// `3128` carries no `@`, so the guard reported no credentials and redaction
/// returned the string untouched, while the username still reached
/// `lxc-attach` argv.
///
/// `@` is not in the grammar and a prefix carrying userinfo always contains
/// one, so refusing non-schemes is what sends the whole value through as an
/// authority -- where the `@` is found. A hostname alone still satisfies the
/// grammar (`proxy.example.com` is ALPHA and `.`), and that is harmless: it
/// leaves the authority as the bare port, which carries no credential either
/// way.
fn is_uri_scheme(candidate: &str) -> bool {
    let mut chars = candidate.chars();
    if !chars
        .next()
        .is_some_and(|first| first.is_ascii_alphabetic())
    {
        return false;
    }
    chars.all(|c| c.is_ascii_alphanumeric() || c == '+' || c == '-' || c == '.')
}

/// The userinfo an authority carries, split from its host, or `None` when it
/// carries none worth hiding.
///
/// Empty userinfo is not a credential: `http://@proxy.example.com` and
/// `http://:@proxy.example.com` name neither a user nor a password, and
/// refusing them would reject a configuration that leaks nothing. A single
/// component *is* one, though -- `http://token@proxy.example.com` is how a
/// bearer token is passed, and `http://:secret@proxy.example.com` is a
/// password with the username omitted -- so anything other than colons counts.
///
/// Sharing this between the two public functions is what makes them unable to
/// disagree about a given string.
fn credential_userinfo(authority: &str) -> Option<(&str, &str)> {
    let (userinfo, host) = authority.rsplit_once('@')?;
    if userinfo.chars().all(|c| c == ':') {
        return None;
    }
    Some((userinfo, host))
}

/// Whether a proxy URL carries `user:pass@` userinfo.
///
/// This is the single definition of "carries credentials", so a backend that
/// must refuse such a URL and the config parser that rejects it up front
/// cannot drift apart.
///
/// It deliberately does not ask whether [`redact_proxy_url`] changes the
/// string. That answers a different question — how to render a URL safely —
/// and returns the input unchanged when the userinfo is already the literal
/// redaction marker, which would report a credential-bearing URL as clean.
pub fn proxy_url_has_credentials(url: &str) -> bool {
    let normalized = normalize_as_the_url_parser_does(url);
    credential_userinfo(split_proxy_authority(&normalized).authority).is_some()
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
/// This is the LXC entry point. It delegates to [`apply_cooperative_proxy_env`]
/// so LXC scrubs and sets exactly the same key set as Bubblewrap and WSLc,
/// rather than maintaining a parallel list that can drift.
///
/// `env` uses the `ExecutionRequest::env` representation: `KEY=VALUE` strings.
/// An entry with no `=` is treated as a bare key, so a valueless `HTTP_PROXY`
/// is still scrubbed.
///
/// Returns whether the caller must force a clean environment. This is always
/// `true`, including when `env` ends up empty: the return value tells the
/// caller to emit `--clear-env`, and an empty vector must still stop
/// `lxc-attach` inheriting the MXC host process environment, which carries
/// both proxy vars and credentials.
pub fn apply_proxy_env(env: &mut Vec<String>, proxy: &ProxyConfig) -> bool {
    if let Some(address) = &proxy.address {
        *env = apply_cooperative_proxy_env(env, &address.to_url());
        return true;
    }

    // With the proxy disabled the vars are still stripped, so a caller cannot
    // point the sandbox at an egress path the policy never authorized.
    env.retain(|entry| !is_managed_proxy_key(env_key(entry)));
    true
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
}
