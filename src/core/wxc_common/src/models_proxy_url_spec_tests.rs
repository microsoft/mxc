//! Spec-derived tests for `ProxyAddress::rewrite_url_host`.
//! Written from the documented contract and the review that produced the fix.
//!
//! Primary contract source: doc comment on `rewrite_url_host`:
//!   "Replace the host of `raw` with `ip`, preserving scheme, credentials,
//!    port and path. Returns `None` when `raw` is not a parseable URL or the
//!    host cannot be replaced."
//!
//! Additional requirement (sourced from PR #632 review by Soham, NOT from the
//! doc comment):  a URL carrying a query string and/or a fragment must survive
//! the rewrite intact.  The doc comment is silent on query and fragment —
//! that silence is reported under CONTRACT GAPS below.

use super::*;

// ─── Helper ──────────────────────────────────────────────────────────────────

/// Assert that `result` is `Some`, that it contains `new_ip`, that it does NOT
/// contain `old_host`, and that every non-host component in `expected_parts`
/// is still present.  Also compare against the full `expected` string so that
/// failures are legible.
fn assert_rewrite(
    input: &str,
    new_ip: &str,
    old_host: &str,
    expected_parts: &[&str],
    expected: &str,
) {
    let result = ProxyAddress::rewrite_url_host(input, new_ip);
    assert!(
        result.is_some(),
        "input={input:?} new_ip={new_ip:?} — expected Some(..), got None"
    );
    let out = result.unwrap();
    assert_eq!(
        out, expected,
        "input={input:?} new_ip={new_ip:?} — full output mismatch"
    );
    assert!(
        out.contains(new_ip),
        "input={input:?} — output {out:?} does not contain new ip {new_ip:?}"
    );
    assert!(
        !out.contains(old_host),
        "input={input:?} — output {out:?} still contains old host {old_host:?}"
    );
    for part in expected_parts {
        assert!(
            out.contains(part),
            "input={input:?} — output {out:?} is missing component {part:?}"
        );
    }
}

// ─── Plain http://host:port/path ─────────────────────────────────────────────

#[test]
fn a_plain_url_with_port_and_path_rewrites_the_host() {
    // Contract: "preserving scheme, credentials, port and path"
    assert_rewrite(
        "http://original.host:3128/some/path",
        "192.168.1.5",
        "original.host",
        &["http://", ":3128", "/some/path"],
        "http://192.168.1.5:3128/some/path",
    );
}

#[test]
fn a_url_without_a_path_rewrites_the_host() {
    // Contract: path preservation; no path edge case.
    assert_rewrite(
        "http://proxy.example.com:8080",
        "10.0.0.1",
        "proxy.example.com",
        &["http://", ":8080"],
        "http://10.0.0.1:8080",
    );
}

#[test]
fn a_url_without_a_port_rewrites_the_host() {
    // Contract: "preserving … port" — absence of a port must also be preserved.
    assert_rewrite(
        "http://proxy.example.com/path",
        "10.0.0.2",
        "proxy.example.com",
        &["http://", "/path"],
        "http://10.0.0.2/path",
    );
    // Must not insert a spurious port: the only colon in the output is in "http:"
    let out = ProxyAddress::rewrite_url_host("http://proxy.example.com/path", "10.0.0.2").unwrap();
    let after_scheme = out.trim_start_matches("http://");
    assert!(
        !after_scheme.contains(':'),
        "output {out:?} must not contain a port-colon when no port was present in input"
    );
}

// ─── Query string ─────────────────────────────────────────────────────────────
// Requirement sourced from PR #632 review (Soham), NOT from the doc comment.
// The prior pop()-based implementation corrupted query strings.

#[test]
fn a_query_string_survives_the_host_rewrite() {
    // Review requirement: query string must survive intact.
    assert_rewrite(
        "http://proxy.example.com:3128/path?a=1&b=2",
        "192.0.2.1",
        "proxy.example.com",
        &["http://", ":3128", "/path", "?a=1&b=2"],
        "http://192.0.2.1:3128/path?a=1&b=2",
    );
}

#[test]
fn a_query_string_without_a_path_survives_the_host_rewrite() {
    // Review requirement: query string must survive even with no explicit path.
    // Note: URL normalization may insert a "/" before the "?" — the expected
    // string accounts for this; the invariant assertion (query present, old
    // host absent) is the binding requirement.
    let input = "http://proxy.example.com:3128?token=abc";
    let new_ip = "192.0.2.1";
    let result = ProxyAddress::rewrite_url_host(input, new_ip);
    assert!(
        result.is_some(),
        "input={input:?} — expected Some(..), got None"
    );
    let out = result.unwrap();
    assert!(
        out.contains("?token=abc"),
        "input={input:?} — query string must survive; output was {out:?}"
    );
    assert!(
        out.contains(new_ip),
        "input={input:?} — output {out:?} does not contain new ip {new_ip:?}"
    );
    assert!(
        !out.contains("proxy.example.com"),
        "input={input:?} — output {out:?} still contains old host"
    );
    assert!(
        out.contains(":3128"),
        "input={input:?} — port must survive; output was {out:?}"
    );
}

// ─── Fragment ────────────────────────────────────────────────────────────────
// Requirement sourced from PR #632 review (Soham), NOT from the doc comment.

#[test]
fn a_fragment_survives_the_host_rewrite() {
    // Review requirement: fragment must survive intact.
    assert_rewrite(
        "http://proxy.example.com:3128/page#section",
        "192.0.2.2",
        "proxy.example.com",
        &["http://", ":3128", "/page", "#section"],
        "http://192.0.2.2:3128/page#section",
    );
}

#[test]
fn both_a_query_string_and_a_fragment_survive_the_host_rewrite() {
    // Review requirement: both must survive together — the pop()-based bug
    // corrupted whichever appeared last.
    assert_rewrite(
        "http://proxy.example.com:3128/path?q=1#anchor",
        "192.0.2.3",
        "proxy.example.com",
        &["http://", ":3128", "/path", "?q=1", "#anchor"],
        "http://192.0.2.3:3128/path?q=1#anchor",
    );
}

// ─── Credentials ─────────────────────────────────────────────────────────────

#[test]
fn credentials_survive_the_host_rewrite() {
    // Contract: "preserving scheme, credentials, port and path"
    assert_rewrite(
        "http://user:pass@proxy.example.com:3128/",
        "172.16.0.1",
        "proxy.example.com",
        &["http://", "user:pass@", ":3128", "/"],
        "http://user:pass@172.16.0.1:3128/",
    );
}

// ─── None cases ──────────────────────────────────────────────────────────────

#[test]
fn an_unparseable_input_returns_none() {
    // Contract: "Returns `None` when `raw` is not a parseable URL"
    let result = ProxyAddress::rewrite_url_host("not a url at all !!!!", "192.0.2.9");
    assert!(
        result.is_none(),
        "input='not a url at all !!!!' — expected None for unparseable input, got {result:?}"
    );
}

// ─── Characterization tests for contract-silent cases ────────────────────────
// These record the *observed* behavior of a live, deterministic implementation.
// The contract is silent on each case — so these are not required guarantees,
// but they ARE live assertions.  A change to either behavior must be a
// conscious decision, not a silent drift.  See CONTRACT GAPS in the report.

#[test]
fn an_empty_host_url_rewrites_the_host() {
    // Contract gap: contract says "None when host cannot be replaced", but does
    // not define whether an empty-host URL qualifies.  Observed: the url crate
    // treats an empty authority host as replaceable, so the implementation
    // returns Some and fills in the new IP.  Pin that behavior.
    let result = ProxyAddress::rewrite_url_host("file:///etc/passwd", "192.0.2.10");
    assert_eq!(
        result,
        Some("file://192.0.2.10/etc/passwd".to_string()),
        "input='file:///etc/passwd' ip='192.0.2.10' — \
         implementation currently fills the empty authority; pin to detect changes"
    );
}

#[test]
fn an_ipv6_target_ip_is_bracketed_in_the_rewrite_output() {
    // Previously SUSPECTED BUG; now fixed by bracket_if_ipv6.
    // Contract gap: the doc comment is silent on whether an IPv6 ip is bracketed
    // in the output.  The fix brackets before set_host, so the output contains
    // "[::1]" and is a parseable URL.
    let ip = "::1";
    let input = "http://proxy.example.com:3128/path";
    let result = ProxyAddress::rewrite_url_host(input, ip);
    assert!(
        result.is_some(),
        "input={input:?} ip={ip:?} — expected Some(..), got None"
    );
    let out = result.unwrap();
    assert!(
        out.contains("[::1]"),
        "input={input:?} ip={ip:?} — output {out:?} must contain bracketed '[::1]'"
    );
    assert!(
        !out.contains("proxy.example.com"),
        "input={input:?} — old host must not appear in output {out:?}"
    );
    assert!(
        out.contains(":3128"),
        "input={input:?} — port must survive; output was {out:?}"
    );
    // Strongest assertion: the output must be a parseable URL with [::1] as host.
    let parsed =
        url::Url::parse(&out).unwrap_or_else(|_| panic!("output {out:?} must be parseable"));
    assert_eq!(
        parsed.host_str(),
        Some("[::1]"),
        "parsed host must be [::1] (url crate includes brackets in host_str for IPv6); output={out:?}"
    );
}

// ─── pinned_to_ip with IPv6 ip ────────────────────────────────────────────────
// These cover the production call site (models.rs:pinned_to_ip) for the fallback
// and rewrite paths with a bare IPv6 ip.

#[test]
fn pinned_to_ip_with_ipv6_and_no_original_url_produces_parseable_url() {
    // The None branch: fallback = format!("http://{}:{}", ip_host, port).
    // Without bracket_if_ipv6 this was "http://::1:3128" — an unparseable URL.
    let proxy = ProxyAddress {
        address: "proxy.example.com".to_string(),
        port: 3128,
        original_url: None,
    };
    let pinned = proxy.pinned_to_ip("::1");
    let url_str = pinned
        .original_url
        .as_deref()
        .expect("pinned_to_ip must set original_url");
    let parsed = url::Url::parse(url_str)
        .unwrap_or_else(|_| panic!("original_url={url_str:?} must be a parseable URL"));
    assert_eq!(
        parsed.host_str(),
        Some("[::1]"),
        "original_url={url_str:?} — host must round-trip to [::1]"
    );
    assert_eq!(
        parsed.port(),
        Some(3128),
        "original_url={url_str:?} — port must be 3128"
    );
}

#[test]
fn pinned_to_ip_with_ipv6_and_original_url_produces_parseable_url() {
    // The Some(raw) branch: rewrite_url_host uses bracket_if_ipv6.
    // Without the fix, rewrite_url_host returned None and fell back to the broken
    // fallback; now it rewrites correctly.
    let proxy = ProxyAddress {
        address: "proxy.example.com".to_string(),
        port: 3128,
        original_url: Some("http://proxy.example.com:3128/path?q=1".to_string()),
    };
    let pinned = proxy.pinned_to_ip("::1");
    let url_str = pinned
        .original_url
        .as_deref()
        .expect("pinned_to_ip must set original_url");
    let parsed = url::Url::parse(url_str)
        .unwrap_or_else(|_| panic!("original_url={url_str:?} must be a parseable URL"));
    assert_eq!(
        parsed.host_str(),
        Some("[::1]"),
        "original_url={url_str:?} — host must round-trip to [::1]"
    );
    assert_eq!(
        parsed.port(),
        Some(3128),
        "original_url={url_str:?} — port must survive"
    );
    assert_eq!(
        parsed.query(),
        Some("q=1"),
        "original_url={url_str:?} — query must survive"
    );
}

// ─── IpAddr parsing behavior — evidence for bracket_if_ipv6 strategy ─────────

#[test]
fn ipaddr_parse_behavior_underlying_bracket_if_ipv6() {
    // Evidence that the IpAddr-parse approach used in bracket_if_ipv6 is correct:
    // V6 addresses parse as V6 (need bracketing), V4 and hostnames do not.
    // Verified by running this test before the fix was written.
    use std::net::IpAddr;
    assert!(
        matches!("::1".parse::<IpAddr>().unwrap(), IpAddr::V6(_)),
        "'::1' must parse as IpAddr::V6 — these are the inputs that need bracketing"
    );
    assert!(
        matches!("10.0.0.2".parse::<IpAddr>().unwrap(), IpAddr::V4(_)),
        "'10.0.0.2' must parse as IpAddr::V4 — must NOT be bracketed"
    );
    assert!(
        "proxy.example.com".parse::<IpAddr>().is_err(),
        "'proxy.example.com' must not parse as IpAddr — must NOT be bracketed"
    );
    // Already-bracketed form does not parse; bracket_if_ipv6 catches this via
    // starts_with('[') before attempting the parse.
    assert!(
        "[::1]".parse::<IpAddr>().is_err(),
        "'[::1]' must not parse as IpAddr — brackets are not IpAddr notation"
    );
}
