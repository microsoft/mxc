// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Black-box contract tests for `wxc_common::models::ProxyAddress` and
//! `ProxyHostPin`.
//!
//! These live in the integration-test directory on purpose: from here only the
//! crate's public API is visible, so the tests exercise the same surface the
//! real callers do and cannot accidentally couple to a private helper.  They
//! were written from the documented contract without reading the
//! implementation, so a bug baked into the code cannot silently teach the tests
//! to expect it.
//!
//! Why this surface matters.  The "deny-all-except-proxy" network policy
//! requires the sandbox and the firewall to agree on exactly one proxy
//! endpoint.  If the URL handed to the sandbox names a different endpoint than
//! the firewall authorized -- or if the sandbox is left free to re-resolve a
//! hostname under round-robin or split-horizon DNS -- that is a policy bypass.
//! `to_url` decides the endpoint string the sandbox receives, and `host_pin` /
//! `hosts_line` express the resolved mapping as a hosts-file pin so the
//! hostname stays in the URL and TLS identity is preserved.
//!
//! Client status, verified against the tree on the day these tests were
//! written:
//!
//! * The URL surface (`new`, `from_url`, `to_url`, and the `original_url`
//!   field) has live callers today.  `appcontainer_runner::inject_proxy_vars`
//!   turns `to_url()` into the `HTTP_PROXY` / `HTTPS_PROXY` values injected into
//!   the sandboxed process, `proxy_coordinator` uses it to launch the elevated
//!   shim, `unix_proxy_coordinator` logs it, `config_parser` produces addresses
//!   via `from_url`, and `wsl_container_runner` reads the `original_url` field
//!   directly.
//! * The pin surface (`host_pin`, `hosts_line`, `ProxyHostPin`) still has no
//!   callers.  It is planned wiring for the firewall / hosts-file consumer, so
//!   the tests below name that consumer as planned, not present.  `ProxyHostPin`
//!   has no public constructor -- the only way to obtain one is `host_pin` on a
//!   hostname -- so the tests build pins that way through the `pin_for` helper.
//!
//! `host_pin` returns `Result<Option<ProxyHostPin>, WxcError>`, and the three
//! arms are the whole point of the type after PR 789:
//!
//! * `Ok(None)` -- and only this -- means the address is an IP literal (bare or
//!   bracketed), so there is nothing to resolve and no pin is needed.
//! * `Ok(Some(pin))` means the address is a hostname and the pin is required.
//! * `Err(_)` means a pin is required but impossible: the address is empty or
//!   holds characters invalid in a hostname (notably whitespace or a newline,
//!   the hosts-file injection vectors).  Conflating this with `Ok(None)` would
//!   fail open -- the caller would skip a required pin and let the sandbox
//!   re-resolve the name freely -- so the tests assert the specific arm, not
//!   merely `is_err` or `is_none`.
//!
//! Test list (the scenarios these tests are meant to cover, enumerated before
//! the assertions were written):
//!   1. `to_url` with no original URL constructs `http://{address}:{port}` from
//!      the struct's own address -- for loopback, for a non-loopback address
//!      that must not be rewritten to loopback, and for bare and
//!      already-bracketed IPv6 literals.
//!   2. `to_url` with an original URL returns it verbatim -- including a
//!      trailing slash, credentials, a path and query, and an `https` scheme.
//!   3. The two constructors differ only in whether they record `original_url`.
//!   4. `host_pin` returns `Ok(Some)` for a hostname (with a hyphen accepted and
//!      the typed IP read back through `ip()`), `Ok(None)` for every IP literal,
//!      and `Err` for the empty address and for hostnames carrying a newline or
//!      a space.
//!   5. `host_pin` does not disturb `to_url`.
//!   6. `hosts_line` writes `{ip} {hostname}` with the address bare, which is
//!      the deliberate asymmetry against `to_url`'s bracketing of IPv6.

use std::net::IpAddr;

use wxc_common::models::{ProxyAddress, ProxyHostPin};

// `ProxyHostPin` has no public constructor: the only way to obtain one is
// `ProxyAddress::host_pin` on a hostname address, which must return
// `Ok(Some(pin))`.  This helper centralizes that construction and fails the
// test with a precise message if either non-`Ok(Some)` arm comes back, so the
// pin-shape tests can read like ordinary value assertions.
fn pin_for(address: &str, ip: IpAddr) -> ProxyHostPin {
    match ProxyAddress::new(address.to_string(), 8080).host_pin(ip) {
        Ok(Some(pin)) => pin,
        Ok(None) => panic!("expected a pin for hostname {address:?}, got Ok(None)"),
        Err(_) => panic!("expected a pin for hostname {address:?}, got Err"),
    }
}

// Protects `appcontainer_runner::inject_proxy_vars` and the proxy coordinators,
// which build the sandbox's proxy URL from an address created with `new`.  A
// loopback bind address is the common case for the builtin test proxy.
#[test]
fn to_url_constructs_http_url_for_loopback_when_no_original_url() {
    let addr = ProxyAddress::new("127.0.0.1".to_string(), 8080);

    assert_eq!(addr.to_url(), "http://127.0.0.1:8080");
}

// Protects `appcontainer_runner::inject_proxy_vars`.  A proxy bound to a
// non-loopback address is constructible via `new`, and the sandbox must be told
// that exact endpoint.  Reporting `127.0.0.1` here would hand the sandbox a
// different endpoint than the firewall authorized -- a policy bypass.
#[test]
fn to_url_preserves_non_loopback_address_and_does_not_assume_loopback() {
    let addr = ProxyAddress::new("10.1.2.3".to_string(), 3128);

    assert_eq!(addr.to_url(), "http://10.1.2.3:3128");
}

// Protects every client that turns a `new`-built address into a URL when the
// proxy is bound to an IPv6 address.  An unbracketed IPv6 literal is not a valid
// URL host component, so the constructed URL must bracket it.
#[test]
fn to_url_brackets_bare_ipv6_literal() {
    let addr = ProxyAddress::new("2001:db8::1".to_string(), 8080);

    assert_eq!(addr.to_url(), "http://[2001:db8::1]:8080");
}

// Protects the same URL-building clients against a double-bracketing bug when
// the address is already in bracketed form.
#[test]
fn to_url_does_not_double_bracket_already_bracketed_ipv6() {
    let addr = ProxyAddress::new("[2001:db8::1]".to_string(), 8080);

    assert_eq!(addr.to_url(), "http://[2001:db8::1]:8080");
}

// Protects `wsl_container_runner` and the env-var injection path, which forward
// the operator-supplied proxy URL unchanged.  When an original URL was recorded
// via `from_url`, `to_url` must return it byte for byte.
#[test]
fn to_url_returns_original_url_verbatim() {
    let addr = ProxyAddress::from_url(
        "http://proxy.example.com:8080",
        "proxy.example.com".to_string(),
        8080,
    );

    assert_eq!(addr.to_url(), "http://proxy.example.com:8080");
}

// Protects `wsl_container_runner` against the trailing-slash mangling an earlier
// implementation exhibited.  The original URL must pass through exactly, slash
// and all.
#[test]
fn to_url_preserves_trailing_slash_in_original_url() {
    let addr = ProxyAddress::from_url(
        "http://proxy.example.com:8080/",
        "proxy.example.com".to_string(),
        8080,
    );

    assert_eq!(addr.to_url(), "http://proxy.example.com:8080/");
}

// Protects `wsl_container_runner` and the env-var injection path for a
// fully-specified URL.  Credentials, path, and query must all survive verbatim;
// dropping the credentials would silently change how the proxy authenticates.
#[test]
fn to_url_preserves_credentials_path_and_query_in_original_url() {
    let addr = ProxyAddress::from_url(
        "http://user:pass@proxy.example.com:8080/path?token=abc",
        "proxy.example.com".to_string(),
        8080,
    );

    assert_eq!(
        addr.to_url(),
        "http://user:pass@proxy.example.com:8080/path?token=abc"
    );
}

// Protects the whole reason `ProxyHostPin` exists instead of rewriting the host
// to an IP: an `https` proxy must keep its hostname and scheme so the client's
// SNI and certificate validation still work.  The original URL passes through
// unchanged, including the `https` scheme.
#[test]
fn to_url_preserves_https_scheme_original_url_verbatim() {
    let addr = ProxyAddress::from_url(
        "https://proxy.example.com:8443",
        "proxy.example.com".to_string(),
        8443,
    );

    assert_eq!(addr.to_url(), "https://proxy.example.com:8443");
}

// Protects `wsl_container_runner`, which reads the `original_url` field
// directly.  `from_url` must record the original string and `new` must leave it
// empty; that single difference is what selects passthrough versus construction
// in `to_url`.
#[test]
fn from_url_records_original_url_and_new_does_not() {
    let from_url = ProxyAddress::from_url(
        "http://proxy.example.com:8080",
        "proxy.example.com".to_string(),
        8080,
    );
    let constructed = ProxyAddress::new("127.0.0.1".to_string(), 8080);

    assert_eq!(
        from_url.original_url,
        Some("http://proxy.example.com:8080".to_string())
    );
    assert_eq!(constructed.original_url, None);
}

// Protects the planned firewall / hosts-file consumer.  A hostname address
// requires resolution, so `host_pin` must return `Ok(Some(pin))` carrying the
// hostname and the typed IP it was handed.
#[test]
fn host_pin_returns_pin_for_hostname() {
    let ip: IpAddr = "10.0.0.5".parse().unwrap();

    let pin = pin_for("proxy.example.com", ip);

    assert_eq!(pin.hostname(), "proxy.example.com");
    assert_eq!(pin.ip(), ip);
}

// Protects the planned firewall / hosts-file consumer against an over-strict
// validator.  Hyphens and dots are legal in a hostname, so a label containing a
// hyphen must still pin rather than being rejected as invalid.
#[test]
fn host_pin_accepts_hostname_with_hyphen() {
    let ip: IpAddr = "10.0.0.5".parse().unwrap();

    let pin = pin_for("my-proxy.example.com", ip);

    assert_eq!(pin.hostname(), "my-proxy.example.com");
}

// Protects the planned firewall / hosts-file consumer.  `ip()` now returns a
// typed `IpAddr`, so a pin built for a hostname with a resolved IPv6 address
// must return that exact address through the accessor -- not a string, and not a
// lossy reformatting.
#[test]
fn host_pin_ip_accessor_returns_typed_ipv6_address() {
    let ip: IpAddr = "2001:db8::1".parse().unwrap();

    let pin = pin_for("proxy.example.com", ip);

    assert_eq!(pin.ip(), ip);
}

// Protects the planned firewall / hosts-file consumer.  An IPv4 literal address
// is already an endpoint, so there is nothing to resolve: the one and only
// `Ok(None)` case ("no pin needed"), which must not be confused with `Err`
// ("pin needed but impossible").
#[test]
fn host_pin_returns_ok_none_for_ipv4_literal() {
    let ip: IpAddr = "10.0.0.5".parse().unwrap();

    match ProxyAddress::new("127.0.0.1".to_string(), 8080).host_pin(ip) {
        Ok(None) => {}
        Ok(Some(_)) => panic!("an IPv4 literal needs no pin; expected Ok(None), got Ok(Some)"),
        Err(_) => panic!("an IPv4 literal needs no pin; expected Ok(None), got Err"),
    }
}

// Protects the planned firewall / hosts-file consumer.  A bare IPv6 literal is
// likewise already an endpoint and needs no hosts entry.
#[test]
fn host_pin_returns_ok_none_for_bare_ipv6_literal() {
    let ip: IpAddr = "10.0.0.5".parse().unwrap();

    match ProxyAddress::new("2001:db8::1".to_string(), 8080).host_pin(ip) {
        Ok(None) => {}
        Ok(Some(_)) => panic!("a bare IPv6 literal needs no pin; expected Ok(None), got Ok(Some)"),
        Err(_) => panic!("a bare IPv6 literal needs no pin; expected Ok(None), got Err"),
    }
}

// Protects the planned firewall / hosts-file consumer.  A bracketed IPv6 literal
// is unbracketed before classification, so `[::1]` is still an IP literal and
// must be `Ok(None)`, never treated as a hostname to pin.
#[test]
fn host_pin_returns_ok_none_for_bracketed_ipv6_literal() {
    let ip: IpAddr = "10.0.0.5".parse().unwrap();

    match ProxyAddress::new("[::1]".to_string(), 8080).host_pin(ip) {
        Ok(None) => {}
        Ok(Some(_)) => {
            panic!("a bracketed IPv6 literal needs no pin; expected Ok(None), got Ok(Some)")
        }
        Err(_) => panic!("a bracketed IPv6 literal needs no pin; expected Ok(None), got Err"),
    }
}

// Protects the planned firewall / hosts-file consumer, and pins the security fix
// from PR 789.  An empty address is a pin that is REQUIRED but impossible, so it
// must be `Err`, never `Ok(None)`.  If these two arms were swapped the caller
// would read "no hosts entry needed", skip the pin, and let the sandbox
// re-resolve the name freely -- failing open and defeating the firewall.
#[test]
fn host_pin_returns_err_for_empty_address() {
    let ip: IpAddr = "10.0.0.5".parse().unwrap();

    match ProxyAddress::new(String::new(), 8080).host_pin(ip) {
        Err(_) => {}
        Ok(None) => {
            panic!("empty address must be Err (pin required but impossible), not Ok(None); Ok(None) fails open")
        }
        Ok(Some(_)) => panic!("empty address cannot yield a pin; expected Err, got Ok(Some)"),
    }
}

// Protects the planned firewall / hosts-file consumer against hosts-file
// injection, the defect PR 789 fixed.  A newline would end the hosts record and
// begin a second, unauthorized mapping, so an address carrying one must be `Err`
// and never reach `hosts_line`.
#[test]
fn host_pin_returns_err_for_hostname_with_newline() {
    let ip: IpAddr = "10.0.0.5".parse().unwrap();
    let injected = "proxy.example.com\n10.0.0.1 evil.example.com";

    match ProxyAddress::new(injected.to_string(), 8080).host_pin(ip) {
        Err(_) => {}
        Ok(None) => {
            panic!("a newline-bearing address must be Err, not Ok(None); Ok(None) fails open")
        }
        Ok(Some(_)) => {
            panic!("a newline-bearing address must be Err; Ok(Some) would inject a hosts record")
        }
    }
}

// Protects the planned firewall / hosts-file consumer against hosts-file
// injection.  A space splits one hosts record into an address and a second,
// unauthorized name, so an address containing whitespace must be `Err`.
#[test]
fn host_pin_returns_err_for_hostname_with_space() {
    let ip: IpAddr = "10.0.0.5".parse().unwrap();

    match ProxyAddress::new("proxy.example.com evil".to_string(), 8080).host_pin(ip) {
        Err(_) => {}
        Ok(None) => {
            panic!("a space-bearing address must be Err, not Ok(None); Ok(None) fails open")
        }
        Ok(Some(_)) => {
            panic!("a space-bearing address must be Err; Ok(Some) would inject a hosts record")
        }
    }
}

// Protects both the URL clients and the planned pin consumer.  Computing a pin
// is documented not to alter the URL, so `to_url` must return the same verbatim
// original after `host_pin` as before it.
#[test]
fn host_pin_does_not_change_to_url() {
    let addr = ProxyAddress::from_url(
        "https://proxy.example.com:8443",
        "proxy.example.com".to_string(),
        8443,
    );
    let ip: IpAddr = "10.0.0.5".parse().unwrap();

    let before = addr.to_url();
    match addr.host_pin(ip) {
        Ok(Some(_)) => {}
        Ok(None) => panic!("a hostname address should require a pin, got Ok(None)"),
        Err(_) => panic!("a hostname address should pin cleanly, got Err"),
    }

    assert_eq!(addr.to_url(), before);
    assert_eq!(addr.to_url(), "https://proxy.example.com:8443");
}

// Protects the planned firewall / hosts-file consumer.  A hosts line is
// "{ip} {hostname}" -- address first, then hostname, separated by a single
// space, with no trailing newline.
#[test]
fn hosts_line_writes_ip_then_hostname() {
    let ip: IpAddr = "10.0.0.5".parse().unwrap();

    let pin = pin_for("proxy.example.com", ip);

    assert_eq!(pin.hosts_line(), "10.0.0.5 proxy.example.com");
}

// Protects the planned firewall / hosts-file consumer.  A hosts file takes an
// unbracketed IPv6 literal, so `hosts_line` must write the address bare -- the
// deliberate opposite of how `to_url` renders IPv6.
#[test]
fn hosts_line_writes_ipv6_address_without_brackets() {
    let ip: IpAddr = "2001:db8::1".parse().unwrap();

    let pin = pin_for("proxy.example.com", ip);
    let line = pin.hosts_line();

    assert!(
        !line.contains('['),
        "hosts line must not bracket IPv6: {line:?}"
    );
    assert_eq!(line, "2001:db8::1 proxy.example.com");
}

// Protects both surfaces at once by pinning the asymmetry the contract calls out
// explicitly: for the very same IPv6 literal, the URL host component is
// bracketed while the hosts-file line is bare.  A well-meaning refactor that
// unified the two would break exactly one of them, and this test names which.
#[test]
fn ipv6_is_bracketed_in_url_but_bare_in_hosts_line() {
    let ip: IpAddr = "2001:db8::1".parse().unwrap();

    let url = ProxyAddress::new("2001:db8::1".to_string(), 8080).to_url();
    let line = pin_for("proxy.example.com", ip).hosts_line();

    assert_eq!(url, "http://[2001:db8::1]:8080");
    assert_eq!(line, "2001:db8::1 proxy.example.com");
}
