//! Spec-derived tests for loopback proxy-host rejection.
//! Written from the documented contract only.
//!
//! Contract source: doc comment on `host_is_loopback`:
//!   "127.0.0.0/8, ::1, or the name "localhost".
//!    Accepts bracketed IPv6 literals (e.g. `[::1]`)."

use super::*;

// ─── 127.0.0.0/8 ─────────────────────────────────────────────────────────────
// Contract: "127.0.0.0/8" — the entire /8 block is loopback, not just .1.

#[test]
fn the_canonical_loopback_address_is_loopback() {
    // Contract: 127.0.0.0/8
    assert!(
        host_is_loopback("127.0.0.1"),
        "input=127.0.0.1 — canonical loopback must be rejected"
    );
}

#[test]
fn a_non_canonical_address_inside_127_slash_8_is_loopback() {
    // Contract: "127.0.0.0/8" — the *whole* block, not only .1.
    // This case distinguishes a correct /8 check from an exact-match on 127.0.0.1.
    assert!(
        host_is_loopback("127.0.0.2"),
        "input=127.0.0.2 — entire 127.0.0.0/8 block must be loopback"
    );
}

#[test]
fn the_upper_bound_of_127_slash_8_is_loopback() {
    // Contract: "127.0.0.0/8" — 127.255.255.254 is the last usable host in the block.
    assert!(
        host_is_loopback("127.255.255.254"),
        "input=127.255.255.254 — top of 127.0.0.0/8 must be loopback"
    );
}

#[test]
fn a_midrange_127_address_is_loopback() {
    // Contract: "127.0.0.0/8"
    assert!(
        host_is_loopback("127.1.2.3"),
        "input=127.1.2.3 — mid-range 127.x.x.x must be loopback"
    );
}

#[test]
fn the_network_address_of_127_slash_8_is_loopback() {
    // Contract: "127.0.0.0/8" — network address itself is inside the block.
    assert!(
        host_is_loopback("127.0.0.0"),
        "input=127.0.0.0 — 127.0.0.0/8 network address must be loopback"
    );
}

// ─── 127.x.x.x near-misses ───────────────────────────────────────────────────

#[test]
fn an_address_just_above_127_slash_8_is_not_loopback() {
    // Contract negation: 128.0.0.1 is outside 127.0.0.0/8.
    assert!(
        !host_is_loopback("128.0.0.1"),
        "input=128.0.0.1 — outside 127.0.0.0/8, must NOT be loopback"
    );
}

#[test]
fn an_address_just_below_127_slash_8_is_not_loopback() {
    // Contract negation: 126.255.255.255 is outside 127.0.0.0/8.
    assert!(
        !host_is_loopback("126.255.255.255"),
        "input=126.255.255.255 — outside 127.0.0.0/8, must NOT be loopback"
    );
}

#[test]
fn a_private_rfc1918_address_is_not_loopback() {
    // Contract negation: only 127.0.0.0/8, ::1, or "localhost" are loopback.
    assert!(
        !host_is_loopback("10.0.3.1"),
        "input=10.0.3.1 — RFC 1918 private address must NOT be loopback"
    );
}

#[test]
fn the_unspecified_address_is_not_loopback() {
    // Contract negation: 0.0.0.0 is not listed as loopback.
    assert!(
        !host_is_loopback("0.0.0.0"),
        "input=0.0.0.0 — unspecified address must NOT be loopback"
    );
}

// ─── ::1 ─────────────────────────────────────────────────────────────────────
// Contract: "::1"

#[test]
fn the_ipv6_loopback_address_is_loopback() {
    // Contract: "::1"
    assert!(
        host_is_loopback("::1"),
        "input=::1 — IPv6 loopback must be rejected"
    );
}

// ─── Bracketed IPv6 ──────────────────────────────────────────────────────────
// Contract: "Accepts bracketed IPv6 literals (e.g. `[::1]`) as stored by the
//            proxy URL parser."

#[test]
fn bracketed_ipv6_loopback_is_loopback() {
    // Contract: explicit bracketed-form acceptance.
    assert!(
        host_is_loopback("[::1]"),
        "input=[::1] — bracketed IPv6 loopback must be rejected"
    );
}

#[test]
fn bracketed_non_loopback_ipv6_is_not_loopback() {
    // Contract: bracket stripping must not make a non-loopback address loopback.
    assert!(
        !host_is_loopback("[2001:db8::1]"),
        "input=[2001:db8::1] — bracketed non-loopback IPv6 must NOT be loopback"
    );
}

// ─── "localhost" ─────────────────────────────────────────────────────────────
// Contract: `or the name "localhost"` (exact name, not a prefix/substring rule).

#[test]
fn the_name_localhost_is_loopback() {
    // Contract: `or the name "localhost"`
    assert!(
        host_is_loopback("localhost"),
        "input=localhost — the name localhost must be loopback"
    );
}

#[test]
fn a_host_merely_prefixed_with_localhost_is_not_loopback() {
    // Contract: "the name" — exact match only.
    // A substring/prefix match would accept localhost.evil.com; the contract forbids it.
    assert!(
        !host_is_loopback("localhost.evil.com"),
        "input=localhost.evil.com — must NOT be loopback; contract requires exact name match"
    );
}

#[test]
fn a_host_that_contains_localhost_as_a_suffix_is_not_loopback() {
    // Contract: exact name match, not substring.
    assert!(
        !host_is_loopback("notlocalhost"),
        "input=notlocalhost — must NOT be loopback; contract requires exact name match"
    );
}

// ─── Characterization tests for contract-silent cases ────────────────────────
// These record the *observed* behavior of a live, deterministic implementation.
// The contract is silent on each case — so these are not required guarantees,
// but they ARE live assertions.  A change to any of these behaviors must be
// a conscious decision, not a silent drift.  See CONTRACT GAPS in the report.

#[test]
fn empty_string_is_not_loopback() {
    // Contract is silent on empty string.  The three named families (127.0.0.0/8,
    // ::1, "localhost") do not include ""; this assertion pins that it stays false.
    // For a security predicate, silently flipping "" to loopback would be a bug.
    assert!(
        !host_is_loopback(""),
        "input='' — empty string must not be treated as loopback"
    );
}

#[test]
fn uppercase_localhost_is_loopback() {
    // Contract gap 2: the doc comment says `the name "localhost"` without
    // specifying case.  The implementation uses `eq_ignore_ascii_case`, so
    // "LOCALHOST" and "LocalHost" are treated as loopback today.
    // This is a characterization test — the contract does not require it,
    // but a change here should be intentional.
    assert!(
        host_is_loopback("LOCALHOST"),
        "input=LOCALHOST — implementation treats this as loopback (eq_ignore_ascii_case); \
         pin to catch silent changes"
    );
    assert!(
        host_is_loopback("LocalHost"),
        "input=LocalHost — implementation treats this as loopback (eq_ignore_ascii_case); \
         pin to catch silent changes"
    );
}

#[test]
fn ipv4_mapped_ipv6_loopback_is_not_loopback() {
    // Contract gap 3: the contract names "127.0.0.0/8" and "::1" but not
    // IPv4-mapped IPv6 (::ffff:127.0.0.1).  Rust's IpAddr::is_loopback()
    // returns false for IPv4-mapped addresses; this test pins that behavior.
    // For this call site (config_parser.rs:1028) a false negative is
    // fail-safe: the container is given an unreachable proxy, not open access.
    assert!(
        !host_is_loopback("::ffff:127.0.0.1"),
        "input=::ffff:127.0.0.1 — IPv4-mapped IPv6 loopback; not in contract; \
         currently returns false (not caught); pin to detect behavior change"
    );
    assert!(
        !host_is_loopback("[::ffff:127.0.0.1]"),
        "input=[::ffff:127.0.0.1] — bracketed IPv4-mapped form; also currently false; \
         pin to detect behavior change"
    );
}

#[test]
fn trailing_dot_localhost_is_not_loopback() {
    // Contract gap 5: the contract says `the name "localhost"` with no mention
    // of FQDN trailing-dot form.  "localhost." does not equal "localhost" under
    // exact-match or eq_ignore_ascii_case, and does not parse as an IpAddr,
    // so the implementation returns false.  Pin that.
    assert!(
        !host_is_loopback("localhost."),
        "input='localhost.' — trailing-dot FQDN form; contract requires exact \
         name match; must NOT be loopback"
    );
}
