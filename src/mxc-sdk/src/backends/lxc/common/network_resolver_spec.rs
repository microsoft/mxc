// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use super::run_callback;
use std::fs;

#[test]
fn dns_servers_and_domain_fallback_form_the_resolver_configuration() {
    let root = tempfile::tempdir_in(".").expect("create DHCP callback fixture directory");
    let output = run_callback(
        root.path(),
        "bound",
        &[
            ("dns", "192.0.2.53 198.51.100.53"),
            ("domain", "corp.example"),
        ],
    );
    let resolver = fs::read_to_string(root.path().join("resolv.conf"))
        .expect("read DHCP resolver configuration");

    assert_eq!(
        resolver,
        concat!(
            "nameserver 192.0.2.53\n",
            "nameserver 198.51.100.53\n",
            "search corp.example\n",
        ),
        "DHCP dns='192.0.2.53 198.51.100.53', domain='corp.example' must preserve DNS order \
         and use the domain fallback; status={:?}, stderr={}",
        output.status,
        String::from_utf8_lossy(&output.stderr)
    );
}

#[test]
fn search_domains_override_the_domain_fallback() {
    let root = tempfile::tempdir_in(".").expect("create DHCP callback fixture directory");
    let output = run_callback(
        root.path(),
        "renew",
        &[
            ("dns", "192.0.2.53"),
            ("domain", "fallback.example"),
            ("search", "eng.example.com qa.example.com"),
        ],
    );
    let resolver = fs::read_to_string(root.path().join("resolv.conf"))
        .expect("read DHCP resolver configuration");

    assert_eq!(
        resolver,
        concat!(
            "nameserver 192.0.2.53\n",
            "search eng.example.com qa.example.com\n",
        ),
        "DHCP search='eng.example.com qa.example.com' must replace domain='fallback.example'; \
         status={:?}, stderr={}",
        output.status,
        String::from_utf8_lossy(&output.stderr)
    );
}
