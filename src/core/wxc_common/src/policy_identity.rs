// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Canonical policy identity — a stable hash of the *effective* enforcement
//! policy for a run.
//!
//! [`policy_hash`] answers "which policy is this sandbox running under?" with a
//! value that is:
//!
//! * **stable** across formatting, key ordering, and base64-vs-file input, so
//!   two runs of the same policy produce the same hash;
//! * **sensitive** to every enforcement-relevant field, so changing one
//!   `readwritePaths` entry changes it;
//! * **insensitive** to things that do not change enforcement (telemetry
//!   settings, dry-run, testing flags);
//! * **free of credential material**, so it cannot be used as a confirmation
//!   oracle against a secret embedded in a config.
//!
//! The value is emitted on the `mxc.PolicyHash` audit record.
//!
//! # What is hashed
//!
//! An explicit **allow-list** projection of [`ExecutionRequest`], not the whole
//! struct. An allow-list is deliberate: a field added to the model later is
//! excluded until someone opts it in, which fails safe (a missing field
//! weakens sensitivity) rather than unsafe (an accidentally-hashed secret is a
//! disclosure risk that cannot be undone once hashes are in logs).
//!
//! To stop that safety property from silently rotting into a coverage gap,
//! [`policy_projection`] **exhaustively destructures** `ExecutionRequest` and
//! `ExperimentalConfig`. Adding a field to either is a compile error until it is
//! classified as hashed or explicitly excluded with a reason.
//!
//! # What is excluded, and why
//!
//! | Excluded | Reason |
//! |---|---|
//! | `script_code` | The command line is *what runs*, not the policy under which it runs; it also routinely embeds credentials (`curl -H "Authorization: …"`). |
//! | `env` | Environment variables are the classic secret carrier. |
//! | `experimental.telemetry` | Does not affect enforcement. |
//! | `experimental.isolation_session[.start].user` | Carries a WAM bearer token and a UPN. |
//! | `network_proxy.original_url` | A proxy URL can embed `user:password@`. The host and port *are* hashed. |
//! | `dry_run`, `testing_features_enabled` | Invocation modes, not policy. |
//!
//! `ContainerPolicy::network_proxy` is `#[serde(skip)]`, so the proxy's
//! credential-bearing URL cannot reach the hash through the blanket policy
//! serialization even by accident; the enforcement-relevant parts (enabled,
//! host, port) are added back explicitly.
//!
//! # Residual disclosure property (accepted, documented)
//!
//! The hash is deterministic and unkeyed, so it is a **confirmation oracle for
//! the fields it covers**: a reader who already knows every hashed field but one
//! can brute-force the remaining one. In practice that means someone holding the
//! log can test a guess at, say, a single `readwritePaths` entry — but only if
//! they already know the container id, working directory, timeout, capability
//! list, network policy, and every other path exactly. This is deliberately
//! accepted:
//!
//! * the alternative (a keyed digest) needs a machine-local secret whose
//!   storage, rotation, and failure modes are out of scope for a local
//!   diagnostic log;
//! * the fields covered are the operator's own policy, already visible to anyone
//!   who can read the config the log sits next to;
//! * the genuinely sensitive inputs — command line, environment, tokens, proxy
//!   userinfo — are excluded from the hash entirely, so no oracle exists for
//!   them at any difficulty.
//!
//! Do not add a low-entropy secret to the projection without switching to a
//! keyed construction first.

use serde_json::{Map, Value};
use sha2::{Digest, Sha256};

use crate::models::{ExecutionRequest, ExperimentalConfig};

/// Algorithm tag prefixed to the hex digest, so the algorithm can change
/// without breaking a consumer that only does equality comparison.
const ALGORITHM_TAG: &str = "sha256";

/// Compute the canonical policy hash for `request`, formatted as
/// `"sha256:<64 lowercase hex chars>"`.
///
/// Call this **after** every mutation that changes enforcement (CLI command
/// override, `--audit`'s permissive-learning-mode injection, capability
/// injection), so the hash describes what actually ran rather than what was
/// requested.
pub fn policy_hash(request: &ExecutionRequest) -> String {
    let canonical = canonical_json(&policy_projection(request));
    let digest = Sha256::digest(canonical.as_bytes());
    let mut out = String::with_capacity(ALGORITHM_TAG.len() + 1 + digest.len() * 2);
    out.push_str(ALGORITHM_TAG);
    out.push(':');
    for byte in digest {
        use std::fmt::Write as _;
        let _ = write!(out, "{byte:02x}");
    }
    out
}

/// Build the allow-listed projection of the request that the hash covers.
///
/// `ExecutionRequest` is **exhaustively destructured** (no `..`), so adding a
/// field to the model is a compile error here until it is either hashed or
/// bound to a named `_excluded_*` local with a reason. That is the tripwire
/// that keeps the allow-list from silently falling behind the model.
fn policy_projection(request: &ExecutionRequest) -> Value {
    let ExecutionRequest {
        schema_version,
        container_id,
        working_directory,
        script_timeout,
        containment,
        lifecycle,
        policy,
        lxc_config,
        seatbelt,
        experimental_enabled,
        experimental,
        // --- deliberately excluded; see the module docs ---
        // The command line is what runs, not the policy it runs under, and it
        // routinely embeds credentials.
        script_code: _excluded_command_line,
        // Environment variables are the classic secret carrier.
        env: _excluded_environment,
        // Invocation modes, not policy.
        dry_run: _excluded_dry_run,
        testing_features_enabled: _excluded_testing_features,
    } = request;

    let mut root = Map::new();

    root.insert(
        "schemaVersion".into(),
        Value::String(schema_version.clone()),
    );
    root.insert(
        "containment".into(),
        Value::String(containment.wire_name().to_string()),
    );
    root.insert("containerId".into(), Value::String(container_id.clone()));
    root.insert(
        "workingDirectory".into(),
        Value::String(working_directory.clone()),
    );
    root.insert(
        "scriptTimeout".into(),
        Value::Number((*script_timeout).into()),
    );
    root.insert(
        "experimentalEnabled".into(),
        Value::Bool(*experimental_enabled),
    );
    root.insert(
        "lifecycle".into(),
        serde_json::to_value(lifecycle).unwrap_or(Value::Null),
    );
    // `ContainerPolicy` serialization already omits `network_proxy`
    // (`#[serde(skip)]`), so no credential-bearing proxy URL can reach the hash
    // through this line.
    root.insert(
        "policy".into(),
        serde_json::to_value(policy).unwrap_or(Value::Null),
    );
    root.insert("proxy".into(), proxy_projection(request));
    root.insert(
        "lxc".into(),
        serde_json::to_value(lxc_config).unwrap_or(Value::Null),
    );
    root.insert(
        "seatbelt".into(),
        serde_json::to_value(seatbelt).unwrap_or(Value::Null),
    );
    root.insert("experimental".into(), experimental_projection(experimental));

    Value::Object(root)
}

/// The enforcement-relevant, non-credential parts of the experimental block.
///
/// These matter: for `windows_sandbox`, `wslc`, and `isolation_session` the
/// experimental section carries the sandbox's **entire** filesystem / network /
/// resource policy. Omitting it wholesale (the first cut of this module did)
/// would have made two materially different policies hash identically on those
/// backends.
///
/// `ExperimentalConfig` is exhaustively destructured for the same tripwire
/// reason as [`policy_projection`].
fn experimental_projection(experimental: &ExperimentalConfig) -> Value {
    let ExperimentalConfig {
        windows_sandbox,
        wslc,
        isolation_session,
        // A placeholder feature with no enforcement effect.
        test: _excluded_test_feature,
        // Telemetry settings do not affect enforcement.
        telemetry: _excluded_telemetry,
    } = experimental;

    let mut out = Map::new();
    out.insert(
        "windows_sandbox".into(),
        serde_json::to_value(windows_sandbox).unwrap_or(Value::Null),
    );
    out.insert(
        "wslc".into(),
        serde_json::to_value(wslc).unwrap_or(Value::Null),
    );
    // `IsolationSessionConfig::user` carries a WAM bearer token and a UPN, so
    // the section is serialized and then the credential key is stripped rather
    // than being passed through.
    let mut iso = serde_json::to_value(isolation_session).unwrap_or(Value::Null);
    strip_keys(&mut iso, &["user"]);
    out.insert("isolation_session".into(), iso);

    Value::Object(out)
}

/// Recursively remove every object entry whose key is in `keys`.
///
/// Used to excise credential-bearing sub-objects from an otherwise
/// blanket-serialized section, so the section's enforcement-relevant fields can
/// still be hashed.
fn strip_keys(value: &mut Value, keys: &[&str]) {
    match value {
        Value::Object(map) => {
            for key in keys {
                map.remove(*key);
            }
            for child in map.values_mut() {
                strip_keys(child, keys);
            }
        }
        Value::Array(items) => {
            for item in items {
                strip_keys(item, keys);
            }
        }
        _ => {}
    }
}

/// The enforcement-relevant, non-credential parts of the proxy configuration:
/// whether a proxy is in force, its host, and its port. The original URL is
/// deliberately dropped because it can carry `user:password@` userinfo.
fn proxy_projection(request: &ExecutionRequest) -> Value {
    let proxy = &request.policy.network_proxy;
    let mut out = Map::new();
    out.insert("enabled".into(), Value::Bool(proxy.is_enabled()));
    out.insert(
        "builtinTestServer".into(),
        Value::Bool(proxy.builtin_test_server),
    );
    match &proxy.address {
        Some(addr) => {
            out.insert("address".into(), Value::String(addr.address.clone()));
            out.insert("port".into(), Value::Number(addr.port.into()));
        }
        None => {
            out.insert("address".into(), Value::Null);
            out.insert("port".into(), Value::Null);
        }
    }
    Value::Object(out)
}

/// Render `value` as canonical JSON: object keys sorted lexicographically at
/// every depth, array order preserved (array order is semantically meaningful
/// for path lists), and no insignificant whitespace.
///
/// Only the *container* kinds are walked by hand, and only to pin key ordering:
/// `serde_json::Map` is a `BTreeMap` unless the `preserve_order` feature is on,
/// so its iteration order is usually already sorted — but a feature flag flipped
/// by an unrelated crate in the dependency graph must not silently change every
/// hash MXC has ever emitted. Scalars are handed straight to `serde_json`, so
/// string escaping and number formatting are not reimplemented here.
fn canonical_json(value: &Value) -> String {
    let mut out = String::new();
    write_canonical(value, &mut out);
    out
}

fn write_canonical(value: &Value, out: &mut String) {
    match value {
        Value::Object(map) => {
            let mut keys: Vec<&String> = map.keys().collect();
            keys.sort_unstable();
            out.push('{');
            for (i, key) in keys.iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                out.push_str(&scalar_json(&Value::String((*key).clone())));
                out.push(':');
                // A key present in `keys` is by construction present in `map`.
                if let Some(child) = map.get(*key) {
                    write_canonical(child, out);
                }
            }
            out.push('}');
        }
        Value::Array(items) => {
            out.push('[');
            for (i, item) in items.iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                write_canonical(item, out);
            }
            out.push(']');
        }
        // Null / Bool / Number / String have no ordering concern, so there is
        // nothing to hand-roll: `serde_json` already renders them canonically.
        scalar => out.push_str(&scalar_json(scalar)),
    }
}

/// Render a non-container `Value`. Serializing a scalar `Value` to a `String`
/// is infallible (the only failure mode of the `String` serializer is an I/O
/// error, which cannot occur for an in-memory buffer).
fn scalar_json(value: &Value) -> String {
    serde_json::to_string(value).expect("serializing a scalar Value to JSON is infallible")
}

/// Render a sandbox identity so it is safe to write to a diagnostic log file.
///
/// Two distinct hazards are handled:
///
/// 1. **UPN-shaped identities.** For `isolation_session` Entra sandboxes the
///    `provisionId` **is the user's UPN** (`state_aware.rs::provision` sets
///    `provision_id = user.upn`). A UPN must never be written to a file that is
///    routinely attached to a bug report.
/// 2. **Caller-supplied identities.** On the ProcessContainer path the identity
///    is the AppContainer profile name, i.e. the config's `containerId`. That is
///    a config value and is handled by [`crate::audit::sanitize_identity`].
///
/// For (1) this function emits the bounded marker `"entra-upn"` and **no
/// account-derived value at all**.
///
/// > A truncated SHA-256 of a UPN was considered and rejected. A UPN is
/// > low-entropy and enumerable within a tenant, so an unsalted digest is
/// > trivially reversed by dictionary attack — it is pseudonymisation, not
/// > redaction, and would have made the log's privacy posture look stronger than
/// > it is. A keyed HMAC would work but needs a machine-local secret whose own
/// > storage, rotation, and failure modes are out of scope here. The cost of the
/// > marker is that Entra sandboxes have **no MXC-side join key** in the local
/// > log; the OS-side `Microsoft.Windows.IsolationSession` records still carry
/// > the real `provisionId` for anyone who legitimately needs to correlate.
pub fn redact_identity(identity: &str) -> String {
    if is_upn_shaped(identity) {
        return ENTRA_UPN_MARKER.to_string();
    }
    crate::audit::sanitize_identity(identity).to_string()
}

/// Marker written in place of a UPN-derived identity. Bounded and constant, so
/// it discloses only the *kind* of identity, never the account.
pub const ENTRA_UPN_MARKER: &str = "entra-upn";

/// Whether `identity` looks like a UPN (or a `<prefix>:<upn>` sandbox id).
///
/// An `@` is the discriminator: none of the identity shapes MXC mints itself
/// (`sandbox-<hex>`, `wxc-<token>`, `wsb:<hex>`, `iso:wxc-<token>`) contains one,
/// and every UPN does.
fn is_upn_shaped(identity: &str) -> bool {
    identity.contains('@')
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::{ContainmentBackend, ProxyAddress};

    fn request() -> ExecutionRequest {
        let mut r = ExecutionRequest {
            schema_version: "0.7.0-alpha".to_string(),
            container_id: "test".to_string(),
            script_code: "echo hello".to_string(),
            working_directory: "C:\\work".to_string(),
            script_timeout: 30,
            containment: ContainmentBackend::ProcessContainer,
            ..Default::default()
        };
        r.policy.readwrite_paths.push("C:\\tmp".to_string());
        r.policy.readonly_paths.push("C:\\ro".to_string());
        r
    }

    #[test]
    fn hash_is_prefixed_and_hex() {
        let h = policy_hash(&request());
        let Some(hex) = h.strip_prefix("sha256:") else {
            panic!("missing algorithm tag: {h}");
        };
        assert_eq!(hex.len(), 64, "got: {h}");
        assert!(
            hex.chars()
                .all(|c| c.is_ascii_digit() || ('a'..='f').contains(&c)),
            "not lowercase hex: {h}"
        );
    }

    #[test]
    fn identical_policies_hash_identically() {
        assert_eq!(policy_hash(&request()), policy_hash(&request()));
    }

    #[test]
    fn changing_a_readwrite_path_changes_the_hash() {
        let baseline = policy_hash(&request());
        let mut changed = request();
        changed.policy.readwrite_paths[0] = "C:\\other".to_string();
        assert_ne!(baseline, policy_hash(&changed));
    }

    #[test]
    fn adding_a_denied_path_changes_the_hash() {
        let baseline = policy_hash(&request());
        let mut changed = request();
        changed.policy.denied_paths.push("C:\\secret".to_string());
        assert_ne!(baseline, policy_hash(&changed));
    }

    #[test]
    fn changing_the_network_policy_changes_the_hash() {
        let baseline = policy_hash(&request());
        let mut changed = request();
        changed.policy.default_network_policy = crate::models::NetworkPolicy::Allow;
        assert_ne!(baseline, policy_hash(&changed));
    }

    #[test]
    fn changing_the_containment_backend_changes_the_hash() {
        let baseline = policy_hash(&request());
        let mut changed = request();
        changed.containment = ContainmentBackend::Lxc;
        assert_ne!(baseline, policy_hash(&changed));
    }

    #[test]
    fn changing_the_proxy_port_changes_the_hash() {
        let baseline = policy_hash(&request());
        let mut changed = request();
        changed.policy.network_proxy.address =
            Some(ProxyAddress::new("localhost".to_string(), 8080));
        let with_8080 = policy_hash(&changed);
        assert_ne!(baseline, with_8080);

        changed.policy.network_proxy.address =
            Some(ProxyAddress::new("localhost".to_string(), 9090));
        assert_ne!(with_8080, policy_hash(&changed));
    }

    #[test]
    fn telemetry_settings_do_not_change_the_hash() {
        let baseline = policy_hash(&request());
        let mut changed = request();
        changed.experimental.telemetry = Some(crate::models::TelemetryConfig {
            enabled: Some(true),
        });
        assert_eq!(
            baseline,
            policy_hash(&changed),
            "telemetry does not affect enforcement and must not perturb the policy identity"
        );
    }

    #[test]
    fn credential_bearing_fields_do_not_change_the_hash() {
        let baseline = policy_hash(&request());

        // A proxy URL that embeds userinfo must not become a confirmation
        // oracle: only host + port are hashed.
        let mut with_userinfo = request();
        with_userinfo.policy.network_proxy.address = Some(ProxyAddress::from_url(
            "http://user:hunter2@localhost:8080",
            "localhost".to_string(),
            8080,
        ));
        let mut without_userinfo = request();
        without_userinfo.policy.network_proxy.address =
            Some(ProxyAddress::new("localhost".to_string(), 8080));
        assert_eq!(
            policy_hash(&with_userinfo),
            policy_hash(&without_userinfo),
            "the proxy URL's userinfo must not reach the hash"
        );

        // Environment variables and the command line routinely carry secrets.
        let mut with_secrets = request();
        with_secrets.env.push("API_KEY=hunter2".to_string());
        with_secrets.script_code = "curl -H 'Authorization: Bearer hunter2'".to_string();
        assert_eq!(
            baseline,
            policy_hash(&with_secrets),
            "env and command line are excluded from the policy identity"
        );
    }

    #[test]
    fn invocation_modes_do_not_change_the_hash() {
        let baseline = policy_hash(&request());
        let mut changed = request();
        changed.dry_run = true;
        changed.testing_features_enabled = true;
        assert_eq!(baseline, policy_hash(&changed));
    }

    #[test]
    fn canonical_json_sorts_keys_at_every_depth() {
        let value: Value =
            serde_json::from_str(r#"{"b":1,"a":{"z":[3,1,2],"y":true}}"#).expect("valid JSON");
        assert_eq!(
            canonical_json(&value),
            r#"{"a":{"y":true,"z":[3,1,2]},"b":1}"#
        );
    }

    #[test]
    fn canonical_json_preserves_array_order() {
        // Path lists are order-bearing in the policy, so reordering them is a
        // real change and must produce a different canonical form.
        let a: Value = serde_json::from_str(r#"["x","y"]"#).expect("valid JSON");
        let b: Value = serde_json::from_str(r#"["y","x"]"#).expect("valid JSON");
        assert_ne!(canonical_json(&a), canonical_json(&b));
    }

    #[test]
    fn canonical_json_escapes_strings() {
        let value = Value::String("quote\" and \\ backslash".to_string());
        let rendered = canonical_json(&value);
        assert_eq!(rendered, r#""quote\" and \\ backslash""#);
        // Round-trips, so the canonical form is still parseable JSON.
        let reparsed: Value = serde_json::from_str(&rendered).expect("valid JSON");
        assert_eq!(reparsed, value);
    }

    #[test]
    fn opaque_identities_pass_through_unredacted() {
        for id in [
            "sandbox-a3f1c8e40029bd17",
            "wxc-abcd1234",
            "iso:wxc-abcd1234",
            "wsb:deadbeef",
            "CLI",
            "",
        ] {
            assert_eq!(redact_identity(id), id);
        }
    }

    #[test]
    fn upn_shaped_identities_never_reach_the_log() {
        for upn in [
            "alice@contoso.com",
            "iso:alice@contoso.com",
            "BOB@Contoso.OnMicrosoft.com",
        ] {
            let redacted = redact_identity(upn);
            assert_eq!(redacted, ENTRA_UPN_MARKER, "got: {redacted}");
        }
    }

    /// The marker must be constant, so it cannot be reversed by dictionary
    /// attack the way a truncated unsalted digest of a low-entropy UPN could.
    #[test]
    fn the_upn_marker_carries_no_account_derived_entropy() {
        assert_eq!(
            redact_identity("alice@contoso.com"),
            redact_identity("bob@fabrikam.com"),
            "distinct accounts must render identically; any per-account value \
             would be a reversible pseudonym"
        );
    }

    /// A caller-supplied `containerId` becomes the sandbox identity on the
    /// ProcessContainer path, so non-opaque values must be redacted rather than
    /// echoed into a record.
    #[test]
    fn non_opaque_identities_are_redacted() {
        assert_eq!(
            redact_identity("C:\\Users\\alice\\ticket-1234"),
            crate::audit::REDACTED_IDENTITY
        );
    }

    #[test]
    fn experimental_backend_policy_changes_the_hash() {
        // The experimental block carries the ENTIRE enforcement policy for
        // windows_sandbox / wslc / isolation_session. Omitting it would make two
        // materially different policies hash identically on those backends.
        let mut baseline = request();
        baseline.containment = ContainmentBackend::Wslc;
        let before = policy_hash(&baseline);

        let mut changed = baseline.clone();
        changed.experimental.wslc = Some(crate::models::WslcConfig {
            image: "python:3.12".to_string(),
            gpu: true,
            ..Default::default()
        });
        assert_ne!(before, policy_hash(&changed));

        let mut more = changed.clone();
        if let Some(cfg) = more.experimental.wslc.as_mut() {
            cfg.memory_mb = Some(4096);
        }
        assert_ne!(policy_hash(&changed), policy_hash(&more));
    }

    #[test]
    fn isolation_session_credentials_do_not_change_the_hash() {
        let mut baseline = request();
        baseline.containment = ContainmentBackend::IsolationSession;
        baseline.experimental.isolation_session =
            Some(crate::models::IsolationSessionConfig::default());
        let before = policy_hash(&baseline);

        let mut with_user = baseline.clone();
        if let Some(cfg) = with_user.experimental.isolation_session.as_mut() {
            cfg.user = Some(crate::models::IsolationSessionUser {
                upn: "alice@contoso.com".to_string(),
                wam_token: "super-secret-bearer-token".to_string(),
            });
        }
        assert_eq!(
            before,
            policy_hash(&with_user),
            "the WAM token and UPN must be stripped before hashing"
        );
    }

    #[test]
    fn strip_keys_removes_nested_credential_objects() {
        let mut value: serde_json::Value =
            serde_json::from_str(r#"{"a":{"user":{"wamToken":"x"},"keep":1},"b":[{"user":2}]}"#)
                .expect("valid JSON");
        strip_keys(&mut value, &["user"]);
        assert_eq!(canonical_json(&value), r#"{"a":{"keep":1},"b":[{}]}"#);
    }
}
