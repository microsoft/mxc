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
//! # Acknowledgment-scoped presence facts
//!
//! `ContainerPolicy`'s parse-derived presence flags are `#[serde(skip)]`, so
//! they normally stay out of the projection — un-skipping them would move every
//! backend's hash. A request that carries an explicit unrestricted-network
//! acknowledgment additionally gets an `unrestrictedNetworkAcknowledgment`
//! object holding the network presence facts, because for those requests an
//! omitted `network` section, `network: {}`, and an authored directional deny
//! normalize to identical policy *values* while meaning different things. The
//! key is absent from every other request, so no pre-existing identity moves.
//! This records what the caller supplied; it is not a verdict, and no backend
//! validation is consulted.
//!
//! # What is excluded, and why
//!
//! | Excluded | Reason |
//! |---|---|
//! | `script_code` | The command line is *what runs*, not the policy under which it runs; it also routinely embeds credentials (`curl -H "Authorization: …"`). |
//! | `env` | Environment variables are the classic secret carrier. |
//! | `experimental.telemetry` | Does not affect enforcement. |
//! | `network_proxy.original_url` | A proxy URL can embed `user:password@`. The host and port *are* hashed. |
//! | `capture_denials.output_path` | Only decides where the diagnostic JSON deliverable is written; not enforcement. `capture_denials.mode` remains hashed. |
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

use crate::models::{
    ExecutionRequest, ExperimentalConfig, IsolationSessionProvisionConfig, WslcProvisionConfig,
};
use crate::state_aware_operation::{StateAwareOperation, StateAwareProvision};

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
    hash_canonical_json(&canonical)
}

/// Compute a state-aware policy identity from the backend resolved from the
/// lifecycle request and its typed operation.
///
/// Only allow-listed provision fields enter the hash. An absent config remains
/// JSON `null`, a present config with no fields remains `{}`, and explicit empty
/// strings remain distinct, preserving identities for exact accepted requests.
pub fn state_aware_policy_hash(
    request: &ExecutionRequest,
    backend: &str,
    operation: &StateAwareOperation,
) -> String {
    let mut projection = policy_projection(request);
    if let Value::Object(root) = &mut projection {
        root.insert("containment".into(), Value::String(backend.to_string()));
        root.insert(
            "stateAware".into(),
            serde_json::json!({
                "backend": backend,
                "phase": operation.phase().as_str(),
                "config": state_aware_config_projection(operation),
            }),
        );
        if state_aware_acknowledges_unrestricted_network(operation) {
            insert_unrestricted_network_acknowledgment(root, request);
        }
    }
    hash_canonical_json(&canonical_json(&projection))
}

/// True when the typed lifecycle operation itself carries the acknowledgment.
///
/// Exhaustively matched for the same tripwire reason as the projections: a new
/// acknowledgment-bearing phase must be classified rather than silently
/// defaulting to "not acknowledged".
fn state_aware_acknowledges_unrestricted_network(operation: &StateAwareOperation) -> bool {
    match operation {
        StateAwareOperation::Provision(StateAwareProvision::IsolationSession(config)) => config
            .as_ref()
            .is_some_and(|config| config.acknowledge_unrestricted_network.is_some()),
        // No other backend or phase accepts the acknowledgment.
        StateAwareOperation::Provision(
            StateAwareProvision::WindowsSandbox | StateAwareProvision::Wslc(_),
        )
        | StateAwareOperation::Start { .. }
        | StateAwareOperation::Exec { .. }
        | StateAwareOperation::Stop { .. }
        | StateAwareOperation::Deprovision { .. } => false,
    }
}

/// Record the parse-derived presence facts that separate a caller-authored
/// network policy from parser-generated defaults.
///
/// This runs **only** for acknowledgment-bearing requests, so no pre-existing
/// identity moves. It exists because an omitted `network` section, an explicit
/// `network: {}`, and an explicitly authored directional deny can normalize to
/// identical `ContainerPolicy` *values* while differing in acknowledgment
/// semantics — the first is accepted alongside an acknowledgment, the other two
/// are refused. The distinguishing flags are `#[serde(skip)]` on
/// `ContainerPolicy` (removing that would move every backend's hash), so the
/// relevant ones are re-added here, scoped to this case.
///
/// Classification of the presence flags:
///
/// * `network_specified`, `network_mode_specified` and
///   `runtime_network_proxy_specified` are **included**: each one decides
///   whether an acknowledgment-bearing request is accepted or refused.
/// * `ui_specified` is **excluded**: it is not network authorship, and its
///   accept/reject behavior is identical with and without an acknowledgment.
///
/// This is configuration identity, not authorization: it records what the
/// caller supplied, never a verdict, and no backend validation is consulted.
fn insert_unrestricted_network_acknowledgment(
    root: &mut Map<String, Value>,
    request: &ExecutionRequest,
) {
    let policy = &request.policy;
    root.insert(
        "unrestrictedNetworkAcknowledgment".into(),
        serde_json::json!({
            "networkSpecified": policy.network_specified,
            "networkModeSpecified": policy.network_mode_specified,
            "runtimeNetworkProxySpecified": policy.runtime_network_proxy_specified,
        }),
    );
}

/// Exhaustive matching forces new operation/config fields to be classified
/// explicitly instead of accidentally hashing a newly added secret.
fn state_aware_config_projection(operation: &StateAwareOperation) -> Value {
    match operation {
        StateAwareOperation::Provision(StateAwareProvision::IsolationSession(Some(
            IsolationSessionProvisionConfig {
                app_id,
                acknowledge_unrestricted_network,
            },
        ))) => {
            let mut config = Map::new();
            if let Some(app_id) = app_id {
                config.insert("appId".into(), Value::String(app_id.clone()));
            }
            // Key inserted only when acknowledged, so every acknowledgment-free
            // provision request keeps the identity it had before Phase 10a.
            if acknowledge_unrestricted_network.is_some() {
                config.insert("acknowledgeUnrestrictedNetwork".into(), Value::Bool(true));
            }
            Value::Object(config)
        }
        StateAwareOperation::Provision(StateAwareProvision::Wslc(Some(WslcProvisionConfig {
            image,
            image_tar_path,
        }))) => {
            let mut config = Map::new();
            if let Some(image) = image {
                config.insert("image".into(), Value::String(image.clone()));
            }
            if let Some(image_tar_path) = image_tar_path {
                config.insert("imageTarPath".into(), Value::String(image_tar_path.clone()));
            }
            Value::Object(config)
        }
        StateAwareOperation::Provision(
            StateAwareProvision::IsolationSession(None)
            | StateAwareProvision::WindowsSandbox
            | StateAwareProvision::Wslc(None),
        ) => Value::Null,
        // Sandbox IDs are not policy and can contain account identities.
        StateAwareOperation::Start {
            sandbox_id: _excluded_sandbox_id,
        }
        | StateAwareOperation::Exec {
            sandbox_id: _excluded_sandbox_id,
        }
        | StateAwareOperation::Stop {
            sandbox_id: _excluded_sandbox_id,
        }
        | StateAwareOperation::Deprovision {
            sandbox_id: _excluded_sandbox_id,
        } => Value::Null,
    }
}

fn hash_canonical_json(canonical: &str) -> String {
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
        // Telemetry settings do not affect enforcement.
        telemetry: _excluded_telemetry,
        experimental_enabled,
        experimental,
        // --- deliberately excluded; see the module docs ---
        // The command line is what runs, not the policy it runs under, and it
        // routinely embeds credentials.
        script_code: _excluded_command_line,
        // Environment variables are the classic secret carrier.
        env: _excluded_environment,
        // Whether the default environment is merged is process launch
        // behavior, not an enforcement decision.
        inherit_default_env: _excluded_environment_mode,
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
    //
    // `captureDenials.outputPath` is stripped: it only controls where the
    // diagnostic JSON deliverable is written and has no effect on enforcement.
    // Hashing it would perturb the policy identity across otherwise-identical
    // runs whose only difference is the output-file location — an operator
    // moving the diagnostic file has not changed the policy the sandbox ran
    // under. `captureDenials.mode` DOES stay hashed: it decides whether each
    // recorded access is blocked or allowed, which is an enforcement change.
    let mut policy_value = serde_json::to_value(policy).unwrap_or(Value::Null);
    if let Value::Object(policy_map) = &mut policy_value {
        if let Some(Value::Object(cd)) = policy_map.get_mut("capture_denials") {
            cd.remove("output_path");
        }
    }
    root.insert("policy".into(), policy_value);
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

    if experimental
        .isolation_session
        .as_ref()
        .is_some_and(|config| config.acknowledge_unrestricted_network.is_some())
    {
        insert_unrestricted_network_acknowledgment(&mut root, request);
    }

    Value::Object(root)
}

/// The enforcement-relevant, non-credential parts of the experimental block.
///
/// These matter: for `windows_sandbox` and `wslc` the experimental section
/// carries the sandbox's **entire** filesystem / network / resource policy.
/// Omitting it wholesale (the first cut of this module did) would have made two
/// materially different policies hash identically on those backends.
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
    // The one-shot IsolationSession section carries the unrestricted-network
    // acknowledgment, which is enforcement-relevant: it decides whether an
    // otherwise-unauthored network request is accepted. An absent section stays
    // `null`, exactly as it was before the section existed, so acknowledgment-free
    // identities do not move. State-aware phase config (including `appId`) is
    // projected separately.
    out.insert(
        "isolation_session".into(),
        serde_json::to_value(isolation_session).unwrap_or(Value::Null),
    );

    Value::Object(out)
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
///
/// Writes into a single growing `Vec<u8>` buffer and converts to `String`
/// exactly once at the end, rather than allocating (and immediately
/// discarding) a separate `String` per object key and per scalar value —
/// which this hash computation used to do at every level of every request's
/// policy tree.
fn canonical_json(value: &Value) -> String {
    let mut out = Vec::new();
    write_canonical(value, &mut out);
    // `write_canonical` only ever appends JSON structural bytes (all ASCII)
    // and `serde_json`'s own string/number encoding, both of which are
    // guaranteed valid UTF-8.
    String::from_utf8(out).expect("canonical JSON writer only ever emits valid UTF-8")
}

fn write_canonical(value: &Value, out: &mut Vec<u8>) {
    match value {
        Value::Object(map) => {
            let mut keys: Vec<&String> = map.keys().collect();
            keys.sort_unstable();
            out.push(b'{');
            for (i, key) in keys.iter().enumerate() {
                if i > 0 {
                    out.push(b',');
                }
                write_scalar(key.as_str(), out);
                out.push(b':');
                // A key present in `keys` is by construction present in `map`.
                if let Some(child) = map.get(*key) {
                    write_canonical(child, out);
                }
            }
            out.push(b'}');
        }
        Value::Array(items) => {
            out.push(b'[');
            for (i, item) in items.iter().enumerate() {
                if i > 0 {
                    out.push(b',');
                }
                write_canonical(item, out);
            }
            out.push(b']');
        }
        // Null / Bool / Number / String have no ordering concern, so there is
        // nothing to hand-roll: `serde_json` already renders them canonically.
        scalar => write_scalar(scalar, out),
    }
}

/// Serialize any `serde_json::Serialize` scalar (a `&str` object key or a
/// non-container `Value`) directly into `out`. Serializing a `&str` renders
/// identically to serializing the equivalent `Value::String`, so object keys
/// need no intermediate `Value` wrapper. Writing to a `Vec<u8>` is infallible
/// (the only failure mode of `serde_json`'s writer is an I/O error, which
/// cannot occur for an in-memory buffer).
fn write_scalar<T: serde::Serialize + ?Sized>(value: &T, out: &mut Vec<u8>) {
    serde_json::to_writer(out, value).expect("serializing a scalar value to JSON is infallible");
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

    /// `captureDenials.outputPath` decides where the diagnostic JSON file is
    /// written and has no effect on enforcement. It must not perturb the
    /// policy identity: moving the output file is a diagnostic-plumbing
    /// change, not a policy change.
    #[test]
    fn capture_denials_output_path_does_not_change_the_hash() {
        use crate::models::{CaptureDenialsConfig, CaptureDenialsMode};

        let mut baseline = request();
        baseline.policy.capture_denials = Some(CaptureDenialsConfig {
            mode: CaptureDenialsMode::Block,
            output_path: None,
            ..Default::default()
        });
        let base = policy_hash(&baseline);

        for path in [
            Some("C:\\logs\\denials.json".to_string()),
            Some("D:\\other\\denials.json".to_string()),
            None,
        ] {
            let mut changed = baseline.clone();
            if let Some(cd) = changed.policy.capture_denials.as_mut() {
                cd.output_path = path;
            }
            assert_eq!(
                base,
                policy_hash(&changed),
                "output_path controls diagnostic plumbing only and must not enter the hash"
            );
        }
    }

    /// `captureDenials.mode` decides whether each recorded access is blocked
    /// or allowed, which is an enforcement decision. Changing it MUST change
    /// the hash — this is the other half of the finding-3 contract.
    #[test]
    fn capture_denials_mode_changes_the_hash() {
        use crate::models::{CaptureDenialsConfig, CaptureDenialsMode};

        let mut baseline = request();
        baseline.policy.capture_denials = Some(CaptureDenialsConfig {
            mode: CaptureDenialsMode::Block,
            output_path: Some("C:\\logs\\denials.json".to_string()),
            ..Default::default()
        });
        let block_hash = policy_hash(&baseline);

        let mut allow = baseline.clone();
        if let Some(cd) = allow.policy.capture_denials.as_mut() {
            cd.mode = CaptureDenialsMode::Allow;
        }
        let allow_hash = policy_hash(&allow);
        assert_ne!(
            block_hash, allow_hash,
            "capture_denials.mode is an enforcement decision and MUST enter the hash"
        );
    }

    #[test]
    fn telemetry_settings_do_not_change_the_hash() {
        let baseline = policy_hash(&request());
        let mut changed = request();
        changed.telemetry = Some(crate::models::TelemetryConfig {
            enabled: Some(true),
            requested_sandbox_kind: Some("process"),
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
        with_secrets.env = Some(vec!["API_KEY=hunter2".to_string()]);
        with_secrets.inherit_default_env = true;
        with_secrets.script_code = "curl -H 'Authorization: Bearer hunter2'".to_string();
        assert_eq!(
            baseline,
            policy_hash(&with_secrets),
            "env, environment mode, and command line are excluded from the policy identity"
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
    fn mxc_minted_identities_pass_through_unredacted() {
        for id in [
            "sandbox-a3f1c8e40029bd17",
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
    /// ProcessContainer path, so it must be redacted rather than echoed into a
    /// record — even when it happens to look like an opaque token, since
    /// character/length checks alone cannot prove it wasn't chosen by the
    /// caller (e.g. `alice`, `ticket-1234`).
    #[test]
    fn caller_supplied_identities_are_redacted() {
        for id in ["C:\\Users\\alice\\ticket-1234", "alice", "ticket-1234"] {
            assert_eq!(redact_identity(id), crate::audit::REDACTED_IDENTITY);
        }
    }

    #[test]
    fn experimental_backend_policy_changes_the_hash() {
        // The experimental block carries the ENTIRE enforcement policy for
        // windows_sandbox / wslc. Omitting it would make two
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

    fn parse_state_aware(json: &str) -> crate::state_aware_request::ParsedStateAwareRequest {
        let mut logger = crate::logger::Logger::new(crate::logger::Mode::Buffer);
        let parsed = crate::config_parser::load_mxc_request_from_json(json, &mut logger)
            .expect("accepted exact state-aware request");
        let crate::state_aware_request::MxcRequest::StateAware(parsed) = parsed else {
            panic!("expected state-aware request");
        };
        parsed
    }

    fn parsed_state_aware_hash(json: &str, backend: &str) -> String {
        let parsed = parse_state_aware(json);
        state_aware_policy_hash(parsed.request(), backend, parsed.operation())
    }

    fn provision_json(backend: &str, extra_fields: &str) -> String {
        let network = if backend == "isolation_session" {
            r#","network":{"defaultPolicy":"allow","allowLocalNetwork":true}"#
        } else {
            ""
        };
        format!(
            r#"{{"version":"0.9.0-alpha","phase":"provision","containment":"{backend}"{network}{extra_fields}}}"#
        )
    }

    // Preserve the historical stateAware envelope independently of the typed
    // projection. Each caller supplies explicit expected phase/config values,
    // never values read back from the operation under test.
    fn expected_state_aware_hash(
        request: &ExecutionRequest,
        backend: &str,
        phase: &str,
        config: Value,
    ) -> String {
        let mut expected = policy_projection(request);
        expected["containment"] = serde_json::json!(backend);
        expected["stateAware"] = serde_json::json!({
            "backend": backend,
            "phase": phase,
            "config": config,
        });
        hash_canonical_json(&canonical_json(&expected))
    }

    #[test]
    fn state_aware_provision_hash_preserves_exact_config_shape() {
        let mut hashes = std::collections::HashSet::new();
        for (backend, payload, expected_config) in [
            ("isolation_session", None, Value::Null),
            ("isolation_session", Some("{}"), serde_json::json!({})),
            (
                "isolation_session",
                Some(r#"{"appId":""}"#),
                serde_json::json!({"appId": ""}),
            ),
            (
                "isolation_session",
                Some(r#"{"appId":"Contoso.App"}"#),
                serde_json::json!({"appId": "Contoso.App"}),
            ),
            ("windows_sandbox", None, Value::Null),
            ("wslc", None, Value::Null),
            ("wslc", Some("{}"), serde_json::json!({})),
            (
                "wslc",
                Some(r#"{"image":""}"#),
                serde_json::json!({"image": ""}),
            ),
            (
                "wslc",
                Some(r#"{"imageTarPath":""}"#),
                serde_json::json!({"imageTarPath": ""}),
            ),
            (
                "wslc",
                Some(r#"{"image":"","imageTarPath":""}"#),
                serde_json::json!({"image": "", "imageTarPath": ""}),
            ),
            (
                "wslc",
                Some(r#"{"image":"alpine:latest"}"#),
                serde_json::json!({"image": "alpine:latest"}),
            ),
            (
                "wslc",
                Some(r#"{"imageTarPath":"C:\\images\\custom.tar"}"#),
                serde_json::json!({"imageTarPath": "C:\\images\\custom.tar"}),
            ),
            (
                "wslc",
                Some(r#"{"image":"alpine:latest","imageTarPath":"C:\\images\\custom.tar"}"#),
                serde_json::json!({
                    "image": "alpine:latest",
                    "imageTarPath": "C:\\images\\custom.tar",
                }),
            ),
        ] {
            let experimental = payload
                .map(|payload| {
                    format!(r#","experimental":{{"{backend}":{{"provision":{payload}}}}}"#)
                })
                .unwrap_or_default();
            let json = provision_json(backend, &experimental);
            let parsed = parse_state_aware(&json);
            assert_eq!(
                state_aware_config_projection(parsed.operation()),
                expected_config,
                "{json}"
            );
            let hash = state_aware_policy_hash(parsed.request(), backend, parsed.operation());
            assert_eq!(
                hash,
                expected_state_aware_hash(parsed.request(), backend, "provision", expected_config),
                "{json}"
            );
            assert!(
                hashes.insert(hash),
                "absent, empty and supplied provision fields must stay distinct: {json}"
            );
        }
    }

    #[test]
    fn state_aware_hash_uses_each_operations_phase() {
        let request = request();
        let mut hashes = std::collections::HashSet::new();
        for (operation, expected_phase) in [
            (
                StateAwareOperation::Provision(StateAwareProvision::WindowsSandbox),
                "provision",
            ),
            (
                StateAwareOperation::Start {
                    sandbox_id: "wsb:deadbeef".into(),
                },
                "start",
            ),
            (
                StateAwareOperation::Exec {
                    sandbox_id: "wsb:deadbeef".into(),
                },
                "exec",
            ),
            (
                StateAwareOperation::Stop {
                    sandbox_id: "wsb:deadbeef".into(),
                },
                "stop",
            ),
            (
                StateAwareOperation::Deprovision {
                    sandbox_id: "wsb:deadbeef".into(),
                },
                "deprovision",
            ),
        ] {
            let hash = state_aware_policy_hash(&request, "windows_sandbox", &operation);
            assert_eq!(
                hash,
                expected_state_aware_hash(&request, "windows_sandbox", expected_phase, Value::Null)
            );
            assert!(hashes.insert(hash), "phase must affect the policy hash");
        }
    }

    #[test]
    fn state_aware_hash_ignores_empty_wrappers_through_public_parser() {
        for backend in ["isolation_session", "windows_sandbox", "wslc"] {
            let baseline = parsed_state_aware_hash(&provision_json(backend, ""), backend);
            for extra_fields in [
                r#","experimental":{}"#.to_string(),
                r#","telemetry":{}"#.to_string(),
                r#","_comment":{"user":{"CLIENTSECRET":"ignored"},"UPN":"alice@example.test"}"#
                    .to_string(),
            ] {
                assert_eq!(
                    baseline,
                    parsed_state_aware_hash(&provision_json(backend, &extra_fields), backend),
                    "{backend}: {extra_fields}"
                );
            }
            if backend != "windows_sandbox" {
                let extra_fields = format!(r#","experimental":{{"{backend}":{{}}}}"#);
                assert_eq!(
                    baseline,
                    parsed_state_aware_hash(&provision_json(backend, &extra_fields), backend),
                    "{backend}: an empty backend wrapper is not a provision config"
                );
            }
        }

        for phase in ["start", "exec", "stop", "deprovision"] {
            let process = if phase == "exec" {
                r#","process":{"commandLine":"echo hello"}"#
            } else {
                ""
            };
            let source = |extra_fields: &str| {
                format!(
                    r#"{{"version":"0.9.0-alpha","phase":"{phase}","sandboxId":"wsb:deadbeef"{process}{extra_fields}}}"#
                )
            };
            assert_eq!(
                parsed_state_aware_hash(&source(""), "windows_sandbox"),
                parsed_state_aware_hash(&source(r#","experimental":{}"#), "windows_sandbox"),
                "{phase}: an empty experimental wrapper is not a phase config"
            );
        }
    }

    // === Phase 10a identity baselines ===
    //
    // These digests were captured from the projection as it stood *before* the
    // Phase 10a acknowledgment work and are pinned as literals on purpose: an
    // expectation recomputed from `policy_projection` would silently rewrite
    // its own baseline the moment the projection changed, which is exactly the
    // regression these guard against. Every fixture below is expressible
    // without the acknowledgment, so all three acknowledgment-free shapes —
    // one-shot legacy, another backend, and each state-aware provision config
    // shape — must keep their historical identity.
    const GOLDEN_ONE_SHOT_LEGACY_ACKNOWLEDGMENT: &str =
        "sha256:7bc1f77e6b0f3fbac7f83e7fe9d1bfb86af0d95866802575870342f847f91e5e";
    const GOLDEN_ONE_SHOT_PROCESS_CONTAINER: &str =
        "sha256:7b8d0f3aaf5a0b339033cef8fb21dc5e68bfbe7dec4f3175cae9eadfeeebb7ce";
    const GOLDEN_PROVISION_CONFIG_ABSENT: &str =
        "sha256:72eda4c69af7feb89d985dd1512ef8fd9be5aa4980d45a5d2cb03c64369d0431";
    const GOLDEN_PROVISION_CONFIG_EMPTY: &str =
        "sha256:17d8dfb624577cbc7a74f56df98c75b187f2999582e21c16afccd034673417e7";
    const GOLDEN_PROVISION_APP_ID: &str =
        "sha256:fbe0b7d682837ba0bd7ad074f30b1080364168e29bde00baef776bd41abfd3f3";
    const GOLDEN_PROVISION_WSLC_ABSENT: &str =
        "sha256:6e02bba71db65abfcaf5a86b4c8372661cb0aeacc1f65f26b9f6f125b4803475";

    /// A one-shot IsolationSession request carrying only the legacy canonical
    /// unrestricted-network acknowledgment.
    fn golden_one_shot_legacy_acknowledgment() -> ExecutionRequest {
        ExecutionRequest {
            schema_version: "0.9.0-alpha".to_string(),
            container_id: "golden".to_string(),
            script_code: "cmd /c ver".to_string(),
            working_directory: "C:\\work".to_string(),
            script_timeout: 30,
            containment: ContainmentBackend::IsolationSession,
            policy: crate::models::ContainerPolicy {
                default_network_policy: crate::models::NetworkPolicy::Allow,
                allow_local_network: true,
                ..Default::default()
            },
            ..Default::default()
        }
    }

    /// An unrelated backend, proving the acknowledgment projection does not
    /// perturb identities outside IsolationSession.
    fn golden_one_shot_process_container() -> ExecutionRequest {
        ExecutionRequest {
            schema_version: "0.9.0-alpha".to_string(),
            container_id: "golden".to_string(),
            script_code: "cmd /c ver".to_string(),
            working_directory: "C:\\work".to_string(),
            script_timeout: 30,
            containment: ContainmentBackend::ProcessContainer,
            ..Default::default()
        }
    }

    fn golden_state_aware_request() -> ExecutionRequest {
        ExecutionRequest {
            schema_version: "0.9.0-alpha".to_string(),
            container_id: "golden".to_string(),
            working_directory: "C:\\work".to_string(),
            script_timeout: 30,
            containment: ContainmentBackend::IsolationSession,
            policy: crate::models::ContainerPolicy {
                default_network_policy: crate::models::NetworkPolicy::Allow,
                allow_local_network: true,
                ..Default::default()
            },
            ..Default::default()
        }
    }

    fn isolation_session_provision(
        config: Option<IsolationSessionProvisionConfig>,
    ) -> StateAwareOperation {
        StateAwareOperation::Provision(StateAwareProvision::IsolationSession(config))
    }

    #[test]
    fn phase_10a_preserves_pre_existing_policy_identities() {
        assert_eq!(
            policy_hash(&golden_one_shot_legacy_acknowledgment()),
            GOLDEN_ONE_SHOT_LEGACY_ACKNOWLEDGMENT,
            "the legacy one-shot acknowledgment identity must not move",
        );
        assert_eq!(
            policy_hash(&golden_one_shot_process_container()),
            GOLDEN_ONE_SHOT_PROCESS_CONTAINER,
            "unrelated backends must not be perturbed",
        );

        let request = golden_state_aware_request();
        assert_eq!(
            state_aware_policy_hash(
                &request,
                "isolation_session",
                &isolation_session_provision(None)
            ),
            GOLDEN_PROVISION_CONFIG_ABSENT,
            "absent provision config must keep its identity",
        );
        assert_eq!(
            state_aware_policy_hash(
                &request,
                "isolation_session",
                &isolation_session_provision(Some(IsolationSessionProvisionConfig::default())),
            ),
            GOLDEN_PROVISION_CONFIG_EMPTY,
            "present-empty provision config must keep its identity",
        );
        assert_eq!(
            state_aware_policy_hash(
                &request,
                "isolation_session",
                &isolation_session_provision(Some(IsolationSessionProvisionConfig {
                    app_id: Some("Contoso.App".to_string()),
                    ..Default::default()
                })),
            ),
            GOLDEN_PROVISION_APP_ID,
            "appId values must keep their identity",
        );

        let mut wslc = golden_state_aware_request();
        wslc.containment = ContainmentBackend::Wslc;
        assert_eq!(
            state_aware_policy_hash(
                &wslc,
                "wslc",
                &StateAwareOperation::Provision(StateAwareProvision::Wslc(None)),
            ),
            GOLDEN_PROVISION_WSLC_ABSENT,
            "other state-aware backends must not be perturbed",
        );
    }

    /// The directional deny values `apply_directional_network` writes for a
    /// v0.9 request whose `network` section is absent, `{}`, or an explicitly
    /// authored deny — all three normalize to exactly these values.
    fn implicit_directional_defaults(policy: &mut crate::models::ContainerPolicy) {
        policy.network_egress = Some(crate::models::NetworkEgressPolicy::default());
        policy.network_ingress = Some(crate::models::NetworkIngressPolicy::default());
    }

    fn acknowledged_one_shot() -> ExecutionRequest {
        let mut request = golden_one_shot_process_container();
        request.containment = ContainmentBackend::IsolationSession;
        request.experimental.isolation_session = Some(crate::models::IsolationSessionConfig {
            acknowledge_unrestricted_network: Some(
                crate::models::UnrestrictedNetworkAcknowledgment,
            ),
        });
        implicit_directional_defaults(&mut request.policy);
        request
    }

    #[test]
    fn one_shot_acknowledgment_forms_have_distinct_identities() {
        // Legacy-only, new-only, and both-consistent are deliberately distinct
        // identities: they are different configuration inputs, even though they
        // request the same posture.
        let legacy_only = golden_one_shot_legacy_acknowledgment();
        let new_only = acknowledged_one_shot();

        let mut both = new_only.clone();
        both.policy.default_network_policy = crate::models::NetworkPolicy::Allow;
        both.policy.allow_local_network = true;
        both.policy.network_egress = None;
        both.policy.network_ingress = None;

        let hashes = [
            policy_hash(&legacy_only),
            policy_hash(&new_only),
            policy_hash(&both),
        ];
        let unique: std::collections::HashSet<_> = hashes.iter().collect();
        assert_eq!(
            unique.len(),
            hashes.len(),
            "legacy-only, new-only and both-consistent forms must stay distinct: {hashes:?}"
        );
        assert_eq!(
            policy_hash(&legacy_only),
            GOLDEN_ONE_SHOT_LEGACY_ACKNOWLEDGMENT,
            "the legacy form keeps its historical identity",
        );
    }

    #[test]
    fn one_shot_acknowledgment_separates_absent_empty_and_authored_network() {
        // An omitted network section, `network: {}`, and an explicitly authored
        // directional deny normalize to identical policy VALUES; only the
        // parse-derived presence flags tell them apart, and those flags are
        // `#[serde(skip)]`. The acknowledgment projection must not collapse
        // them, because the first is accepted and the others are refused.
        let absent = acknowledged_one_shot();

        let mut empty_section = absent.clone();
        empty_section.policy.network_specified = true;

        let mut authored_deny = empty_section.clone();
        authored_deny.policy.network_mode_specified = true;

        let mut runtime_proxy_only = absent.clone();
        runtime_proxy_only.policy.runtime_network_proxy_specified = true;

        let projected = |request: &ExecutionRequest| policy_projection(request)["policy"].clone();
        assert_eq!(
            projected(&absent),
            projected(&empty_section),
            "the collision this test guards must actually exist",
        );
        assert_eq!(projected(&absent), projected(&authored_deny));
        assert_eq!(projected(&absent), projected(&runtime_proxy_only));

        let hashes = [
            policy_hash(&absent),
            policy_hash(&empty_section),
            policy_hash(&authored_deny),
            policy_hash(&runtime_proxy_only),
        ];
        let unique: std::collections::HashSet<_> = hashes.iter().collect();
        assert_eq!(
            unique.len(),
            hashes.len(),
            "authored presence must survive into the identity: {hashes:?}"
        );
    }

    #[test]
    fn presence_flags_only_reach_the_hash_through_an_acknowledgment() {
        // Without an acknowledgment the flags stay skipped, so no other
        // backend's identity moves.
        let mut baseline = golden_one_shot_process_container();
        implicit_directional_defaults(&mut baseline.policy);
        let mut flagged = baseline.clone();
        flagged.policy.network_specified = true;
        flagged.policy.network_mode_specified = true;
        flagged.policy.runtime_network_proxy_specified = true;
        flagged.policy.ui_specified = true;
        assert_eq!(policy_hash(&baseline), policy_hash(&flagged));
    }

    #[test]
    fn state_aware_acknowledgment_forms_have_distinct_identities() {
        let request = golden_state_aware_request();
        let acknowledged = IsolationSessionProvisionConfig {
            acknowledge_unrestricted_network: Some(
                crate::models::UnrestrictedNetworkAcknowledgment,
            ),
            ..Default::default()
        };

        let mut unauthored = golden_state_aware_request();
        unauthored.policy = crate::models::ContainerPolicy::default();
        implicit_directional_defaults(&mut unauthored.policy);

        let mut authored_empty = unauthored.clone();
        authored_empty.policy.network_specified = true;

        let hashes = [
            // legacy-only: canonical allow policy, no acknowledgment field
            state_aware_policy_hash(
                &request,
                "isolation_session",
                &isolation_session_provision(Some(IsolationSessionProvisionConfig::default())),
            ),
            // both-consistent: canonical allow policy plus the acknowledgment
            state_aware_policy_hash(
                &request,
                "isolation_session",
                &isolation_session_provision(Some(acknowledged.clone())),
            ),
            // new-only: acknowledgment with no authored network
            state_aware_policy_hash(
                &unauthored,
                "isolation_session",
                &isolation_session_provision(Some(acknowledged.clone())),
            ),
            // refused shape: acknowledgment plus an authored empty section
            state_aware_policy_hash(
                &authored_empty,
                "isolation_session",
                &isolation_session_provision(Some(acknowledged)),
            ),
        ];
        let unique: std::collections::HashSet<_> = hashes.iter().collect();
        assert_eq!(
            unique.len(),
            hashes.len(),
            "acknowledgment and authored presence must all be distinguishable: {hashes:?}"
        );
        assert_eq!(
            hashes[0], GOLDEN_PROVISION_CONFIG_EMPTY,
            "the acknowledgment-free provision config keeps its identity",
        );
    }

    #[test]
    fn acknowledgment_projection_appears_only_for_acknowledged_requests() {
        let unacknowledged = policy_projection(&golden_one_shot_legacy_acknowledgment());
        assert!(unacknowledged
            .get("unrestrictedNetworkAcknowledgment")
            .is_none());
        assert_eq!(
            unacknowledged["experimental"]["isolation_session"],
            Value::Null
        );

        let acknowledged = policy_projection(&acknowledged_one_shot());
        assert_eq!(
            acknowledged["unrestrictedNetworkAcknowledgment"],
            serde_json::json!({
                "networkSpecified": false,
                "networkModeSpecified": false,
                "runtimeNetworkProxySpecified": false,
            })
        );
        assert_eq!(
            acknowledged["experimental"]["isolation_session"],
            serde_json::json!({"acknowledgeUnrestrictedNetwork": true})
        );
    }

    #[test]
    fn acknowledgment_does_not_admit_credentials_or_sandbox_ids() {
        let mut baseline = acknowledged_one_shot();
        baseline.script_code = "curl -H \"Authorization: synthetic-secret\"".to_string();
        baseline.env = Some(vec!["API_KEY=synthetic-environment-secret".to_string()]);

        let mut changed = acknowledged_one_shot();
        changed.script_code = "echo other".to_string();
        changed.env = Some(vec!["API_KEY=other-synthetic-secret".to_string()]);
        assert_eq!(
            policy_hash(&baseline),
            policy_hash(&changed),
            "command and environment stay excluded for acknowledged requests"
        );

        let request = golden_state_aware_request();
        let acknowledged = IsolationSessionProvisionConfig {
            acknowledge_unrestricted_network: Some(
                crate::models::UnrestrictedNetworkAcknowledgment,
            ),
            ..Default::default()
        };
        assert_eq!(
            state_aware_policy_hash(
                &request,
                "isolation_session",
                &isolation_session_provision(Some(acknowledged.clone())),
            ),
            state_aware_policy_hash(
                &request,
                "isolation_session",
                &isolation_session_provision(Some(acknowledged)),
            ),
            "no sandbox id or other unverified identity enters the projection"
        );
    }

    #[test]
    fn state_aware_hash_excludes_credentials_and_unverified_ids() {
        let baseline = parse_state_aware(
            r#"{
                "version":"0.9.0-alpha",
                "phase":"exec",
                "sandboxId":"wslc:0123456789abcdef0123456789abcdef",
                "process":{"commandLine":"echo hello"},
                "network":{"proxy":{"url":"http://localhost:8080"}}
            }"#,
        );
        let mut changed = parse_state_aware(
            r#"{
                "version":"0.9.0-alpha",
                "phase":"exec",
                "sandboxId":"wslc:alice@example.test",
                "process":{
                    "commandLine":"echo synthetic-command-secret",
                    "env":["API_KEY=synthetic-environment-secret"]
                },
                "network":{"proxy":{"url":"http://alice:synthetic-password@localhost:8080"}},
                "telemetry":{"enabled":true},
                "_comment":{"user":{"wamToken":"synthetic-comment-secret"}}
            }"#,
        );
        changed.set_dry_run(true);
        assert_eq!(
            state_aware_policy_hash(baseline.request(), "wslc", baseline.operation()),
            state_aware_policy_hash(changed.request(), "wslc", changed.operation()),
            "command, env, proxy userinfo, telemetry, comments, dry-run and unverified IDs are excluded"
        );
    }
}
