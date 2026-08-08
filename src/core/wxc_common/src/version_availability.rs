// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Per-field schema-availability ranges — the runtime half of
//! `#[derive(VersionAvailability)]`.
//!
//! An availability range is the inclusive span of config schema versions a wire
//! field may be used: `since = "0.8"` rejects it in an older config,
//! `until = "0.7"` rejects it in a newer one. Both compare `major.minor` only,
//! matching the parser's supported-range check.
//!
//! Annotation is opt-in — an unannotated field is valid across the whole
//! supported range — and adding one is a behavioural change, not bookkeeping.
//! See `docs/versioning.md#version-availability` for the design and for why a
//! field's first appearance in the JSON Schema is *not* the same as its first
//! appearance in the accepted surface.

use std::fmt;

use serde_json::Value;

/// A `major.minor` schema-version bound.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct MajorMinor {
    pub major: u64,
    pub minor: u64,
}

impl MajorMinor {
    pub const fn new(major: u64, minor: u64) -> Self {
        Self { major, minor }
    }

    /// Parse the `major.minor` line of a full SemVer config version, discarding
    /// patch and pre-release. Shared so the parser's gate and the SDK config
    /// builders derive it one way.
    pub fn parse_semver(version: &str) -> Option<Self> {
        let parsed = semver::Version::parse(version).ok()?;
        Some(Self::new(parsed.major, parsed.minor))
    }
}

impl fmt::Display for MajorMinor {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}.{}", self.major, self.minor)
    }
}

/// The inclusive version range a field may be used in. `None` on either side
/// means unbounded in that direction.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Availability {
    pub since: Option<MajorMinor>,
    pub until: Option<MajorMinor>,
}

impl Availability {
    /// The range of an unannotated field: valid everywhere.
    pub const UNBOUNDED: Self = Self {
        since: None,
        until: None,
    };

    pub fn admits(&self, declared: MajorMinor) -> bool {
        self.check(declared).is_ok()
    }

    fn check(&self, declared: MajorMinor) -> Result<(), ViolationKind> {
        if let Some(since) = self.since {
            if declared < since {
                return Err(ViolationKind::NotYetIntroduced);
            }
        }
        if let Some(until) = self.until {
            if declared > until {
                return Err(ViolationKind::Retired);
            }
        }
        Ok(())
    }

    fn is_annotated(&self) -> bool {
        self.since.is_some() || self.until.is_some()
    }
}

/// One deserialisable wire field: how it is spelled on the wire, its range,
/// and how to reach the nested type's node.
#[derive(Debug, Clone, Copy)]
pub struct FieldAvailability {
    pub rust_name: &'static str,
    /// The primary JSON key, exactly as `serde` spells it.
    pub name: &'static str,
    /// Extra spellings from `#[serde(alias = ...)]`. An alias is the *same*
    /// field, so it shares this availability range and is not separately annotatable.
    pub aliases: &'static [&'static str],
    pub availability: Availability,
    /// The nested type's node, or `None` for a leaf.
    pub nested: fn() -> Option<&'static NodeAvailability>,
}

impl FieldAvailability {
    fn matches(&self, key: &str) -> bool {
        self.name == key || self.aliases.contains(&key)
    }
}

/// The availability metadata for one wire struct.
#[derive(Debug, Clone, Copy)]
pub struct NodeAvailability {
    pub type_name: &'static str,
    pub fields: &'static [FieldAvailability],
}

impl NodeAvailability {
    pub fn field(&self, key: &str) -> Option<&'static FieldAvailability> {
        self.fields.iter().find(|f| f.matches(key))
    }
}

/// Implemented for every wire type. Structs return their node; leaves return
/// `None`.
///
/// The leaf impls are explicit rather than a blanket impl so a new wire field
/// whose type has no impl fails to compile, forcing an answer to "does it nest?".
pub trait VersionAvailability {
    fn availability() -> Option<&'static NodeAvailability>;
}

macro_rules! leaf {
    ($($ty:ty),* $(,)?) => {
        $(impl VersionAvailability for $ty {
            fn availability() -> Option<&'static NodeAvailability> { None }
        })*
    };
}

leaf!(
    bool,
    char,
    i8,
    i16,
    i32,
    i64,
    i128,
    isize,
    u8,
    u16,
    u32,
    u64,
    u128,
    usize,
    f32,
    f64,
    String,
    serde_json::Value,
);

impl<T: VersionAvailability> VersionAvailability for Option<T> {
    fn availability() -> Option<&'static NodeAvailability> {
        T::availability()
    }
}

impl<T: VersionAvailability> VersionAvailability for Vec<T> {
    fn availability() -> Option<&'static NodeAvailability> {
        T::availability()
    }
}

impl<T: VersionAvailability> VersionAvailability for Box<T> {
    fn availability() -> Option<&'static NodeAvailability> {
        T::availability()
    }
}

// ---------------------------------------------------------------------------
// Violations
// ---------------------------------------------------------------------------

/// Which side of the range was breached.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ViolationKind {
    NotYetIntroduced,
    Retired,
}

/// A structured version incompatibility, carrying enough to render the wire
/// `details` object without re-parsing a message. Models the supported-range
/// failure too (`field: "version"`), so both classes share one error code.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VersionIncompatibility {
    /// Dotted JSON path of the offending field, or `"version"`.
    pub field: String,
    /// As written in the config; callers must escape it for diagnostics first.
    pub declared_version: String,
    pub since: Option<String>,
    pub until: Option<String>,
    pub message: String,
}

impl VersionIncompatibility {
    /// The wire `details` object. Absent bounds emit JSON `null` so the key set
    /// is stable for consumers.
    pub fn details(&self) -> Value {
        serde_json::json!({
            "field": self.field,
            "declaredVersion": self.declared_version,
            "since": self.since,
            "until": self.until,
        })
    }
}

impl fmt::Display for VersionIncompatibility {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.message)
    }
}

// ---------------------------------------------------------------------------
// Document validation
// ---------------------------------------------------------------------------

/// Validate every populated field in `document` against its range.
///
/// `declared_raw` is used verbatim in messages, so callers must escape it for
/// diagnostics first.
///
/// Traversal is driven by the *document*, so it covers nested objects, arrays
/// and `experimental`. Keys with no matching field carry no range and are
/// skipped; closed structs reject them during typed deserialisation anyway. A
/// JSON `null` counts as **absent**, matching how serde maps it to `None`.
pub fn validate_document(
    document: &Value,
    declared: MajorMinor,
    declared_raw: &str,
    root: &'static NodeAvailability,
) -> Result<(), VersionIncompatibility> {
    let mut path = String::new();
    walk(document, declared, declared_raw, root, &mut path)
}

fn walk(
    value: &Value,
    declared: MajorMinor,
    declared_raw: &str,
    node: &'static NodeAvailability,
    path: &mut String,
) -> Result<(), VersionIncompatibility> {
    let Value::Object(map) = value else {
        // Typed deserialisation reports a wrong-shaped value with full path.
        return Ok(());
    };

    for (key, child) in map {
        let Some(field) = node.field(key) else {
            continue;
        };
        if child.is_null() {
            continue;
        }

        let restore = path.len();
        if !path.is_empty() {
            path.push('.');
        }
        // Report the spelling the config used, so an alias names itself.
        path.push_str(key);

        if let Err(kind) = field.availability.check(declared) {
            return Err(incompatibility(
                kind,
                path,
                declared_raw,
                &field.availability,
            ));
        }

        if let Some(nested) = (field.nested)() {
            walk_value(child, declared, declared_raw, nested, path)?;
        }

        path.truncate(restore);
    }

    Ok(())
}

/// Descend into a field's value: objects walked directly, arrays per element.
///
/// Arrays recurse through *any* depth — `Vec<Vec<Inner>>` is a shape serde
/// accepts, and stopping at the outer array would leave `Inner`'s ranges
/// unchecked, i.e. silently fail open.
fn walk_value(
    value: &Value,
    declared: MajorMinor,
    declared_raw: &str,
    node: &'static NodeAvailability,
    path: &mut String,
) -> Result<(), VersionIncompatibility> {
    match value {
        Value::Object(_) => walk(value, declared, declared_raw, node, path),
        Value::Array(items) => {
            for (index, item) in items.iter().enumerate() {
                let restore = path.len();
                path.push_str(&format!("[{index}]"));
                walk_value(item, declared, declared_raw, node, path)?;
                path.truncate(restore);
            }
            Ok(())
        }
        _ => Ok(()),
    }
}

fn incompatibility(
    kind: ViolationKind,
    field: &str,
    declared_raw: &str,
    availability: &Availability,
) -> VersionIncompatibility {
    let message = match kind {
        ViolationKind::NotYetIntroduced => {
            let since = availability
                .since
                .expect("NotYetIntroduced implies a since bound");
            format!(
                "Config field '{field}' was introduced in schema version {since} but the config \
                 declares '{declared_raw}'. Raise the config's 'version' to {since} or newer, or \
                 remove the field."
            )
        }
        ViolationKind::Retired => {
            let until = availability.until.expect("Retired implies an until bound");
            format!(
                "Config field '{field}' is not supported in schema version '{declared_raw}'; it \
                 was retired after {until}. Use the replacement field for this version, or \
                 declare a 'version' of {until} or older."
            )
        }
    };
    VersionIncompatibility {
        field: field.to_string(),
        declared_version: declared_raw.to_string(),
        since: availability.since.map(|v| v.to_string()),
        until: availability.until.map(|v| v.to_string()),
        message,
    }
}

/// Every annotated field in `node` and its descendants, as dotted paths.
///
/// Array nesting is not marked: a field inside `Vec<T>` is `parent.child`, not
/// `parent[].child`. Consumers normalise the schema side the same way.
pub fn declared_availability(root: &'static NodeAvailability) -> Vec<(String, Availability)> {
    let mut out = Vec::new();
    let mut path = String::new();
    let mut stack = Vec::new();
    collect(root, &mut path, &mut out, &mut stack);
    out
}

fn collect(
    node: &'static NodeAvailability,
    path: &mut String,
    out: &mut Vec<(String, Availability)>,
    stack: &mut Vec<&'static str>,
) {
    // Acyclic today; guard so a future self-referential type truncates rather
    // than hangs.
    if stack.contains(&node.type_name) {
        return;
    }
    stack.push(node.type_name);
    for field in node.fields {
        let restore = path.len();
        if !path.is_empty() {
            path.push('.');
        }
        path.push_str(field.name);
        if field.availability.is_annotated() {
            out.push((path.clone(), field.availability));
        }
        if let Some(nested) = (field.nested)() {
            collect(nested, path, out, stack);
        }
        path.truncate(restore);
    }
    stack.pop();
}

/// Every distinct node reachable from `root`, deduplicated by type name.
///
/// A struct reached from two places (`Seatbelt` is both the top-level section
/// and `experimental.seatbelt`) appears once, because it *is* one node — which
/// is why a range belongs on the containing field, not inside a shared struct.
pub fn all_nodes(root: &'static NodeAvailability) -> Vec<&'static NodeAvailability> {
    let mut out: Vec<&'static NodeAvailability> = Vec::new();
    let mut queue = vec![root];
    while let Some(node) = queue.pop() {
        if out.iter().any(|seen| seen.type_name == node.type_name) {
            continue;
        }
        out.push(node);
        for field in node.fields {
            if let Some(nested) = (field.nested)() {
                queue.push(nested);
            }
        }
    }
    out.sort_by_key(|node| node.type_name);
    out
}

/// Every annotated field, as `(owning type name, JSON key, range)`. Keyed by
/// type because that is how the schema is organised
/// (`definitions.<TypeName>.properties.<key>`).
pub fn annotated_fields(
    root: &'static NodeAvailability,
) -> Vec<(&'static str, &'static str, Availability)> {
    let mut out = Vec::new();
    for node in all_nodes(root) {
        for field in node.fields {
            if field.availability.is_annotated() {
                out.push((node.type_name, field.name, field.availability));
            }
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use mxc_version_derive::VersionAvailability;
    use serde::Deserialize;
    use serde_json::json;

    // A miniature wire model exercising the machinery end to end: renamed keys,
    // an alias, nesting, arrays, and both range directions. Fields exist to be
    // deserialised, not read, hence `allow(dead_code)`.
    #[derive(Debug, Deserialize, VersionAvailability)]
    #[serde(rename_all = "camelCase", deny_unknown_fields)]
    #[allow(dead_code)]
    struct Root {
        version: Option<String>,
        #[mxc_version(until = "0.7")]
        default_policy: Option<String>,
        #[mxc_version(since = "0.8")]
        egress: Option<Egress>,
        plain_field: Option<String>,
        #[serde(alias = "legacySection")]
        section: Option<Section>,
        #[serde(rename = "$schema")]
        schema: Option<String>,
    }

    #[derive(Debug, Deserialize, VersionAvailability)]
    #[serde(rename_all = "camelCase", deny_unknown_fields)]
    #[allow(dead_code)]
    struct Egress {
        rules: Option<Vec<Rule>>,
    }

    #[derive(Debug, Deserialize, VersionAvailability)]
    #[serde(rename_all = "camelCase", deny_unknown_fields)]
    #[allow(dead_code)]
    struct Rule {
        cidr: Option<String>,
        #[mxc_version(since = "0.9")]
        except: Option<Vec<String>>,
    }

    #[derive(Debug, Deserialize, VersionAvailability)]
    #[serde(rename_all = "camelCase", deny_unknown_fields)]
    #[allow(dead_code)]
    struct Section {
        #[mxc_version(until = "0.7")]
        retired_leaf: Option<bool>,
        kept: Option<bool>,
    }

    #[derive(Debug, Deserialize, VersionAvailability)]
    #[serde(rename_all = "lowercase")]
    #[allow(dead_code)]
    enum Leaf {
        A,
        B,
    }

    fn root() -> &'static NodeAvailability {
        Root::availability().expect("a struct derives a node")
    }

    fn check(doc: serde_json::Value, version: &str) -> Result<(), VersionIncompatibility> {
        let (major, minor) = version
            .split_once('.')
            .map(|(a, b)| {
                (
                    a.parse().unwrap(),
                    b.split(['.', '-']).next().unwrap().parse().unwrap(),
                )
            })
            .unwrap();
        validate_document(&doc, MajorMinor::new(major, minor), version, root())
    }

    #[test]
    fn enums_are_leaves() {
        assert!(Leaf::availability().is_none());
    }

    #[test]
    fn derived_json_names_follow_serde() {
        let names: Vec<_> = root().fields.iter().map(|f| f.name).collect();
        assert!(names.contains(&"defaultPolicy"), "{names:?}");
        assert!(names.contains(&"plainField"), "{names:?}");
        assert!(names.contains(&"$schema"), "{names:?}");
    }

    #[test]
    fn unannotated_field_is_valid_across_the_whole_range() {
        for version in ["0.6.0-alpha", "0.7.0-alpha", "0.8.0-alpha"] {
            assert!(
                check(json!({"plainField": "x"}), version).is_ok(),
                "{version}"
            );
        }
    }

    #[test]
    fn until_field_is_accepted_at_and_below_its_bound() {
        for version in ["0.6.0-alpha", "0.7.0-alpha"] {
            assert!(
                check(json!({"defaultPolicy": "block"}), version).is_ok(),
                "{version}"
            );
        }
    }

    #[test]
    fn until_field_is_rejected_above_its_bound() {
        let err = check(json!({"defaultPolicy": "block"}), "0.8.0-alpha").unwrap_err();
        assert_eq!(err.field, "defaultPolicy");
        assert_eq!(err.until.as_deref(), Some("0.7"));
        assert_eq!(err.since, None);
        assert_eq!(err.declared_version, "0.8.0-alpha");
        assert!(err.message.contains("retired after 0.7"), "{}", err.message);
    }

    #[test]
    fn since_field_is_rejected_below_its_bound() {
        for version in ["0.6.0-alpha", "0.7.0-alpha"] {
            let err = check(json!({"egress": {}}), version).unwrap_err();
            assert_eq!(err.field, "egress");
            assert_eq!(err.since.as_deref(), Some("0.8"));
            assert!(err.message.contains("introduced in schema version 0.8"));
        }
    }

    #[test]
    fn since_field_is_accepted_at_and_above_its_bound() {
        assert!(check(json!({"egress": {}}), "0.8.0-alpha").is_ok());
    }

    #[test]
    fn nested_fields_are_checked() {
        let err = check(json!({"section": {"retiredLeaf": true}}), "0.8.0-alpha").unwrap_err();
        assert_eq!(err.field, "section.retiredLeaf");
    }

    #[test]
    fn nested_field_under_an_alias_reports_the_spelling_used() {
        let err = check(
            json!({"legacySection": {"retiredLeaf": true}}),
            "0.8.0-alpha",
        )
        .unwrap_err();
        assert_eq!(err.field, "legacySection.retiredLeaf");
    }

    #[test]
    fn an_alias_shares_its_field_availability() {
        // `section` itself is unannotated, so both spellings are accepted.
        assert!(check(json!({"legacySection": {"kept": true}}), "0.6.0-alpha").is_ok());
    }

    #[test]
    fn array_elements_are_checked_and_indexed() {
        let doc =
            json!({"egress": {"rules": [{"cidr": "10.0.0.0/8"}, {"except": ["10.1.0.0/16"]}]}});
        let err = check(doc, "0.8.0-alpha").unwrap_err();
        assert_eq!(err.field, "egress.rules[1].except");
        assert_eq!(err.since.as_deref(), Some("0.9"));
    }

    #[test]
    fn null_counts_as_absent() {
        // serde maps `null` to `None`, so treating it as use would reject a
        // config that explicitly nulls a field it does not set.
        assert!(check(json!({"defaultPolicy": null}), "0.8.0-alpha").is_ok());
        assert!(check(json!({"egress": null}), "0.6.0-alpha").is_ok());
    }

    #[test]
    fn an_empty_object_still_counts_as_use() {
        assert!(check(json!({"egress": {}}), "0.6.0-alpha").is_err());
    }

    #[test]
    fn unknown_keys_carry_no_availability() {
        assert!(check(json!({"totallyUnknown": {"whatever": 1}}), "0.6.0-alpha").is_ok());
    }

    #[test]
    fn non_object_values_do_not_panic() {
        assert!(check(json!({"section": 42}), "0.6.0-alpha").is_ok());
        assert!(check(json!({"egress": {"rules": "not-an-array"}}), "0.8.0-alpha").is_ok());
        assert!(check(json!({"egress": {"rules": [1, 2, 3]}}), "0.8.0-alpha").is_ok());
    }

    #[test]
    fn nested_arrays_are_still_checked() {
        // Regression: descending only into direct array elements skipped
        // `Vec<Vec<_>>` entirely — a silent fail-open.
        let doc = json!({"egress": {"rules": [[{"except": ["10.0.0.0/8"]}]]}});
        let err = check(doc, "0.8.0-alpha").unwrap_err();
        assert_eq!(err.field, "egress.rules[0][0].except");
        assert_eq!(err.since.as_deref(), Some("0.9"));
    }

    #[test]
    fn deeply_nested_arrays_are_checked_at_every_level() {
        let doc = json!({"egress": {"rules": [[[{"except": []}]]]}});
        let err = check(doc, "0.8.0-alpha").unwrap_err();
        assert_eq!(err.field, "egress.rules[0][0][0].except");
    }

    #[test]
    fn availability_admits_matches_check() {
        let w = Availability {
            since: Some(MajorMinor::new(0, 7)),
            until: Some(MajorMinor::new(0, 8)),
        };
        assert!(!w.admits(MajorMinor::new(0, 6)));
        assert!(w.admits(MajorMinor::new(0, 7)));
        assert!(w.admits(MajorMinor::new(0, 8)));
        assert!(!w.admits(MajorMinor::new(0, 9)));
        assert!(Availability::UNBOUNDED.admits(MajorMinor::new(1, 0)));
    }

    #[test]
    fn bounds_are_inclusive_on_both_sides() {
        assert!(check(json!({"defaultPolicy": "block"}), "0.7.0-alpha").is_ok());
        assert!(check(json!({"egress": {}}), "0.8.0-alpha").is_ok());
    }

    #[test]
    fn details_carries_the_stable_key_set() {
        let err = check(json!({"defaultPolicy": "block"}), "0.8.0-alpha").unwrap_err();
        assert_eq!(
            err.details(),
            json!({
                "field": "defaultPolicy",
                "declaredVersion": "0.8.0-alpha",
                "since": null,
                "until": "0.7",
            })
        );
    }

    #[test]
    fn declared_availability_lists_annotated_paths_only() {
        let listed: Vec<String> = declared_availability(root())
            .into_iter()
            .map(|(path, _)| path)
            .collect();
        assert!(listed.contains(&"defaultPolicy".to_string()));
        assert!(listed.contains(&"egress".to_string()));
        assert!(listed.contains(&"egress.rules.except".to_string()));
        assert!(listed.contains(&"section.retiredLeaf".to_string()));
        assert!(!listed.contains(&"plainField".to_string()));
    }
}
