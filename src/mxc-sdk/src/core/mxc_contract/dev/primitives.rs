// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use serde::{de, Deserialize, Deserializer};

/// Deserialize a present optional settings object without accepting Serde's
/// positional-array representation of structs.
pub(crate) fn deserialize_optional_object<'de, D, T>(
    deserializer: D,
) -> Result<OptionalField<T>, D::Error>
where
    D: Deserializer<'de>,
    T: Deserialize<'de>,
{
    struct ObjectVisitor<T>(std::marker::PhantomData<T>);

    impl<'de, T: Deserialize<'de>> de::Visitor<'de> for ObjectVisitor<T> {
        type Value = OptionalField<T>;

        fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            formatter.write_str("a settings object")
        }

        fn visit_map<A: de::MapAccess<'de>>(self, map: A) -> Result<Self::Value, A::Error> {
            T::deserialize(de::value::MapAccessDeserializer::new(map)).map(OptionalField::present)
        }
    }

    deserializer.deserialize_map(ObjectVisitor(std::marker::PhantomData))
}

/// A marker that deserializes only from the JSON value `true`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct True;

#[cfg(feature = "schema-gen")]
impl schemars::JsonSchema for True {
    fn schema_name() -> String {
        "True".to_string()
    }

    fn json_schema(_generator: &mut schemars::gen::SchemaGenerator) -> schemars::schema::Schema {
        use schemars::schema::{InstanceType, Schema, SchemaObject, SingleOrVec};

        Schema::Object(SchemaObject {
            instance_type: Some(SingleOrVec::Single(Box::new(InstanceType::Boolean))),
            enum_values: Some(vec![serde_json::Value::Bool(true)]),
            ..Default::default()
        })
    }
}

impl<'de> Deserialize<'de> for True {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        if bool::deserialize(deserializer)? {
            Ok(Self)
        } else {
            Err(de::Error::custom("expected true"))
        }
    }
}

/// An optional JSON field that distinguishes omission from explicit `null`.
///
/// A missing field becomes an empty `OptionalField` through Serde's `default`
/// handling. A present field must deserialize as `T`; explicit `null` is
/// therefore rejected unless `T` itself accepts it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OptionalField<T>(Option<T>);

#[cfg(feature = "schema-gen")]
impl<T> schemars::JsonSchema for OptionalField<T>
where
    T: schemars::JsonSchema,
{
    fn schema_name() -> String {
        T::schema_name()
    }

    fn json_schema(generator: &mut schemars::gen::SchemaGenerator) -> schemars::schema::Schema {
        generator.subschema_for::<T>()
    }

    fn is_referenceable() -> bool {
        false
    }
}

impl<T> Default for OptionalField<T> {
    fn default() -> Self {
        Self(None)
    }
}

impl<T> OptionalField<T> {
    /// Construct a field that is present with `value`.
    pub fn present(value: T) -> Self {
        Self(Some(value))
    }

    /// Returns a shared reference to the value when the field was present.
    pub fn as_ref(&self) -> Option<&T> {
        self.0.as_ref()
    }

    /// Converts the field into its optional value.
    pub fn into_option(self) -> Option<T> {
        self.0
    }
}

impl<'de, T> Deserialize<'de> for OptionalField<T>
where
    T: Deserialize<'de>,
{
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        T::deserialize(deserializer).map(|value| Self(Some(value)))
    }
}

/// A non-empty string.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NonEmptyString(String);

#[cfg(feature = "schema-gen")]
impl schemars::JsonSchema for NonEmptyString {
    fn schema_name() -> String {
        "NonEmptyString".to_string()
    }

    fn json_schema(_generator: &mut schemars::gen::SchemaGenerator) -> schemars::schema::Schema {
        use schemars::schema::{InstanceType, Schema, SchemaObject, SingleOrVec, StringValidation};

        Schema::Object(SchemaObject {
            instance_type: Some(SingleOrVec::Single(Box::new(InstanceType::String))),
            string: Some(Box::new(StringValidation {
                min_length: Some(1),
                ..Default::default()
            })),
            ..Default::default()
        })
    }
}

impl NonEmptyString {
    /// Creates a validated string.
    ///
    /// Returns an error when `value` is empty.
    pub fn new(value: String) -> Result<Self, String> {
        if value.is_empty() {
            Err("string must not be empty".to_string())
        } else {
            Ok(Self(value))
        }
    }

    /// Returns the validated string as a borrowed string slice.
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// Consumes the wrapper and returns the validated string.
    pub fn into_inner(self) -> String {
        self.0
    }
}

impl<'de> Deserialize<'de> for NonEmptyString {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value = String::deserialize(deserializer)?;
        Self::new(value).map_err(de::Error::custom)
    }
}

/// An image reference with an explicit registry. The runtime validates its
/// complete syntax.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ImageReference(String);

impl ImageReference {
    /// Validate image input before any backend state is opened.
    pub fn new(value: String) -> Result<Self, String> {
        Self::validate(&value, "image")?;
        Ok(Self(value))
    }

    /// Require a registry and repository without validating the complete
    /// reference. `field` names the input in the error, such as `aci.image`.
    pub fn validate(value: &str, field: &str) -> Result<(), String> {
        if value.is_empty()
            || value
                .chars()
                .any(|c| c.is_whitespace() || c.is_control() || c == '\u{feff}')
        {
            return Err(format!("{field} must be a nonempty image reference without whitespace or control characters"));
        }
        let valid_registry = |registry: &str| {
            registry == "localhost"
                || registry
                    .char_indices()
                    .any(|(index, c)| c == '.' && index > 0 && index + 1 < registry.len())
                || registry.rsplit_once(':').is_some_and(|(host, port)| {
                    !host.is_empty()
                        && !port.is_empty()
                        && port.bytes().all(|byte| byte.is_ascii_digit())
                })
        };
        if !value.split_once('/').is_some_and(|(registry, repository)| {
            valid_registry(registry)
                && repository
                    .chars()
                    .next()
                    .is_some_and(|c| !matches!(c, '/' | ':' | '@'))
        }) {
            return Err(format!("{field} must include a registry host and image repository, such as docker.io/library/python:3.12-alpine"));
        }
        Ok(())
    }

    /// Consume the validated input.
    pub fn into_inner(self) -> String {
        self.0
    }
}

impl<'de> Deserialize<'de> for ImageReference {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        Self::new(String::deserialize(deserializer)?).map_err(de::Error::custom)
    }
}

#[cfg(feature = "schema-gen")]
impl schemars::JsonSchema for ImageReference {
    fn schema_name() -> String {
        "ImageReference".to_owned()
    }

    fn json_schema(generator: &mut schemars::gen::SchemaGenerator) -> schemars::schema::Schema {
        let mut schema = <String as schemars::JsonSchema>::json_schema(generator).into_object();
        let string = schema.string.get_or_insert_with(Default::default);
        string.min_length = Some(1);
        string.pattern = Some(
            r"^(?:localhost|[^\s\x00-\x1f\x7f-\x9f/][^\s\x00-\x1f\x7f-\x9f/.]*\.[^\s\x00-\x1f\x7f-\x9f/]+|[^\s\x00-\x1f\x7f-\x9f/]+:[0-9]+)/[^/:\u0040\s\x00-\x1f\x7f-\x9f][^\s\x00-\x1f\x7f-\x9f]*(?![\s\S])".to_owned(),
        );
        schema.into()
    }
}

/// The ARM resource ID of an Azure Container Instances (ACI) sandbox group,
/// `/subscriptions/<id>/resourceGroups/<name>/providers/Microsoft.ContainerInstance/sandboxGroups/<name>`.
///
/// Fixed segments match case-insensitively, as in ARM. The subscription is a
/// GUID and the names use ASCII letters, digits, and `._()-`, so the ID can
/// be placed in a request URL without escaping.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AciSandboxGroupId(String);

impl AciSandboxGroupId {
    const SHAPE: &'static str = "/subscriptions/<subscription-id>/resourceGroups/<resource-group>/providers/Microsoft.ContainerInstance/sandboxGroups/<sandbox-group>";
    const MAX_RESOURCE_GROUP_LEN: usize = 90;
    const MAX_NAME_LEN: usize = 260;

    /// Validate a sandbox group ID before any backend state is opened.
    pub fn new(value: String) -> Result<Self, String> {
        Self::validate(&value)?;
        Ok(Self(value))
    }

    /// Require the ARM resource ID shape described on [`AciSandboxGroupId`].
    pub fn validate(value: &str) -> Result<(), String> {
        let invalid = || {
            format!(
                "sandbox group must be an ARM resource ID of the form {}",
                Self::SHAPE
            )
        };
        let segments: Vec<&str> = value
            .strip_prefix('/')
            .ok_or_else(invalid)?
            .split('/')
            .collect();
        let [subscriptions, subscription, resource_groups, resource_group, providers, namespace, sandbox_groups, name] =
            segments.as_slice()
        else {
            return Err(invalid());
        };
        let fixed = [
            (subscriptions, "subscriptions"),
            (resource_groups, "resourceGroups"),
            (providers, "providers"),
            (namespace, "Microsoft.ContainerInstance"),
            (sandbox_groups, "sandboxGroups"),
        ];
        if fixed
            .iter()
            .any(|(actual, expected)| !actual.eq_ignore_ascii_case(expected))
        {
            return Err(invalid());
        }
        if !is_guid(subscription) {
            return Err("sandbox group subscription ID must be a GUID".to_owned());
        }
        let resource_group_char =
            |c: char| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '(' | ')' | '-');
        if resource_group.is_empty()
            || resource_group.len() > Self::MAX_RESOURCE_GROUP_LEN
            || !resource_group.chars().all(resource_group_char)
            || resource_group.ends_with('.')
        {
            return Err(format!(
                "sandbox group resource group name must be 1-{} ASCII letters, digits, or `._()-` and must not end with `.`",
                Self::MAX_RESOURCE_GROUP_LEN
            ));
        }
        let name_char = |c: char| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-');
        if name.len() > Self::MAX_NAME_LEN
            || !name.starts_with(|c: char| c.is_ascii_alphanumeric())
            || !name.chars().all(name_char)
        {
            return Err(format!(
                "sandbox group name must be 1-{} ASCII letters, digits, or `._-` and start with a letter or digit",
                Self::MAX_NAME_LEN
            ));
        }
        Ok(())
    }

    /// Returns the validated resource ID.
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// Consume the validated input.
    pub fn into_inner(self) -> String {
        self.0
    }
}

fn is_guid(value: &str) -> bool {
    value.len() == 36
        && value.char_indices().all(|(index, c)| match index {
            8 | 13 | 18 | 23 => c == '-',
            _ => c.is_ascii_hexdigit(),
        })
}

impl<'de> Deserialize<'de> for AciSandboxGroupId {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        Self::new(String::deserialize(deserializer)?).map_err(de::Error::custom)
    }
}

#[cfg(feature = "schema-gen")]
impl schemars::JsonSchema for AciSandboxGroupId {
    fn schema_name() -> String {
        "AciSandboxGroupId".to_owned()
    }

    fn json_schema(generator: &mut schemars::gen::SchemaGenerator) -> schemars::schema::Schema {
        // JSON Schema patterns have no case-insensitive flag, so fixed ARM
        // segments are spelled as per-letter character classes.
        let any_case = |literal: &str| -> String {
            literal
                .chars()
                .map(|c| match c {
                    c if c.is_ascii_alphabetic() => {
                        format!("[{}{}]", c.to_ascii_lowercase(), c.to_ascii_uppercase())
                    }
                    '.' => r"\.".to_owned(),
                    c => c.to_string(),
                })
                .collect()
        };
        let hex = |count: usize| format!("[0-9a-fA-F]{{{count}}}");
        let mut schema = <String as schemars::JsonSchema>::json_schema(generator).into_object();
        let string = schema.string.get_or_insert_with(Default::default);
        string.min_length = Some(1);
        string.pattern = Some(format!(
            r"^/{}/{}-{}-{}-{}-{}/{}/[A-Za-z0-9._()-]{{0,{}}}[A-Za-z0-9_()-]/{}/{}/{}/[A-Za-z0-9][A-Za-z0-9._-]{{0,{}}}(?![\s\S])",
            any_case("subscriptions"),
            hex(8),
            hex(4),
            hex(4),
            hex(4),
            hex(12),
            any_case("resourceGroups"),
            Self::MAX_RESOURCE_GROUP_LEN - 1,
            any_case("providers"),
            any_case("Microsoft.ContainerInstance"),
            any_case("sandboxGroups"),
            Self::MAX_NAME_LEN - 1,
        ));
        schema.into()
    }
}

/// A JSON array that must contain at least one element.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NonEmptyVec<T>(Vec<T>);

#[cfg(feature = "schema-gen")]
impl<T> schemars::JsonSchema for NonEmptyVec<T>
where
    T: schemars::JsonSchema,
{
    fn schema_name() -> String {
        format!("NonEmptyArray_of_{}", T::schema_name())
    }

    fn json_schema(generator: &mut schemars::gen::SchemaGenerator) -> schemars::schema::Schema {
        use schemars::schema::{ArrayValidation, InstanceType, Schema, SchemaObject, SingleOrVec};

        Schema::Object(SchemaObject {
            instance_type: Some(SingleOrVec::Single(Box::new(InstanceType::Array))),
            array: Some(Box::new(ArrayValidation {
                items: Some(SingleOrVec::Single(Box::new(
                    generator.subschema_for::<T>(),
                ))),
                min_items: Some(1),
                ..Default::default()
            })),
            ..Default::default()
        })
    }

    fn is_referenceable() -> bool {
        false
    }
}

impl<T> NonEmptyVec<T> {
    /// Creates a validated array.
    ///
    /// Returns an error when `value` is empty.
    pub fn new(value: Vec<T>) -> Result<Self, String> {
        if value.is_empty() {
            Err("array must not be empty".to_string())
        } else {
            Ok(Self(value))
        }
    }

    /// Returns the validated elements as a slice.
    pub fn as_slice(&self) -> &[T] {
        &self.0
    }

    /// Consumes the wrapper and returns the validated elements.
    pub fn into_inner(self) -> Vec<T> {
        self.0
    }
}

impl<'de, T> Deserialize<'de> for NonEmptyVec<T>
where
    T: Deserialize<'de>,
{
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value = Vec::<T>::deserialize(deserializer)?;
        Self::new(value).map_err(de::Error::custom)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn non_empty_string_accepts_valid() {
        let value = NonEmptyString::new("abc".to_string()).unwrap();
        assert_eq!(value.as_str(), "abc");
    }

    #[test]
    fn non_empty_string_rejects_empty() {
        let error = NonEmptyString::new(String::new()).unwrap_err();
        assert_eq!(error, "string must not be empty");
    }

    #[test]
    fn optional_field_constructs_present_value() {
        let field = OptionalField::present("value".to_string());

        assert_eq!(field.into_option().as_deref(), Some("value"));
    }

    #[test]
    fn optional_field_default_is_absent() {
        let field: OptionalField<String> = OptionalField::default();

        assert_eq!(field.into_option(), None);
    }

    const SANDBOX_GROUP: &str = "/subscriptions/51aca303-03da-4510-849d-d4f32d3f39ac/resourceGroups/tryme-01/providers/Microsoft.ContainerInstance/sandboxGroups/sbg-001";

    #[test]
    fn aci_sandbox_group_id_accepts_arm_resource_ids_in_any_case() {
        for id in [
            SANDBOX_GROUP,
            "/SUBSCRIPTIONS/51ACA303-03DA-4510-849D-D4F32D3F39AC/resourcegroups/rg_(1).a/PROVIDERS/microsoft.containerinstance/SANDBOXGROUPS/Group.Name_1",
        ] {
            let parsed = AciSandboxGroupId::new(id.to_owned()).unwrap();
            assert_eq!(parsed.as_str(), id);
        }
    }

    #[test]
    fn aci_sandbox_group_id_rejects_other_shapes_and_url_unsafe_names() {
        for id in [
            String::new(),
            SANDBOX_GROUP.trim_start_matches('/').to_owned(),
            format!("{SANDBOX_GROUP}/"),
            format!("{SANDBOX_GROUP}/sandboxes/x"),
            SANDBOX_GROUP.replace("Microsoft.ContainerInstance", "Microsoft.Compute"),
            SANDBOX_GROUP.replace("sandboxGroups", "containerGroups"),
            SANDBOX_GROUP.replace("51aca303-03da-4510-849d-d4f32d3f39ac", "not-a-guid"),
            SANDBOX_GROUP.replace("tryme-01", ""),
            SANDBOX_GROUP.replace("tryme-01", "trailing."),
            SANDBOX_GROUP.replace("tryme-01", "has space"),
            SANDBOX_GROUP.replace("tryme-01", &"r".repeat(91)),
            SANDBOX_GROUP.replace("sbg-001", "-leading"),
            SANDBOX_GROUP.replace("sbg-001", "a?b"),
            SANDBOX_GROUP.replace("sbg-001", "a%2fb"),
            SANDBOX_GROUP.replace("sbg-001", ".."),
            SANDBOX_GROUP.replace("sbg-001", "sbg#1"),
            SANDBOX_GROUP.replace("sbg-001", &"s".repeat(261)),
        ] {
            let error = AciSandboxGroupId::new(id.clone()).unwrap_err();
            assert!(error.starts_with("sandbox group"), "{id}: {error}");
        }
    }

    #[test]
    fn image_reference_errors_name_the_caller_field() {
        let error = ImageReference::validate("python:3.12", "aci.image").unwrap_err();
        assert!(
            error.starts_with("aci.image must include a registry host"),
            "{error}"
        );
        let error = ImageReference::new(" ".to_owned()).unwrap_err();
        assert!(
            error.starts_with("image must be a nonempty image reference"),
            "{error}"
        );
    }

    #[cfg(feature = "schema-gen")]
    #[test]
    fn constrained_primitive_schemas_match_deserialization() {
        use schemars::JsonSchema;

        let mut generator = schemars::gen::SchemaGenerator::default();
        let true_schema = serde_json::to_value(True::json_schema(&mut generator)).unwrap();
        assert_eq!(true_schema["type"], "boolean");
        assert_eq!(true_schema["enum"], serde_json::json!([true]));

        let non_empty = serde_json::to_value(NonEmptyString::json_schema(&mut generator)).unwrap();
        assert_eq!(non_empty["type"], "string");
        assert_eq!(non_empty["minLength"], 1);
    }

    #[cfg(feature = "schema-gen")]
    #[test]
    fn optional_field_schema_is_transparent_and_not_referenceable() {
        use schemars::JsonSchema;

        let mut generator = schemars::gen::SchemaGenerator::default();
        let schema =
            serde_json::to_value(OptionalField::<String>::json_schema(&mut generator)).unwrap();

        assert_eq!(schema["type"], "string");
        assert!(schema.get("anyOf").is_none());
        assert!(!OptionalField::<String>::is_referenceable());
    }
}
