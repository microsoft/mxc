// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use serde::{de, Deserialize, Deserializer};

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

/// A string containing at least one non-whitespace character.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NonBlankString(String);

#[cfg(feature = "schema-gen")]
impl schemars::JsonSchema for NonBlankString {
    fn schema_name() -> String {
        "NonBlankString".to_string()
    }

    fn json_schema(_generator: &mut schemars::gen::SchemaGenerator) -> schemars::schema::Schema {
        use schemars::schema::{InstanceType, Schema, SchemaObject, SingleOrVec, StringValidation};

        Schema::Object(SchemaObject {
            instance_type: Some(SingleOrVec::Single(Box::new(InstanceType::String))),
            string: Some(Box::new(StringValidation {
                pattern: Some(r"\S".to_string()),
                ..Default::default()
            })),
            ..Default::default()
        })
    }
}

impl NonBlankString {
    /// Creates a validated string.
    ///
    /// Returns an error when `value` contains only whitespace.
    pub fn new(value: String) -> Result<Self, String> {
        if value.trim().is_empty() {
            Err("string must contain a non-whitespace character".to_string())
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

impl<'de> Deserialize<'de> for NonBlankString {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        Self::new(String::deserialize(deserializer)?).map_err(de::Error::custom)
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
    fn new(value: Vec<T>) -> Result<Self, String> {
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
    fn non_blank_string_accepts_surrounding_whitespace() {
        let value = NonBlankString::new(" alpine ".to_string()).unwrap();
        assert_eq!(value.as_str(), " alpine ");
    }

    #[test]
    fn non_blank_string_rejects_whitespace_only() {
        let error = NonBlankString::new(" \t\n".to_string()).unwrap_err();
        assert_eq!(error, "string must contain a non-whitespace character");
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

        let non_blank = serde_json::to_value(NonBlankString::json_schema(&mut generator)).unwrap();
        assert_eq!(non_blank["type"], "string");
        assert_eq!(non_blank["pattern"], r"\S");
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
