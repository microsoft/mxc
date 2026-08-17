// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use serde::{de, Deserialize, Deserializer};

/// A marker that deserializes only from the JSON value `true`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct True;

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

impl NonEmptyString {
    /// Creates a validated string.
    ///
    /// Returns an error when `value` is empty.
    fn new(value: String) -> Result<Self, String> {
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
}
