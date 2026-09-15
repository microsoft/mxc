// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use serde::de::DeserializeOwned;

pub(crate) fn assert_valid<T>(json: &str)
where
    T: DeserializeOwned,
{
    serde_json::from_str::<T>(json).unwrap();
}

pub(crate) fn assert_invalid<T>(json: &str)
where
    T: DeserializeOwned,
{
    // First ensure the test itself is valid JSON.
    serde_json::from_str::<serde_json::Value>(json).unwrap();
    assert!(serde_json::from_str::<T>(json).is_err());
}
