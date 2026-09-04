// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Immutable wire types for the published `0.7.0-alpha` configuration contract.
//!
//! These types validate the JSON structure and value constraints of the
//! published contract. They preserve omitted optional fields for a later
//! adapter to default and normalize.

// Serde's default fieldless-enum deserializer also accepts externally
// tagged object forms such as {"process": null}. Published contracts accept
// only string values. This macro generates a string-only deserializer while
// supporting explicit compatibility aliases.
macro_rules! string_enum {
    (
        $(#[$enum_meta:meta])*
        $vis:vis enum $name:ident {
            $(
                $(#[$variant_meta:meta])*
                $variant:ident => [
                    $canonical:literal
                    $(, $alias:literal)*
                ]
            ),+ $(,)?
        }
    ) => {
        $(#[$enum_meta])*
        $vis enum $name {
            $(
                $(#[$variant_meta])*
                $variant,
            )+
        }

        impl $name {
            const WIRE_VALUES: &'static [&'static str] = &[
                $(
                    $canonical,
                    $($alias,)*
                )+
            ];
        }

        impl<'de> serde::Deserialize<'de> for $name {
            fn deserialize<D>(
                deserializer: D,
            ) -> Result<Self, D::Error>
            where
                D: serde::Deserializer<'de>,
            {
                struct StringEnumVisitor;

                impl<'de> serde::de::Visitor<'de>
                    for StringEnumVisitor
                {
                    type Value = $name;

                    fn expecting(
                        &self,
                        formatter: &mut std::fmt::Formatter<'_>,
                    ) -> std::fmt::Result {
                        write!(
                            formatter,
                            "a valid {} string",
                            stringify!($name)
                        )
                    }

                    fn visit_str<E>(
                        self,
                        value: &str,
                    ) -> Result<Self::Value, E>
                    where
                        E: serde::de::Error,
                    {
                        match value {
                            $(
                                $canonical
                                $(| $alias)*
                                    => Ok($name::$variant),
                            )+
                            _ => Err(E::unknown_variant(
                                value,
                                $name::WIRE_VALUES,
                            )),
                        }
                    }
                }

                deserializer.deserialize_str(StringEnumVisitor)
            }
        }

        // Generate a test for each string enum variant and its aliases.
        // The test ensures that the enum deserializes from the canonical and
        // alias string values (if any), and that it rejects externally tagged
        // and non-string values. Emitted here as part of the macro to avoid
        // repeating the same test logic for each enum in a separate location
        // where the enum's private WIRE_VALUES constant is not accessible.
        #[cfg(test)]
        #[allow(non_snake_case)]
        #[test]
        fn $name() {
            $(
                for wire_value in [
                    $canonical,
                    $($alias,)*
                ] {
                    let json = serde_json::to_string(wire_value).unwrap();
                    let parsed: $name = serde_json::from_str(&json).unwrap();

                    assert!(
                        matches!(parsed, $name::$variant),
                        "{wire_value:?} did not map to {}::{}",
                        stringify!($name),
                        stringify!($variant),
                    );

                    let externally_tagged = format!("{{{json}:null}}");
                    assert!(
                        serde_json::from_str::<$name>(&externally_tagged).is_err(),
                        "{} accepted externally tagged value {externally_tagged}",
                        stringify!($name),
                    );
                }
            )+

            for json in ["null", "true", "0", "[]", "{}"] {
                assert!(
                    serde_json::from_str::<$name>(json).is_err(),
                    "{} accepted non-string value {json}",
                    stringify!($name),
                );
            }
        }
    };
}

mod network;
mod primitives;
mod request;

pub use network::{DefaultNetworkPolicy, Network, NetworkEnforcementMode, NetworkProxy};
pub use primitives::{NonEmptyString, OptionalField, True};
pub use request::{
    Containment, Fallback, Filesystem, LaunchMethod, Lifecycle, Lxc, Process, ProcessContainer,
    ProcessContainerUi, ProcessContainerUiIsolation, Request, Seatbelt, Ui, UiClipboard, Version,
};
