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
// supporting explicit compatibility aliases. Note that this macro should be
// preceded by `#[rustfmt::skip]` because it uses a syntax pattern that is not
// supported by rustfmt.
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
