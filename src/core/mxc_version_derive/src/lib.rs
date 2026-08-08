// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! `#[derive(VersionAvailability)]` — lifts per-field schema-availability ranges out of
//! the wire model so the config parser and the JSON-Schema generator read the
//! same declaration.
//!
//! A derive rather than `#[schemars(extend(...))]`, because the schemars
//! attributes sit behind the `schema-gen` feature and so can never be consulted
//! by the parser — an annotation nothing enforces is documentation, not a
//! contract.
//!
//! ```ignore
//! #[derive(Serialize, Deserialize, VersionAvailability)]
//! #[serde(rename_all = "camelCase", deny_unknown_fields)]
//! pub struct Network {
//!     pub default_policy: Option<NetworkPolicy>,   // valid everywhere
//!     #[mxc_version(since = "0.8")]
//!     pub egress: Option<NetworkEgress>,
//!     #[mxc_version(until = "0.7")]
//!     pub allowed_hosts: Option<Vec<String>>,
//! }
//! ```
//!
//! Anything this macro cannot model exactly is a compile error, never a silent
//! approximation: a derived name that disagrees with what serde accepts would
//! fail *open*, since the availability range is enforced by matching that name against a
//! JSON key. Hence the rejections of `flatten`, split `rename`/`rename_all`,
//! unknown `rename_all` rules, data-carrying variants and malformed literals.

use proc_macro::TokenStream;
use proc_macro2::TokenStream as TokenStream2;
use quote::quote;
use syn::punctuated::Punctuated;
use syn::{
    Attribute, Data, DeriveInput, Error, Expr, ExprLit, Fields, Lit, Meta, Result, Token, Type,
};

/// Derives `wxc_common::version_availability::VersionAvailability`.
///
/// Structs emit a node describing every deserialisable field. Enums are leaves:
/// an availability range constrains where a *field* may appear, not which values it may take.
#[proc_macro_derive(VersionAvailability, attributes(mxc_version))]
pub fn derive_version_availabilitys(input: TokenStream) -> TokenStream {
    let input = syn::parse_macro_input!(input as DeriveInput);
    expand(input)
        .unwrap_or_else(Error::into_compile_error)
        .into()
}

fn expand(input: DeriveInput) -> Result<TokenStream2> {
    let ident = &input.ident;
    let type_name = ident.to_string();

    // `static NODE` cannot depend on a type parameter, and no wire type is generic.
    if !input.generics.params.is_empty() {
        return Err(Error::new_spanned(
            &input.generics,
            "VersionAvailability does not support generic types; the wire model is concrete",
        ));
    }

    let body = match &input.data {
        Data::Struct(data) => {
            let rename_all = container_rename_all(&input.attrs)?;
            let fields = match &data.fields {
                Fields::Named(named) => &named.named,
                Fields::Unit => {
                    return Err(Error::new_spanned(
                        ident,
                        "VersionAvailability requires a struct with named fields",
                    ))
                }
                Fields::Unnamed(unnamed) => {
                    return Err(Error::new_spanned(
                        unnamed,
                        "VersionAvailability does not support tuple structs; \
                         a wire field needs a name to key its availability range on",
                    ))
                }
            };

            let mut entries = Vec::new();
            for field in fields {
                let Some(field_ident) = field.ident.as_ref() else {
                    continue;
                };
                let attrs = FieldAttrs::parse(&field.attrs)?;
                if attrs.skipped {
                    // Not deserialisable, so an availability range on it could never fire.
                    if attrs.availability.is_annotated() {
                        return Err(Error::new_spanned(
                            field_ident,
                            "#[mxc_version] on a #[serde(skip)] field can never fire: \
                             the field is not deserialisable",
                        ));
                    }
                    continue;
                }

                let rust_name = field_ident.to_string();
                let json_name = attrs
                    .rename
                    .clone()
                    .unwrap_or_else(|| rename_all.apply_to_field(&rust_name));
                let aliases = &attrs.aliases;
                let availability = attrs.availability.to_tokens();
                let ty = strip_leading_underscore_type(&field.ty);

                entries.push(quote! {
                    ::wxc_common::version_availability::FieldAvailability {
                        rust_name: #rust_name,
                        name: #json_name,
                        aliases: &[#(#aliases),*],
                        availability: #availability,
                        nested: <#ty as ::wxc_common::version_availability::VersionAvailability>::availability,
                    }
                });
            }

            quote! {
                static NODE: ::wxc_common::version_availability::NodeAvailability =
                    ::wxc_common::version_availability::NodeAvailability {
                        type_name: #type_name,
                        fields: &[#(#entries),*],
                    };
                ::core::option::Option::Some(&NODE)
            }
        }
        Data::Enum(data) => {
            for variant in &data.variants {
                if !matches!(variant.fields, Fields::Unit) {
                    return Err(Error::new_spanned(
                        variant,
                        "VersionAvailability only supports data-less enum variants; \
                         a variant carrying data has inner fields that would need their own ranges",
                    ));
                }
                if FieldAttrs::parse(&variant.attrs)?
                    .availability
                    .is_annotated()
                {
                    return Err(Error::new_spanned(
                        variant,
                        "#[mxc_version] cannot be applied to an enum variant: an availability range \
                         governs where a field may appear, not which values it may take. \
                         Narrowing a value set is an ordinary schema restriction.",
                    ));
                }
            }
            quote! { ::core::option::Option::None }
        }
        Data::Union(data) => {
            return Err(Error::new_spanned(
                data.union_token,
                "VersionAvailability does not support unions",
            ))
        }
    };

    Ok(quote! {
        #[automatically_derived]
        impl ::wxc_common::version_availability::VersionAvailability for #ident {
            fn availability() -> ::core::option::Option<&'static ::wxc_common::version_availability::NodeAvailability> {
                #body
            }
        }
    })
}

/// Field types are used verbatim.
fn strip_leading_underscore_type(ty: &Type) -> &Type {
    ty
}

// ---------------------------------------------------------------------------
// Attribute parsing
// ---------------------------------------------------------------------------

/// Mirrors `serde_derive`'s `RenameRule` for the field case. Any rule this does
/// not model is a compile error rather than a guess.
#[derive(Clone, Copy, PartialEq, Eq)]
enum RenameAll {
    None,
    Lower,
    Upper,
    Pascal,
    Camel,
    Snake,
    ScreamingSnake,
    Kebab,
    ScreamingKebab,
}

impl RenameAll {
    fn from_str(value: &str) -> Option<Self> {
        Some(match value {
            "lowercase" => Self::Lower,
            "UPPERCASE" => Self::Upper,
            "PascalCase" => Self::Pascal,
            "camelCase" => Self::Camel,
            "snake_case" => Self::Snake,
            "SCREAMING_SNAKE_CASE" => Self::ScreamingSnake,
            "kebab-case" => Self::Kebab,
            "SCREAMING-KEBAB-CASE" => Self::ScreamingKebab,
            _ => return None,
        })
    }

    /// Replicates `RenameRule::apply_to_field`. Field names are already
    /// `snake_case`, hence `lowercase`/`snake_case` being identity.
    fn apply_to_field(self, field: &str) -> String {
        match self {
            Self::None | Self::Lower | Self::Snake => field.to_owned(),
            Self::Upper | Self::ScreamingSnake => field.to_ascii_uppercase(),
            Self::Pascal => pascal_case(field),
            Self::Camel => {
                let pascal = pascal_case(field);
                let mut chars = pascal.chars();
                match chars.next() {
                    Some(first) => first.to_ascii_lowercase().to_string() + chars.as_str(),
                    None => pascal,
                }
            }
            Self::Kebab => field.replace('_', "-"),
            Self::ScreamingKebab => field.to_ascii_uppercase().replace('_', "-"),
        }
    }
}

fn pascal_case(field: &str) -> String {
    let mut out = String::with_capacity(field.len());
    let mut capitalize = true;
    for ch in field.chars() {
        if ch == '_' {
            capitalize = true;
        } else if capitalize {
            out.push(ch.to_ascii_uppercase());
            capitalize = false;
        } else {
            out.push(ch);
        }
    }
    out
}

fn container_rename_all(attrs: &[Attribute]) -> Result<RenameAll> {
    let mut rule = RenameAll::None;
    for meta in serde_metas(attrs)? {
        match &meta {
            // The range is keyed on the deserialised name, so ignoring the split
            // form would derive the wrong key and leave the availability range unreachable.
            Meta::List(list) if list.path.is_ident("rename_all") => {
                return Err(Error::new_spanned(
                    list,
                    "VersionAvailability does not support the \
                     `rename_all(serialize = ..., deserialize = ...)` form; the availability range is keyed \
                     on the deserialised name, so the split form would need an explicit choice",
                ));
            }
            Meta::NameValue(nv) if nv.path.is_ident("rename_all") => {
                let value = string_literal(&nv.value, "serde(rename_all)")?;
                rule = RenameAll::from_str(&value).ok_or_else(|| {
                    Error::new_spanned(
                        &nv.value,
                        format!(
                            "VersionAvailability does not model the `{value}` rename_all rule; \
                             add it to RenameAll (mirroring serde_derive) rather than letting \
                             the derived JSON name silently disagree with serde"
                        ),
                    )
                })?;
            }
            _ => {}
        }
    }
    Ok(rule)
}

#[derive(Default)]
struct AvailabilityAttr {
    since: Option<(u64, u64, proc_macro2::Span)>,
    until: Option<(u64, u64, proc_macro2::Span)>,
}

impl AvailabilityAttr {
    fn is_annotated(&self) -> bool {
        self.since.is_some() || self.until.is_some()
    }

    fn to_tokens(&self) -> TokenStream2 {
        let since = bound_tokens(self.since);
        let until = bound_tokens(self.until);
        quote! {
            ::wxc_common::version_availability::Availability { since: #since, until: #until }
        }
    }
}

fn bound_tokens(bound: Option<(u64, u64, proc_macro2::Span)>) -> TokenStream2 {
    match bound {
        Some((major, minor, _)) => quote! {
            ::core::option::Option::Some(
                ::wxc_common::version_availability::MajorMinor { major: #major, minor: #minor }
            )
        },
        None => quote! { ::core::option::Option::None },
    }
}

#[derive(Default)]
struct FieldAttrs {
    rename: Option<String>,
    aliases: Vec<String>,
    skipped: bool,
    availability: AvailabilityAttr,
}

impl FieldAttrs {
    fn parse(attrs: &[Attribute]) -> Result<Self> {
        let mut out = FieldAttrs::default();

        for meta in serde_metas(attrs)? {
            match &meta {
                Meta::Path(path) => {
                    if path.is_ident("skip") || path.is_ident("skip_deserializing") {
                        out.skipped = true;
                    }
                    if path.is_ident("flatten") {
                        return Err(Error::new_spanned(
                            path,
                            "VersionAvailability does not support #[serde(flatten)]: a flattened \
                             field's keys appear at the parent level, so they cannot be keyed \
                             by this field's name",
                        ));
                    }
                }
                Meta::NameValue(nv) => {
                    if nv.path.is_ident("rename") {
                        out.rename = Some(string_literal(&nv.value, "serde(rename)")?);
                    } else if nv.path.is_ident("alias") {
                        out.aliases.push(string_literal(&nv.value, "serde(alias)")?);
                    }
                }
                Meta::List(list) => {
                    if list.path.is_ident("rename") {
                        return Err(Error::new_spanned(
                            list,
                            "VersionAvailability does not support the \
                             `rename(serialize = ..., deserialize = ...)` form; the availability range is \
                             keyed on the deserialised name, so the split form would need an \
                             explicit choice",
                        ));
                    }
                }
            }
        }

        for attr in attrs {
            if !attr.path().is_ident("mxc_version") {
                continue;
            }
            let nested = attr.parse_args_with(Punctuated::<Meta, Token![,]>::parse_terminated)?;
            if nested.is_empty() {
                return Err(Error::new_spanned(
                    attr,
                    "#[mxc_version] requires at least one of `since = \"X.Y\"` or `until = \"X.Y\"`",
                ));
            }
            for meta in nested {
                let Meta::NameValue(nv) = &meta else {
                    return Err(Error::new_spanned(
                        &meta,
                        "expected `since = \"X.Y\"` or `until = \"X.Y\"`",
                    ));
                };
                let is_since = nv.path.is_ident("since");
                let is_until = nv.path.is_ident("until");
                if !is_since && !is_until {
                    return Err(Error::new_spanned(
                        &nv.path,
                        "unknown #[mxc_version] key; expected `since` or `until`",
                    ));
                }
                let literal = string_literal(&nv.value, "mxc_version")?;
                let parsed = parse_major_minor(&literal).ok_or_else(|| {
                    Error::new_spanned(
                        &nv.value,
                        format!(
                            "`{literal}` is not a major.minor schema version (e.g. \"0.8\"). \
                             Availability ranges compare major.minor only, matching the parser's \
                             supported-range check, so a patch or pre-release component \
                             would be misleading."
                        ),
                    )
                })?;
                let span = proc_macro2::Span::call_site();
                let slot = if is_since {
                    &mut out.availability.since
                } else {
                    &mut out.availability.until
                };
                if slot.is_some() {
                    return Err(Error::new_spanned(&nv.path, "duplicate #[mxc_version] key"));
                }
                *slot = Some((parsed.0, parsed.1, span));
            }
        }

        if let (Some(since), Some(until)) = (out.availability.since, out.availability.until) {
            if (since.0, since.1) > (until.0, until.1) {
                return Err(Error::new_spanned(
                    attrs
                        .iter()
                        .find(|a| a.path().is_ident("mxc_version"))
                        .expect("an availability range was parsed, so the attribute exists"),
                    format!(
                        "empty availability range: since {}.{} is newer than until {}.{}, \
                         so the field could never be used",
                        since.0, since.1, until.0, until.1
                    ),
                ));
            }
        }

        Ok(out)
    }
}

/// Flattens every `#[serde(...)]` attribute into its entries. Parsing into
/// [`Meta`] lets unrecognised serde options be consumed and ignored.
fn serde_metas(attrs: &[Attribute]) -> Result<Vec<Meta>> {
    let mut out = Vec::new();
    for attr in attrs {
        if !attr.path().is_ident("serde") {
            continue;
        }
        let nested = attr.parse_args_with(Punctuated::<Meta, Token![,]>::parse_terminated)?;
        out.extend(nested);
    }
    Ok(out)
}

fn string_literal(expr: &Expr, context: &str) -> Result<String> {
    match expr {
        Expr::Lit(ExprLit {
            lit: Lit::Str(s), ..
        }) => Ok(s.value()),
        other => Err(Error::new_spanned(
            other,
            format!("expected a string literal for {context}"),
        )),
    }
}

fn parse_major_minor(value: &str) -> Option<(u64, u64)> {
    let (major, minor) = value.split_once('.')?;
    if major.is_empty() || minor.is_empty() {
        return None;
    }
    // Reject leading zeros and non-digits so "0.08" / "0.8.0-alpha" cannot pass.
    for part in [major, minor] {
        if !part.bytes().all(|b| b.is_ascii_digit()) {
            return None;
        }
        if part.len() > 1 && part.starts_with('0') {
            return None;
        }
    }
    Some((major.parse().ok()?, minor.parse().ok()?))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn camel_case_matches_serde_for_wire_field_names() {
        let camel = RenameAll::Camel;
        assert_eq!(camel.apply_to_field("command_line"), "commandLine");
        assert_eq!(camel.apply_to_field("cwd"), "cwd");
        assert_eq!(camel.apply_to_field("memory_mb"), "memoryMb");
        assert_eq!(camel.apply_to_field("image_tar_path"), "imageTarPath");
        assert_eq!(camel.apply_to_field("wam_token"), "wamToken");
        // serde capitalises the first *letter*, so a leading underscore is
        // dropped rather than yielding "Comment".
        assert_eq!(camel.apply_to_field("_comment"), "comment");
    }

    #[test]
    fn other_rules_match_serde() {
        assert_eq!(
            RenameAll::None.apply_to_field("command_line"),
            "command_line"
        );
        assert_eq!(
            RenameAll::Snake.apply_to_field("command_line"),
            "command_line"
        );
        assert_eq!(
            RenameAll::Lower.apply_to_field("command_line"),
            "command_line"
        );
        assert_eq!(
            RenameAll::Pascal.apply_to_field("command_line"),
            "CommandLine"
        );
        assert_eq!(
            RenameAll::Kebab.apply_to_field("command_line"),
            "command-line"
        );
        assert_eq!(
            RenameAll::ScreamingSnake.apply_to_field("command_line"),
            "COMMAND_LINE"
        );
        assert_eq!(
            RenameAll::ScreamingKebab.apply_to_field("command_line"),
            "COMMAND-LINE"
        );
        assert_eq!(RenameAll::Upper.apply_to_field("cwd"), "CWD");
    }

    #[test]
    fn unknown_rename_all_is_rejected() {
        assert!(RenameAll::from_str("camelCase").is_some());
        assert!(RenameAll::from_str("weirdCase").is_none());
    }

    #[test]
    fn major_minor_parsing_is_strict() {
        assert_eq!(parse_major_minor("0.8"), Some((0, 8)));
        assert_eq!(parse_major_minor("1.12"), Some((1, 12)));
        assert_eq!(parse_major_minor("0.0"), Some((0, 0)));
        // Availability ranges compare major.minor only; a full SemVer would imply precision
        // this does not honour.
        assert_eq!(parse_major_minor("0.8.0"), None);
        assert_eq!(parse_major_minor("0.8.0-alpha"), None);
        assert_eq!(parse_major_minor("0.08"), None);
        assert_eq!(parse_major_minor("08.1"), None);
        assert_eq!(parse_major_minor("0"), None);
        assert_eq!(parse_major_minor(""), None);
        assert_eq!(parse_major_minor("0."), None);
        assert_eq!(parse_major_minor(".8"), None);
        assert_eq!(parse_major_minor("x.y"), None);
    }
}
