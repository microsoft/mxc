// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! TypeScript emitter for the SDK wire types.
//!
//! Walks the generated JSON Schema as a `serde_json::Value` — built from the
//! `MxcConfig` wire model, the same value that
//! [`crate::wire::generate_config_schema_json`] renders to JSON text — and emits
//! the SDK's wire TypeScript types, with no third-party generator.
//! The result is `sdk/src/generated/wire.ts`, a drift oracle that the SDK's
//! hand-written public types are asserted to conform to (and that a CI gate
//! regenerates + diffs).
//!
//! Only the JSON Schema constructs the MXC schema actually uses are handled:
//! enums (`oneOf` of single-value `enum`s, or a direct `enum` array), closed and
//! open objects, `$ref`, `anyOf [T, null]` nullable wrappers, arrays, and scalar
//! types (`string`/`integer`/`number`/`boolean`). The emitter is deterministic:
//! `serde_json`'s default `Map` is a `BTreeMap`, so definitions and properties
//! come out in stable alphabetical order.

use serde_json::Value;

const BANNER: &str = "\
// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

/* eslint-disable */
/**
 * GENERATED FILE — DO NOT EDIT BY HAND.
 *
 * Emitted from the generated JSON Schema (itself generated from the Rust wire
 * model `wxc_common::wire`) by the `mxc_schema_gen --ts` TypeScript emitter
 * (`wxc_common::ts_emit`). This is a drift oracle, not public API: it is never
 * exported from the SDK. The conformance test asserts the hand-written public
 * types in `../types.ts` still match these. CI gate:
 * `scripts/versioning/check-sdk-types-codegen.js`.
 *
 * Regenerate with:
 *   cargo run --manifest-path src/Cargo.toml -p mxc_schema_gen -- --ts sdk/src/generated/wire.ts
 */
";

/// Root interface name (mirrors the json-schema-to-typescript convention of
/// deriving it from the schema `title`, "MXC Configuration").
const ROOT_NAME: &str = "MXCConfiguration";

/// Emit the full `wire.ts` content for the given schema root value.
pub fn emit_ts(schema: &Value) -> String {
    let root = schema.as_object().expect("schema root is an object");
    let mut out = String::from(BANNER);

    if let Some(Value::Object(defs)) = root.get("definitions") {
        for (name, def) in defs {
            emit_definition(&mut out, name, def);
        }
    }

    // The root itself is an object schema; emit it as the top-level interface.
    emit_object(&mut out, ROOT_NAME, root);

    out
}

/// Emit one named definition: an enum (string union) or an object interface.
fn emit_definition(out: &mut String, name: &str, def: &Value) {
    let obj = match def.as_object() {
        Some(o) => o,
        None => {
            push_doc(out, def.get("description"));
            out.push_str(&format!("export type {name} = unknown;\n\n"));
            return;
        }
    };

    if let Some(variants) = enum_variants(obj) {
        push_doc(out, obj.get("description"));
        let union = variants
            .iter()
            .map(|v| format!("\"{v}\""))
            .collect::<Vec<_>>()
            .join(" | ");
        out.push_str(&format!("export type {name} = {union};\n\n"));
        return;
    }

    emit_object(out, name, obj_as_map(def));
}

/// Collect a string-union's members from either a `oneOf` of single-value
/// `enum`s or a direct `enum` array. Returns `None` if the definition is not an
/// enum.
fn enum_variants(obj: &serde_json::Map<String, Value>) -> Option<Vec<String>> {
    if let Some(Value::Array(one_of)) = obj.get("oneOf") {
        let mut variants = Vec::new();
        for branch in one_of {
            let e = branch.get("enum")?.as_array()?;
            let s = e.first()?.as_str()?;
            variants.push(s.to_string());
        }
        return Some(variants);
    }
    if let Some(Value::Array(e)) = obj.get("enum") {
        let variants: Vec<String> = e
            .iter()
            .filter_map(|v| v.as_str().map(String::from))
            .collect();
        if !variants.is_empty() {
            return Some(variants);
        }
    }
    None
}

fn obj_as_map(def: &Value) -> &serde_json::Map<String, Value> {
    def.as_object().expect("object definition")
}

/// Emit an `export interface Name { ... }` from an object schema.
fn emit_object(out: &mut String, name: &str, obj: &serde_json::Map<String, Value>) {
    push_doc(out, obj.get("description"));
    out.push_str(&format!("export interface {name} {{\n"));

    let required: Vec<&str> = obj
        .get("required")
        .and_then(|r| r.as_array())
        .map(|a| a.iter().filter_map(|v| v.as_str()).collect())
        .unwrap_or_default();

    if let Some(Value::Object(props)) = obj.get("properties") {
        for (pname, pval) in props {
            let (ty, nullable) = ts_type(pval);
            let optional = !required.contains(&pname.as_str());
            push_field_doc(out, pval.get("description"));
            let key = field_key(pname);
            let opt = if optional { "?" } else { "" };
            let nul = if nullable { " | null" } else { "" };
            out.push_str(&format!("  {key}{opt}: {ty}{nul};\n"));
        }
    }

    // Open objects (no `additionalProperties: false`) carry an index signature,
    // matching how the permissive experimental block is modeled.
    if is_open_object(obj) {
        out.push_str("  [k: string]: unknown;\n");
    }

    out.push_str("}\n\n");
}

/// An object is "open" unless it explicitly sets `additionalProperties: false`.
fn is_open_object(obj: &serde_json::Map<String, Value>) -> bool {
    !matches!(obj.get("additionalProperties"), Some(Value::Bool(false)))
}

/// Resolve a property schema to a `(typescript-type, nullable)` pair.
fn ts_type(prop: &Value) -> (String, bool) {
    let obj = match prop.as_object() {
        Some(o) => o,
        None => return ("unknown".to_string(), false),
    };

    if let Some(r) = obj.get("$ref").and_then(|v| v.as_str()) {
        return (ref_name(r), false);
    }

    if let Some(Value::Array(any_of)) = obj.get("anyOf") {
        let mut nullable = false;
        let mut ty = "unknown".to_string();
        for branch in any_of {
            if is_null_schema(branch) {
                nullable = true;
            } else {
                let (t, n) = ts_type(branch);
                ty = t;
                nullable = nullable || n;
            }
        }
        return (ty, nullable);
    }

    match obj.get("type") {
        Some(Value::String(s)) => (scalar(s, obj), false),
        Some(Value::Array(types)) => {
            let mut nullable = false;
            let mut base = "unknown".to_string();
            for t in types {
                match t.as_str() {
                    Some("null") => nullable = true,
                    Some(s) => base = scalar(s, obj),
                    None => {}
                }
            }
            (base, nullable)
        }
        _ => ("unknown".to_string(), false),
    }
}

/// Map a JSON Schema scalar/array `type` to its TypeScript spelling.
fn scalar(ty: &str, obj: &serde_json::Map<String, Value>) -> String {
    match ty {
        "string" => "string".to_string(),
        "integer" | "number" => "number".to_string(),
        "boolean" => "boolean".to_string(),
        "array" => {
            let items = obj.get("items").cloned().unwrap_or(Value::Null);
            let (item_ty, item_nullable) = ts_type(&items);
            if item_nullable {
                format!("({item_ty} | null)[]")
            } else {
                format!("{item_ty}[]")
            }
        }
        "object" => "{ [k: string]: unknown }".to_string(),
        "null" => "null".to_string(),
        _ => "unknown".to_string(),
    }
}

fn is_null_schema(v: &Value) -> bool {
    v.get("type").and_then(|t| t.as_str()) == Some("null")
}

fn ref_name(reference: &str) -> String {
    reference
        .rsplit('/')
        .next()
        .unwrap_or(reference)
        .to_string()
}

/// Quote a property name only when it is not a plain TS identifier.
fn field_key(name: &str) -> String {
    let is_ident = !name.is_empty()
        && name.chars().enumerate().all(|(i, c)| {
            c == '_' || c == '$' || c.is_ascii_alphabetic() || (i > 0 && c.is_ascii_digit())
        });
    if is_ident {
        name.to_string()
    } else {
        format!("\"{name}\"")
    }
}

/// Emit a top-level JSDoc block (no indentation) for a definition.
fn push_doc(out: &mut String, description: Option<&Value>) {
    if let Some(text) = description.and_then(|v| v.as_str()) {
        out.push_str("/**\n");
        for line in jsdoc_lines(text) {
            out.push_str(&format!(" * {line}\n"));
        }
        out.push_str(" */\n");
    }
}

/// Emit a two-space-indented JSDoc block for an interface field.
fn push_field_doc(out: &mut String, description: Option<&Value>) {
    if let Some(text) = description.and_then(|v| v.as_str()) {
        out.push_str("  /**\n");
        for line in jsdoc_lines(text) {
            out.push_str(&format!("   * {line}\n"));
        }
        out.push_str("   */\n");
    }
}

/// Split a description into JSDoc lines, neutralizing any `*/` that would close
/// the comment early.
fn jsdoc_lines(text: &str) -> Vec<String> {
    text.replace("*/", "* /")
        .split('\n')
        .map(|l| l.trim_end().to_string())
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn emits_string_union_from_one_of() {
        let schema = json!({
            "type": "object",
            "additionalProperties": false,
            "properties": {},
            "definitions": {
                "Color": {
                    "description": "A color.",
                    "oneOf": [
                        { "enum": ["red"], "type": "string" },
                        { "enum": ["green"], "type": "string" }
                    ]
                }
            }
        });
        let ts = emit_ts(&schema);
        assert!(
            ts.contains("export type Color = \"red\" | \"green\";"),
            "{ts}"
        );
    }

    #[test]
    fn emits_interface_with_optional_nullable_and_ref_fields() {
        let schema = json!({
            "type": "object",
            "additionalProperties": false,
            "properties": {},
            "definitions": {
                "Thing": {
                    "type": "object",
                    "additionalProperties": false,
                    "required": ["name"],
                    "properties": {
                        "name": { "type": "string" },
                        "count": { "type": ["integer", "null"] },
                        "tags": { "type": ["array", "null"], "items": { "type": "string" } },
                        "child": {
                            "anyOf": [ { "$ref": "#/definitions/Thing" }, { "type": "null" } ]
                        }
                    }
                }
            }
        });
        let ts = emit_ts(&schema);
        // Required, non-null.
        assert!(ts.contains("name: string;"), "{ts}");
        // Optional + nullable scalar.
        assert!(ts.contains("count?: number | null;"), "{ts}");
        // Optional + nullable array.
        assert!(ts.contains("tags?: string[] | null;"), "{ts}");
        // Optional ref made nullable by the anyOf null branch.
        assert!(ts.contains("child?: Thing | null;"), "{ts}");
    }

    #[test]
    fn open_object_gets_index_signature_closed_does_not() {
        let schema = json!({
            "type": "object",
            "additionalProperties": false,
            "properties": {},
            "definitions": {
                "Open": { "type": "object", "properties": {} },
                "Closed": { "type": "object", "additionalProperties": false, "properties": {} }
            }
        });
        let ts = emit_ts(&schema);
        let open = ts.split("export interface Open").nth(1).unwrap();
        let open_body = open.split('}').next().unwrap();
        assert!(open_body.contains("[k: string]: unknown;"), "{ts}");
        let closed = ts.split("export interface Closed").nth(1).unwrap();
        let closed_body = closed.split('}').next().unwrap();
        assert!(!closed_body.contains("[k: string]: unknown;"), "{ts}");
    }
}
