// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Dependency-light rendering and TypeScript emission shared by MXC schema
//! generators.

mod ts_emit;

use serde_json::{Map, Value};

/// Applies common post-processing to a generated JSON Schema.
pub fn prepare_schema(value: &mut Value, schema_id: &str) {
    normalize_integer_formats(value);
    if let Value::Object(map) = value {
        map.insert("$id".to_string(), Value::String(schema_id.to_string()));
    }
}

/// Renders a root schema object with metadata first and all remaining keys in
/// deterministic alphabetical order.
pub fn render_root_ordered(map: &Map<String, Value>) -> String {
    const ORDER: &[&str] = &["$schema", "$id", "title", "description"];
    let rank = |key: &str| {
        ORDER
            .iter()
            .position(|candidate| *candidate == key)
            .unwrap_or(ORDER.len())
    };

    let mut keys: Vec<&String> = map.keys().collect();
    keys.sort_by_key(|key| rank(key));

    let mut output = String::from("{\n");
    for (index, key) in keys.iter().enumerate() {
        let value =
            serde_json::to_string_pretty(&map[*key]).expect("schema value serializes to JSON");
        let mut lines = value.lines();
        let mut indented = lines.next().unwrap_or("").to_string();
        for line in lines {
            indented.push_str("\n  ");
            indented.push_str(line);
        }
        let key = serde_json::to_string(key).expect("object key serializes to JSON");
        output.push_str("  ");
        output.push_str(&key);
        output.push_str(": ");
        output.push_str(&indented);
        if index + 1 < keys.len() {
            output.push(',');
        }
        output.push('\n');
    }
    output.push('}');
    output
}

/// Emits TypeScript wire types from a generated JSON Schema.
pub fn emit_ts(schema: &Value) -> String {
    ts_emit::emit_ts(schema)
}

/// Emits the versioned contract TypeScript wire oracle.
pub fn emit_contract_ts(schema: &Value, version: &str) -> String {
    ts_emit::emit_contract_ts(schema, version)
}

fn normalize_integer_formats(value: &mut Value) {
    match value {
        Value::Object(map) => {
            if let Some(Value::String(format)) = map.get("format") {
                let format = format.clone();
                if let Some((minimum, maximum)) = integer_bounds(&format) {
                    map.remove("format");
                    map.entry("minimum").or_insert(Value::Number(minimum));
                    map.entry("maximum").or_insert(Value::Number(maximum));
                }
            }
            for child in map.values_mut() {
                normalize_integer_formats(child);
            }
        }
        Value::Array(items) => {
            for child in items {
                normalize_integer_formats(child);
            }
        }
        _ => {}
    }
}

fn integer_bounds(format: &str) -> Option<(serde_json::Number, serde_json::Number)> {
    let unsigned = |maximum: u64| {
        (
            serde_json::Number::from(0),
            serde_json::Number::from(maximum),
        )
    };
    let signed = |minimum: i64, maximum: i64| {
        (
            serde_json::Number::from(minimum),
            serde_json::Number::from(maximum),
        )
    };

    match format {
        "uint8" => Some(unsigned(u8::MAX.into())),
        "uint16" => Some(unsigned(u16::MAX.into())),
        "uint32" => Some(unsigned(u32::MAX.into())),
        "uint64" | "uint" => Some(unsigned(u64::MAX)),
        "int8" => Some(signed(i8::MIN.into(), i8::MAX.into())),
        "int16" => Some(signed(i16::MIN.into(), i16::MAX.into())),
        "int32" => Some(signed(i32::MIN.into(), i32::MAX.into())),
        "int64" | "int" => Some(signed(i64::MIN, i64::MAX)),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn prepares_schema_id_and_integer_constraints() {
        let mut schema = json!({
            "definitions": {
                "Unsigned": { "type": "integer", "format": "uint32" },
                "Signed": { "type": "integer", "format": "int64" },
                "Uri": { "type": "string", "format": "uri" }
            }
        });

        prepare_schema(&mut schema, "https://example.test/schema.json");

        assert_eq!(schema["$id"], "https://example.test/schema.json");
        assert_eq!(schema["definitions"]["Unsigned"]["minimum"], 0);
        assert_eq!(
            schema["definitions"]["Unsigned"]["maximum"],
            serde_json::Value::from(u32::MAX)
        );
        assert!(schema["definitions"]["Unsigned"].get("format").is_none());
        assert_eq!(
            schema["definitions"]["Signed"]["minimum"],
            serde_json::Value::from(i64::MIN)
        );
        assert_eq!(
            schema["definitions"]["Signed"]["maximum"],
            serde_json::Value::from(i64::MAX)
        );
        assert!(schema["definitions"]["Signed"].get("format").is_none());
        assert_eq!(schema["definitions"]["Uri"]["format"], "uri");
    }
}
