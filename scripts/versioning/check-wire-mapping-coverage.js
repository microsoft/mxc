#!/usr/bin/env node
// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

// Validates that every field declared on the wire model
// (src/core/wxc_common/src/wire.rs) is actually consumed by the mapping layer
// (config_parser.rs / models.rs), so a field cannot be added to the wire model
// -- and therefore advertised by the generated JSON schema and the generated
// SDK types -- while the parser silently drops it.
//
// This closes a gap the existing codegen gates cannot: check-schema-codegen and
// check-sdk-types-codegen both *generate from* the wire model, so an unmapped
// new field regenerates cleanly and passes them both.
//
// A field counts as consumed when the mapping layer either reads it by dotted
// access (`cfg.foo`) or binds it in a destructuring pattern (`foo,`). The
// preferred form is destructuring without `..`, which additionally makes an
// unmapped field a compile error -- see the "Destructure (no `..`)" comments in
// config_parser.rs. This script is the backstop for the structs that still use
// inline field access.
//
//   node scripts/versioning/check-wire-mapping-coverage.js

const { readFileSync } = require("fs");
const { join } = require("path");

const repoRoot = join(__dirname, "..", "..");
const WIRE = "src/core/wxc_common/src/wire.rs";
const CONSUMERS = [
  "src/core/wxc_common/src/config_parser.rs",
  "src/core/wxc_common/src/models.rs",
];

// Fields the parser deliberately accepts and ignores. Each entry must stay
// documented as such in the wire model's own doc comment.
const INTENTIONALLY_IGNORED = new Set([
  "MxcConfig.schema", // `$schema`  -- editor-only annotation
  "MxcConfig.comment", // `_comment` -- human annotation
]);

const read = (relPath) => readFileSync(join(repoRoot, relPath), "utf8");

// Strip `#[cfg(test)] mod tests { ... }` so a field only referenced by a test
// does not count as mapped by production code.
const productionOnly = (source) => {
  const marker = source.indexOf("\nmod tests {");
  return marker === -1 ? source : source.slice(0, marker);
};

const wireSource = read(WIRE);
const consumerSource = CONSUMERS.map((p) => productionOnly(read(p))).join("\n");

const structs = [];
const structRe = /pub struct (\w+) \{([\s\S]*?)\n\}/g;
let match;
while ((match = structRe.exec(wireSource)) !== null) {
  const fields = [...match[2].matchAll(/\n {4}pub (\w+):/g)].map((m) => m[1]);
  structs.push({ name: match[1], fields });
}

if (structs.length === 0) {
  console.error(`Wire mapping coverage check FAILED:`);
  console.error(`  - parsed 0 structs from ${WIRE}; the parser regex is stale.`);
  process.exit(1);
}

// A field counts as consumed when the mapping layer reads it by dotted access
// (`cfg.foo`) or binds it in a destructuring pattern (`{ foo, bar }`, or one
// binding per line). Matching is by field *name*, not struct-scoped, so this is
// a backstop rather than a proof: the real guard is destructuring without `..`,
// which makes an unmapped field a compile error.
const isConsumed = (field) =>
  new RegExp(`\\.\\s*${field}\\b`).test(consumerSource) ||
  new RegExp(`[{,]\\s*${field}\\s*[,}:]`).test(consumerSource);

const unmapped = [];
for (const { name, fields } of structs) {
  for (const field of fields) {
    if (INTENTIONALLY_IGNORED.has(`${name}.${field}`)) continue;
    if (!isConsumed(field)) unmapped.push(`${name}.${field}`);
  }
}

if (unmapped.length) {
  console.error("Wire mapping coverage check FAILED:");
  console.error(
    `  ${unmapped.length} wire field(s) are declared but never consumed by the mapping layer.`
  );
  console.error(
    "  The generated schema and SDK types advertise them, but the parser drops them silently."
  );
  for (const field of unmapped) console.error(`  - wire::${field}`);
  console.error("");
  console.error("  Fix by one of:");
  console.error("    * map the field in config_parser.rs (preferred: destructure without `..`);");
  console.error("    * reject it explicitly, so callers get an error instead of silence;");
  console.error("    * remove it from the wire model;");
  console.error(
    "    * if it is deliberately accepted-and-ignored, document that in its wire doc"
  );
  console.error("      comment and add it to INTENTIONALLY_IGNORED in this script.");
  process.exit(1);
}

const fieldCount = structs.reduce((n, s) => n + s.fields.length, 0);
console.log(
  `Wire mapping coverage OK: ${fieldCount} field(s) across ${structs.length} wire struct(s) ` +
    `are mapped (${INTENTIONALLY_IGNORED.size} documented accept-and-ignore exemptions).`
);
