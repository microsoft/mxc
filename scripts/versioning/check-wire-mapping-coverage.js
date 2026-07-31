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
// A struct is checked one of two ways:
//
//   1. If the mapping layer destructures it without a `..` rest pattern
//      (`let wire::Foo { a, b, c } = ...`), the compiler already refuses to
//      build when a field is added and not named. That is a proof, not a
//      heuristic, so every field on such a struct is accepted outright. This is
//      the preferred form -- see the "Destructure (no `..`)" comments in
//      config_parser.rs.
//
//   2. Otherwise each field must appear as a dotted read (`cfg.foo`) or a
//      destructuring binding (`foo,`) in the mapping layer. That is a text
//      heuristic and therefore a backstop, not a proof.
//
// The heuristic matches over *code only*: comments and string literals are
// stripped first, `..foo` range syntax is not a read of `foo`, and `.foo(` is a
// method call rather than a field access. Without those exclusions the check is
// far weaker than it looks -- see the self-test in the sibling
// check-wire-mapping-coverage.test.js, which pins the two false-positive
// classes that once let a real dropped field through.
//
//   node scripts/versioning/check-wire-mapping-coverage.js
//   node --test scripts/versioning/check-wire-mapping-coverage.test.js

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

// Remove comments and string literals, preserving newlines so offsets stay
// roughly readable. A field name mentioned in prose (`experimental.iso.provision`
// in a doc comment) or inside an error message is not a use of that field, and
// counting it as one silently weakens every check below.
const stripNonCode = (source) => {
  let out = "";
  let state = "code";
  for (let i = 0; i < source.length; ) {
    const c = source[i];
    const d = source[i + 1];
    if (state === "code") {
      if (c === "/" && d === "/") { state = "line"; i += 2; continue; }
      if (c === "/" && d === "*") { state = "block"; i += 2; continue; }
      if (c === '"') { state = "string"; out += " "; i += 1; continue; }
      out += c;
      i += 1;
    } else if (state === "line") {
      if (c === "\n") { state = "code"; out += "\n"; }
      i += 1;
    } else if (state === "block") {
      if (c === "*" && d === "/") { state = "code"; i += 2; continue; }
      if (c === "\n") out += "\n";
      i += 1;
    } else {
      if (c === "\\") { i += 2; continue; }
      if (c === '"') state = "code";
      if (c === "\n") out += "\n";
      i += 1;
    }
  }
  return out;
};

// True when the mapping layer destructures `wire::<name>` without a `..` rest
// pattern. Rust then refuses to compile if a field is added and not named, so
// every field on the struct is proven handled -- no text matching required.
const destructuredExhaustively = (source, name) => {
  const re = new RegExp(`wire::${name}\\s*\\{([^{}]*)\\}`, "g");
  for (let m = re.exec(source); m !== null; m = re.exec(source)) {
    if (!/\.\./.test(m[1])) return true;
  }
  return false;
};

// A field counts as consumed when the mapping layer reads it by dotted access
// (`cfg.foo`) or binds it in a destructuring pattern (`{ foo, bar }`, or one
// binding per line). Two exclusions keep this from matching non-uses:
//   * `(?<!\.)` -- `..start` is range syntax, not a read of a field `start`;
//   * `(?!\s*\()` -- `.version(` is a method call, not a field access.
// Matching is still by field *name* rather than by owning struct, so this stays
// a backstop for the structs that are not destructured exhaustively.
const isConsumed = (source, field) =>
  new RegExp(`(?<!\\.)\\.\\s*${field}\\b(?!\\s*\\()`).test(source) ||
  new RegExp(`[{,]\\s*${field}\\s*[,}:]`).test(source);

const analyze = (wireSource, rawConsumerSources) => {
  // Strip tests per file: applied to the joined text, the first `mod tests`
  // marker would truncate every later file.
  const consumerSource = rawConsumerSources
    .map((s) => stripNonCode(productionOnly(s)))
    .join("\n");

  const structs = [];
  const structRe = /pub struct (\w+) \{([\s\S]*?)\n\}/g;
  for (let m = structRe.exec(wireSource); m !== null; m = structRe.exec(wireSource)) {
    const fields = [...m[2].matchAll(/\n {4}pub (\w+):/g)].map((f) => f[1]);
    structs.push({ name: m[1], fields });
  }

  const unmapped = [];
  let proven = 0;
  for (const { name, fields } of structs) {
    if (destructuredExhaustively(consumerSource, name)) {
      proven += fields.length;
      continue;
    }
    for (const field of fields) {
      if (INTENTIONALLY_IGNORED.has(`${name}.${field}`)) continue;
      if (!isConsumed(consumerSource, field)) unmapped.push(`${name}.${field}`);
    }
  }
  return { structs, unmapped, proven };
};

module.exports = { stripNonCode, destructuredExhaustively, isConsumed, analyze };

if (require.main === module) main();

function main() {
  const { structs, unmapped, proven } = analyze(
    read(WIRE),
    CONSUMERS.map((p) => read(p))
  );

  if (structs.length === 0) {
    console.error(`Wire mapping coverage check FAILED:`);
    console.error(`  - parsed 0 structs from ${WIRE}; the parser regex is stale.`);
    process.exit(1);
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
      `are mapped -- ${proven} proven by exhaustive destructure, ` +
      `${fieldCount - proven} by text match ` +
      `(${INTENTIONALLY_IGNORED.size} documented accept-and-ignore exemptions).`
  );
}

