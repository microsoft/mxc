// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

// Self-test for check-wire-mapping-coverage.js.
//
// The gate exists to stop a wire field being declared -- and therefore
// advertised by the generated JSON schema and SDK types -- while the mapping
// layer silently drops it. An earlier revision of the gate matched bare field
// names against raw file text, so two real dropped fields
// (`wire::IsolationSession.provision` / `.start`) both registered as consumed:
// one via a dotted path inside a doc comment, the other via `..start` range
// syntax. The gate reported OK on the revision that contained the bug.
//
// These tests pin the exclusions that close those classes, so the gate cannot
// silently weaken back into passing everything.
//
//   node --test scripts/versioning/

const test = require("node:test");
const assert = require("node:assert");

const {
  stripNonCode,
  destructuredExhaustively,
  isConsumed,
  analyze,
} = require("./check-wire-mapping-coverage.js");

test("stripNonCode removes line, doc and block comments", () => {
  const out = stripNonCode(`
    /// Nested under \`experimental.isolation_session.provision\`.
    let a = 1; // trailing
    /* block .provision */
    let b = 2;
  `);
  assert.ok(!out.includes("provision"), "comment text survived stripping");
  assert.ok(out.includes("let a = 1;"));
  assert.ok(out.includes("let b = 2;"));
});

test("stripNonCode removes string literals but keeps surrounding code", () => {
  const out = stripNonCode(`let msg = "field .provision is missing"; let x = 1;`);
  assert.ok(!out.includes("provision"), "string literal survived stripping");
  assert.ok(out.includes("let x = 1;"));
});

test("stripNonCode does not treat // inside a string as a comment", () => {
  const out = stripNonCode(`let url = "http://example.com"; let kept = 1;`);
  assert.ok(out.includes("let kept = 1;"), "code after a URL string was eaten");
});

// --- the two false-positive classes that let the real bug through ---

test("a field named only in a doc comment is not consumed", () => {
  const src = stripNonCode(
    "/// Nested under `experimental.isolation_session.provision`. Carries Entra\npub struct X;"
  );
  assert.strictEqual(isConsumed(src, "provision"), false);
});

test("`..start` range syntax does not consume a field named start", () => {
  const src = stripNonCode("let (p, s) = match (json.get(..start), json.get(end..)) { _ => () };");
  assert.strictEqual(isConsumed(src, "start"), false);
});

test("a method call does not consume a field of the same name", () => {
  const src = stripNonCode("let v = other.version();");
  assert.strictEqual(isConsumed(src, "version"), false);
});

// --- genuine consumption still counts ---

test("dotted field access consumes", () => {
  assert.strictEqual(isConsumed(stripNonCode("let v = cfg.timeout;"), "timeout"), true);
});

test("destructuring binding consumes", () => {
  assert.strictEqual(isConsumed(stripNonCode("let X { alpha, beta } = v;"), "alpha"), true);
});

// --- exhaustive destructure is a proof, `..` is not ---

test("exhaustive destructure of wire::Name is detected", () => {
  const src = "let wire::Thing { alpha, beta } = v;";
  assert.strictEqual(destructuredExhaustively(src, "Thing"), true);
});

test("a destructure with a `..` rest pattern is not exhaustive", () => {
  const src = "let wire::Thing { alpha, .. } = v;";
  assert.strictEqual(destructuredExhaustively(src, "Thing"), false);
});

test("a path-qualified destructure (crate::wire::Name) is still detected", () => {
  const src = "let crate::wire::Thing { alpha, beta } = v;";
  assert.strictEqual(destructuredExhaustively(src, "Thing"), true);
});

// --- end-to-end: the gate must catch a field that is only named in prose ---

test("analyze flags a field referenced solely in a comment", () => {
  const wire = [
    "pub struct Sample {",
    "    /// doc",
    "    pub mapped: Option<String>,",
    "    /// doc",
    "    pub dropped: Option<String>,",
    "}",
  ].join("\n");
  const consumer = [
    "// The `sample.dropped` block is described here but never read.",
    "fn f(s: Sample) { let _ = s.mapped; }",
  ].join("\n");

  const { unmapped } = analyze(wire, [consumer]);
  assert.deepStrictEqual(unmapped, ["Sample.dropped"]);
});

test("analyze accepts every field of an exhaustively destructured struct", () => {
  const wire = ["pub struct Sample {", "    pub alpha: u8,", "    pub beta: u8,", "}"].join("\n");
  const consumer = "fn f(s: Sample) { let wire::Sample { alpha, beta } = s; }";

  const { unmapped, proven } = analyze(wire, [consumer]);
  assert.deepStrictEqual(unmapped, []);
  assert.strictEqual(proven, 2);
});

test("analyze strips tests per file, not across the joined source", () => {
  const wire = ["pub struct Sample {", "    pub alpha: u8,", "}"].join("\n");
  // First file has a test module; the real mapping lives in the second file.
  // Truncating the joined text at the first marker would discard it.
  const first = "fn a() {}\nmod tests {\n    fn t() {}\n}\n";
  const second = "fn b(s: Sample) { let _ = s.alpha; }";

  assert.deepStrictEqual(analyze(wire, [first, second]).unmapped, []);
});
