// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

const test = require("node:test");
const assert = require("node:assert/strict");
const { readFileSync } = require("fs");
const { resolve } = require("path");
const { scanBuildRs } = require("../lib/build-rs-inputs");

const BUILD_RS = resolve(
  __dirname,
  "..",
  "..",
  "..",
  "src",
  "ffi",
  "mxc_ffi",
  "build.rs"
);

// Every negative case asserts the ghost path is absent: counting a declaration
// cargo never receives is a silent pass of the gate that consumes this scan.
function declared(text) {
  return scanBuildRs(text).declaredInputs;
}

test("a live declaration is collected", () => {
  assert.deepEqual(
    declared('fn main() {\n    println!("cargo:rerun-if-changed=src/lib.rs");\n}\n'),
    ["src/lib.rs"]
  );
});

test("a declaration in column zero is collected", () => {
  assert.deepEqual(
    declared('println!("cargo:rerun-if-changed=src/lib.rs");\n'),
    ["src/lib.rs"]
  );
});

test("the cargo:: form is collected", () => {
  assert.deepEqual(
    declared('    println!("cargo::rerun-if-changed=src/lib.rs");\n'),
    ["src/lib.rs"]
  );
});

test("a line-commented declaration is not collected", () => {
  assert.deepEqual(
    declared('    // println!("cargo:rerun-if-changed=src/lead.rs");\n'),
    []
  );
});

test("a declaration after a trailing line comment is not collected", () => {
  assert.deepEqual(
    declared(
      '    let x = 1; // println!("cargo:rerun-if-changed=src/trail.rs");\n'
    ),
    []
  );
});

test("a block-commented declaration is not collected", () => {
  assert.deepEqual(
    declared('    /* println!("cargo:rerun-if-changed=src/block.rs"); */\n'),
    []
  );
});

test("a declaration inside a multi-line block comment is not collected", () => {
  assert.deepEqual(
    declared(
      "    /* disabled for now\n" +
        '    println!("cargo:rerun-if-changed=src/multi.rs");\n' +
        "    */\n"
    ),
    []
  );
});

test("a declaration inside a nested block comment is not collected", () => {
  // Rust block comments nest, so a non-greedy match ends at the first `*/` and
  // leaves the rest of the outer comment looking live.
  assert.deepEqual(
    declared(
      "    /* outer\n" +
        "    /* inner */\n" +
        '    println!("cargo:rerun-if-changed=src/nested.rs");\n' +
        "    */\n"
    ),
    []
  );
});

test("an eprintln! declaration is not collected", () => {
  // `eprintln!` contains `println!` from its second character, and writes to
  // stderr, which cargo does not read for directives.
  assert.deepEqual(
    declared('    eprintln!("cargo:rerun-if-changed=src/eprint.rs");\n'),
    []
  );
});

test("a formatted declaration names no comparable path and is not collected", () => {
  assert.deepEqual(
    declared('    println!("cargo:rerun-if-changed={}", out.display());\n'),
    []
  );
});

test("a csbindgen input is collected and a commented one is not", () => {
  const { csbindgenInputs, unparseable } = scanBuildRs(
    "    .input_extern_file(\"src/lib.rs\")\n" +
      "    // .input_extern_file(\"src/gone.rs\")\n"
  );
  assert.deepEqual(csbindgenInputs, ["src/lib.rs"]);
  assert.deepEqual(unparseable, []);
});

test("a csbindgen input that is not a plain literal is reported, not skipped", () => {
  const { csbindgenInputs, unparseable } = scanBuildRs(
    "    .input_extern_file(SOURCE)\n"
  );
  assert.deepEqual(csbindgenInputs, []);
  assert.equal(unparseable.length, 1);
  assert.match(unparseable[0], /SOURCE/);
});

test("a line comment containing a block-comment opener does not swallow the file", () => {
  // `src/*.rs` in an ordinary comment contains `/*`. A reader that strips block
  // comments before line comments opens a depth that never closes, silently
  // discarding every later call while leaving the count non-zero.
  const { csbindgenInputs } = scanBuildRs(
    '        .input_extern_file("src/lib.rs")\n' +
      "        // keep in sync with src/ffi/mxc_ffi/src/*.rs\n" +
      '        .input_extern_file("src/streaming.rs")\n'
  );
  assert.deepEqual(csbindgenInputs, ["src/lib.rs", "src/streaming.rs"]);
});

test("a doc comment containing a block-comment opener does not swallow the file", () => {
  const { csbindgenInputs } = scanBuildRs(
    '        .input_extern_file("src/lib.rs")\n' +
      "        /// keep in sync with src/ffi/mxc_ffi/src/*.rs\n" +
      '        .input_extern_file("src/streaming.rs")\n'
  );
  assert.deepEqual(csbindgenInputs, ["src/lib.rs", "src/streaming.rs"]);
});

test("a directive quoted inside a raw string is data, not a declaration", () => {
  // The body opens with a quote, so a reader that does not understand raw
  // strings closes an empty string there and reads the rest as code.
  assert.deepEqual(
    declared(
      '    let example = r#"" println!("cargo:rerun-if-changed=src/ghost.rs")"#;\n' +
        '    println!("cargo:rerun-if-changed=src/real.rs");\n'
    ),
    ["src/real.rs"]
  );
});

test("a directive quoted inside an ordinary string is data, not a declaration", () => {
  assert.deepEqual(
    declared(
      '    let example = "println!(\\"cargo:rerun-if-changed=src/ghost.rs\\")";\n' +
        '    println!("cargo:rerun-if-changed=src/real.rs");\n'
    ),
    ["src/real.rs"]
  );
});

test("a second declaration on the same line is not ignored", () => {
  assert.deepEqual(
    declared(
      '    println!("cargo:rerun-if-changed=src/a.rs"); println!("cargo:rerun-if-changed=src/b.rs");\n'
    ),
    ["src/a.rs", "src/b.rs"]
  );
});

test("a lifetime does not open a character literal that swallows the file", () => {
  // A reader that pairs each quote with the next treats everything between two
  // lifetimes as one character literal, discarding the call in between.
  const { csbindgenInputs } = scanBuildRs(
    "        fn a<'x>() {}\n" +
      '        .input_extern_file("src/lib.rs")\n' +
      "        fn b<'y>() {}\n"
  );
  assert.deepEqual(csbindgenInputs, ["src/lib.rs"]);
});

test("a directive quoted inside a raw C string is data, not a declaration", () => {
  // `cr` is a stable raw C string. A reader that does not know the prefix reads
  // `cr#` as code, opens an ordinary string at the quote, and from there both
  // invents a declaration and loses the next real one.
  assert.deepEqual(
    declared(
      '    let s = cr#"" println!("cargo:rerun-if-changed=src/ghost.rs")"#;\n' +
        '    println!("cargo:rerun-if-changed=src/real.rs");\n'
    ),
    ["src/real.rs"]
  );
});

test("a macro whose name merely ends in println! is not a declaration", () => {
  // Rust identifiers are not ASCII-only, so a non-ASCII prefix makes a distinct
  // macro look like `println!`.
  assert.deepEqual(
    declared(
      '    \u00e9println!("cargo:rerun-if-changed=src/ghost.rs");\n' +
        '    my_println!("cargo:rerun-if-changed=src/other.rs");\n' +
        '    println!("cargo:rerun-if-changed=src/real.rs");\n'
    ),
    ["src/real.rs"]
  );
});

test("a stray quote from an escaped-quote literal does not cascade into a string", () => {
  // Consuming one character short leaves a stray quote that pairs with the next
  // literal's opening quote, exposing its `"` payload as a string opener that
  // swallows every declaration after it.
  assert.deepEqual(
    declared(
      "    let _ = ('\\'','\"');\n" +
        '    println!("cargo:rerun-if-changed=src/real.rs");\n'
    ),
    ["src/real.rs"]
  );
});

test("the real build.rs declares every source csbindgen reads", () => {
  const { csbindgenInputs, unparseable, declaredInputs } = scanBuildRs(
    readFileSync(BUILD_RS, "utf8")
  );
  assert.deepEqual(unparseable, []);
  assert.ok(csbindgenInputs.length > 0, "expected csbindgen inputs");
  const notDeclared = csbindgenInputs.filter((p) => !declaredInputs.includes(p));
  assert.deepEqual(notDeclared, []);
});
