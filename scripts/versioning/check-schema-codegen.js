#!/usr/bin/env node
// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

// Schema codegen gate: the committed dev JSON Schema must be identical (modulo
// line endings) to the schema generated from the Rust wire model
// (`wxc_common::wire`), so the schema can never drift from its single source of
// truth. Regenerates the schema into a temp file via the `mxc_schema_gen` tool
// and diffs it against the committed
// `schemas/dev/mxc-config.schema.<devSchemaFile>.json`.
//
// Run from anywhere (paths resolved relative to repo root):
//   node scripts/versioning/check-schema-codegen.js

const { readFileSync, mkdtempSync, rmSync } = require("fs");
const { join } = require("path");
const os = require("os");
const { execFileSync } = require("child_process");

const repoRoot = join(__dirname, "..", "..");

function fail(msg) {
  console.error("Schema codegen check FAILED:");
  console.error("  - " + msg);
  process.exit(1);
}

const schemaVer = JSON.parse(
  readFileSync(join(repoRoot, "schemas", "schema-version.json"), "utf8")
);
const committedPath = join(
  repoRoot,
  "schemas",
  "dev",
  `mxc-config.schema.${schemaVer.devSchemaFile}.json`
);

let committed;
try {
  committed = readFileSync(committedPath, "utf8");
} catch (e) {
  fail(`could not read committed schema ${committedPath}: ${e.message}`);
}

const tmpDir = mkdtempSync(join(os.tmpdir(), "mxc-schema-gen-"));
const tmpOut = join(tmpDir, "generated.json");
try {
  // Build + run the generator. Quiet so only our diagnostics surface.
  execFileSync(
    "cargo",
    ["run", "-q", "-p", "mxc_schema_gen", "--", tmpOut],
    { cwd: join(repoRoot, "src"), stdio: ["ignore", "ignore", "inherit"] }
  );
  const generated = readFileSync(tmpOut, "utf8");

  // Compare modulo line endings: the schema is committed with LF, but on a
  // Windows checkout with core.autocrlf=true the working-tree copy has CRLF.
  // The generator always writes LF, so normalize both sides to avoid a
  // false-positive "stale" failure that only reproduces on Windows.
  const normalize = (s) => s.replace(/\r\n/g, "\n");
  if (normalize(generated) !== normalize(committed)) {
    // Find the first differing line for a helpful pointer.
    const g = normalize(generated).split("\n");
    const c = normalize(committed).split("\n");
    let line = 0;
    while (line < g.length && line < c.length && g[line] === c[line]) line++;
    fail(
      `committed schema is stale at ${committedPath}.\n` +
        `    First difference at line ${line + 1}:\n` +
        `      committed:  ${JSON.stringify(c[line])}\n` +
        `      generated:  ${JSON.stringify(g[line])}\n` +
        `    Regenerate with (from the repo root; the Cargo workspace is in src/):\n` +
        `      cargo run --manifest-path src/Cargo.toml -p mxc_schema_gen -- schemas/dev/mxc-config.schema.${schemaVer.devSchemaFile}.json`
    );
  }
} finally {
  rmSync(tmpDir, { recursive: true, force: true });
}

console.log(
  `Schema codegen OK: committed dev schema matches the generated output (${schemaVer.devSchemaFile}).`
);
