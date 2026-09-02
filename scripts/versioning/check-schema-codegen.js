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
const configSchemaPath = join(
  repoRoot,
  "schemas",
  "dev",
  `mxc-config.schema.${schemaVer.devSchemaFile}.json`
);
const tmpDir = mkdtempSync(join(os.tmpdir(), "mxc-schema-gen-"));
const tmpConfigOut = join(tmpDir, "generated-config.json");
try {
  const normalize = (s) => s.replace(/\r\n/g, "\n");

  function compareGeneratedSchema({
    committedPath,
    generatedPath,
    generatorArgs,
    regenCommand,
  }) {
    let committed;
    try {
      committed = readFileSync(committedPath, "utf8");
    } catch (e) {
      fail(`could not read committed schema ${committedPath}: ${e.message}`);
    }

    execFileSync(
      "cargo",
      [
        "run",
        "-q",
        "-p",
        "mxc_schema_gen",
        "--",
        ...generatorArgs,
        "--out",
        generatedPath,
      ],
      { cwd: join(repoRoot, "src"), stdio: ["ignore", "ignore", "inherit"] }
    );

    const generated = readFileSync(generatedPath, "utf8");
    if (normalize(generated) !== normalize(committed)) {
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
          `      ${regenCommand}`
      );
    }
  }

  compareGeneratedSchema({
    committedPath: configSchemaPath,
    generatedPath: tmpConfigOut,
    generatorArgs: ["schema", "--legacy-wire"],
    regenCommand: `cargo run --manifest-path src/Cargo.toml -p mxc_schema_gen -- schema --legacy-wire --out schemas/dev/mxc-config.schema.${schemaVer.devSchemaFile}.json`,
  });
} finally {
  rmSync(tmpDir, { recursive: true, force: true });
}

console.log(
  `Schema codegen OK: committed config schema matches generated output (${schemaVer.devSchemaFile}).`
);
