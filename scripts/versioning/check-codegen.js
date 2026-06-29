#!/usr/bin/env node
// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

// Codegen drift gate (merged): both artifacts generated from the Rust wire model
// (`wxc_common::wire`) must match their committed copies, so neither the dev JSON
// Schema nor the SDK wire TypeScript can drift from their single source of truth.
// Regenerates each via `mxc_schema_gen` into a temp file and diffs it against the
// committed copy (modulo line endings). Replaces the former check-schema-codegen.js
// and check-sdk-types-codegen.js.
//
// Run from anywhere (paths resolved relative to repo root):
//   node scripts/versioning/check-codegen.js

const { readFileSync, mkdtempSync, rmSync } = require("fs");
const { join } = require("path");
const os = require("os");
const { execFileSync } = require("child_process");

const repoRoot = join(__dirname, "..", "..");
const schemaVer = JSON.parse(
  readFileSync(join(repoRoot, "schemas", "schema-version.json"), "utf8")
);

// Each artifact: the generator args (relative out path is appended), the
// committed file, and the human-facing regenerate hint.
const artifacts = [
  {
    label: "dev schema",
    genArgs: [],
    committed: join(
      "schemas",
      "dev",
      `mxc-config.schema.${schemaVer.devSchemaFile}.json`
    ),
    tmpName: "generated.json",
    hint: `cargo run --manifest-path src/Cargo.toml -p mxc_schema_gen -- schemas/dev/mxc-config.schema.${schemaVer.devSchemaFile}.json`,
  },
  {
    label: "SDK wire types",
    genArgs: ["--ts"],
    committed: join("sdk", "src", "generated", "wire.ts"),
    tmpName: "wire.ts",
    hint: "cargo run --manifest-path src/Cargo.toml -p mxc_schema_gen -- --ts sdk/src/generated/wire.ts",
  },
];

function fail(msg) {
  console.error("Codegen check FAILED:");
  console.error("  - " + msg);
  process.exit(1);
}

// Compare modulo line endings: artifacts are committed with LF, but a Windows
// checkout with core.autocrlf=true has CRLF in the working tree. The generator
// always writes LF, so normalize both sides to avoid a Windows-only false stale.
const normalize = (s) => s.replace(/\r\n/g, "\n");

const tmpDir = mkdtempSync(join(os.tmpdir(), "mxc-codegen-"));
try {
  for (const a of artifacts) {
    const committedPath = join(repoRoot, a.committed);
    let committed;
    try {
      committed = readFileSync(committedPath, "utf8");
    } catch (e) {
      fail(`could not read committed ${committedPath}: ${e.message}`);
    }

    const tmpOut = join(tmpDir, a.tmpName);
    // Build + run the generator. Quiet so only our diagnostics surface. The
    // first run builds mxc_schema_gen; later runs reuse the compiled binary.
    execFileSync(
      "cargo",
      ["run", "-q", "-p", "mxc_schema_gen", "--", ...a.genArgs, tmpOut],
      { cwd: join(repoRoot, "src"), stdio: ["ignore", "ignore", "inherit"] }
    );
    const generated = readFileSync(tmpOut, "utf8");

    if (normalize(generated) !== normalize(committed)) {
      const g = normalize(generated).split("\n");
      const c = normalize(committed).split("\n");
      let line = 0;
      while (line < g.length && line < c.length && g[line] === c[line]) line++;
      fail(
        `committed ${a.label} is stale at ${a.committed}.\n` +
          `    First difference at line ${line + 1}:\n` +
          `      committed:  ${JSON.stringify(c[line])}\n` +
          `      generated:  ${JSON.stringify(g[line])}\n` +
          `    Regenerate with (from the repo root; the Cargo workspace is in src/):\n` +
          `      ${a.hint}`
      );
    }
  }
} finally {
  rmSync(tmpDir, { recursive: true, force: true });
}

console.log(
  `Codegen OK: dev schema (${schemaVer.devSchemaFile}) and SDK wire types match the Rust wire model.`
);
