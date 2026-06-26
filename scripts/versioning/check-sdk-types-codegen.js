#!/usr/bin/env node
// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

// SDK wire-types codegen gate: the committed `sdk/src/generated/wire.ts` must
// be identical (modulo line endings) to the output of the Rust TypeScript
// emitter (`mxc_schema_gen --ts`), so the SDK's drift oracle can never go stale
// relative to the Rust wire model. The emitter lives in `wxc_common::ts_emit`
// and uses no third-party generator.
//
// Mirrors `check-schema-codegen.js`. Run from anywhere:
//   node scripts/versioning/check-sdk-types-codegen.js

const { readFileSync, mkdtempSync, rmSync } = require("fs");
const { join } = require("path");
const os = require("os");
const { execFileSync } = require("child_process");

const repoRoot = join(__dirname, "..", "..");
const committedPath = join(repoRoot, "sdk", "src", "generated", "wire.ts");

function fail(msg) {
  console.error("SDK wire-types codegen check FAILED:");
  console.error("  - " + msg);
  process.exit(1);
}

let committed;
try {
  committed = readFileSync(committedPath, "utf8");
} catch (e) {
  fail(`could not read committed ${committedPath}: ${e.message}`);
}

const tmpDir = mkdtempSync(join(os.tmpdir(), "mxc-ts-emit-"));
const tmpOut = join(tmpDir, "wire.ts");
try {
  // Build + run the emitter. Quiet so only our diagnostics surface.
  execFileSync(
    "cargo",
    ["run", "-q", "-p", "mxc_schema_gen", "--", "--ts", tmpOut],
    { cwd: join(repoRoot, "src"), stdio: ["ignore", "ignore", "inherit"] }
  );
  const generated = readFileSync(tmpOut, "utf8");

  // Compare modulo line endings: the file is committed with LF, but a Windows
  // checkout with core.autocrlf=true has CRLF in the working tree. The emitter
  // always writes LF.
  const normalize = (s) => s.replace(/\r\n/g, "\n");
  if (normalize(generated) !== normalize(committed)) {
    const g = normalize(generated).split("\n");
    const c = normalize(committed).split("\n");
    let line = 0;
    while (line < g.length && line < c.length && g[line] === c[line]) line++;
    fail(
      `committed SDK wire types are stale at ${committedPath}.\n` +
        `    First difference at line ${line + 1}:\n` +
        `      committed:  ${JSON.stringify(c[line])}\n` +
        `      generated:  ${JSON.stringify(g[line])}\n` +
        `    Regenerate with (from the repo root; the Cargo workspace is in src/):\n` +
        `      cargo run --manifest-path src/Cargo.toml -p mxc_schema_gen -- --ts sdk/src/generated/wire.ts`
    );
  }
} finally {
  rmSync(tmpDir, { recursive: true, force: true });
}

console.log(
  "SDK wire-types codegen OK: committed sdk/src/generated/wire.ts matches the Rust emitter output."
);
