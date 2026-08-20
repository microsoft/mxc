#!/usr/bin/env node
// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

const { execFileSync } = require("child_process");
const { readFileSync, mkdtempSync, rmSync } = require("fs");
const { join } = require("path");
const os = require("os");

const repoRoot = join(__dirname, "..", "..");
const artifacts = [
  {
    args: ["--telemetry-consent"],
    committed: join(
      repoRoot,
      "schemas",
      "dev",
      "mxc-telemetry-consent.schema.1.json"
    ),
    name: "telemetry consent schema",
  },
  {
    args: ["--telemetry-consent-ts"],
    committed: join(
      repoRoot,
      "sdk",
      "node",
      "src",
      "generated",
      "telemetry-consent-wire.ts"
    ),
    name: "telemetry consent TypeScript wire types",
  },
];

function normalize(content) {
  return content.replace(/\r\n/g, "\n");
}

function fail(message) {
  console.error("Telemetry consent codegen check FAILED:");
  console.error(`  - ${message}`);
  process.exit(1);
}

const tempDir = mkdtempSync(join(os.tmpdir(), "mxc-consent-codegen-"));
try {
  for (const [index, artifact] of artifacts.entries()) {
    const output = join(tempDir, `artifact-${index}`);
    execFileSync(
      "cargo",
      ["run", "-q", "-p", "mxc_schema_gen", "--", ...artifact.args, output],
      {
        cwd: join(repoRoot, "src"),
        stdio: ["ignore", "ignore", "inherit"],
      }
    );

    let committed;
    try {
      committed = readFileSync(artifact.committed, "utf8");
    } catch (error) {
      fail(`could not read ${artifact.committed}: ${error.message}`);
    }
    const generated = readFileSync(output, "utf8");
    if (normalize(generated) !== normalize(committed)) {
      fail(
        `${artifact.name} is stale at ${artifact.committed}. ` +
          `Regenerate it with mxc_schema_gen ${artifact.args.join(" ")}.`
      );
    }
  }
} finally {
  rmSync(tempDir, { recursive: true, force: true });
}

console.log(
  "Telemetry consent codegen OK: schema and TypeScript wire types match Rust."
);
