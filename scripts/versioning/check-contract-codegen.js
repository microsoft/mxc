#!/usr/bin/env node
// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

// Regenerates every registered development-contract artifact, compares it to
// the committed copy, and validates the per-root fixture corpus against the
// generated schema.

const { execFileSync } = require("child_process");
const {
  mkdtempSync,
  readFileSync,
  readdirSync,
  rmSync,
} = require("fs");
const os = require("os");
const { join } = require("path");
const Ajv = require("ajv");

const repoRoot = join(__dirname, "..", "..");
const cargoRoot = join(repoRoot, "src");
const fixtureRoot = join(
  cargoRoot,
  "core",
  "mxc_config_contract",
  "tests",
  "v0_8_0_alpha",
  "fixtures"
);
const roots = {
  one_shot: "OneShotRequest",
  windows_sandbox_provision: "WindowsSandboxProvisionRequest",
  isolation_session_provision: "IsolationSessionProvisionRequest",
  wslc_provision: "WslcProvisionRequest",
  start: "StartRequest",
  exec: "ExecRequest",
  stop: "StopRequest",
  deprovision: "DeprovisionRequest",
};

function fail(message) {
  console.error("Contract codegen check FAILED:");
  console.error("  - " + message);
  process.exit(1);
}

function runGenerator(args, options = {}) {
  return execFileSync(
    "cargo",
    ["run", "-q", "-p", "mxc_schema_gen", "--", ...args],
    {
      cwd: cargoRoot,
      encoding: options.encoding,
      stdio: options.encoding
        ? ["ignore", "pipe", "inherit"]
        : ["ignore", "ignore", "inherit"],
    }
  );
}

function normalize(content) {
  return content.replace(/\r\n/g, "\n");
}

function compareArtifact(committedPath, generatedPath, command) {
  const committed = normalize(readFileSync(committedPath, "utf8"));
  const generated = normalize(readFileSync(generatedPath, "utf8"));
  if (committed === generated) {
    return;
  }

  const committedLines = committed.split("\n");
  const generatedLines = generated.split("\n");
  let line = 0;
  while (
    line < committedLines.length &&
    line < generatedLines.length &&
    committedLines[line] === generatedLines[line]
  ) {
    line++;
  }
  fail(
    `committed artifact is stale at ${committedPath}.\n` +
      `    First difference at line ${line + 1}:\n` +
      `      committed: ${JSON.stringify(committedLines[line])}\n` +
      `      generated: ${JSON.stringify(generatedLines[line])}\n` +
      `    Regenerate with:\n` +
      `      ${command}`
  );
}

function readFixtures(root, kind) {
  const directory = join(fixtureRoot, root, kind);
  return readdirSync(directory)
    .filter((name) => name.endsWith(".json"))
    .sort()
    .map((name) => ({
      name: `${root}/${kind}/${name}`,
      value: JSON.parse(readFileSync(join(directory, name), "utf8")),
    }));
}

function validateFixtures(schema) {
  const composed = new Ajv({ allErrors: true, strict: false }).compile(schema);

  for (const [directory, definition] of Object.entries(roots)) {
    const rootSchema = {
      $schema: schema.$schema,
      definitions: schema.definitions,
      $ref: `#/definitions/${definition}`,
    };
    const validateRoot = new Ajv({
      allErrors: true,
      strict: false,
    }).compile(rootSchema);

    for (const fixture of readFixtures(directory, "valid")) {
      if (!validateRoot(fixture.value)) {
        fail(
          `valid fixture ${fixture.name} failed ${definition}: ` +
            JSON.stringify(validateRoot.errors)
        );
      }
      if (!composed(fixture.value)) {
        fail(
          `valid fixture ${fixture.name} failed the composed schema: ` +
            JSON.stringify(composed.errors)
        );
      }
    }

    for (const fixture of readFixtures(directory, "invalid")) {
      if (validateRoot(fixture.value)) {
        fail(`invalid fixture ${fixture.name} passed ${definition}`);
      }
    }
  }

  const malformedExec = readFixtures("exec", "invalid")[0];
  if (composed(malformedExec.value)) {
    fail("malformed exec diagnostic fixture unexpectedly passed");
  }
  const diagnostics = JSON.stringify(composed.errors);
  if (
    !diagnostics.includes('"missingProperty":"process"') ||
    diagnostics.includes("OneShotRequest") ||
    diagnostics.includes("StartRequest") ||
    diagnostics.includes("StopRequest")
  ) {
    fail(
      "if/then dispatch produced unfocused diagnostics for malformed exec: " +
        diagnostics
    );
  }
}

let registry;
try {
  registry = JSON.parse(
    runGenerator(["versions", "--json"], { encoding: "utf8" })
  );
} catch (error) {
  fail(`could not read generator registry: ${error.message}`);
}

const development = registry.filter(
  (contract) => contract.status === "development"
);
if (development.length === 0) {
  fail("registry did not report a development contract");
}

const temporary = mkdtempSync(join(os.tmpdir(), "mxc-contract-codegen-"));
try {
  for (const contract of development) {
    if (!contract.typescriptPath) {
      fail(`development contract ${contract.version} has no TypeScript path`);
    }

    const schemaOut = join(temporary, `${contract.version}.schema.json`);
    const typesOut = join(temporary, `${contract.version}.wire.ts`);
    runGenerator([
      "schema",
      "--version",
      contract.version,
      "--out",
      schemaOut,
    ]);
    runGenerator([
      "types",
      "--version",
      contract.version,
      "--out",
      typesOut,
    ]);

    const schemaCommand =
      `cargo run --manifest-path src/Cargo.toml -p mxc_schema_gen -- ` +
      `schema --version ${contract.version} --out ${contract.schemaPath}`;
    const typesCommand =
      `cargo run --manifest-path src/Cargo.toml -p mxc_schema_gen -- ` +
      `types --version ${contract.version} --out ${contract.typescriptPath}`;
    compareArtifact(
      join(repoRoot, contract.schemaPath),
      schemaOut,
      schemaCommand
    );
    compareArtifact(
      join(repoRoot, contract.typescriptPath),
      typesOut,
      typesCommand
    );

    validateFixtures(JSON.parse(readFileSync(schemaOut, "utf8")));
  }
} finally {
  rmSync(temporary, { recursive: true, force: true });
}

console.log(
  `Contract codegen OK: ${development.length} development contract artifact set(s) match and validate.`
);
