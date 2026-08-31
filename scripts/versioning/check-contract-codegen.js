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

// The fixture corpus lives beside the contract it exercises, in the crate's
// own module naming (`0.9.0-alpha` -> `v0_9_0_alpha`). Deriving it from the
// registry keeps the gate version-driven, so a publication that advances the
// development contract validates its own fixtures rather than the previous
// contract's.
function fixtureRootFor(contract) {
  const module = `v${contract.version.replace(/[.-]/g, "_")}`;
  return join(
    cargoRoot,
    "core",
    "mxc_config_contract",
    "tests",
    module,
    "fixtures"
  );
}

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

function readFixtures(fixtureRoot, root, kind) {
  const directory = join(fixtureRoot, root, kind);
  const fixtures = readdirSync(directory)
    .filter((name) => name.endsWith(".json"))
    .sort()
    .map((name) => readFixture(fixtureRoot, root, kind, name));
  if (fixtures.length === 0) {
    fail(`fixture directory ${root}/${kind} is empty`);
  }
  return fixtures;
}

function readFixture(fixtureRoot, root, kind, name) {
  return {
    name: `${root}/${kind}/${name}`,
    value: JSON.parse(
      readFileSync(join(fixtureRoot, root, kind, name), "utf8")
    ),
  };
}

function collectDispatchRoots(value, references = new Set()) {
  if (Array.isArray(value)) {
    for (const child of value) {
      collectDispatchRoots(child, references);
    }
  } else if (value && typeof value === "object") {
    if (typeof value.$ref === "string") {
      const prefix = "#/definitions/";
      if (value.$ref.startsWith(prefix)) {
        references.add(value.$ref.slice(prefix.length));
      }
    }
    for (const [key, child] of Object.entries(value)) {
      if (key !== "definitions") {
        collectDispatchRoots(child, references);
      }
    }
  }
  return references;
}

function validateFixtures(schema, fixtureRoot) {
  const dispatchedRoots = collectDispatchRoots(schema);
  const expectedRoots = new Set(Object.values(roots));
  const missing = [...dispatchedRoots].filter((root) => !expectedRoots.has(root));
  const stale = [...expectedRoots].filter((root) => !dispatchedRoots.has(root));
  if (missing.length || stale.length) {
    fail(
      `fixture roots do not match schema dispatch; missing mappings: ` +
        `${missing.join(", ") || "none"}; stale mappings: ` +
        `${stale.join(", ") || "none"}`
    );
  }

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

    for (const fixture of readFixtures(fixtureRoot, directory, "valid")) {
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

    for (const fixture of readFixtures(fixtureRoot, directory, "invalid")) {
      if (validateRoot(fixture.value)) {
        fail(`invalid fixture ${fixture.name} passed ${definition}`);
      }
    }
  }

  const malformedExec = readFixture(
    fixtureRoot,
    "exec",
    "invalid",
    "missing_process.json"
  );
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

    validateFixtures(
      JSON.parse(readFileSync(schemaOut, "utf8")),
      fixtureRootFor(contract)
    );
  }
} finally {
  rmSync(temporary, { recursive: true, force: true });
}

console.log(
  `Contract codegen OK: ${development.length} development contract artifact set(s) match and validate.`
);
