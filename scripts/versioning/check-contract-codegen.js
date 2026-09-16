#!/usr/bin/env node
// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

// Regenerates every exact contract with a registered TypeScript oracle,
// compares it to the committed copy, and validates the per-root fixture corpus
// against the generated schema.

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
const {
  listFilesAtCommit,
  readFileAtCommit,
  resolveBaseCommit,
} = require("./lib/git-base.js");
const { compareVersions, parseVersion } = require("./lib/version.js");

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

function fail(message) {
  throw new Error(message);
}

function formatFailure(error) {
  const message = error instanceof Error ? error.message : String(error);
  return `Contract codegen check FAILED:\n  - ${message}`;
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

function stableSchemaVersion(path) {
  return /^schemas\/stable\/mxc-config\.schema\.(.+)\.json$/.exec(path)?.[1] ??
    null;
}

function validateStableHistory(baseSchemas, currentSchemas) {
  const errors = [];
  for (const [path, before] of baseSchemas) {
    const after = currentSchemas.get(path);
    if (after === undefined) {
      errors.push(`stable schema was removed: ${path}`);
    } else if (normalize(before) !== normalize(after)) {
      errors.push(`stable schema changed after publication: ${path}`);
    }
  }
  return errors;
}

function validatePublishedRegistry(registry, stableSchemas, minimumVersion) {
  const errors = [];
  const development = registry.filter(
    (contract) => contract.status === "development"
  );
  if (development.length !== 1) {
    errors.push(
      `registry must report exactly one development contract, found ` +
        development.length
    );
  }

  const byVersion = new Map(
    registry.map((contract) => [contract.version, contract])
  );
  const minimum = parseVersion(minimumVersion);
  if (!minimum) {
    return [`invalid minimum schema version ${minimumVersion}`];
  }

  for (const [path, content] of stableSchemas) {
    const version = stableSchemaVersion(path);
    if (!version) continue;
    const parsed = parseVersion(version);
    if (!parsed) {
      errors.push(`stable schema has an invalid versioned name: ${path}`);
      continue;
    }
    if (compareVersions(parsed, minimum) < 0) continue;

    const contract = byVersion.get(version);
    if (!contract) {
      errors.push(`supported stable schema ${version} is absent from the registry`);
      continue;
    }
    if (contract.status !== "published") {
      errors.push(
        `stable schema ${version} is registered as ${contract.status}, not published`
      );
    }
    if (contract.schemaPath !== path) {
      errors.push(
        `published contract ${version} changed schema path: ` +
          `${contract.schemaPath} instead of ${path}`
      );
    }
    let schema;
    try {
      schema = JSON.parse(content);
    } catch (error) {
      errors.push(`stable schema ${path} is not valid JSON: ${error.message}`);
      continue;
    }
    if (schema.$id !== contract.schemaId) {
      errors.push(
        `published contract ${version} changed schema identity: ` +
          `${contract.schemaId} instead of ${schema.$id}`
      );
    }
  }
  return errors;
}

function currentStableSchemas() {
  const directory = join(repoRoot, "schemas", "stable");
  return new Map(
    readdirSync(directory)
      .filter((name) => /^mxc-config\.schema\..+\.json$/.test(name))
      .sort()
      .map((name) => {
        const path = `schemas/stable/${name}`;
        return [path, readFileSync(join(repoRoot, path), "utf8")];
      })
  );
}

function validatePublishedHistory(registry) {
  const { ref, commit } = resolveBaseCommit(repoRoot);
  const baseFiles = listFilesAtCommit(
    repoRoot,
    commit,
    "schemas/stable"
  ).filter((path) => stableSchemaVersion(path));
  const baseSchemas = new Map(
    baseFiles.map((path) => {
      const content = readFileAtCommit(repoRoot, commit, path);
      if (content === null) {
        fail(`could not read stable schema ${path} at ${commit}`);
      }
      return [path, content];
    })
  );
  const currentSchemas = currentStableSchemas();
  const schemaVersions = JSON.parse(
    readFileSync(join(repoRoot, "schemas", "schema-version.json"), "utf8")
  );
  const errors = [
    ...validateStableHistory(baseSchemas, currentSchemas),
    ...validatePublishedRegistry(registry, currentSchemas, schemaVersions.min),
  ];
  if (errors.length > 0) {
    fail(
      `published contract history does not match ${ref}:\n  - ` +
        errors.join("\n  - ")
    );
  }
  return ref;
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

function requestRootsForContract(contract) {
  if (!Array.isArray(contract.requestRoots) || contract.requestRoots.length === 0) {
    fail(`exact contract ${contract.version} has no request-root metadata`);
  }
  const roots = new Map();
  const schemaDefinitions = new Set();
  for (const root of contract.requestRoots) {
    if (
      typeof root?.fixtureDirectory !== "string" ||
      root.fixtureDirectory.length === 0 ||
      typeof root?.schemaDefinition !== "string" ||
      root.schemaDefinition.length === 0
    ) {
      fail(`exact contract ${contract.version} has invalid request-root metadata`);
    }
    if (roots.has(root.fixtureDirectory)) {
      fail(
        `exact contract ${contract.version} repeats fixture root ${root.fixtureDirectory}`
      );
    }
    if (schemaDefinitions.has(root.schemaDefinition)) {
      fail(
        `exact contract ${contract.version} repeats schema root ${root.schemaDefinition}`
      );
    }
    roots.set(root.fixtureDirectory, root.schemaDefinition);
    schemaDefinitions.add(root.schemaDefinition);
  }
  return roots;
}

function contractsWithGeneratedArtifacts(registry) {
  const selected = [];
  for (const contract of registry) {
    if (typeof contract.generatesArtifacts !== "boolean") {
      fail(
        `exact contract ${contract.version} has no boolean generatesArtifacts value`
      );
    }
    if (
      typeof contract.schemaPath !== "string" ||
      contract.schemaPath.length === 0
    ) {
      fail(`exact contract ${contract.version} has no schema path`);
    }
    const hasTypeScriptPath =
      typeof contract.typescriptPath === "string" &&
      contract.typescriptPath.length > 0;
    if (contract.generatesArtifacts && !hasTypeScriptPath) {
      fail(
        `renderable exact contract ${contract.version} has no TypeScript oracle path`
      );
    }
    if (!contract.generatesArtifacts && contract.typescriptPath !== null) {
      fail(
        `non-renderable exact contract ${contract.version} has a TypeScript oracle path`
      );
    }
    if (contract.generatesArtifacts) {
      requestRootsForContract(contract);
      selected.push(contract);
    } else if (
      !Array.isArray(contract.requestRoots) ||
      contract.requestRoots.length !== 0
    ) {
      fail(
        `non-renderable exact contract ${contract.version} has request-root metadata`
      );
    }
  }
  if (selected.length === 0) {
    fail("registry has no exact contracts with generated artifacts");
  }
  return selected;
}

function validateDispatchRoots(schema, contract) {
  const expected = requestRootsForContract(contract);
  const dispatched = collectDispatchRoots(schema);
  const expectedDefinitions = new Set(expected.values());
  const missing = [...expectedDefinitions].filter(
    (root) => !dispatched.has(root)
  );
  const unexpected = [...dispatched].filter(
    (root) => !expectedDefinitions.has(root)
  );
  if (missing.length || unexpected.length) {
    const errors = [];
    if (missing.length) {
      errors.push(`missing dispatched roots: ${missing.join(", ")}`);
    }
    if (unexpected.length) {
      errors.push(`unexpected dispatched roots: ${unexpected.join(", ")}`);
    }
    fail(
      `exact contract ${contract.version} request roots do not match: ${errors.join("; ")}`
    );
  }
  return expected;
}

const removedNetworkProperties = new Set([
  "defaultPolicy", "enforcementMode", "allowedHosts", "blockedHosts",
  "allowLocalNetwork", "proxy",
]);

// Traverse schema structure, not data examples or arbitrary text. In particular,
// a command containing "network.proxy" is not a contract property.
function assertDirectionalNetworkOnly(schema, requestRoots) {
  for (const root of requestRoots) {
    const visited = new Set();
    function walk(node, path, networkObject = false) {
      if (!node || typeof node !== "object") return;
      if (typeof node.$ref === "string") {
        const reference = node.$ref;
        if (!reference.startsWith("#/")) {
          throw new Error(`Unresolved schema reference ${reference} at ${path}`);
        }
        const key = `${reference}:${networkObject}`;
        if (!visited.has(key)) {
          visited.add(key);
          let target = schema;
          for (const token of reference.slice(2).split("/")) {
            target = target?.[token.replace(/~1/g, "/").replace(/~0/g, "~")];
          }
          if (target === undefined) {
            throw new Error(`Unresolved schema reference ${reference} at ${path}`);
          }
          walk(target, path, networkObject);
        }
      }
      for (const [name, child] of Object.entries(node.properties || {})) {
        if (networkObject && removedNetworkProperties.has(name)) {
          throw new Error(`Removed v0.9 network property reachable from ${root}: ${path}.${name}`);
        }
        walk(child, `${path}.${name}`, name === "network");
      }
      for (const keyword of ["allOf", "anyOf", "oneOf"]) {
        for (const child of node[keyword] || []) walk(child, path, networkObject);
      }
      for (const keyword of ["if", "then", "else", "not", "items", "additionalProperties",
        "contains", "propertyNames"]) {
        const child = node[keyword];
        if (Array.isArray(child)) {
          for (const item of child) walk(item, path, networkObject);
        } else {
          walk(child, path, networkObject);
        }
      }
      for (const child of Object.values(node.patternProperties || {})) {
        walk(child, path, networkObject);
      }
    }
    if (!schema.definitions?.[root]) {
      throw new Error(`Missing exact request root ${root}`);
    }
    walk(schema.definitions[root], root);
  }
}

function validateFixtures(schema, fixtureRoot, requestRoots) {
  const composed = new Ajv({ allErrors: true, strict: false }).compile(schema);

  for (const [directory, definition] of requestRoots) {
    const rootSchema = {
      $schema: schema.$schema,
      definitions: schema.definitions,
      $ref: `#/definitions/${definition}`,
    };
    const validateRoot = new Ajv({
      allErrors: true,
      strict: false,
    }).compile(rootSchema);

    const validFixtures = readFixtures(fixtureRoot, directory, "valid");
    for (const fixture of validFixtures) {
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

    for (const field of removedNetworkProperties) {
      const fixture = structuredClone(validFixtures[0].value);
      fixture.network = { [field]: field === "proxy" ? { url: "http://localhost:8080" } : null };
      if (validateRoot(fixture) || composed(fixture)) {
        fail(`removed field network.${field} passed ${definition}`);
      }
    }

    for (const fixture of readFixtures(fixtureRoot, directory, "invalid")) {
      if (validateRoot(fixture.value) && composed(fixture.value)) {
        fail(`invalid fixture ${fixture.name} passed ${definition} and composed dispatch`);
      }
    }
  }

  const execDirectory = [...requestRoots].find(
    ([, definition]) => definition === "ExecRequest"
  )?.[0];
  if (execDirectory) {
    const malformedExec = readFixture(
      fixtureRoot,
      execDirectory,
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
}

function main() {
  let registry;
  try {
    registry = JSON.parse(
      runGenerator(["versions", "--json"], { encoding: "utf8" })
    );
  } catch (error) {
    fail(`could not read generator registry: ${error.message}`);
  }

  const exactContracts = contractsWithGeneratedArtifacts(registry);
  const historyBase = validatePublishedHistory(registry);

  const temporary = mkdtempSync(join(os.tmpdir(), "mxc-contract-codegen-"));
  try {
    for (const contract of exactContracts) {
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

      const schema = JSON.parse(readFileSync(schemaOut, "utf8"));
      const requestRoots = validateDispatchRoots(schema, contract);
      assertDirectionalNetworkOnly(schema, [...requestRoots.values()]);
      validateFixtures(schema, fixtureRootFor(contract), requestRoots);
    }
  } finally {
    rmSync(temporary, { recursive: true, force: true });
  }

  console.log(
    `Contract codegen OK: ${exactContracts.length} exact contract artifact ` +
      `set(s) match and validate; published schemas match ${historyBase}.`
  );
}

module.exports = {
  assertDirectionalNetworkOnly,
  contractsWithGeneratedArtifacts,
  formatFailure,
  requestRootsForContract,
  stableSchemaVersion,
  validateDispatchRoots,
  validateFixtures,
  validatePublishedRegistry,
  validateStableHistory,
};
if (require.main === module) {
  try {
    main();
  } catch (error) {
    console.error(formatFailure(error));
    process.exitCode = 1;
  }
}
