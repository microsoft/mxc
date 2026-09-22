// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

const { execFileSync } = require("child_process");
const { readFileSync } = require("fs");
const { join, resolve } = require("path");
const { parseVersion } = require("./version.js");

const repoRoot = resolve(__dirname, "..", "..", "..");
const cargoRoot = join(repoRoot, "src");

function fail(message) {
  throw new Error(message);
}

function requireString(contract, field) {
  if (typeof contract[field] !== "string" || contract[field].length === 0) {
    fail(`exact contract descriptor has no ${field}`);
  }
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
        `exact contract ${contract.version} repeats fixture root ` +
          root.fixtureDirectory
      );
    }
    if (schemaDefinitions.has(root.schemaDefinition)) {
      fail(
        `exact contract ${contract.version} repeats schema root ` +
          root.schemaDefinition
      );
    }
    roots.set(root.fixtureDirectory, root.schemaDefinition);
    schemaDefinitions.add(root.schemaDefinition);
  }
  return roots;
}

function parseContractRegistry(content, source) {
  let registry;
  try {
    registry = JSON.parse(content);
  } catch (error) {
    fail(`${source} returned invalid JSON: ${error.message}`);
  }
  if (!Array.isArray(registry) || registry.length === 0) {
    fail(`${source} returned no registered contracts`);
  }

  const byVersion = new Map();
  for (const contract of registry) {
    if (!contract || typeof contract !== "object" || Array.isArray(contract)) {
      fail("exact contract registry contains an invalid descriptor");
    }
    for (const field of ["version", "status", "schemaId", "schemaPath"]) {
      requireString(contract, field);
    }
    if (!parseVersion(contract.version)) {
      fail(`exact contract descriptor has invalid version ${contract.version}`);
    }
    if (
      contract.status !== "published" &&
      contract.status !== "development"
    ) {
      fail(
        `exact contract ${contract.version} has invalid status ${contract.status}`
      );
    }
    if (
      contract.typescriptPath !== null &&
      (typeof contract.typescriptPath !== "string" ||
        contract.typescriptPath.length === 0)
    ) {
      fail(`exact contract ${contract.version} has invalid typescriptPath`);
    }
    if (typeof contract.generatesArtifacts !== "boolean") {
      fail(
        `exact contract ${contract.version} has no boolean ` +
          "generatesArtifacts value"
      );
    }
    if (!Array.isArray(contract.requestRoots)) {
      fail(`exact contract ${contract.version} has invalid requestRoots`);
    }
    if (contract.requestRoots.length > 0) {
      requestRootsForContract(contract);
    }
    if (byVersion.has(contract.version)) {
      fail(`exact contract registry repeats version ${contract.version}`);
    }
    byVersion.set(contract.version, contract);
  }

  return { registry, byVersion };
}

function loadContractRegistry() {
  const snapshot = process.env.MXC_CONTRACT_REGISTRY_PATH;
  if (snapshot) {
    const path = resolve(snapshot);
    let content;
    try {
      content = readFileSync(path, "utf8");
    } catch (error) {
      fail(`could not read exact contract registry snapshot ${path}: ${error.message}`);
    }
    return parseContractRegistry(content, `registry snapshot ${path}`);
  }

  let output;
  try {
    output = execFileSync(
      "cargo",
      ["run", "--locked", "-q", "-p", "mxc_schema_gen", "--", "versions", "--json"],
      {
        cwd: cargoRoot,
        encoding: "utf8",
        stdio: ["ignore", "pipe", "pipe"],
      }
    );
  } catch (error) {
    const stderr = error?.stderr?.toString().trim();
    fail(
      "could not load exact contract registry through mxc_schema_gen" +
        (stderr ? `: ${stderr}` : "")
    );
  }
  return parseContractRegistry(output, "mxc_schema_gen versions --json");
}

module.exports = {
  loadContractRegistry,
  parseContractRegistry,
  requestRootsForContract,
};
