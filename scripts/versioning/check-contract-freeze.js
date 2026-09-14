#!/usr/bin/env node
// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

const { execFileSync } = require("child_process");
const { createHash } = require("crypto");
const {
  existsSync,
  mkdtempSync,
  readFileSync,
  rmSync,
} = require("fs");
const os = require("os");
const { isAbsolute, join, relative, resolve } = require("path");
const {
  listFilesAtCommit,
  readFileAtCommit,
  resolveBaseCommit,
} = require("./lib/git-base.js");

const repoRoot = join(__dirname, "..", "..");
const registryPath = join("schemas", "contract-registry.generated.json");
const immutableIdentityFields = [
  "rustVariant",
  "rustModule",
  "schemaId",
  "schemaPath",
  "contractModulePath",
  "adapterPath",
  "builderPath",
  "fixturePath",
  "schemaSha256",
];

function fail(messages) {
  const errors = Array.isArray(messages) ? messages : [messages];
  console.error("Contract freeze check FAILED:");
  for (const message of errors) console.error(`  - ${message}`);
  process.exit(1);
}

function normalize(content) {
  return content.replace(/\r\n/g, "\n");
}

function sha256(content) {
  return createHash("sha256").update(content).digest("hex");
}

function schemaSha256(content) {
  return sha256(Buffer.from(normalize(content.toString("utf8")), "utf8"));
}

function publishedByVersion(registry) {
  return new Map(
    registry.contracts
      .filter((contract) => contract.status === "published")
      .map((contract) => [contract.version, contract])
  );
}

function safeRepoPath(value) {
  if (typeof value !== "string" || value.length === 0 || isAbsolute(value)) {
    return null;
  }
  const resolved = resolve(repoRoot, value);
  const fromRoot = relative(repoRoot, resolved);
  if (fromRoot === "" || fromRoot.startsWith("..") || isAbsolute(fromRoot)) {
    return null;
  }
  return resolved;
}

function validatePublishedHistory(baseRegistry, currentRegistry) {
  const errors = [];
  const current = new Map(
    currentRegistry.contracts.map((contract) => [contract.version, contract])
  );
  for (const [version, before] of publishedByVersion(baseRegistry)) {
    const after = current.get(version);
    if (!after) {
      errors.push(`published contract ${version} was removed from the registry`);
      continue;
    }
    if (after.status !== "published") {
      errors.push(`published contract ${version} changed status to ${after.status}`);
    }
    for (const field of immutableIdentityFields) {
      if (after[field] !== before[field]) {
        errors.push(
          `published contract ${version} changed ${field}: ` +
            `${JSON.stringify(before[field])} -> ${JSON.stringify(after[field])}`
        );
      }
    }
  }
  return errors;
}

function validatePublishedFixturesAtBase(commit, baseRegistry) {
  const errors = [];
  for (const contract of publishedByVersion(baseRegistry).values()) {
    const files = listFilesAtCommit(repoRoot, commit, contract.fixturePath);
    if (files.length === 0) {
      errors.push(
        `published contract ${contract.version} had no fixtures at base ${commit}`
      );
      continue;
    }
    for (const file of files) {
      const currentPath = safeRepoPath(file);
      if (!currentPath || !existsSync(currentPath)) {
        errors.push(
          `published contract ${contract.version} fixture was removed: ${file}`
        );
        continue;
      }
      const before = readFileAtCommit(repoRoot, commit, file);
      const after = readFileSync(currentPath, "utf8");
      if (normalize(before) !== normalize(after)) {
        errors.push(
          `published contract ${contract.version} fixture changed: ${file}`
        );
      }
    }
  }
  return errors;
}

function validateCurrentRegistry(registry) {
  const errors = [];
  if (registry.formatVersion !== 1) {
    errors.push(`unsupported registry formatVersion ${registry.formatVersion}`);
  }
  if (!Array.isArray(registry.contracts) || registry.contracts.length === 0) {
    errors.push("registry contains no contracts");
    return errors;
  }
  const development = registry.contracts.filter(
    (contract) => contract.status === "development"
  );
  if (development.length !== 1) {
    errors.push(
      `registry must contain exactly one development contract, found ${development.length}`
    );
  }
  const versions = new Set();
  for (const contract of registry.contracts) {
    if (versions.has(contract.version)) {
      errors.push(`duplicate contract version ${contract.version}`);
    }
    versions.add(contract.version);
    for (const field of [
      "schemaPath",
      "contractModulePath",
      "adapterPath",
      "builderPath",
      "fixturePath",
    ]) {
      const path = safeRepoPath(contract[field]);
      if (!path || !existsSync(path)) {
        errors.push(`${contract.version} ${field} does not exist: ${contract[field]}`);
      }
    }
    if (contract.status === "published") {
      if (contract.typescriptPath !== null) {
        errors.push(`${contract.version} published typescriptPath must be null`);
      }
      if (!/^[0-9a-f]{64}$/.test(contract.schemaSha256 || "")) {
        errors.push(`${contract.version} has no valid lowercase schemaSha256`);
      } else {
        const schemaPath = safeRepoPath(contract.schemaPath);
        if (!schemaPath || !existsSync(schemaPath)) continue;
        const content = readFileSync(schemaPath);
        const actual = schemaSha256(content);
        if (actual !== contract.schemaSha256) {
          errors.push(
            `${contract.version} schema digest mismatch: ` +
              `recorded ${contract.schemaSha256}, actual ${actual}`
          );
        }
      }
    } else {
      if (contract.schemaSha256 !== null) {
        errors.push(`${contract.version} development schemaSha256 must be null`);
      }
      if (!contract.typescriptPath) {
        errors.push(`${contract.version} development typescriptPath is missing`);
      } else {
        const typescriptPath = safeRepoPath(contract.typescriptPath);
        if (typescriptPath && existsSync(typescriptPath)) continue;
        errors.push(
          `${contract.version} typescriptPath does not exist: ${contract.typescriptPath}`
        );
      }
    }
  }
  return errors;
}

function compareGeneratedRegistry() {
  const temporary = mkdtempSync(join(os.tmpdir(), "mxc-contract-registry-"));
  try {
    const generated = join(temporary, "contract-registry.generated.json");
    execFileSync(
      "cargo",
      [
        "run",
        "-q",
        "-p",
        "mxc_schema_gen",
        "--",
        "registry",
        "--repo-root",
        repoRoot,
        "--out",
        generated,
      ],
      {
        cwd: join(repoRoot, "src"),
        stdio: ["ignore", "ignore", "inherit"],
      }
    );
    const committed = normalize(
      readFileSync(join(repoRoot, registryPath), "utf8")
    );
    const expected = normalize(readFileSync(generated, "utf8"));
    return committed === expected
      ? []
      : [
          `${registryPath} is stale; regenerate with ` +
            "cargo run --manifest-path src/Cargo.toml -p mxc_schema_gen -- registry",
        ];
  } finally {
    rmSync(temporary, { recursive: true, force: true });
  }
}

function baseRegistry(commit, currentRegistry) {
  const source = readFileAtCommit(repoRoot, commit, registryPath);
  if (source !== null) return JSON.parse(source);

  return {
    formatVersion: 1,
    contracts: currentRegistry.contracts
      .filter((contract) => contract.status === "published")
      .map((contract) => {
        const schema = readFileAtCommit(repoRoot, commit, contract.schemaPath);
        if (schema === null) {
          throw new Error(
            `published schema ${contract.schemaPath} did not exist at base ${commit}`
          );
        }
        return { ...contract, schemaSha256: schemaSha256(Buffer.from(schema)) };
      }),
  };
}

function main() {
  const registry = JSON.parse(readFileSync(join(repoRoot, registryPath), "utf8"));
  const errors = validateCurrentRegistry(registry);
  errors.push(...compareGeneratedRegistry());

  let base;
  try {
    const { ref, commit } = resolveBaseCommit(repoRoot);
    base = baseRegistry(commit, registry);
    errors.push(...validatePublishedHistory(base, registry));
    errors.push(...validatePublishedFixturesAtBase(commit, base));
    if (errors.length === 0) {
      console.log(
        `Contract freeze OK: ${publishedByVersion(registry).size} published ` +
          `contract(s) match recorded digests and immutable identities against ${ref}.`
      );
      return;
    }
  } catch (error) {
    errors.push(error.message);
  }
  fail(errors);
}

module.exports = {
  publishedByVersion,
  safeRepoPath,
  schemaSha256,
  sha256,
  validateCurrentRegistry,
  validatePublishedFixturesAtBase,
  validatePublishedHistory,
};

if (require.main === module) main();
