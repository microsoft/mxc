#!/usr/bin/env node
// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

// Validates the SCHEMA version constants — the exact Rust contract registry,
// the SDKs, and the schema filenames must all agree with the canonical source
// of truth at schemas/schema-version.json. This tracks the config wire format
// and is deliberately separate from the PRODUCT version (Cargo / npm package),
// which is checked by scripts/check-version-sync.js.
//
// Run from anywhere (paths are resolved relative to the repo root):
//
//   node scripts/versioning/check-schema-versions.js

const { readFileSync } = require("fs");
const { execFileSync } = require("child_process");
const { join } = require("path");
const {
  loadContractRegistry,
  requestRootsForContract,
} = require("./lib/contract-registry.js");

const repoRoot = join(__dirname, "..", "..");
const errors = [];

function read(...parts) {
  return readFileSync(join(repoRoot, ...parts), "utf8");
}

try {
  execFileSync(
    process.execPath,
    [join(__dirname, "generate-schema-version-metadata.js"), "--check"],
    {
      cwd: repoRoot,
      encoding: "utf8",
      stdio: ["ignore", "pipe", "pipe"],
    }
  );
} catch (error) {
  const stderr = error?.stderr?.toString().trim();
  errors.push(
    "Generated schema-version metadata is stale" + (stderr ? `: ${stderr}` : "")
  );
}

// ---------------------------------------------------------------------------
// Schema version constants vs canonical source
// ---------------------------------------------------------------------------
const schemaVer = JSON.parse(read("schemas", "schema-version.json"));
const {
  min,
  maxSupported,
  stateAware,
  stateAwareWindowsSandbox,
  stateAwareWslc,
  stableLatest,
} = schemaVer;

// -- Exact Rust contract registry (mxc_config_contract) --
let registry = [];
let registryByVersion = new Map();
try {
  ({ registry, byVersion: registryByVersion } = loadContractRegistry());
} catch (error) {
  errors.push(`Could not load exact Rust contract registry: ${error.message}`);
}

if (registry[0]?.version !== min) {
  errors.push(
    `Exact Rust contract registry minimum is "${registry[0]?.version}" but canonical min is "${min}"`
  );
}
if (registry.at(-1)?.version !== maxSupported) {
  errors.push(
    `Exact Rust contract registry maximum is "${registry.at(-1)?.version}" but canonical maxSupported is "${maxSupported}"`
  );
}
const publishedVersions = registry
  .filter(contract => contract?.status === "published")
  .map(contract => contract.version);
if (publishedVersions.at(-1) !== stableLatest) {
  errors.push(
    `Exact Rust contract registry latest published version is "${publishedVersions.at(-1)}" but canonical stableLatest is "${stableLatest}"`
  );
}
for (const [label, version, requiredRoot] of [
  ["stateAware", stateAware, "isolation_session_provision"],
  [
    "stateAwareWindowsSandbox",
    stateAwareWindowsSandbox,
    "windows_sandbox_provision",
  ],
  ["stateAwareWslc", stateAwareWslc, "wslc_provision"],
]) {
  if (!registryByVersion.has(version)) {
    errors.push(`Canonical ${label} version "${version}" is absent from the exact Rust registry`);
    continue;
  }
  try {
    const roots = requestRootsForContract(registryByVersion.get(version));
    if (!roots.has(requiredRoot)) {
      errors.push(
        `Canonical ${label} version "${version}" does not support ${requiredRoot}`
      );
    }
  } catch (error) {
    errors.push(
      `Canonical ${label} version "${version}" has no exact request-root matrix: ${error.message}`
    );
  }
}

// -- Canonical stable + development descriptors have the expected status --
if (registryByVersion.get(stableLatest)?.status !== "published") {
  errors.push(`Canonical stableLatest "${stableLatest}" is not published in the exact registry`);
}
if (registryByVersion.get(maxSupported)?.status !== "development") {
  errors.push(
    `Canonical maxSupported "${maxSupported}" is not the development contract in the exact registry`
  );
}

// ---------------------------------------------------------------------------
// Report
// ---------------------------------------------------------------------------
if (errors.length > 0) {
  console.error("Schema version sync FAILED:");
  for (const e of errors) console.error(`  - ${e}`);
  console.error(
    "\nFix the offending constant, or update schemas/schema-version.json if the canonical value changed."
  );
  process.exit(1);
}

console.log(
  `Schema version sync OK: maxSupported ${maxSupported} ` +
    `(min ${min}, state-aware ${stateAware}, Windows Sandbox state-aware ${stateAwareWindowsSandbox}, WSLC state-aware ${stateAwareWslc}, ` +
    `stable ${stableLatest})`
);
