// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

// Validates the repository's example and test config corpus against the exact
// registered schema named by each document's version field.
//
// Run from anywhere (paths are resolved relative to the repo root):
//   node scripts/versioning/validate-configs.js

const { readFileSync, readdirSync, existsSync } = require("fs");
const { join, resolve } = require("path");
const Ajv = require("ajv");

const repoRoot = resolve(__dirname, "..", "..");

function readJson(...parts) {
  return JSON.parse(readFileSync(join(repoRoot, ...parts), "utf8"));
}

const schemaVer = readJson("schemas", "schema-version.json");
const stableSchemaDir = join(repoRoot, "schemas", "stable");
const stableVersions = readdirSync(stableSchemaDir)
  .map((name) => /^mxc-config\.schema\.(.+)\.json$/.exec(name)?.[1])
  .filter(Boolean)
  .sort();
const minimumIndex = stableVersions.indexOf(schemaVer.min);
if (minimumIndex < 0) {
  throw new Error(`Minimum registered schema not found: ${schemaVer.min}`);
}

const schemaPaths = new Map(
  stableVersions.slice(minimumIndex).map((version) => [
    version,
    join("schemas", "stable", `mxc-config.schema.${version}.json`),
  ])
);
schemaPaths.set(
  schemaVer.stateAware,
  join("schemas", "dev", `mxc-config.schema.${schemaVer.stateAware}.json`)
);

// Directories whose *.json files (recursively) are configs we expect to validate.
const CONFIG_DIRS = [join("tests", "examples"), join("tests", "configs")];

// Files that are intentionally invalid (negative tests) and must NOT validate.
const exemptionsPath = join(repoRoot, "scripts", "versioning", "config-validation-exemptions.json");
const exemptions = existsSync(exemptionsPath)
  ? new Set(JSON.parse(readFileSync(exemptionsPath, "utf8")).intentionallyInvalid)
  : new Set();

const ajv = new Ajv({ allErrors: true, strict: false });
const validators = new Map(
  [...schemaPaths].map(([version, schemaPath]) => [
    version,
    ajv.compile(readJson(schemaPath)),
  ])
);
const RESERVED_LEARNING_MODE_CAPABILITIES = [
  "learningModeLogging",
  "permissiveLearningMode",
];

// Recursively collect repo-root-relative paths of *.json files under `dir`, so
// configs in nested directories are not silently skipped.
function listJson(dir) {
  const abs = join(repoRoot, dir);
  if (!existsSync(abs)) return [];
  const out = [];
  for (const entry of readdirSync(abs, { withFileTypes: true })) {
    const childRel = join(dir, entry.name);
    if (entry.isDirectory()) {
      out.push(...listJson(childRel));
    } else if (entry.name.endsWith(".json")) {
      out.push(childRel);
    }
  }
  return out;
}

const files = CONFIG_DIRS.flatMap(listJson).sort();

let unexpectedInvalid = 0;
let unexpectedValid = 0;
let staleExemptions = 0;
const unexpectedInvalidDetails = [];

// Keep the exemption list from rotting: every listed file must still exist.
const knownFiles = new Set(files.map((f) => f.split("\\").join("/")));
for (const ex of exemptions) {
  if (!knownFiles.has(ex)) {
    staleExemptions++;
    const reason = existsSync(join(repoRoot, ex))
      ? "exists but is not under a scanned config dir"
      : "does not exist";
    unexpectedInvalidDetails.push(
      `${ex}: listed as intentionallyInvalid but ${reason} — fix or remove the exemption`
    );
  }
}

for (const rel of files) {
  const relNorm = rel.split("\\").join("/");
  const isExempt = exemptions.has(relNorm);
  let data;
  try {
    data = JSON.parse(readFileSync(join(repoRoot, rel), "utf8"));
  } catch (e) {
    if (!isExempt) {
      unexpectedInvalid++;
      unexpectedInvalidDetails.push(`${relNorm}: not valid JSON (${e.message})`);
    }
    continue;
  }

  const validate =
    typeof data.version === "string" ? validators.get(data.version) : undefined;
  const ok = validate ? validate(data) : false;
  const errors = validate
    ? validate.errors
    : [{
        instancePath: "/version",
        message:
          typeof data.version === "string"
            ? `must name a registered schema (${[...validators.keys()].join(", ")})`
            : "must be a string naming a registered schema",
      }];
  if (ok && isExempt) {
    unexpectedValid++;
    unexpectedInvalidDetails.push(
      `${relNorm}: listed as intentionallyInvalid but now PASSES — remove it from the exemption list`
    );
  } else if (!ok && !isExempt) {
    unexpectedInvalid++;
    const msgs = (errors || [])
      .map((e) => `      ${e.instancePath || "/"} ${e.message}`)
      .join("\n");
    unexpectedInvalidDetails.push(`${relNorm}:\n${msgs}`);
  } else if (ok && !isExempt) {
    const processContainer = data.processContainer ?? data.appContainer;
    const capabilities = processContainer?.capabilities;
    if (Array.isArray(capabilities)) {
      const reserved = capabilities.find(
        (capability) =>
          typeof capability === "string" &&
          RESERVED_LEARNING_MODE_CAPABILITIES.some(
            (name) => name.toLowerCase() === capability.toLowerCase()
          )
      );
      if (reserved !== undefined) {
        unexpectedInvalid++;
        unexpectedInvalidDetails.push(
          `${relNorm}: processContainer.capabilities contains reserved learning-mode capability '${reserved}'`
        );
      }
    }
  }
}

console.log(
  `Validated ${files.length} config(s) against ${validators.size} exact registered schemas ` +
    `(${exemptions.size} exempt as intentionally-invalid).`
);

if (unexpectedInvalid > 0 || unexpectedValid > 0 || staleExemptions > 0) {
  console.error("\nConfig schema validation FAILED:");
  for (const d of unexpectedInvalidDetails) console.error(`  - ${d}`);
  console.error(
    `\n${unexpectedInvalid} unexpected invalid, ${unexpectedValid} exemptions that now pass, ${staleExemptions} stale exemption(s).`
  );
  process.exit(1);
}

console.log("Config schema validation OK.");
