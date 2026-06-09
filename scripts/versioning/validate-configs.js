// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

// Validates the repository's example and test config corpus against the dev
// JSON schema, so the schema and the configs cannot silently drift apart.
//
// The dev schema version is read from the canonical schemas/schema-version.json
// (devSchemaFile). Files known to be intentionally invalid (negative parser
// tests, etc.) are listed in config-validation-exemptions.json and are required
// to FAIL validation — if an exempt file starts passing, that is also flagged
// so the exemption list cannot rot.
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
const devSchemaPath = join(
  "schemas",
  "dev",
  `mxc-config.schema.${schemaVer.devSchemaFile}.json`
);
const schema = readJson(devSchemaPath);

// Directories whose *.json files (recursively) are configs we expect to validate.
const CONFIG_DIRS = [join("tests", "examples"), join("tests", "configs")];

// Files that are intentionally invalid (negative tests) and must NOT validate.
const exemptionsPath = join(repoRoot, "scripts", "versioning", "config-validation-exemptions.json");
const exemptions = existsSync(exemptionsPath)
  ? new Set(JSON.parse(readFileSync(exemptionsPath, "utf8")).intentionallyInvalid)
  : new Set();

const ajv = new Ajv({ allErrors: true, strict: false });
const validate = ajv.compile(schema);

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

  const ok = validate(data);
  if (ok && isExempt) {
    unexpectedValid++;
    unexpectedInvalidDetails.push(
      `${relNorm}: listed as intentionallyInvalid but now PASSES — remove it from the exemption list`
    );
  } else if (!ok && !isExempt) {
    unexpectedInvalid++;
    const msgs = (validate.errors || [])
      .map((e) => `      ${e.instancePath || "/"} ${e.message}`)
      .join("\n");
    unexpectedInvalidDetails.push(`${relNorm}:\n${msgs}`);
  }
}

console.log(
  `Validated ${files.length} config(s) against ${devSchemaPath.split("\\").join("/")} ` +
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
