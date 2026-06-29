// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

// Schema-conformance gate: every JSON config instance the repo produces or ships
// must validate against the dev JSON schema, so the schema and the things that
// must satisfy it cannot silently drift apart. This is the single home for all
// instance-conformance checks against the dev schema:
//
//   * Corpus    — the tests/examples + tests/configs files (with an
//                 intentionally-invalid exemption list that must keep failing).
//   * (Phase 4b-emit) SDK emission — configs the SDK actually emits per
//                 containment, so platform-gated SDK builders can't ship a field
//                 the strict parser rejects. Added as a second section here
//                 rather than a separate gate.
//
// Replaces the former validate-configs.js. Run from anywhere:
//   node scripts/versioning/check-schema-conformance.js

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
const devSchemaLabel = devSchemaPath.split("\\").join("/");

const ajv = new Ajv({ allErrors: true, strict: false });
// Shared compiled validator — reused by every conformance section.
const validate = ajv.compile(schema);

// Format ajv errors for a single instance into indented lines.
function formatErrors() {
  return (validate.errors || [])
    .map((e) => `      ${e.instancePath || "/"} ${e.message}`)
    .join("\n");
}

// ===========================================================================
// Section 1 — Config corpus
// ===========================================================================

// Directories whose *.json files (recursively) are configs we expect to validate.
const CONFIG_DIRS = [join("tests", "examples"), join("tests", "configs")];

function checkCorpus(failures) {
  // Files that are intentionally invalid (negative tests) and must NOT validate.
  const exemptionsPath = join(
    repoRoot,
    "scripts",
    "versioning",
    "config-validation-exemptions.json"
  );
  const exemptions = existsSync(exemptionsPath)
    ? new Set(JSON.parse(readFileSync(exemptionsPath, "utf8")).intentionallyInvalid)
    : new Set();

  // Recursively collect repo-root-relative paths of *.json files under `dir`.
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
  const knownFiles = new Set(files.map((f) => f.split("\\").join("/")));

  // Keep the exemption list from rotting: every listed file must still exist.
  for (const ex of exemptions) {
    if (!knownFiles.has(ex)) {
      const reason = existsSync(join(repoRoot, ex))
        ? "exists but is not under a scanned config dir"
        : "does not exist";
      failures.push(
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
      if (!isExempt) failures.push(`${relNorm}: not valid JSON (${e.message})`);
      continue;
    }

    const ok = validate(data);
    if (ok && isExempt) {
      failures.push(
        `${relNorm}: listed as intentionallyInvalid but now PASSES — remove it from the exemption list`
      );
    } else if (!ok && !isExempt) {
      failures.push(`${relNorm}:\n${formatErrors()}`);
    }
  }

  console.log(
    `Corpus: validated ${files.length} config(s) against ${devSchemaLabel} ` +
      `(${exemptions.size} exempt as intentionally-invalid).`
  );
}

// ===========================================================================
// Section 2 — SDK emission (Phase 4b-emit)
// ===========================================================================
// Builds a config via the SDK config builder for each containment and asserts
// the emitted JSON validates against the dev schema, so platform-gated builders
// cannot ship a field the strict wire parser rejects. Implemented in Phase
// 4b-emit; it will reuse `validate` / `formatErrors` above.

// ===========================================================================
// Driver
// ===========================================================================

const failures = [];
checkCorpus(failures);
// checkSdkEmission(failures);  // Phase 4b-emit

if (failures.length > 0) {
  console.error("\nSchema conformance FAILED:");
  for (const d of failures) console.error(`  - ${d}`);
  console.error(`\n${failures.length} conformance failure(s).`);
  process.exit(1);
}

console.log("Schema conformance OK.");

