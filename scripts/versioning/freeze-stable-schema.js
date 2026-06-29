#!/usr/bin/env node
// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

// Freeze generator (Phase 5a): derive a STABLE JSON schema from the GENERATED
// dev schema by stripping the experimental + state-aware surface, so stable
// release schemas are generated (not hand-authored) and provably reflect the
// current stability state declared in schemas/config-stability.json.
//
// This is a RELEASE-TIME tool, NOT a continuous drift gate: released stable
// schemas are immutable, so we never regenerate-and-diff old ones. The `--check`
// mode is a cheap CI invariant that the *current* dev schema can be frozen
// cleanly (valid, no dangling $refs, experimental surface fully removed); it
// writes nothing.
//
// Usage (from anywhere):
//   node scripts/versioning/freeze-stable-schema.js --check
//   node scripts/versioning/freeze-stable-schema.js --write <version>   # e.g. 0.8.0-alpha
//
// The generated stable schema intentionally does NOT reproduce the legacy
// hand-authored stables' shape or their top-level allOf cross-field rules (the
// parser owns those invariants at runtime, as the dev schema already does).
// Legacy stable files (0.4-0.7) stay frozen as historical artifacts and are
// never diffed against generated stables.

const { readFileSync, writeFileSync } = require("fs");
const { join, resolve } = require("path");
const Ajv = require("ajv");

const repoRoot = resolve(__dirname, "..", "..");
const readJson = (...p) => JSON.parse(readFileSync(join(repoRoot, ...p), "utf8"));

// Top-level properties that are not part of the stable surface.
const STRIP_PROPS = ["experimental", "phase", "sandboxId"];

function fail(msg) {
  console.error("Freeze stable schema FAILED:");
  console.error("  - " + msg);
  process.exit(1);
}

// Collect every internal "#/definitions/<name>" (and "#/$defs/<name>") $ref
// reachable from `node`, recursing into already-found definitions.
function reachableDefs(root) {
  const defsKey = root.definitions ? "definitions" : root.$defs ? "$defs" : null;
  const defs = defsKey ? root[defsKey] : {};
  const reached = new Set();
  const refsIn = (node, out) => {
    if (Array.isArray(node)) {
      for (const v of node) refsIn(v, out);
    } else if (node && typeof node === "object") {
      for (const [k, v] of Object.entries(node)) {
        if (k === "$ref" && typeof v === "string") {
          const m = /^#\/(?:definitions|\$defs)\/(.+)$/.exec(v);
          if (m) out.push(m[1]);
        } else {
          refsIn(v, out);
        }
      }
    }
  };
  // Seed from everything except the definitions block itself.
  const seed = [];
  for (const [k, v] of Object.entries(root)) {
    if (k !== defsKey) refsIn(v, seed);
  }
  const queue = [...seed];
  while (queue.length) {
    const name = queue.pop();
    if (reached.has(name)) continue;
    reached.add(name);
    if (defs[name]) refsIn(defs[name], queue);
  }
  return { defsKey, reached };
}

// Find every "#/definitions/<name>" $ref string anywhere in the schema.
function allRefNames(node, out = new Set()) {
  if (Array.isArray(node)) {
    for (const v of node) allRefNames(v, out);
  } else if (node && typeof node === "object") {
    for (const [k, v] of Object.entries(node)) {
      if (k === "$ref" && typeof v === "string") {
        const m = /^#\/(?:definitions|\$defs)\/(.+)$/.exec(v);
        if (m) out.add(m[1]);
      } else {
        allRefNames(v, out);
      }
    }
  }
  return out;
}

function generateStable(version) {
  const schemaVer = readJson("schemas", "schema-version.json");
  const manifest = readJson("schemas", "config-stability.json");
  const dev = readJson(
    "schemas",
    "dev",
    `mxc-config.schema.${schemaVer.devSchemaFile}.json`
  );
  const stableContainment = new Set(manifest.stableContainment || []);
  if (stableContainment.size === 0) {
    fail("config-stability.json has no stableContainment allowlist.");
  }

  const out = JSON.parse(JSON.stringify(dev));

  // 1. Strip experimental + state-aware top-level properties (and from required).
  for (const p of STRIP_PROPS) {
    if (out.properties) delete out.properties[p];
  }
  if (Array.isArray(out.required)) {
    out.required = out.required.filter((r) => !STRIP_PROPS.includes(r));
    if (out.required.length === 0) delete out.required;
  }

  // 2. Filter the Containment enum to the stable allowlist (oneOf of {enum:[v]}).
  const defsKey = out.definitions ? "definitions" : "$defs";
  const cont = out[defsKey] && out[defsKey].Containment;
  if (cont && Array.isArray(cont.oneOf)) {
    cont.oneOf = cont.oneOf.filter((b) => {
      const v = Array.isArray(b.enum) ? b.enum[0] : b.const;
      return stableContainment.has(v);
    });
  }

  // 3. Reachability-prune definitions (drop anything only the stripped surface
  //    referenced — Experimental, Phase, IsolationSession*, etc.).
  const { reached } = reachableDefs(out);
  for (const name of Object.keys(out[defsKey] || {})) {
    if (!reached.has(name)) delete out[defsKey][name];
  }

  // 4. Rewrite $id and pin the version surface to the stable release.
  out.$id = `https://github.com/microsoft/mxc/schemas/stable/mxc-config.schema.${version}.json`;
  if (out.properties && out.properties.version) {
    out.properties.version.examples = [version];
  }

  return { out, defsKey, version };
}

function validateStable({ out, defsKey, version }) {
  const errors = [];

  // No dangling $refs: every referenced def must still exist.
  const present = new Set(Object.keys(out[defsKey] || {}));
  for (const name of allRefNames(out)) {
    if (!present.has(name)) errors.push(`dangling $ref to removed definition "${name}"`);
  }

  // Experimental / state-aware surface fully removed.
  for (const p of STRIP_PROPS) {
    if (out.properties && out.properties[p]) errors.push(`stable schema still has top-level "${p}"`);
  }
  for (const bad of ["Experimental", "Phase", "IsolationSession", "IsolationSessionPhase", "IsolationUser", "IsolationConfigurationId", "TestFeature", "WindowsSandbox", "Wslc"]) {
    if (out[defsKey] && out[defsKey][bad]) errors.push(`stable schema still defines experimental/state-aware "${bad}"`);
  }

  // Containment exactly equals the stable allowlist.
  const manifest = readJson("schemas", "config-stability.json");
  const cont = out[defsKey] && out[defsKey].Containment;
  const got = (cont && cont.oneOf ? cont.oneOf : []).map((b) => (Array.isArray(b.enum) ? b.enum[0] : b.const)).sort();
  const want = [...manifest.stableContainment].sort();
  if (JSON.stringify(got) !== JSON.stringify(want)) {
    errors.push(`stable containment ${JSON.stringify(got)} != allowlist ${JSON.stringify(want)}`);
  }

  // Compiles as a schema, and accepts a minimal stable config while rejecting
  // an experimental one.
  const ajv = new Ajv({ allErrors: true, strict: false });
  let validate;
  try {
    validate = ajv.compile(out);
  } catch (e) {
    errors.push(`generated stable schema does not compile: ${e.message}`);
  }
  if (validate) {
    const stableCfg = { version, containment: "seatbelt", process: { commandLine: "echo hi" }, seatbelt: {} };
    if (!validate(stableCfg)) {
      errors.push(`a representative stable config should validate: ${ajv.errorsText(validate.errors)}`);
    }
    const expCfg = { version, process: { commandLine: "echo hi" }, experimental: { wslc: {} } };
    if (validate(expCfg)) {
      errors.push("an experimental config (experimental.wslc) must NOT validate against the stable schema");
    }
  }

  return errors;
}

// --- main ---
const args = process.argv.slice(2);
const mode = args[0];

if (mode === "--check") {
  const schemaVer = readJson("schemas", "schema-version.json");
  // Dry-run freeze at the current dev minor's prospective stable version.
  const version = schemaVer.maxSupported;
  const result = generateStable(version);
  const errors = validateStable(result);
  if (errors.length) {
    console.error("Freeze stable schema FAILED (--check):");
    for (const e of errors) console.error("  - " + e);
    process.exit(1);
  }
  console.log(
    `Freeze check OK: dev schema can be frozen to a valid stable schema at ${version} ` +
      `(${Object.keys(result.out[result.defsKey] || {}).length} defs, containment ${[...readJson("schemas", "config-stability.json").stableContainment].join("/")}).`
  );
} else if (mode === "--write") {
  const version = args[1];
  if (!version) fail("--write requires a <version>, e.g. 0.8.0-alpha");
  const result = generateStable(version);
  const errors = validateStable(result);
  if (errors.length) {
    console.error("Freeze stable schema FAILED (--write):");
    for (const e of errors) console.error("  - " + e);
    process.exit(1);
  }
  const rel = join("schemas", "stable", `mxc-config.schema.${version}.json`);
  writeFileSync(join(repoRoot, rel), JSON.stringify(result.out, null, 2) + "\n");
  console.log(`Wrote stable schema ${rel}. Remember to update schemas/schema-version.json stableLatest and the docs.`);
} else {
  fail("usage: freeze-stable-schema.js --check | --write <version>");
}
