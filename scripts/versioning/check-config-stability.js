#!/usr/bin/env node
// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

// Promotion guard for the MXC config surface (Phase 4a). The set of experimental
// sub-keys under the top-level `experimental` object can only change in lockstep
// with the manifest schemas/config-stability.json, and a feature can only be
// promoted to stable (moved out of `experimental` to a top-level field) by
// turning it into a tombstone AND bumping the schema minor. This makes silent
// promotions a CI failure instead of a quiet contract break.
//
// Source of truth for the active surface is the generated dev schema; the
// manifest is the human-curated expectation. Both must agree. Run from anywhere:
//
//   node scripts/versioning/check-config-stability.js

const { readFileSync } = require("fs");
const { join } = require("path");
const {
  readFileAtCommit,
  resolveBaseCommit,
} = require("./lib/git-base");

const repoRoot = join(__dirname, "..", "..");
const errors = [];

function read(...parts) {
  return readFileSync(join(repoRoot, ...parts), "utf8");
}

function majorMinor(v) {
  const m = /^(\d+)\.(\d+)\./.exec(v);
  return m ? `${m[1]}.${m[2]}` : null;
}

// minorRank("0.8") -> 8 within major 0; used to require monotonic bumps.
function minorParts(mm) {
  const m = /^(\d+)\.(\d+)$/.exec(mm || "");
  return m ? [Number(m[1]), Number(m[2])] : null;
}
function minorGreater(a, b) {
  const pa = minorParts(a), pb = minorParts(b);
  if (!pa || !pb) return false;
  return pa[0] > pb[0] || (pa[0] === pb[0] && pa[1] > pb[1]);
}

function baseManifest() {
  let base;
  try {
    base = resolveBaseCommit(repoRoot);
  } catch (error) {
    errors.push(error.message);
    return { manifest: null, base: null };
  }
  const content = readFileAtCommit(
    repoRoot,
    base.commit,
    "schemas/config-stability.json"
  );
  return {
    manifest: content === null ? null : JSON.parse(content),
    base,
  };
}

const manifest = JSON.parse(read("schemas", "config-stability.json"));
const schemaVer = JSON.parse(read("schemas", "schema-version.json"));
const devSchema = JSON.parse(
  read("schemas", "dev", `mxc-config.schema.${schemaVer.devSchemaFile}.json`)
);

const topLevel = new Set(Object.keys(devSchema.properties || {}));
const defs = devSchema.definitions || devSchema.$defs || {};
const experimentalDef = defs.Experimental || {};
const experimentalKeys = new Set(Object.keys(experimentalDef.properties || {}));

const active = new Set(manifest.experimental || []);
const tombstones = new Set(Object.keys(manifest.movedToStable || {}));

// 1. Dev schema minor must match the manifest's declared minor.
const devMinor = majorMinor(schemaVer.maxSupported);
if (manifest.schemaMinor !== devMinor) {
  errors.push(
    `config-stability.json schemaMinor "${manifest.schemaMinor}" != dev schema minor ${devMinor} ` +
      `(schema-version.json maxSupported ${schemaVer.maxSupported}). Bump both together when promoting.`
  );
}

// 2. Every experimental key in the schema must be accounted for (active or tombstone).
for (const k of experimentalKeys) {
  if (!active.has(k) && !tombstones.has(k)) {
    errors.push(
      `experimental.${k} is in the dev schema but not in config-stability.json. ` +
        `Add it to "experimental" (active) or "movedToStable" (promoted).`
    );
  }
}

// 3. Every manifest key must still exist in the schema's Experimental block.
for (const k of [...active, ...tombstones]) {
  if (!experimentalKeys.has(k)) {
    errors.push(
      `config-stability.json lists "${k}" but experimental.${k} is gone from the dev schema. ` +
        `Remove it from the manifest, or restore the wire field (tombstones stay for migration rejection).`
    );
  }
}

// 4. Active experimental keys must NOT be top-level (a top-level twin = silent promotion).
for (const k of active) {
  if (topLevel.has(k)) {
    errors.push(
      `"${k}" is active experimental but also a top-level field — that is a promotion. ` +
        `Move it to "movedToStable" and bump the schema minor.`
    );
  }
}

// 5. Tombstones MUST be top-level (the promoted stable field) and bumped at/below current minor.
for (const [k, atMinor] of Object.entries(manifest.movedToStable || {})) {
  if (!topLevel.has(k)) {
    errors.push(`tombstone "${k}" has no top-level stable field; promotion is incomplete.`);
  }
  if (!/^\d+\.\d+$/.test(atMinor)) {
    errors.push(`movedToStable["${k}"] = "${atMinor}" must be a major.minor string.`);
  } else if (minorGreater(atMinor, manifest.schemaMinor)) {
    errors.push(
      `movedToStable["${k}"] = "${atMinor}" is newer than schemaMinor ${manifest.schemaMinor}.`
    );
  }
}

// 6. History-aware promotion guard (catches lockstep promotions a snapshot
//    check misses). Compare against the manifest at the base ref: any key that
//    was active experimental and is no longer active MUST now be a tombstone,
//    AND the schema minor MUST have advanced. A key that simply vanished (delete
//    + promote) is therefore caught even though nothing top-level references its
//    experimental past.
const { manifest: base, base: baseInfo } = baseManifest();
if (base) {
  const baseActive = new Set(base.experimental || []);
  const baseTombstones = new Set(Object.keys(base.movedToStable || {}));
  for (const k of baseActive) {
    if (active.has(k)) continue; // still experimental — fine
    if (!tombstones.has(k)) {
      errors.push(
        `"${k}" left "experimental" but is not in "movedToStable". A feature can only ` +
          `leave experimental by becoming a tombstone (promotion); deleting it is a silent break.`
      );
    } else if (!minorGreater(manifest.schemaMinor, base.schemaMinor)) {
      errors.push(
        `"${k}" was promoted to stable but schemaMinor did not advance ` +
          `(base ${base.schemaMinor} -> now ${manifest.schemaMinor}). Promotion requires a minor bump.`
      );
    } else if (manifest.movedToStable[k] !== manifest.schemaMinor) {
      errors.push(
        `"${k}" was promoted in schema minor ${manifest.schemaMinor}, so its tombstone must record that exact minor.`
      );
    }
  }
  for (const k of baseTombstones) {
    if (!tombstones.has(k)) {
      errors.push(`"${k}" was a tombstone at base but is gone now; tombstones are permanent.`);
    } else if (manifest.movedToStable[k] !== base.movedToStable[k]) {
      errors.push(
        `tombstone "${k}" changed its recorded promotion minor ` +
          `${base.movedToStable[k]} -> ${manifest.movedToStable[k]}; tombstone metadata is immutable.`
      );
    }
  }
} else if (baseInfo) {
  console.log(
    `Config stability history: no manifest at ${baseInfo.ref} (${baseInfo.commit.slice(0, 8)}); treating this as the initial introduction.`
  );
}

if (errors.length) {
  console.error("Config stability check FAILED:");
  for (const e of errors) console.error("  - " + e);
  process.exit(1);
}
console.log(
  `Config stability OK: ${active.size} active experimental key(s), ${tombstones.size} promoted (minor ${manifest.schemaMinor}).`
);
