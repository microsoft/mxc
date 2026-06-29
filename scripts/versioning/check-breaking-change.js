#!/usr/bin/env node
// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

// Breaking-change guard (Phase 5b): when a stable release schema changes, a
// breaking change to the config contract must be matched by an adequate version
// bump. Compares the current `stableLatest` schema against the previous stable
// schema already in the tree and, only when the version gap DISALLOWS a breaking
// change, fails if a breaking change is detected.
//
// Semver policy (the runtime compares major.minor; patch/pre-release are
// ignored):
//   * pre-1.0 (0.x): per semver §4, breaking changes are allowed at a MINOR
//     bump. They are NOT allowed when only patch/pre-release differs (same
//     major.minor). So the detector runs only for same-major.minor transitions.
//   * >=1.0: breaking requires a MAJOR bump. The detector runs when the major is
//     unchanged.
//
// Because a real release always moves at least a minor, the legacy
// hand-authored stables (0.4-0.7) vs the first generated stable are a >=minor
// gap and are never structurally diffed here — sidestepping their shape
// differences. The detector only fires between same-major.minor stables, which
// (going forward) are consistently generated.
//
// Run from anywhere:
//   node scripts/versioning/check-breaking-change.js

const { readFileSync, existsSync, readdirSync } = require("fs");
const { join, resolve } = require("path");

const repoRoot = resolve(__dirname, "..", "..");
const readJson = (...p) => JSON.parse(readFileSync(join(repoRoot, ...p), "utf8"));

const STABLE_DIR = join("schemas", "stable");
const FILE_RE = /^mxc-config\.schema\.(.+)\.json$/;

// Parse "X.Y.Z[-pre]" → {major,minor,patch,pre,raw}. Returns null if unparseable.
function parseVer(v) {
  const m = /^(\d+)\.(\d+)\.(\d+)(?:-(.+))?$/.exec(v);
  if (!m) return null;
  return { major: +m[1], minor: +m[2], patch: +m[3], pre: m[4] || "", raw: v };
}
// Compare two dot-separated pre-release strings per semver (numeric identifiers
// compared numerically; numeric < alphanumeric; fewer identifiers sorts lower).
function cmpPre(a, b) {
  if (a === b) return 0;
  if (!a) return 1; // no prerelease > has prerelease
  if (!b) return -1;
  const as = a.split("."), bs = b.split(".");
  for (let i = 0; i < Math.max(as.length, bs.length); i++) {
    if (as[i] === undefined) return -1;
    if (bs[i] === undefined) return 1;
    const an = /^\d+$/.test(as[i]), bn = /^\d+$/.test(bs[i]);
    if (an && bn) {
      const d = Number(as[i]) - Number(bs[i]);
      if (d) return d < 0 ? -1 : 1;
    } else if (an !== bn) {
      return an ? -1 : 1; // numeric identifiers have lower precedence
    } else if (as[i] !== bs[i]) {
      return as[i] < bs[i] ? -1 : 1;
    }
  }
  return 0;
}
// Compare by major.minor.patch then pre (absence of pre > presence).
function cmp(a, b) {
  if (a.major !== b.major) return a.major - b.major;
  if (a.minor !== b.minor) return a.minor - b.minor;
  if (a.patch !== b.patch) return a.patch - b.patch;
  return cmpPre(a.pre, b.pre);
}

function fail(lines) {
  console.error("Breaking-change guard FAILED:");
  for (const l of lines) console.error("  - " + l);
  process.exit(1);
}

// ---- normalization ------------------------------------------------------
const ANNOTATIONS = new Set([
  "$id", "$schema", "title", "description", "default", "examples", "$comment", "readOnly", "writeOnly",
]);

// Resolve an internal pointer ref ("#/definitions|$defs/<name>" or
// "#/properties/<name>") against the root.
function resolveRef(root, ref, seen) {
  let target;
  let m = /^#\/(?:definitions|\$defs)\/(.+)$/.exec(ref);
  if (m) {
    if (seen.has(ref)) return {}; // cycle guard
    const defs = root.definitions || root.$defs || {};
    target = defs[m[1]];
  } else if ((m = /^#\/properties\/(.+)$/.exec(ref))) {
    if (seen.has(ref)) return {};
    target = root.properties && root.properties[m[1]];
  } else {
    return {};
  }
  return normalize(root, target || {}, new Set(seen).add(ref));
}

// Produce a comparable, dereferenced, annotation-free view of a schema node.
function normalize(root, node, seen = new Set()) {
  if (!node || typeof node !== "object") return node;
  if (node.$ref) return resolveRef(root, node.$ref, seen);

  // Collapse `anyOf:[T,{type:null}]` and `type:[..,"null"]` to the core schema.
  if (Array.isArray(node.anyOf)) {
    const nonNull = node.anyOf.filter((b) => !(b && b.type === "null"));
    if (nonNull.length === 1) return normalize(root, nonNull[0], seen);
  }
  // Collapse `oneOf` of singleton enums into a single enum set.
  if (Array.isArray(node.oneOf) && node.oneOf.every((b) => b && Array.isArray(b.enum) && b.enum.length === 1)) {
    return { enum: node.oneOf.map((b) => b.enum[0]).sort() };
  }

  const out = {};
  for (const [k, v] of Object.entries(node)) {
    if (ANNOTATIONS.has(k)) continue;
    if (k === "properties" && v && typeof v === "object") {
      out.properties = {};
      for (const [pk, pv] of Object.entries(v)) out.properties[pk] = normalize(root, pv, seen);
    } else if (k === "items") {
      out.items = normalize(root, v, seen);
    } else if ((k === "allOf" || k === "oneOf" || k === "anyOf") && Array.isArray(v)) {
      out[k] = v.map((b) => normalize(root, b, seen));
    } else if ((k === "if" || k === "then" || k === "else" || k === "not") && v && typeof v === "object") {
      out[k] = normalize(root, v, seen);
    } else if (k === "type" && Array.isArray(v)) {
      out.type = v.filter((t) => t !== "null").sort();
    } else if (k === "enum" && Array.isArray(v)) {
      out.enum = [...v].sort();
    } else {
      out[k] = v;
    }
  }
  // Absent additionalProperties means open.
  if ((out.type === "object" || out.properties) && !("additionalProperties" in out)) {
    out.additionalProperties = true;
  }
  return out;
}

// ---- breaking-change detection -----------------------------------------
// High-confidence, shape-robust accept-side breaking signals only.
function diffNode(path, prev, next, breaks) {
  if (!prev || !next || typeof prev !== "object" || typeof next !== "object") return;

  // additionalProperties true/absent -> false closes a previously-open object.
  if (prev.additionalProperties === true && next.additionalProperties === false) {
    breaks.push(`${path}: additionalProperties tightened true -> false`);
  }

  // Property removed from a CLOSED object (open objects still accept it).
  if (prev.properties) {
    const closed = next.additionalProperties === false;
    for (const key of Object.keys(prev.properties)) {
      if (!next.properties || !(key in next.properties)) {
        if (closed) breaks.push(`${path}.${key}: property removed from a closed object`);
      } else {
        diffNode(`${path}.${key}`, prev.properties[key], next.properties[key], breaks);
      }
    }
  }

  // New required property.
  const prevReq = new Set(prev.required || []);
  for (const r of next.required || []) {
    if (!prevReq.has(r)) breaks.push(`${path}: new required property "${r}"`);
  }

  // Enum value removed.
  if (Array.isArray(prev.enum) && Array.isArray(next.enum)) {
    const nextSet = new Set(next.enum);
    for (const v of prev.enum) {
      if (!nextSet.has(v)) breaks.push(`${path}: enum value "${v}" removed`);
    }
  }

  // Type narrowed (allowed primitive types reduced).
  const pt = Array.isArray(prev.type) ? prev.type : prev.type ? [prev.type] : null;
  const nt = Array.isArray(next.type) ? next.type : next.type ? [next.type] : null;
  if (pt && nt) {
    const ns = new Set(nt);
    for (const t of pt) if (!ns.has(t)) breaks.push(`${path}: type "${t}" no longer accepted`);
  }

  // Recurse into array items.
  if (prev.items && next.items) diffNode(`${path}[]`, prev.items, next.items, breaks);

  // Combinators. Compare order-independently: remove exact-match branches first
  // (so a pure reorder is a no-op), then classify the leftovers. Generated
  // schemas are deterministically ordered, but legacy allOf clauses are not.
  //   allOf: more branches = tighter. A leftover added branch = breaking.
  //   oneOf/anyOf: fewer branches = fewer accepted shapes. A leftover removed
  //   branch = breaking. Remaining leftovers are diffed pairwise to catch an
  //   in-branch modification precisely.
  for (const key of ["allOf", "oneOf", "anyOf"]) {
    const pb = Array.isArray(prev[key]) ? prev[key] : null;
    const nb = Array.isArray(next[key]) ? next[key] : null;
    if (!pb && !nb) continue;
    if (!pb || !nb) {
      breaks.push(`${path}: "${key}" was ${pb ? "removed" : "added"} (manual review)`);
      continue;
    }
    const canon = (x) => JSON.stringify(x);
    const nLeft = [...nb];
    const pLeft = [];
    for (const b of pb) {
      const i = nLeft.findIndex((x) => canon(x) === canon(b));
      if (i >= 0) nLeft.splice(i, 1);
      else pLeft.push(b);
    }
    if (key === "allOf" && nLeft.length > pLeft.length) {
      breaks.push(`${path}: allOf added ${nLeft.length - pLeft.length} constraint(s) (tighter)`);
    }
    if ((key === "oneOf" || key === "anyOf") && pLeft.length > nLeft.length) {
      breaks.push(`${path}: ${key} removed ${pLeft.length - nLeft.length} accepted shape(s)`);
    }
    // oneOf is "exactly one": adding a branch can make a previously-valid value
    // match more than one branch (and become invalid). anyOf additions only
    // widen, so they stay safe.
    if (key === "oneOf" && nLeft.length > pLeft.length) {
      breaks.push(`${path}: oneOf added ${nLeft.length - pLeft.length} branch(es) — may break exactly-one matching (manual review)`);
    }
    const common = Math.min(pLeft.length, nLeft.length);
    for (let i = 0; i < common; i++) diffNode(`${path}.${key}[~${i}]`, pLeft[i], nLeft[i], breaks);
  }

  // Conditional / negation subschemas (legacy stables use if/then under allOf);
  // already normalized above, so compare directly.
  for (const key of ["if", "then", "else", "not"]) {
    if (prev[key] && next[key]) {
      diffNode(`${path}.${key}`, prev[key], next[key], breaks);
    } else if (Boolean(prev[key]) !== Boolean(next[key])) {
      breaks.push(`${path}: "${key}" subschema was ${prev[key] ? "removed" : "added"} (manual review)`);
    }
  }

  // A changed const narrows the accepted value.
  if ("const" in prev && "const" in next && JSON.stringify(prev.const) !== JSON.stringify(next.const)) {
    breaks.push(`${path}: const changed ${JSON.stringify(prev.const)} -> ${JSON.stringify(next.const)}`);
  }
}

function detectBreaking(prevSchema, nextSchema) {
  const breaks = [];
  diffNode("$", normalize(prevSchema, prevSchema), normalize(nextSchema, nextSchema), breaks);
  return breaks;
}

// ---- main ---------------------------------------------------------------
const schemaVer = readJson("schemas", "schema-version.json");
const latestRaw = schemaVer.stableLatest;
const latest = parseVer(latestRaw);
if (!latest) fail([`schema-version.json stableLatest "${latestRaw}" is not parseable semver.`]);

// Enumerate stable schema files, pick the one matching stableLatest and the
// highest one strictly below it.
const stableAbs = join(repoRoot, STABLE_DIR);
const versions = readdirSync(stableAbs)
  .map((f) => FILE_RE.exec(f))
  .filter(Boolean)
  .map((m) => parseVer(m[1]))
  .filter(Boolean)
  .sort(cmp);

const newVer = versions.find((v) => v.raw === latestRaw);
if (!newVer) fail([`no stable schema file for stableLatest "${latestRaw}".`]);

const below = versions.filter((v) => cmp(v, newVer) < 0);
if (below.length === 0) {
  console.log(`Breaking-change guard: no prior stable schema below ${latestRaw}; nothing to compare.`);
  process.exit(0);
}
const prevVer = below[below.length - 1];

// Does the version gap allow a breaking change?
const breakingAllowed =
  newVer.major === 0
    ? newVer.minor !== prevVer.minor // 0.x: a minor bump permits breaking
    : newVer.major !== prevVer.major; // >=1.0: a major bump permits breaking

if (breakingAllowed) {
  console.log(
    `Breaking-change guard: ${prevVer.raw} -> ${latestRaw} is a ${newVer.major === 0 ? "minor" : "major"} bump; breaking changes permitted. Skipped.`
  );
  process.exit(0);
}

// Same major.minor (a patch/pre-release-only change): breaking is NOT allowed.
const prevSchema = readJson(STABLE_DIR, `mxc-config.schema.${prevVer.raw}.json`);
const nextSchema = readJson(STABLE_DIR, `mxc-config.schema.${latestRaw}.json`);
const breaks = detectBreaking(prevSchema, nextSchema);

if (breaks.length) {
  fail([
    `${prevVer.raw} -> ${latestRaw} is only a patch/pre-release change but contains breaking schema change(s):`,
    ...breaks,
    `A breaking change requires at least a ${newVer.major === 0 ? "minor" : "major"} version bump.`,
  ]);
}

console.log(
  `Breaking-change guard OK: ${prevVer.raw} -> ${latestRaw} (same ${newVer.major}.${newVer.minor}) has no breaking schema changes.`
);
