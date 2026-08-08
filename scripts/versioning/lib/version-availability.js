// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

// Shared logic for the version-availability oracle gate, kept separate from the CLI
// entry point so each piece is unit-testable on its own.

const SINCE_KEY = "x-mxc-since";
const UNTIL_KEY = "x-mxc-until";
const { parseMajorMinor } = require("./version.js");

// Surfaces whose accepted history is NOT derivable from schema presence, so a
// range here is refused outright rather than checked against a bound that would
// reject configs that have always worked:
//   * `experimental` was an open block before 0.8, so anything under it
//     validated vacuously and has long been accepted.
//   * the state-aware discriminators ride on 0.6 envelopes but only entered the
//     schema at 0.8.
const UNDERIVABLE_ROOTS = [
  { path: "experimental", why: "declared no properties before 0.8, so anything under it validated vacuously" },
  { path: "phase", why: "carried by state-aware requests declaring 0.6 since before the schema described it" },
  { path: "sandboxId", why: "carried by state-aware requests declaring 0.6 since before the schema described it" },
  { path: "correlationVector", why: "carried by state-aware requests declaring 0.6 since before the schema described it" },
];

const MAX_DEPTH = 64;

/// Thrown when traversal hits its depth budget: returning silently would let
/// the gate pass by not looking.
class DepthExceeded extends Error {
  constructor(path) {
    super(
      `schema traversal exceeded ${MAX_DEPTH} levels at '${path || "<root>"}'. ` +
        `Availability ranges below that depth would not be checked, so this fails rather ` +
        `than silently skipping them.`
    );
    this.name = "DepthExceeded";
  }
}

function has(node, key) {
  return node && typeof node === "object" && Object.prototype.hasOwnProperty.call(node, key);
}

function resolvePointer(root, ref) {
  if (typeof ref !== "string" || !ref.startsWith("#/")) return null;
  let target = root;
  for (const encoded of ref.slice(2).split("/")) {
    const part = encoded.replace(/~1/g, "/").replace(/~0/g, "~");
    if (!has(target, part)) return null;
    target = target[part];
  }
  return target;
}

/**
 * Walk every property reachable from the schema root, returning
 * `{ path, ownerType, property, node }`. Array nesting adds no path segment,
 * matching the wire model's own listing.
 */
function collectPropertyPaths(schema, { entries } = {}) {
  const out = [];
  const rootType = "#root";

  const walk = (node, path, ownerType, seenRefs, depth) => {
    if (!node || typeof node !== "object") return;
    if (depth > MAX_DEPTH) throw new DepthExceeded(path);

    if (typeof node.$ref === "string") {
      if (seenRefs.has(node.$ref)) return;
      const target = resolvePointer(schema, node.$ref);
      if (!target) return;
      const name = node.$ref.startsWith("#/definitions/")
        ? node.$ref.slice("#/definitions/".length)
        : ownerType;
      walk(target, path, name, new Set(seenRefs).add(node.$ref), depth + 1);
      return;
    }

    for (const key of ["allOf", "anyOf", "oneOf"]) {
      if (Array.isArray(node[key])) {
        for (const branch of node[key]) walk(branch, path, ownerType, seenRefs, depth + 1);
      }
    }

    // An array contributes no path segment: a range on `Vec<T>`'s element field
    // is keyed the same as a range on a directly nested struct's field.
    if (node.items) walk(node.items, path, ownerType, seenRefs, depth + 1);

    if (node.properties && typeof node.properties === "object") {
      for (const [name, sub] of Object.entries(node.properties)) {
        const childPath = path ? `${path}.${name}` : name;
        out.push({ path: childPath, ownerType, property: name, node: sub });
        walk(sub, childPath, ownerType, seenRefs, depth + 1);
      }
    }
  };

  walk(schema, "", rootType, new Set(), 0);
  return entries ? out : new Set(out.map((e) => e.path));
}

/**
 * Every declared range, keyed by owning type + property (where the annotation
 * lives), with every document path that reaches it. A type reachable from two
 * places yields two paths — which is how a range leaking onto `experimental`
 * gets caught.
 */
function collectDeclaredAvailability(schema) {
  const entries = collectPropertyPaths(schema, { entries: true });
  const byKey = new Map();

  for (const entry of entries) {
    const since = entry.node?.[SINCE_KEY];
    const until = entry.node?.[UNTIL_KEY];
    if (since === undefined && until === undefined) continue;

    const key = `${entry.ownerType}.${entry.property}`;
    if (!byKey.has(key)) {
      byKey.set(key, {
        ownerType: entry.ownerType,
        property: entry.property,
        since,
        until,
        paths: [],
      });
    }
    const record = byKey.get(key);
    if (!record.paths.includes(entry.path)) record.paths.push(entry.path);
  }

  return [...byKey.values()].sort((a, b) =>
    `${a.ownerType}.${a.property}`.localeCompare(`${b.ownerType}.${b.property}`)
  );
}

/**
 * Check declared ranges against the schema timeline.
 *
 * `timeline` is ordered oldest-first: `[{ label, version, paths }]`.
 */
function checkAvailability({ declared, timeline, compareMajorMinor }) {
  const errors = [];
  let checked = 0;

  const firstAppearance = (path) => timeline.find((t) => t.paths.has(path));
  const atLabel = (label) => timeline.find((t) => t.label === label);

  for (const record of declared) {
    const name = `${record.ownerType}.${record.property}`;

    if (record.paths.length === 0) {
      errors.push(
        `${name}: declares a availability range but is not reachable from the schema root, ` +
          `so no config could ever use it`
      );
      continue;
    }

    const underivable = record.paths
      .map((p) => ({
        path: p,
        root: UNDERIVABLE_ROOTS.find((r) => p === r.path || p.startsWith(`${r.path}.`)),
      }))
      .filter((entry) => entry.root);
    if (underivable.length > 0) {
      const { path, root } = underivable[0];
      errors.push(
        `${name}: a availability range cannot be declared at '${underivable
          .map((e) => e.path)
          .join("', '")}'. The '${root.path}' surface ${root.why}, so its first appearance ` +
          `is not derivable from the schemas — a bound taken from schema presence would start ` +
          `rejecting configs that have always worked. If this availability range is on a shared type, move ` +
          `it to the containing field instead.`
      );
      continue;
    }

    let malformed = false;
    for (const key of [SINCE_KEY, UNTIL_KEY]) {
      const raw = key === SINCE_KEY ? record.since : record.until;
      if (raw === undefined) continue;
      if (typeof raw !== "string" || !parseMajorMinor(raw)) {
        errors.push(`${name}: ${key} '${raw}' is not a major.minor version`);
        malformed = true;
      }
    }
    if (malformed) continue;

    if (record.since !== undefined) {
      for (const path of record.paths) {
        const first = firstAppearance(path);
        if (!first) {
          errors.push(
            `${name}: declares ${SINCE_KEY} '${record.since}' but '${path}' appears in none ` +
              `of the ${timeline.map((t) => t.label).join(" / ")} schemas`
          );
          continue;
        }
        if (first.label !== record.since) {
          errors.push(
            `${name}: declares ${SINCE_KEY} '${record.since}' but '${path}' first appears ` +
              `in the ${first.label} schema. Correct the annotation in wire.rs (and ` +
              `regenerate the schema), or confirm the field really did exist earlier.`
          );
        }
      }
      checked++;
    }

    if (record.until !== undefined) {
      const at = atLabel(record.until);
      if (!at) {
        errors.push(
          `${name}: declares ${UNTIL_KEY} '${record.until}', which is not a version this ` +
            `gate has a schema for (${timeline.map((t) => t.label).join(", ")})`
        );
      } else {
        for (const path of record.paths) {
          if (!at.paths.has(path)) {
            errors.push(
              `${name}: declares ${UNTIL_KEY} '${record.until}' but '${path}' does not exist ` +
                `in the ${record.until} schema, so that is not a version it was available in`
            );
          }
        }
      }
      checked++;
    }

    if (record.since !== undefined && record.until !== undefined) {
      const since = parseMajorMinor(record.since);
      const until = parseMajorMinor(record.until);
      if (since && until && compareMajorMinor(since, until) > 0) {
        errors.push(
          `${name}: empty availability range — ${SINCE_KEY} '${record.since}' is newer than ` +
            `${UNTIL_KEY} '${record.until}', so the field could never be used`
        );
      }
    }
  }

  return { errors, checked };
}

module.exports = {
  DepthExceeded,
  MAX_DEPTH,
  SINCE_KEY,
  UNDERIVABLE_ROOTS,
  UNTIL_KEY,
  checkAvailability,
  collectDeclaredAvailability,
  collectPropertyPaths,
};
