// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

const { createHash } = require("crypto");

const ANNOTATIONS = new Set([
  "$id",
  "$schema",
  "title",
  "description",
  "default",
  "examples",
  "$comment",
  "readOnly",
  "writeOnly",
  "deprecated",
  "contentEncoding",
  "contentMediaType",
  // MXC version-window metadata. These record when a field is valid; they do
  // not constrain instances, so a change to one is not a change to the accepted
  // instance set. Listing them here is what keeps adding or adjusting a window
  // from being reported as an unrecognised keyword change.
  "x-mxc-since",
  "x-mxc-until",
]);

// Internal marker for a `$ref` composed with assertion siblings. Not a schema
// keyword: `diffNode` unpacks it explicitly so the name never reaches a report.
const REF_SIBLINGS = "$refWithSiblings";

const HANDLED_KEYS = new Set([
  "properties",
  "required",
  "additionalProperties",
  "additionalItems",
  "items",
  "prefixItems",
  "contains",
  "minContains",
  "maxContains",
  "propertyNames",
  "patternProperties",
  "dependentRequired",
  "dependentSchemas",
  "dependencies",
  "type",
  "enum",
  "const",
  "allOf",
  "oneOf",
  "anyOf",
  "if",
  "then",
  "else",
  "not",
  "minimum",
  "exclusiveMinimum",
  "maximum",
  "exclusiveMaximum",
  "multipleOf",
  "minLength",
  "maxLength",
  "pattern",
  "format",
  "minItems",
  "maxItems",
  "uniqueItems",
  "minProperties",
  "maxProperties",
]);

// Serialises an enum's *data* value with object keys in a stable order, so two
// spellings of the same value compare equal. Enum values are plain JSON, but a
// schema is free to nest them arbitrarily deeply, so this carries the same depth
// budget as schema traversal rather than risking a stack overflow on input a
// single committed file controls.
function canonicalJson(value) {
  return JSON.stringify(canonicalValue(value, 0));
}

function canonicalValue(value, depth) {
  if (depth > MAX_DEPTH) throw new BudgetExceeded("depth");
  if (Array.isArray(value)) return value.map((v) => canonicalValue(v, depth + 1));
  if (!value || typeof value !== "object") return value;
  return Object.fromEntries(
    Object.keys(value)
      .sort()
      .map((key) => [key, canonicalValue(value[key], depth + 1)])
  );
}

// A fixed-size structural digest of a normalised node, memoised on identity.
//
// Normalisation inlines and shares `$ref` targets, so the result is a DAG whose
// unfolded tree can be exponentially larger. Two properties matter: memoising on
// identity keeps the number of computations linear in the DAG, and hashing keeps
// each node's digest a constant size. Building a key by concatenating children's
// keys would satisfy only the first, and the resulting string would still double
// in length at every level.
//
// A digest collision is not a correctness risk: it is used only to bucket
// candidates, and `sameValue` confirms an exact match within the bucket.
// Scoped to one `detectBreaking` call by `resetCaches`. Memo entries are keyed
// on node identity, and an unrecognised keyword's payload keeps the caller's
// own object identity through normalisation, so a cache that outlived the call
// would answer for input the caller is free to mutate in between.
let structuralDigestCache = new WeakMap();

function structuralDigest(node, depth = 0) {
  if (depth > MAX_DEPTH) throw new BudgetExceeded("depth");
  if (!node || typeof node !== "object") {
    return `p:${JSON.stringify(node) ?? "null"}`;
  }
  const cached = structuralDigestCache.get(node);
  if (cached !== undefined) return cached;
  // Seed before recursing so a cycle terminates instead of spinning.
  structuralDigestCache.set(node, "cycle");
  let parts;
  try {
    parts = Array.isArray(node)
      ? node.map((value) => structuralDigest(value, depth + 1))
      : Object.keys(node)
          .sort()
          .map((key) => `${key}\u0000${structuralDigest(node[key], depth + 1)}`);
  } catch (error) {
    // Same reasoning as the equality cache: a placeholder left behind by an
    // aborted walk would be read as a real digest by a later run, mis-bucketing
    // the node it stands for.
    structuralDigestCache.delete(node);
    throw error;
  }
  const digest = createHash("sha1")
    .update(Array.isArray(node) ? "a" : "o")
    .update(parts.join("\u0001"))
    .digest("base64");
  structuralDigestCache.set(node, digest);
  return digest;
}

// Order-insensitive structural equality.
//
// Do not reduce this to serialising both sides and comparing the strings: after
// normalisation inlines and memoises `$ref` targets the schema is a DAG, and
// serialising it materialises the tree it unfolds to, which is exponential in
// the fan-out depth. Comparing structurally, and memoising each pair of node
// identities, keeps the cost proportional to the number of distinct pairs.
let sameValueCache = new WeakMap();

// Discards both identity-keyed memos. They are only ever valid within a single
// comparison: normalised nodes are rebuilt per call, and the values they share
// with the caller -- the untraversed payloads of unrecognised keywords -- are
// the caller's own mutable objects.
function resetCaches() {
  sameValueCache = new WeakMap();
  structuralDigestCache = new WeakMap();
}

function sameValue(left, right, depth = 0) {
  // An unresolved reference is never evidence of equal accepted-instance
  // sets, even when both sentinels name the same target. Keep it out of every
  // equality-based shortcut so the caller must fail closed.
  if (unresolvedSentinel(left) || unresolvedSentinel(right)) return false;
  if (left === right) return true;
  // Unrecognised keywords' values are copied through normalisation untraversed,
  // so their nesting is not covered by the normalisation budget and only this
  // walk ever descends them. Bound it here, or a deep enough extension value
  // exhausts the JS stack instead of producing the promised finding.
  if (depth > MAX_DEPTH) throw new BudgetExceeded("depth");
  if (
    !left ||
    !right ||
    typeof left !== "object" ||
    typeof right !== "object"
  ) {
    return Number.isNaN(left) && Number.isNaN(right);
  }
  let cached = sameValueCache.get(left);
  if (cached) {
    const hit = cached.get(right);
    if (hit !== undefined) return hit;
  } else {
    cached = new WeakMap();
    sameValueCache.set(left, cached);
  }
  // Seed with `true` so a cyclic walk terminates by assuming equality on the
  // back edge; a genuine difference elsewhere in the cycle still fails.
  cached.set(right, true);
  let result;
  try {
    result = sameValueInner(left, right, depth);
  } catch (error) {
    // Drop the provisional entry while unwinding. An aborted comparison
    // established nothing, and the cache is keyed on node identity: an
    // unrecognised keyword's payload is the caller's own object, shared across
    // calls, so a `true` left behind would let a later run clear the very pair
    // that just exhausted the budget.
    cached.delete(right);
    throw error;
  }
  cached.set(right, result);
  return result;
}

function sameValueInner(left, right, depth) {
  if (Array.isArray(left) !== Array.isArray(right)) return false;
  if (Array.isArray(left)) {
    return (
      left.length === right.length &&
      left.every((value, index) => sameValue(value, right[index], depth + 1))
    );
  }
  const leftKeys = Object.keys(left);
  if (leftKeys.length !== Object.keys(right).length) return false;
  return leftKeys.every(
    (key) => has(right, key) && sameValue(left[key], right[key], depth + 1)
  );
}

function has(node, key) {
  return Object.prototype.hasOwnProperty.call(node, key);
}

function patternPropertiesMayApply(patternProperties, propertyName) {
  if (
    !patternProperties ||
    typeof patternProperties !== "object" ||
    Array.isArray(patternProperties)
  ) {
    return false;
  }
  return Object.keys(patternProperties).some((pattern) => {
    try {
      return new RegExp(pattern, "u").test(propertyName);
    } catch {
      // Invalid or unsupported patterns cannot establish non-overlap.
      return true;
    }
  });
}

function resolveRef(root, ref, seen) {
  return resolveRefInner(root, ref, seen, { nodes: 0, memo: new Map(), recursionHits: 0 }, 0);
}

function resolveRefInner(root, ref, seen, ctx, depth) {
  if (!ref.startsWith("#/")) return { $unresolvedRef: ref };
  if (seen.has(ref)) {
    ctx.recursionHits++;
    return { $recursiveRef: ref };
  }

  // Memoise by ref. Without this a fan-out graph re-normalises each shared
  // target once per path that reaches it, which is exponential in the depth of
  // the graph.
  const cached = ctx.memo.get(ref);
  if (cached !== undefined) return cached;

  let target = root;
  for (const encoded of ref.slice(2).split("/")) {
    const part = encoded.replace(/~1/g, "/").replace(/~0/g, "~");
    if (
      !target ||
      typeof target !== "object" ||
      !Object.prototype.hasOwnProperty.call(target, part)
    ) {
      return { $unresolvedRef: ref };
    }
    target = target[part];
  }
  const before = ctx.recursionHits;
  const resolved = normalizeInner(
    root,
    target,
    new Set(seen).add(ref),
    ctx,
    depth + 1
  );
  // Cache only when the result did not depend on the cycle stack. Detect that
  // by counting recursion sentinels produced while expanding this subtree --
  // walking the resolved tree to look for them would itself be exponential on
  // the very inputs the cache exists to make tractable.
  if (ctx.recursionHits === before) ctx.memo.set(ref, resolved);
  return resolved;
}

function normalizeMap(root, value, seen, ctx, depth) {
  return Object.fromEntries(
    Object.entries(value).map(([key, schema]) => [
      key,
      normalizeInner(root, schema, seen, ctx, depth + 1),
    ])
  );
}

// `{"const": x}` is exactly `{"enum": [x]}` in JSON Schema. Rewrite the former
// to the latter so a generator's choice of rendering never reads as a
// structural change.
function constToEnum(node) {
  if (!node || typeof node !== "object" || Array.isArray(node)) return node;
  if (!has(node, "const") || has(node, "enum")) return node;
  const { const: constValue, ...rest } = node;
  return { ...rest, enum: [constValue] };
}

// Traversal budgets. A schema whose `$ref` graph fans out can expand
// exponentially, and a deeply nested one can overflow the JS stack, so a small
// hand-written document could otherwise stall or crash CI. Exceeding either
// budget is reported as a finding, never silently ignored.
const MAX_DEPTH = 200;
const MAX_NODES = 200000;

class BudgetExceeded extends Error {}

function normalize(root, node, seen = new Set(), ctx = null) {
  const context = ctx || { nodes: 0, memo: new Map(), recursionHits: 0 };
  return normalizeInner(root, node, seen, context, 0);
}

function normalizeInner(root, node, seen, ctx, depth) {
  if (depth > MAX_DEPTH) throw new BudgetExceeded("depth");
  if (++ctx.nodes > MAX_NODES) throw new BudgetExceeded("size");
  if (!node || typeof node !== "object") return node;
  if (Array.isArray(node)) {
    return node.map((value) => normalizeInner(root, value, seen, ctx, depth + 1));
  }
  if (node.$ref) {
    const resolved = resolveRefInner(root, node.$ref, seen, ctx, depth);
    // Draft 2019-09 and later apply keywords that sit alongside `$ref`.
    // Returning only the target would silently drop a real restriction such as
    // an added `required` or `additionalProperties: false`. Draft-07 ignores
    // them instead, so composing is the conservative reading: it can only ask
    // for a review that a draft-07 document did not need, never miss one.
    //
    // Annotations are excluded regardless of dialect. They impose nothing in
    // any draft, so a `description` beside a reference is not a restriction to
    // report under either reading.
    const siblings = Object.keys(node).filter(
      (key) =>
        key !== "$ref" &&
        key !== "definitions" &&
        key !== "$defs" &&
        !ANNOTATIONS.has(key)
    );
    if (siblings.length === 0) return resolved;
    const normalizedSiblings = normalizeInner(
      root,
      Object.fromEntries(siblings.map((key) => [key, node[key]])),
      seen,
      ctx,
      depth + 1
    );
    return { [REF_SIBLINGS]: [resolved, normalizedSiblings] };
  }

  // `{"const": x}` and `{"enum": [x]}` accept exactly the same instances, so
  // rewrite `const` to its `enum` equivalent before any structural comparison.
  // Generators differ on which they emit for a single-valued variant, and
  // without this a purely cosmetic rendering change reads as a structural one.
  node = constToEnum(node);
  if (Array.isArray(node.oneOf)) {
    node = { ...node, oneOf: node.oneOf.map(constToEnum) };
  }

  const singletonEnumBranches =
    Array.isArray(node.oneOf) &&
    Object.keys(node).every(
      (key) => key === "oneOf" || ANNOTATIONS.has(key)
    ) &&
    node.oneOf.every(
      (branch) =>
        branch &&
        Array.isArray(branch.enum) &&
        branch.enum.length === 1 &&
        Object.keys(branch).every(
          (key) => key === "enum" || ANNOTATIONS.has(key)
        )
    );
  const singletonEnumValues = singletonEnumBranches
    ? node.oneOf.map((branch) => branch.enum[0])
    : [];
  if (
    singletonEnumBranches &&
    new Set(singletonEnumValues.map(canonicalJson)).size ===
      singletonEnumValues.length
  ) {
    return {
      enum: singletonEnumValues
        .sort((left, right) =>
          canonicalJson(left).localeCompare(canonicalJson(right))
        ),
    };
  }

  // A null-prototype accumulator. A schema keyword legitimately named
  // `__proto__` is an own property on a parsed document, but assigning it to a
  // normal object would invoke the inherited setter instead of creating an own
  // key -- the keyword would vanish from the normalised node and a change to it
  // would clear silently, against the fail-closed contract.
  const out = Object.create(null);
  for (const [key, value] of Object.entries(node)) {
    if (ANNOTATIONS.has(key) || key === "definitions" || key === "$defs") {
      continue;
    }

    if (
      (key === "properties" ||
        key === "patternProperties" ||
        key === "dependentSchemas") &&
      value &&
      typeof value === "object"
    ) {
      out[key] = normalizeMap(root, value, seen, ctx, depth);
    } else if (
      (key === "items" ||
        key === "contains" ||
        key === "propertyNames" ||
        key === "additionalProperties" ||
        key === "additionalItems" ||
        key === "if" ||
        key === "then" ||
        key === "else" ||
        key === "not") &&
      value &&
      typeof value === "object"
    ) {
      out[key] = normalizeInner(root, value, seen, ctx, depth + 1);
    } else if (
      (key === "allOf" ||
        key === "oneOf" ||
        key === "anyOf" ||
        key === "prefixItems") &&
      Array.isArray(value)
    ) {
      out[key] = value.map((branch) => normalizeInner(root, branch, seen, ctx, depth + 1));
    } else if (key === "type" && Array.isArray(value)) {
      out.type = [...value].sort();
    } else if (key === "enum" && Array.isArray(value)) {
      out.enum = [...value].sort((left, right) =>
        canonicalJson(left).localeCompare(canonicalJson(right))
      );
    } else if (key === "required" && Array.isArray(value)) {
      out.required = [...value].sort();
    } else if (key === "dependentRequired" && value) {
      out.dependentRequired = Object.fromEntries(
        Object.entries(value).map(([property, required]) => [
          property,
          [...required].sort(),
        ])
      );
    } else if (key === "dependencies" && value) {
      out.dependencies = Object.fromEntries(
        Object.entries(value).map(([property, dependency]) => [
          property,
          Array.isArray(dependency)
            ? [...dependency].sort()
            : normalizeInner(root, dependency, seen, ctx, depth + 1),
        ])
      );
    } else {
      out[key] = value;
    }
  }

  const types = Array.isArray(out.type)
    ? out.type
    : out.type
      ? [out.type]
      : null;
  if (
    (!types || types.includes("object") || out.properties) &&
    !has(out, "additionalProperties")
  ) {
    out.additionalProperties = true;
  }
  if (Array.isArray(out.items) && !has(out, "additionalItems")) {
    out.additionalItems = true;
  }
  // Collapse an assertion-free schema to the canonical `true` here rather than
  // only where `diffNode` enters a node, so `{}` and `true` stay equivalent in
  // every position -- including ones reached by a keyword comparison rather
  // than by a recursive descent, such as `additionalProperties` or a newly
  // added optional property.
  if (isUnconstrained(out)) return true;
  return out;
}

function lowerBound(node) {
  const candidates = [];
  if (typeof node.minimum === "number") {
    // Draft-04 spells an exclusive bound as a boolean flag modifying `minimum`,
    // so `exclusiveMinimum: false -> true` is a real tightening that a
    // numeric-only reading treats as no change at all.
    candidates.push({
      value: node.minimum,
      inclusive: node.exclusiveMinimum !== true,
    });
  }
  if (typeof node.exclusiveMinimum === "number") {
    candidates.push({ value: node.exclusiveMinimum, inclusive: false });
  }
  return candidates.sort((left, right) => {
    if (left.value !== right.value) return right.value - left.value;
    return Number(left.inclusive) - Number(right.inclusive);
  })[0];
}

function upperBound(node) {
  const candidates = [];
  if (typeof node.maximum === "number") {
    // See lowerBound: draft-04 uses a boolean flag here.
    candidates.push({
      value: node.maximum,
      inclusive: node.exclusiveMaximum !== true,
    });
  }
  if (typeof node.exclusiveMaximum === "number") {
    candidates.push({ value: node.exclusiveMaximum, inclusive: false });
  }
  return candidates.sort((left, right) => {
    if (left.value !== right.value) return left.value - right.value;
    return Number(left.inclusive) - Number(right.inclusive);
  })[0];
}

function compareBounds(path, previous, next, breaks) {
  const previousLower = lowerBound(previous);
  const nextLower = lowerBound(next);
  if (
    nextLower &&
    (!previousLower ||
      nextLower.value > previousLower.value ||
      (nextLower.value === previousLower.value &&
        previousLower.inclusive &&
        !nextLower.inclusive))
  ) {
    breaks.push(`${path}: lower bound was tightened`);
  }

  const previousUpper = upperBound(previous);
  const nextUpper = upperBound(next);
  if (
    nextUpper &&
    (!previousUpper ||
      nextUpper.value < previousUpper.value ||
      (nextUpper.value === previousUpper.value &&
        previousUpper.inclusive &&
        !nextUpper.inclusive))
  ) {
    breaks.push(`${path}: upper bound was tightened`);
  }
}

function compareMinimum(path, key, previous, next, breaks) {
  if (
    has(next, key) &&
    (!has(previous, key) || next[key] > previous[key])
  ) {
    breaks.push(`${path}: ${key} increased to ${next[key]}`);
  }
}

function compareMaximum(path, key, previous, next, breaks) {
  if (
    has(next, key) &&
    (!has(previous, key) || next[key] < previous[key])
  ) {
    breaks.push(`${path}: ${key} decreased to ${next[key]}`);
  }
}

// `minContains` and `maxContains` only have effect alongside `contains`, and
// `contains` itself carries an implicit `minContains: 1` -- which is exactly
// what makes even `contains: true` a restriction, since it rejects the empty
// array. Comparing the keywords as written misses both halves of that: dropping
// an explicit `minContains: 0` while keeping `contains` restores the default and
// starts rejecting arrays with no match, and adding `contains` beside
// `minContains: 0` restricts nothing at all. So compare effective values.
function effectiveMinContains(node) {
  if (!has(node, "contains")) return 0;
  return typeof node.minContains === "number" ? node.minContains : 1;
}

function effectiveMaxContains(node) {
  if (!has(node, "contains")) return Infinity;
  return typeof node.maxContains === "number" ? node.maxContains : Infinity;
}

function compareContains(path, previous, next, breaks) {
  const previousMin = effectiveMinContains(previous);
  const nextMin = effectiveMinContains(next);
  if (nextMin > previousMin) {
    breaks.push(
      has(previous, "contains")
        ? `${path}: minContains increased to ${nextMin}`
        : `${path}: "contains" constraint was added`
    );
  }
  const nextMax = effectiveMaxContains(next);
  if (nextMax < effectiveMaxContains(previous)) {
    breaks.push(`${path}: maxContains decreased to ${nextMax}`);
  }
  if (has(previous, "contains") && has(next, "contains")) {
    // With a finite upper bound the polarity of a `contains` change inverts:
    // widening the subschema lets *more* elements count toward `maxContains`,
    // so `{contains: integer, maxContains: 1}` becoming
    // `{contains: number, maxContains: 1}` newly rejects `[1, 1.5]`. A
    // recursive descent reads that widening as safe, so it cannot be used here.
    // Deciding it properly is inverse containment, which this detector does not
    // attempt.
    if (Number.isFinite(nextMax)) {
      if (!sameValue(previous.contains, next.contains)) {
        breaks.push(
          `${path}: "contains" changed while maxContains is finite; whether ` +
            `every previously accepted array is still accepted requires ` +
            `manual proof`
        );
      }
      return;
    }
    diffNode(`${path}.contains`, previous.contains, next.contains, breaks);
  }
}

function compareAddedOrChanged(path, key, previous, next, breaks) {
  if (
    has(next, key) &&
    (!has(previous, key) || !sameValue(previous[key], next[key]))
  ) {
    breaks.push(`${path}: "${key}" was added or changed (manual review)`);
  }
}

function compareSchemaMap(path, key, previous, next, breaks) {
  if (!sameValue(previous[key], next[key])) {
    breaks.push(`${path}: "${key}" changed (manual review)`);
  }
}

// `{}` accepts every instance, exactly like the boolean schema `true`.
// Normalisation makes the open default explicit as `additionalProperties: true`
// and annotations impose nothing, so ignore both when deciding emptiness.
function isUnconstrained(node) {
  if (node === null || typeof node !== "object" || Array.isArray(node)) {
    return false;
  }
  return Object.entries(node).every(
    ([key, value]) =>
      ANNOTATIONS.has(key) || (key === "additionalProperties" && value === true)
  );
}

// Lists the keywords a now-constrained schema introduced, so the report names
// what tightened.
function constrainingKeywords(node) {
  if (node === false) return "";
  if (!node || typeof node !== "object" || Array.isArray(node)) return "";
  const keywords = Object.keys(node).filter((key) => !ANNOTATIONS.has(key));
  return keywords.length ? ` by "${keywords.sort().join('", "')}"` : "";
}

// Names the reference sentinel present on either side, if any. These are
// internal markers: reporting them through the unrecognised-keyword path would
// leak `$unresolvedRef` / `$recursiveRef` into user-facing output.
function refSentinel(node) {
  if (!node || typeof node !== "object" || Array.isArray(node)) return null;
  if (node.$unresolvedRef) return `"${node.$unresolvedRef}"`;
  if (node.$recursiveRef) return `"${node.$recursiveRef}"`;
  return null;
}

// Names an *unresolved* reference specifically -- one whose target was never
// available to inspect, as distinct from a cycle marker.
function unresolvedSentinel(node) {
  if (!node || typeof node !== "object" || Array.isArray(node)) return null;
  return node.$unresolvedRef ? `"${node.$unresolvedRef}"` : null;
}

// True for the null branch of the `anyOf: [T, null]` nullable idiom. Only a
// branch that asserts nothing but `type: "null"` counts: a branch that merely
// includes null among several types does not pin the correspondence.
function isNullBranch(node) {
  if (!node || typeof node !== "object" || Array.isArray(node)) return false;
  const keys = Object.keys(node);
  if (keys.length !== 1 || keys[0] !== "type") return false;
  const types = Array.isArray(node.type) ? node.type : [node.type];
  return types.length === 1 && types[0] === "null";
}

// Traversal state for the diff walk, reset by `detectBreaking`. Normalisation
// inlines `$ref` targets and memoises them, so its output is a DAG: small in
// memory but exponential to walk as a tree. `seen` collapses that by diffing
// each pair of node identities once, and `nodes` bounds what remains.
const diffBudget = { nodes: 0, exceeded: false, seen: new WeakMap() };

// True the first time this exact pair of normalised nodes is compared. Shared
// `$ref` targets reach the same pair by many paths; without this a fan-out
// graph is walked once per path. A finding on a shared subschema is therefore
// reported at the first path that reaches it rather than at every path.
function firstVisit(previous, next) {
  if (!previous || typeof previous !== "object") return true;
  if (!next || typeof next !== "object") return true;
  let visited = diffBudget.seen.get(previous);
  if (!visited) {
    visited = new WeakSet();
    diffBudget.seen.set(previous, visited);
  }
  if (visited.has(next)) return false;
  visited.add(next);
  return true;
}

function withinDiffBudget(path, breaks) {
  if (diffBudget.exceeded) return false;
  if (++diffBudget.nodes > MAX_NODES) {
    diffBudget.exceeded = true;
    breaks.push(
      `${path}: schema exceeds the traversal budget; compatibility cannot be ` +
        `established (manual review)`
    );
    return false;
  }
  return true;
}

function diffNode(path, previous, next, breaks) {
  if (!withinDiffBudget(path, breaks)) return;
  if (!firstVisit(previous, next)) return;
  // `{}` and `true` both accept every instance, so treat them as one form.
  // Otherwise `true` -> `{}` reports a tightening while `{}` -> `true` is
  // silent, which is asymmetric for two equivalent schemas.
  if (isUnconstrained(previous)) previous = true;
  if (isUnconstrained(next)) next = true;

  if (previous === false || next === true) return;
  if (previous === true && next !== true) {
    breaks.push(
      `${path}: unconstrained schema became constrained` +
        constrainingKeywords(next)
    );
    return;
  }
  if (next === false && previous !== false) {
    breaks.push(`${path}: schema now rejects every value`);
    return;
  }

  // An unresolved reference names a target the comparison never saw, so it can
  // never establish compatibility -- not even when both sides carry the same
  // reference, since identical text says nothing about identical content. A
  // recursive reference is different: it marks a cycle the walk already entered,
  // so the subtree *was* inspected and equal markers really do mean equal
  // structure.
  const unresolved =
    unresolvedSentinel(previous) || unresolvedSentinel(next);
  if (unresolved) {
    breaks.push(
      `${path}: reference ${unresolved} could not be resolved, so compatibility ` +
        `cannot be established (manual review)`
    );
    return;
  }
  const sentinel = refSentinel(previous) || refSentinel(next);
  if (sentinel) {
    if (!sameValue(previous, next)) {
      breaks.push(
        `${path}: recursive reference ${sentinel} changed (manual review)`
      );
    }
    return;
  }

  // A reference carrying assertion siblings is held as an internal composition
  // marker. Compare its two halves directly: routing it through the
  // unrecognised-keyword path would both lose the structure and leak the
  // marker's name into user-facing output.
  const previousComposed = has(previous, REF_SIBLINGS);
  const nextComposed = has(next, REF_SIBLINGS);
  if (previousComposed || nextComposed) {
    if (previousComposed && nextComposed) {
      diffNode(path, previous[REF_SIBLINGS][0], next[REF_SIBLINGS][0], breaks);
      diffNode(path, previous[REF_SIBLINGS][1], next[REF_SIBLINGS][1], breaks);
    } else {
      breaks.push(
        `${path}: keywords alongside a reference were ` +
          `${nextComposed ? "added" : "removed"} (manual review)`
      );
    }
    return;
  }

  if (Array.isArray(previous) || Array.isArray(next)) {
    if (!sameValue(previous, next)) {
      breaks.push(`${path}: tuple schema changed (manual review)`);
    }
    return;
  }
  if (
    !previous ||
    !next ||
    typeof previous !== "object" ||
    typeof next !== "object"
  ) {
    if (!sameValue(previous, next)) {
      breaks.push(`${path}: schema value changed (manual review)`);
    }
    return;
  }

  const previousAdditional = previous.additionalProperties;
  const nextAdditional = next.additionalProperties;
  if (
    (previousAdditional === true &&
      nextAdditional !== true &&
      nextAdditional !== undefined) ||
    (previousAdditional &&
      typeof previousAdditional === "object" &&
      nextAdditional === false)
  ) {
    breaks.push(`${path}: additionalProperties was tightened`);
  } else if (
    previousAdditional &&
    nextAdditional &&
    typeof previousAdditional === "object" &&
    typeof nextAdditional === "object"
  ) {
    diffNode(
      `${path}.*`,
      previousAdditional,
      nextAdditional,
      breaks
    );
  }

  // `additionalItems` only has effect alongside tuple-form `items`; with a
  // single-schema `items` the keyword is ignored, so a change to it cannot
  // reject anything and must not be reported as a tightening. Each side's
  // effective value is decided by that side's own `items` form -- reading the
  // form from either side would make the keyword look active on a side where
  // it is inert.
  const previousAdditionalItems = Array.isArray(previous.items)
    ? previous.additionalItems
    : undefined;
  const nextAdditionalItems = Array.isArray(next.items)
    ? next.additionalItems
    : undefined;
  if (
    (previousAdditionalItems === true ||
      previousAdditionalItems === undefined) &&
    nextAdditionalItems !== true &&
    nextAdditionalItems !== undefined
  ) {
    breaks.push(`${path}: additionalItems was tightened`);
  } else if (
    previousAdditionalItems &&
    nextAdditionalItems &&
    typeof previousAdditionalItems === "object" &&
    typeof nextAdditionalItems === "object"
  ) {
    diffNode(
      `${path}.additionalItems`,
      previousAdditionalItems,
      nextAdditionalItems,
      breaks
    );
  } else if (
    previousAdditionalItems &&
    typeof previousAdditionalItems === "object" &&
    nextAdditionalItems === false
  ) {
    breaks.push(`${path}: additionalItems was tightened`);
  }

  const previousProperties = previous.properties || {};
  const nextProperties = next.properties || {};
  // Sort before descending. Normalised `$ref` targets are identity-shared and
  // `firstVisit` reports a shared subschema at the first path that reaches it,
  // so insertion order would otherwise decide whether a finding reads `$.a` or
  // `$.b` for two properties referencing the same changed definition.
  for (const key of Object.keys(previousProperties).sort()) {
    const previousProperty = previousProperties[key];
    if (has(nextProperties, key)) {
      diffNode(
        `${path}.${key}`,
        previousProperty,
        nextProperties[key],
        breaks
      );
    } else if (nextAdditional === false) {
      breaks.push(`${path}.${key}: property removed from a closed object`);
    } else if (nextAdditional && typeof nextAdditional === "object") {
      diffNode(`${path}.${key}`, previousProperty, nextAdditional, breaks);
    }
  }
  for (const key of Object.keys(nextProperties).sort()) {
    const nextProperty = nextProperties[key];
    if (has(previousProperties, key)) continue;
    if (
      nextProperty !== true &&
      patternPropertiesMayApply(previous.patternProperties, key)
    ) {
      breaks.push(
        `${path}.${key}: optional property overlaps previous patternProperties ` +
          `(manual review)`
      );
      continue;
    }
    if (previousAdditional === false) continue;
    if (previousAdditional === true || previousAdditional === undefined) {
      if (nextProperty !== true) {
        breaks.push(
          `${path}.${key}: optional property now constrains a previously arbitrary value`
        );
      }
    } else if (
      previousAdditional &&
      typeof previousAdditional === "object"
    ) {
      diffNode(`${path}.${key}`, previousAdditional, nextProperty, breaks);
    }
  }

  const previousRequired = new Set(previous.required || []);
  for (const required of next.required || []) {
    if (!previousRequired.has(required)) {
      breaks.push(`${path}: new required property "${required}"`);
    }
  }

  if (Array.isArray(next.enum)) {
    if (!Array.isArray(previous.enum)) {
      breaks.push(`${path}: enum constraint was added`);
    } else {
      const nextValues = new Set(next.enum.map(canonicalJson));
      for (const value of previous.enum) {
        if (!nextValues.has(canonicalJson(value))) {
          breaks.push(`${path}: enum value ${JSON.stringify(value)} removed`);
        }
      }
    }
  }

  const previousTypes = Array.isArray(previous.type)
    ? previous.type
    : previous.type
      ? [previous.type]
      : null;
  const nextTypes = Array.isArray(next.type)
    ? next.type
    : next.type
      ? [next.type]
      : null;
  if (nextTypes && !previousTypes) {
    breaks.push(`${path}: type constraint was added`);
  } else if (previousTypes && nextTypes) {
    const nextSet = new Set(nextTypes);
    for (const type of previousTypes) {
      // `integer` instances are a subset of `number`, so a next-side `number`
      // still accepts every instance a previous-side `integer` did. The
      // converse is a genuine narrowing and is still reported.
      const stillAccepted =
        nextSet.has(type) || (type === "integer" && nextSet.has("number"));
      if (!stillAccepted) {
        breaks.push(`${path}: type "${type}" no longer accepted`);
      }
    }
  }

  if (
    has(next, "const") &&
    (!has(previous, "const") || !sameValue(previous.const, next.const))
  ) {
    breaks.push(`${path}: const was added or changed`);
  }

  compareBounds(path, previous, next, breaks);
  for (const key of ["minLength", "minItems", "minProperties"]) {
    compareMinimum(path, key, previous, next, breaks);
  }
  for (const key of ["maxLength", "maxItems", "maxProperties"]) {
    compareMaximum(path, key, previous, next, breaks);
  }
  for (const key of ["multipleOf", "pattern", "format"]) {
    compareAddedOrChanged(path, key, previous, next, breaks);
  }
  if (next.uniqueItems === true && previous.uniqueItems !== true) {
    breaks.push(`${path}: uniqueItems was enabled`);
  }

  compareContains(path, previous, next, breaks);
  for (const key of ["items", "propertyNames"]) {
    if (!has(previous, key) && has(next, key)) {
      // An assertion-free subschema rejects nothing, so adding `items: true`
      // or `propertyNames: true` leaves the accepted set unchanged.
      const assertionFree =
        next[key] === true || isUnconstrained(next[key]);
      if (assertionFree) continue;
      breaks.push(`${path}: "${key}" constraint was added`);
    } else if (has(previous, key) && has(next, key)) {
      diffNode(`${path}.${key}`, previous[key], next[key], breaks);
    }
  }
  if (!sameValue(previous.prefixItems, next.prefixItems)) {
    compareSchemaMap(path, "prefixItems", previous, next, breaks);
  }
  for (const key of [
    "patternProperties",
    "dependentRequired",
    "dependentSchemas",
    "dependencies",
  ]) {
    if (!sameValue(previous[key], next[key])) {
      compareSchemaMap(path, key, previous, next, breaks);
    }
  }

  for (const key of ["allOf", "oneOf", "anyOf"]) {
    const previousBranches = Array.isArray(previous[key])
      ? previous[key]
      : null;
    const nextBranches = Array.isArray(next[key]) ? next[key] : null;
    if (!previousBranches && !nextBranches) continue;
    if (!previousBranches || !nextBranches) {
      breaks.push(
        `${path}: "${key}" was ${previousBranches ? "removed" : "added"} (manual review)`
      );
      continue;
    }

    // Match branches by structural digest through a map rather than scanning
    // the remaining list for each branch, which is quadratic in the branch
    // count and measurably slow on large unions. The digest only buckets
    // candidates; `sameValue` still confirms the match exactly.
    const nextByDigest = new Map();
    for (const branch of nextBranches) {
      const digest = structuralDigest(branch);
      const bucket = nextByDigest.get(digest);
      if (bucket) bucket.push(branch);
      else nextByDigest.set(digest, [branch]);
    }
    const previousRemaining = [];
    for (const branch of previousBranches) {
      const bucket = nextByDigest.get(structuralDigest(branch));
      const index = bucket
        ? bucket.findIndex((candidate) => sameValue(candidate, branch))
        : -1;
      if (index >= 0) bucket.splice(index, 1);
      else previousRemaining.push(branch);
    }
    const nextRemaining = [];
    for (const bucket of nextByDigest.values()) nextRemaining.push(...bucket);

    if (
      key === "oneOf" &&
      (previousRemaining.length > 0 || nextRemaining.length > 0)
    ) {
      breaks.push(
        `${path}: oneOf branches changed; exactly-one compatibility requires manual proof`
      );
      continue;
    }

    if (key === "allOf" && nextRemaining.length > previousRemaining.length) {
      breaks.push(
        `${path}: allOf added ${nextRemaining.length - previousRemaining.length} constraint(s) (tighter)`
      );
    }
    // Descend into unmatched branches only for the exact `[T, null]` nullable
    // idiom: two branches a side, one of them the null branch, which matches
    // its counterpart exactly and leaves a single possible correspondence for
    // the other. That is the shape the generator emits for every optional
    // field, and descending is what surfaces a property removed from inside
    // `T`.
    //
    // Nothing weaker is sound. One unmatched branch a side does not by itself
    // prove those branches correspond, because a branch that *did* match may
    // already cover the removed one: `[string, const "x"]` becoming
    // `[string, number]` is a pure widening, since `"x"` is still accepted by
    // the unchanged string branch. Pairing the leftovers there would report a
    // restriction that does not exist. Proving coverage in general is
    // subschema containment, which this detector does not attempt, so every
    // other shape is reported as needing manual proof.
    const nullableIdiom =
      previousBranches.length === 2 &&
      nextBranches.length === 2 &&
      previousBranches.some(isNullBranch) &&
      nextBranches.some(isNullBranch);
    const forcedPairing =
      nullableIdiom &&
      previousRemaining.length === 1 &&
      nextRemaining.length === 1;
    // Proof is only needed when a previously accepted branch is gone. If every
    // old branch still matches exactly, adding branches is provably a widening:
    // `anyOf` accepts an instance matching any branch, so an instance that
    // matched before still matches the same branch now.
    if (
      key === "anyOf" &&
      !forcedPairing &&
      previousRemaining.length > 0
    ) {
      breaks.push(
        `${path}: anyOf branches changed (${previousRemaining.length} removed, ` +
          `${nextRemaining.length} added); whether the new branches still accept ` +
          `every previously accepted value requires manual proof`
      );
      continue;
    }
    const common = Math.min(
      previousRemaining.length,
      nextRemaining.length
    );
    for (let index = 0; index < common; index++) {
      diffNode(
        `${path}.${key}[~${index}]`,
        previousRemaining[index],
        nextRemaining[index],
        breaks
      );
    }
  }

  for (const key of ["if", "then", "else", "not"]) {
    if (!sameValue(previous[key], next[key])) {
      breaks.push(`${path}: "${key}" changed (manual review)`);
    }
  }

  const keys = new Set([...Object.keys(previous), ...Object.keys(next)]);
  for (const key of keys) {
    if (HANDLED_KEYS.has(key)) continue;
    if (!sameValue(previous[key], next[key])) {
      breaks.push(
        `${path}: unrecognized schema keyword "${key}" changed (manual review)`
      );
    }
  }
}

function detectBreaking(previousSchema, nextSchema) {
  const breaks = [];
  resetCaches();
  diffBudget.nodes = 0;
  diffBudget.exceeded = false;
  diffBudget.seen = new WeakMap();
  try {
    const previous = normalize(previousSchema, previousSchema);
    const next = normalize(nextSchema, nextSchema);
    diffNode("$", previous, next, breaks);
  } catch (error) {
    if (error instanceof BudgetExceeded) {
      // Fail closed: a schema we cannot fully expand, or fully compare, is one
      // we cannot clear. This covers deeply nested enum *data* as well as the
      // schema graph, so no committed document can crash the gate instead of
      // failing it.
      return [
        `$: schema exceeds the traversal budget (${error.message}); ` +
          `compatibility cannot be established (manual review)`,
      ];
    }
    if (error instanceof RangeError) {
      // Belt and braces for the same contract: whatever the budgets did not
      // catch, a stack exhaustion still has to read as a finding rather than
      // as a crashed gate.
      return [
        `$: schema nesting exhausted the comparison stack; compatibility ` +
          `cannot be established (manual review)`,
      ];
    }
    throw error;
  }
  // Sort so output does not depend on the source documents' key order.
  return [...new Set(breaks)].sort();
}

module.exports = { detectBreaking };
