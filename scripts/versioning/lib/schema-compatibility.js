// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

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
]);

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

function canonical(value) {
  if (Array.isArray(value)) return value.map(canonical);
  if (!value || typeof value !== "object") return value;
  return Object.fromEntries(
    Object.keys(value)
      .sort()
      .map((key) => [key, canonical(value[key])])
  );
}

function sameValue(left, right) {
  return JSON.stringify(canonical(left)) === JSON.stringify(canonical(right));
}

function has(node, key) {
  return Object.prototype.hasOwnProperty.call(node, key);
}

function resolveRef(root, ref, seen) {
  if (!ref.startsWith("#/")) return { $unresolvedRef: ref };
  if (seen.has(ref)) return { $recursiveRef: ref };

  let target = root;
  for (const encoded of ref.slice(2).split("/")) {
    const part = encoded.replace(/~1/g, "/").replace(/~0/g, "~");
    if (!target || typeof target !== "object" || !(part in target)) {
      return { $unresolvedRef: ref };
    }
    target = target[part];
  }
  return normalize(root, target, new Set(seen).add(ref));
}

function normalizeMap(root, value, seen) {
  return Object.fromEntries(
    Object.entries(value).map(([key, schema]) => [
      key,
      normalize(root, schema, seen),
    ])
  );
}

function normalize(root, node, seen = new Set()) {
  if (!node || typeof node !== "object") return node;
  if (Array.isArray(node)) {
    return node.map((value) => normalize(root, value, seen));
  }
  if (node.$ref) return resolveRef(root, node.$ref, seen);

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
    new Set(singletonEnumValues.map((value) => JSON.stringify(value))).size ===
      singletonEnumValues.length
  ) {
    return {
      enum: singletonEnumValues
        .sort((left, right) =>
          JSON.stringify(left).localeCompare(JSON.stringify(right))
        ),
    };
  }

  const out = {};
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
      out[key] = normalizeMap(root, value, seen);
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
      out[key] = normalize(root, value, seen);
    } else if (
      (key === "allOf" ||
        key === "oneOf" ||
        key === "anyOf" ||
        key === "prefixItems") &&
      Array.isArray(value)
    ) {
      out[key] = value.map((branch) => normalize(root, branch, seen));
    } else if (key === "type" && Array.isArray(value)) {
      out.type = [...value].sort();
    } else if (key === "enum" && Array.isArray(value)) {
      out.enum = [...value].sort((left, right) =>
        JSON.stringify(left).localeCompare(JSON.stringify(right))
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
            : normalize(root, dependency, seen),
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
  return out;
}

function lowerBound(node) {
  const candidates = [];
  if (typeof node.minimum === "number") {
    candidates.push({ value: node.minimum, inclusive: true });
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
    candidates.push({ value: node.maximum, inclusive: true });
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

function diffNode(path, previous, next, breaks) {
  if (previous === false || next === true) return;
  if (previous === true && next !== true) {
    breaks.push(`${path}: unconstrained schema became constrained`);
    return;
  }
  if (next === false && previous !== false) {
    breaks.push(`${path}: schema now rejects every value`);
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

  const previousAdditionalItems = previous.additionalItems;
  const nextAdditionalItems = next.additionalItems;
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
  for (const [key, previousProperty] of Object.entries(previousProperties)) {
    if (key in nextProperties) {
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
  for (const [key, nextProperty] of Object.entries(nextProperties)) {
    if (key in previousProperties || previousAdditional === false) continue;
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
      const nextValues = new Set(next.enum.map((value) => JSON.stringify(value)));
      for (const value of previous.enum) {
        if (!nextValues.has(JSON.stringify(value))) {
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
      if (!nextSet.has(type)) {
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
  for (const key of [
    "minLength",
    "minItems",
    "minContains",
    "minProperties",
  ]) {
    compareMinimum(path, key, previous, next, breaks);
  }
  for (const key of [
    "maxLength",
    "maxItems",
    "maxContains",
    "maxProperties",
  ]) {
    compareMaximum(path, key, previous, next, breaks);
  }
  for (const key of ["multipleOf", "pattern", "format"]) {
    compareAddedOrChanged(path, key, previous, next, breaks);
  }
  if (next.uniqueItems === true && previous.uniqueItems !== true) {
    breaks.push(`${path}: uniqueItems was enabled`);
  }

  for (const key of ["items", "contains", "propertyNames"]) {
    if (!has(previous, key) && has(next, key)) {
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

    const nextRemaining = [...nextBranches];
    const previousRemaining = [];
    for (const branch of previousBranches) {
      const index = nextRemaining.findIndex((candidate) =>
        sameValue(candidate, branch)
      );
      if (index >= 0) nextRemaining.splice(index, 1);
      else previousRemaining.push(branch);
    }

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
    if (
      key === "anyOf" &&
      previousRemaining.length > nextRemaining.length
    ) {
      breaks.push(
        `${path}: ${key} removed ${previousRemaining.length - nextRemaining.length} accepted shape(s)`
      );
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
  diffNode(
    "$",
    normalize(previousSchema, previousSchema),
    normalize(nextSchema, nextSchema),
    breaks
  );
  return [...new Set(breaks)];
}

module.exports = { detectBreaking };
