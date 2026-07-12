// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

const test = require("node:test");
const assert = require("node:assert/strict");
const { detectBreaking } = require("../lib/schema-compatibility");

const closedObject = (properties, required = []) => ({
  type: "object",
  additionalProperties: false,
  properties,
  required,
});

test("additive optional properties are compatible", () => {
  const previous = closedObject({ value: { type: "string" } });
  const next = closedObject({
    value: { type: "string" },
    extra: { type: "number" },
  });
  assert.deepEqual(detectBreaking(previous, next), []);
});

test("removed properties and enum values are breaking", () => {
  const previous = closedObject({
    value: { enum: ["a", "b"] },
    removed: { type: "string" },
  });
  const next = closedObject({ value: { enum: ["a"] } });
  const breaks = detectBreaking(previous, next);
  assert.ok(breaks.some((entry) => entry.includes("property removed")));
  assert.ok(breaks.some((entry) => entry.includes('enum value "b"')));
});

test("new required properties and narrowed types are breaking", () => {
  const previous = closedObject({
    value: { type: ["string", "number"] },
  });
  const next = closedObject(
    {
      value: { type: "string" },
      requiredValue: { type: "string" },
    },
    ["requiredValue"]
  );
  const breaks = detectBreaking(previous, next);
  assert.ok(breaks.some((entry) => entry.includes("new required property")));
  assert.ok(breaks.some((entry) => entry.includes('type "number"')));
});

test("tightened numeric constraints are breaking while loosened bounds are safe", () => {
  const previous = {
    type: "number",
    minimum: 1,
    maximum: 100,
  };
  const tightened = {
    type: "number",
    minimum: 2,
    maximum: 99,
  };
  const breaks = detectBreaking(previous, tightened);
  assert.ok(breaks.some((entry) => entry.includes("lower bound")));
  assert.ok(breaks.some((entry) => entry.includes("upper bound")));

  assert.deepEqual(
    detectBreaking(previous, {
      type: "number",
      minimum: 0,
      maximum: 101,
    }),
    []
  );
});

test("string and collection constraints fail closed when tightened", () => {
  const previous = {
    type: "array",
    items: { type: "string", minLength: 1 },
    minItems: 1,
    uniqueItems: false,
  };
  const next = {
    type: "array",
    items: { type: "string", minLength: 2, pattern: "^[a-z]+$" },
    minItems: 2,
    uniqueItems: true,
  };
  const breaks = detectBreaking(previous, next);
  assert.ok(breaks.some((entry) => entry.includes("minLength")));
  assert.ok(breaks.some((entry) => entry.includes("pattern")));
  assert.ok(breaks.some((entry) => entry.includes("minItems")));
  assert.ok(breaks.some((entry) => entry.includes("uniqueItems")));
});

test("adding type, enum, const, or null rejection is breaking", () => {
  assert.ok(detectBreaking({}, { type: "string" }).length > 0);
  assert.ok(detectBreaking({}, { enum: ["a"] }).length > 0);
  assert.ok(detectBreaking({}, { const: "a" }).length > 0);
  assert.ok(
    detectBreaking(
      { type: ["null", "string"] },
      { type: "string" }
    ).some((entry) => entry.includes('type "null"'))
  );
});

test("unknown schema keywords fail closed when changed", () => {
  assert.ok(
    detectBreaking(
      { type: "string", futureConstraint: 1 },
      { type: "string", futureConstraint: 2 }
    ).some((entry) => entry.includes("unrecognized schema keyword"))
  );
});

test("an optional property added to an open object may constrain old input", () => {
  const breaks = detectBreaking(
    {
      type: "object",
      additionalProperties: true,
    },
    {
      type: "object",
      additionalProperties: true,
      properties: { value: { type: "string" } },
    }
  );
  assert.ok(
    breaks.some((entry) => entry.includes("previously arbitrary value"))
  );
});

test("closing an unconstrained object is breaking", () => {
  assert.ok(
    detectBreaking({}, { additionalProperties: false }).some((entry) =>
      entry.includes("additionalProperties")
    )
  );
});

test("changed oneOf branches fail closed because overlap can invalidate input", () => {
  const breaks = detectBreaking(
    { oneOf: [{ type: "string" }, { type: "number" }] },
    { oneOf: [{}, { type: "number" }] }
  );
  assert.ok(
    breaks.some((entry) => entry.includes("exactly-one compatibility"))
  );

  assert.ok(
    detectBreaking(
      { oneOf: [{ enum: ["a"] }] },
      { oneOf: [{ enum: ["a"] }, { enum: ["a"] }] }
    ).some((entry) => entry.includes("oneOf"))
  );
});

test("singleton-enum oneOf normalization preserves parent assertions", () => {
  const oneOf = [{ enum: ["a"] }, { enum: ["b"] }];
  assert.ok(
    detectBreaking(
      { oneOf },
      { pattern: "^a$", oneOf }
    ).some((entry) => entry.includes("pattern"))
  );
});

test("draft-07 dependency references are normalized before comparison", () => {
  const previous = {
    definitions: {
      dependency: {
        type: "object",
        properties: { bar: { type: "string" } },
      },
    },
    dependencies: {
      foo: { $ref: "#/definitions/dependency" },
    },
  };
  const next = {
    definitions: {
      dependency: {
        type: "object",
        properties: { bar: { type: "string" } },
        required: ["bar"],
      },
    },
    dependencies: {
      foo: { $ref: "#/definitions/dependency" },
    },
  };
  assert.ok(
    detectBreaking(previous, next).some((entry) =>
      entry.includes("dependencies")
    )
  );
});
