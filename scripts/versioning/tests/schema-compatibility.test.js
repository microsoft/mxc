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

test("const and a single-element enum are treated as equivalent", () => {
  const previous = { properties: { mode: { enum: ["block"], type: "string" } } };
  const next = { properties: { mode: { const: "block", type: "string" } } };
  assert.deepEqual(detectBreaking(previous, next), []);
  assert.deepEqual(detectBreaking(next, previous), []);
});

test("a oneOf of const branches matches a oneOf of singleton enums", () => {
  const previous = {
    properties: {
      mode: {
        oneOf: [
          { enum: ["block"], type: "string" },
          { enum: ["allow"], type: "string" },
        ],
      },
    },
  };
  const next = {
    properties: {
      mode: {
        oneOf: [
          { const: "block", type: "string" },
          { const: "allow", type: "string" },
        ],
      },
    },
  };
  assert.deepEqual(detectBreaking(previous, next), []);
});

test("a genuinely removed const branch is still detected", () => {
  const previous = {
    properties: {
      mode: {
        oneOf: [
          { const: "block", type: "string" },
          { const: "allow", type: "string" },
        ],
      },
    },
  };
  const next = {
    properties: { mode: { oneOf: [{ const: "block", type: "string" }] } },
  };
  assert.ok(detectBreaking(previous, next).length > 0);
});

// -- Reference handling -------------------------------------------------------

test("keywords beside a $ref are not dropped", () => {
  const base = { definitions: { T: { type: "object" } } };
  const breaks = detectBreaking(
    { ...base, properties: { a: { $ref: "#/definitions/T" } } },
    {
      ...base,
      properties: {
        a: { $ref: "#/definitions/T", additionalProperties: false },
      },
    }
  );
  assert.ok(breaks.length > 0, breaks.join("\n"));
});

test("an unresolvable $ref is reported rather than compared as equal", () => {
  const breaks = detectBreaking(
    { properties: { a: { $ref: "#/definitions/Missing" } } },
    { properties: { a: { $ref: "#/definitions/Gone" } } }
  );
  assert.ok(
    breaks.some((entry) => entry.includes("could not be resolved")),
    breaks.join("\n")
  );
});

test("internal reference sentinels never leak into a report", () => {
  const recursive = {
    definitions: { T: { properties: { next: { $ref: "#/definitions/T" } } } },
    properties: { a: { $ref: "#/definitions/T" } },
  };
  for (const entry of detectBreaking(recursive, recursive)) {
    assert.ok(!entry.includes("$recursiveRef"), entry);
    assert.ok(!entry.includes("$unresolvedRef"), entry);
  }
});

// -- Equivalent spellings -----------------------------------------------------

test("{} and true are the same schema in both directions", () => {
  assert.deepEqual(detectBreaking({ properties: { a: {} } }, { properties: { a: true } }), []);
  assert.deepEqual(detectBreaking({ properties: { a: true } }, { properties: { a: {} } }), []);
});

test("draft-04 boolean exclusiveMinimum is understood", () => {
  const breaks = detectBreaking(
    { properties: { a: { type: "number", minimum: 1 } } },
    { properties: { a: { type: "number", minimum: 1, exclusiveMinimum: true } } }
  );
  assert.ok(
    breaks.some((entry) => entry.includes("lower bound was tightened")),
    breaks.join("\n")
  );
});

test("draft-04 boolean exclusiveMaximum is understood", () => {
  const breaks = detectBreaking(
    { properties: { a: { type: "number", maximum: 9 } } },
    { properties: { a: { type: "number", maximum: 9, exclusiveMaximum: true } } }
  );
  assert.ok(
    breaks.some((entry) => entry.includes("upper bound was tightened")),
    breaks.join("\n")
  );
});

test("x-mxc-since and x-mxc-until are annotations, not constraints", () => {
  assert.deepEqual(
    detectBreaking(
      { properties: { a: { type: "string" } } },
      {
        properties: {
          a: { type: "string", "x-mxc-since": "0.7.0", "x-mxc-until": "0.9.0" },
        },
      }
    ),
    []
  );
});

// -- Traversal budgets --------------------------------------------------------

const fanOut = (depth) => {
  const definitions = {};
  for (let level = 0; level < depth; level += 1) {
    definitions[`L${level}`] =
      level === 0
        ? { type: "string" }
        : {
            allOf: [
              { $ref: `#/definitions/L${level - 1}` },
              { $ref: `#/definitions/L${level - 1}` },
            ],
          };
  }
  return {
    definitions,
    properties: { root: { $ref: `#/definitions/L${depth - 1}` } },
  };
};

test("a $ref graph that fans out exponentially still completes", () => {
  const schema = fanOut(40);
  const started = Date.now();
  assert.deepEqual(detectBreaking(schema, schema), []);
  assert.ok(Date.now() - started < 5000, "fan-out comparison took too long");
});

test("nesting past the depth budget fails closed with a finding", () => {
  let deep = { type: "string" };
  for (let level = 0; level < 5000; level += 1) {
    deep = { properties: { next: deep } };
  }
  const breaks = detectBreaking({ properties: { a: {} } }, { properties: { a: deep } });
  assert.ok(
    breaks.some((entry) => entry.includes("traversal budget")),
    breaks.join("\n")
  );
});

test("findings are ordered deterministically", () => {
  const previous = { properties: { b: {}, a: {}, c: {} } };
  const next = {
    properties: {
      b: { type: "string" },
      a: { type: "number" },
      c: { type: "boolean" },
    },
  };
  const breaks = detectBreaking(previous, next);
  assert.deepEqual(breaks, [...breaks].sort());
});

test("enum values compare by canonical form, not key insertion order", () => {
  assert.deepEqual(
    detectBreaking(
      { properties: { a: { enum: [{ x: 1, y: 2 }] } } },
      { properties: { a: { enum: [{ y: 2, x: 1 }] } } }
    ),
    []
  );
});

test("a property named like an Object.prototype member is still compared", () => {
  const breaks = detectBreaking(
    { type: "object", properties: { constructor: {} } },
    { type: "object", properties: {}, additionalProperties: false }
  );
  assert.ok(
    breaks.some((entry) => entry.includes("constructor")),
    breaks.join("\n")
  );
});

// -- Round-1 review regressions -----------------------------------------------

test("deeply nested enum data fails closed instead of overflowing the stack", () => {
  let deep = { leaf: true };
  for (let level = 0; level < 5000; level += 1) deep = { next: deep };
  const breaks = detectBreaking(
    { properties: { a: { enum: [deep] } } },
    { properties: { a: { enum: [{ other: 1 }] } } }
  );
  assert.ok(
    breaks.some((entry) => entry.includes("traversal budget")),
    breaks.join("\n")
  );
});

test("a large equivalent combinator union matches without quadratic cost", () => {
  const branches = Array.from({ length: 4000 }, (_, i) => ({
    type: "string",
    enum: [`v${i}`],
  }));
  const previous = { properties: { a: { anyOf: branches } } };
  const next = { properties: { a: { anyOf: [...branches].reverse() } } };
  const started = Date.now();
  assert.deepEqual(detectBreaking(previous, next), []);
  assert.ok(Date.now() - started < 2000, "branch matching took too long");
});

test("an identical unresolved reference on both sides is still reported", () => {
  // Matching reference text says nothing about matching targets: neither side
  // was ever inspected, so compatibility cannot be established.
  const schema = { properties: { a: { $ref: "https://example.com/x.json" } } };
  assert.ok(
    detectBreaking(schema, schema).some((entry) =>
      entry.includes("could not be resolved")
    )
  );
  const dangling = { properties: { a: { $ref: "#/definitions/Missing" } } };
  assert.ok(
    detectBreaking(dangling, dangling).some((entry) =>
      entry.includes("could not be resolved")
    )
  );
});

test("an unchanged recursive reference is not reported", () => {
  // A recursion marker means the walk already entered that subtree, so equal
  // markers really do mean equal structure -- unlike an unresolved reference.
  const recursive = {
    definitions: { T: { properties: { next: { $ref: "#/definitions/T" } } } },
    properties: { a: { $ref: "#/definitions/T" } },
  };
  assert.deepEqual(detectBreaking(recursive, recursive), []);
});

test("constraining a prototype-named property on an open object is detected", () => {
  for (const name of ["constructor", "toString", "valueOf", "__proto__"]) {
    const breaks = detectBreaking(
      { properties: { a: { type: "object", properties: {} } } },
      { properties: { a: { type: "object", properties: { [name]: { type: "string" } } } } }
    );
    assert.ok(breaks.length > 0, `${name} was skipped: ${breaks.join("\n")}`);
  }
});

test("additionalItems is ignored unless items is in tuple form", () => {
  assert.deepEqual(
    detectBreaking(
      { type: "array", items: { type: "string" }, additionalItems: true },
      { type: "array", items: { type: "string" }, additionalItems: false }
    ),
    []
  );
  assert.ok(
    detectBreaking(
      { type: "array", items: [{ type: "string" }], additionalItems: true },
      { type: "array", items: [{ type: "string" }], additionalItems: false }
    ).length > 0
  );
});

test("an anyOf replacement is reported as needing proof, not as a removal", () => {
  // Two singleton-enum branches becoming one general `string` branch accepts
  // strictly more, so claiming shapes were removed would be wrong.
  const breaks = detectBreaking(
    { properties: { a: { anyOf: [{ const: "x" }, { const: "y" }] } } },
    { properties: { a: { anyOf: [{ type: "string" }] } } }
  );
  assert.equal(breaks.length, 1, breaks.join("\n"));
  assert.ok(breaks[0].includes("requires manual proof"), breaks[0]);
  assert.ok(!breaks[0].includes("removed 1 accepted"), breaks[0]);
});

test("a modified branch inside a nullable wrapper is still descended into", () => {
  // `anyOf: [T, null]` is the pervasive nullable idiom. The null branches match
  // exactly, leaving one unmatched branch on each side -- equal counts, so they
  // correspond and a property removed inside T must still be reported. Routing
  // this to manual review instead would blind the gate to real removals.
  const wrap = (properties) => ({
    properties: {
      section: {
        anyOf: [
          { type: "object", additionalProperties: false, properties },
          { type: "null" },
        ],
      },
    },
  });
  const breaks = detectBreaking(
    wrap({ keep: { type: "string" }, doomed: { type: "string" } }),
    wrap({ keep: { type: "string" } })
  );
  assert.ok(
    breaks.some((entry) => entry.includes("doomed")),
    breaks.join("\n")
  );
});

test("an equal-count anyOf replacement is not paired by position", () => {
  // Two unmatched branches on each side admit two possible pairings, so there
  // is no basis to choose one. Both singleton enums becoming general `string`
  // branches is a pure relaxation; positional pairing reported it as two added
  // type constraints.
  const breaks = detectBreaking(
    { properties: { a: { anyOf: [{ const: "x" }, { const: "y" }] } } },
    { properties: { a: { anyOf: [{ type: "string" }, { type: "string" }] } } }
  );
  assert.equal(breaks.length, 1, breaks.join("\n"));
  assert.ok(breaks[0].includes("requires manual proof"), breaks[0]);
  assert.ok(!breaks[0].includes("type constraint was added"), breaks[0]);
});

test("annotations beside a reference are not a structural change", () => {
  // No dialect applies annotation siblings, so a description added next to a
  // `$ref` cannot reject anything.
  const withRef = (extra) => ({
    definitions: { T: { type: "string" } },
    properties: { a: { $ref: "#/definitions/T", ...extra } },
  });
  assert.deepEqual(
    detectBreaking(withRef({}), withRef({ description: "doc", "x-mxc-since": "0.8.0" })),
    []
  );
});

test("assertion siblings beside a reference are reported without leaking the marker", () => {
  // Draft 2019-09 applies these; draft-07 ignores them. Composing is the
  // conservative reading -- it can only ask for a review a draft-07 document
  // did not need, never miss a restriction. The internal composition marker
  // must not appear in the report.
  const withRef = (extra) => ({
    definitions: { T: { type: "object" } },
    properties: { a: { $ref: "#/definitions/T", ...extra } },
  });
  const breaks = detectBreaking(withRef({}), withRef({ required: ["x"] }));
  assert.equal(breaks.length, 1, breaks.join("\n"));
  assert.ok(breaks[0].includes("keywords alongside a reference"), breaks[0]);
  assert.ok(!breaks.join("\n").includes("$refWithSiblings"), breaks[0]);
});

test("an empty schema and true are equivalent in every position", () => {
  // `{}` accepts every instance, exactly like `true`. Canonicalising only at
  // the point a diff walk enters a node left nested uses -- an
  // `additionalProperties` value, or a newly added optional property -- reading
  // as tightenings.
  assert.deepEqual(
    detectBreaking(
      { type: "object", additionalProperties: true },
      { type: "object", additionalProperties: {} }
    ),
    []
  );
  assert.deepEqual(
    detectBreaking(
      { type: "object", properties: {} },
      { type: "object", properties: { added: {} } }
    ),
    []
  );
  assert.deepEqual(
    detectBreaking(
      { type: "object", properties: {} },
      { type: "object", properties: { added: { description: "annotation only" } } }
    ),
    []
  );
});

test("additionalItems effectiveness is read from each side's own items form", () => {
  // The keyword is inert beside a single-schema `items`, so a side using that
  // form has no effective value to tighten -- regardless of the other side's
  // form.
  const breaks = detectBreaking(
    { type: "array", items: [{ type: "string" }], additionalItems: true },
    { type: "array", items: { type: "string" }, additionalItems: false }
  );
  assert.ok(
    !breaks.some((entry) => entry.includes("additionalItems")),
    breaks.join("\n")
  );
});

test("anyOf descent is limited to the [T, null] idiom", () => {
  // One unmatched branch a side does not prove correspondence: a branch that
  // matched may already cover the removed one. Here `"x"` is still accepted by
  // the unchanged string branch, so the change is a pure widening.
  const breaks = detectBreaking(
    { anyOf: [{ type: "string" }, { const: "x" }] },
    { anyOf: [{ type: "string" }, { type: "number" }] }
  );
  assert.equal(breaks.length, 1, breaks.join("\n"));
  assert.ok(breaks[0].includes("requires manual proof"), breaks[0]);
  assert.ok(!breaks[0].includes("type constraint was added"), breaks[0]);
});

test("integer is widened by number but not the reverse", () => {
  // `integer` instances are a subset of `number`.
  assert.deepEqual(detectBreaking({ type: "integer" }, { type: "number" }), []);
  assert.deepEqual(
    detectBreaking({ type: ["integer", "null"] }, { type: ["number", "null"] }),
    []
  );
  assert.ok(
    detectBreaking({ type: "number" }, { type: "integer" }).some((entry) =>
      entry.includes('type "number" no longer accepted')
    )
  );
});

test("assertion-free applicators are not added constraints, except contains", () => {
  // `items: true` and `propertyNames: true` reject nothing. `contains: true`
  // still demands at least one element, so it rejects the empty array.
  assert.deepEqual(
    detectBreaking({ type: "array" }, { type: "array", items: true }),
    []
  );
  assert.deepEqual(
    detectBreaking({ type: "object" }, { type: "object", propertyNames: {} }),
    []
  );
  assert.ok(
    detectBreaking({ type: "array" }, { type: "array", contains: true }).some(
      (entry) => entry.includes('"contains" constraint was added')
    )
  );
});

test("a deep unrecognized keyword payload fails closed instead of crashing", () => {
  // Values of unrecognised keywords are copied through normalisation
  // untraversed, so only the equality walk ever descends them. Without a bound
  // there, a deep enough extension value exhausts the stack and the gate
  // crashes rather than reporting.
  const deep = (leaf) => {
    let node = leaf;
    for (let index = 0; index < 20000; index++) node = { nested: node };
    return node;
  };
  for (const [left, right] of [[1, 2], [1, 1]]) {
    const breaks = detectBreaking(
      { type: "object", "x-vendor": deep(left) },
      { type: "object", "x-vendor": deep(right) }
    );
    assert.equal(breaks.length, 1, breaks.join("\n"));
    assert.ok(breaks[0].includes("manual review"), breaks[0]);
  }
});

test("an aborted equality comparison does not poison the cache for later calls", () => {
  // The cache is keyed on node identity, and an unrecognised keyword's payload
  // is the caller's own object rather than a normalised copy, so it is shared
  // across calls. A provisional entry left behind by a budget abort would let a
  // later run clear the very pair that just exhausted the budget.
  const deep = (leaf) => {
    let node = leaf;
    for (let index = 0; index < 6000; index++) node = { nested: node };
    return node;
  };
  const previous = { type: "object", "x-vendor": deep(1) };
  const next = { type: "object", "x-vendor": deep(2) };
  for (let attempt = 0; attempt < 3; attempt++) {
    const breaks = detectBreaking(previous, next);
    assert.equal(breaks.length, 1, `attempt ${attempt}: ${breaks.join("\n")}`);
    assert.ok(breaks[0].includes("manual review"), breaks[0]);
  }
});

test("a schema keyword named __proto__ is compared, not swallowed", () => {
  // JSON.parse makes `__proto__` an own property, but assigning it to a normal
  // accumulator would invoke the inherited setter and drop the keyword.
  const withProto = (value) =>
    JSON.parse(`{"type":"object","__proto__":{"x":${value}}}`);
  const breaks = detectBreaking(withProto(1), withProto(2));
  assert.equal(breaks.length, 1, breaks.join("\n"));
  assert.ok(breaks[0].includes("__proto__"), breaks[0]);
  assert.deepEqual(detectBreaking(withProto(1), withProto(1)), []);
});

test("the reported path does not depend on property insertion order", () => {
  // Normalised `$ref` targets are identity-shared and a shared subschema is
  // reported at the first path that reaches it, so iteration order would
  // otherwise decide whether the finding reads `$.a` or `$.b`.
  const build = (order, properties) => {
    const shared = {};
    for (const key of order) shared[key] = { $ref: "#/definitions/T" };
    return {
      definitions: {
        T: { type: "object", additionalProperties: false, properties },
      },
      properties: shared,
    };
  };
  const before = { keep: { type: "string" }, doomed: { type: "string" } };
  const after = { keep: { type: "string" } };
  assert.deepEqual(
    detectBreaking(build(["a", "b"], before), build(["a", "b"], after)),
    detectBreaking(build(["b", "a"], before), build(["b", "a"], after))
  );
});

test("contains is compared by effective minContains and maxContains", () => {
  const array = (extra) => ({ type: "array", ...extra });
  // Dropping an explicit `minContains: 0` restores the implicit 1, so arrays
  // with no matching element stop being accepted.
  assert.ok(
    detectBreaking(
      array({ contains: true, minContains: 0 }),
      array({ contains: true })
    ).some((entry) => entry.includes("minContains increased to 1"))
  );
  // Adding `contains` beside `minContains: 0` demands nothing.
  assert.deepEqual(
    detectBreaking(array({}), array({ contains: true, minContains: 0 })),
    []
  );
  // Adding it alone still rejects the empty array.
  assert.ok(
    detectBreaking(array({}), array({ contains: true })).some((entry) =>
      entry.includes('"contains" constraint was added')
    )
  );
  // Both keywords are inert without `contains`, and removing `contains`
  // altogether only widens.
  assert.deepEqual(
    detectBreaking(array({ minContains: 1 }), array({ minContains: 9 })),
    []
  );
  assert.deepEqual(
    detectBreaking(
      array({ contains: { type: "string" }, minContains: 2, maxContains: 3 }),
      array({})
    ),
    []
  );
  // A tightened bound or a narrowed subschema is still reported.
  assert.ok(
    detectBreaking(
      array({ contains: true, maxContains: 5 }),
      array({ contains: true, maxContains: 2 })
    ).some((entry) => entry.includes("maxContains decreased to 2"))
  );
  assert.ok(
    detectBreaking(
      array({ contains: { type: ["string", "number"] } }),
      array({ contains: { type: "string" } })
    ).some((entry) => entry.includes('$.contains: type "number"'))
  );
});

test("the equality cache does not outlive a single comparison", () => {
  // Memo entries are keyed on node identity, and an unrecognised keyword's
  // payload keeps the caller's own object identity through normalisation. A
  // cache surviving the call would answer for input the caller has since
  // mutated.
  const payload = { deep: { value: 1 } };
  const previous = { type: "object", "x-vendor": { deep: { value: 1 } } };
  const next = { type: "object", "x-vendor": payload };
  assert.deepEqual(detectBreaking(previous, next), []);
  payload.deep.value = 2;
  const breaks = detectBreaking(previous, next);
  assert.equal(breaks.length, 1, breaks.join("\n"));
  assert.ok(breaks[0].includes("x-vendor"), breaks[0]);
  payload.deep.value = 1;
  assert.deepEqual(detectBreaking(previous, next), []);
});

test("a changed contains under a finite maxContains needs manual proof", () => {
  // The polarity inverts under an upper bound: widening the subschema lets more
  // elements count toward `maxContains`, so `{contains: integer,
  // maxContains: 1}` -> `{contains: number, maxContains: 1}` newly rejects
  // `[1, 1.5]`. A recursive descent would read that widening as safe.
  const breaks = detectBreaking(
    { type: "array", contains: { type: "integer" }, maxContains: 1 },
    { type: "array", contains: { type: "number" }, maxContains: 1 }
  );
  assert.equal(breaks.length, 1, breaks.join("\n"));
  assert.ok(breaks[0].includes("manual proof"), breaks[0]);
  // An unchanged subschema asserts nothing new, and without an upper bound the
  // ordinary polarity holds in both directions.
  assert.deepEqual(
    detectBreaking(
      { type: "array", contains: { type: "integer" }, maxContains: 1 },
      { type: "array", contains: { type: "integer" }, maxContains: 1 }
    ),
    []
  );
  assert.deepEqual(
    detectBreaking(
      { type: "array", contains: { type: "string" } },
      { type: "array", contains: { type: ["string", "number"] } }
    ),
    []
  );
  assert.ok(
    detectBreaking(
      { type: "array", contains: { type: ["string", "number"] } },
      { type: "array", contains: { type: "string" } }
    ).some((entry) => entry.includes('$.contains: type "number"'))
  );
});

test("added anyOf branches are a widening when every old branch still matches", () => {
  // `anyOf` accepts an instance matching any branch, so if no previously
  // accepted branch was removed, an instance that matched before still matches
  // the same branch now.
  assert.deepEqual(
    detectBreaking(
      { anyOf: [{ type: "string" }] },
      { anyOf: [{ type: "string" }, { type: "number" }] }
    ),
    []
  );
  // A removed branch still requires proof.
  const breaks = detectBreaking(
    { anyOf: [{ type: "string" }, { type: "number" }] },
    { anyOf: [{ type: "string" }] }
  );
  assert.equal(breaks.length, 1, breaks.join("\n"));
  assert.ok(breaks[0].includes("requires manual proof"), breaks[0]);
});
