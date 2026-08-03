// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

const test = require("node:test");
const assert = require("node:assert");

const {
  DepthExceeded,
  MAX_DEPTH,
  SINCE_KEY,
  UNDERIVABLE_ROOTS,
  UNTIL_KEY,
  checkAvailability,
  collectDeclaredAvailability,
  collectPropertyPaths,
} = require("../lib/version-availability.js");
const { compareMajorMinor, parseMajorMinor } = require("../lib/version.js");

// --- helpers ---------------------------------------------------------------

function schema(properties, definitions = {}) {
  return { type: "object", properties, definitions };
}

function timelineOf(...schemas) {
  const labels = ["0.6", "0.7", "0.8"];
  return schemas.map((s, i) => ({
    label: labels[i],
    version: parseMajorMinor(labels[i]),
    paths: collectPropertyPaths(s),
  }));
}

function run(devSchema, timeline) {
  return checkAvailability({
    declared: collectDeclaredAvailability(devSchema),
    timeline,
    compareMajorMinor,
  });
}

// --- collectPropertyPaths --------------------------------------------------

test("collectPropertyPaths walks nested objects into dotted paths", () => {
  const s = schema(
    { network: { $ref: "#/definitions/Network" } },
    { Network: { type: "object", properties: { defaultPolicy: { type: "string" } } } }
  );
  const paths = collectPropertyPaths(s);
  assert.ok(paths.has("network"));
  assert.ok(paths.has("network.defaultPolicy"));
});

test("collectPropertyPaths adds no segment for array nesting", () => {
  // A range on an element field is keyed the same as one on a directly nested
  // struct, matching how the wire model lists paths.
  const s = schema(
    { wslc: { $ref: "#/definitions/Wslc" } },
    {
      Wslc: {
        type: "object",
        properties: { portMappings: { type: "array", items: { $ref: "#/definitions/Port" } } },
      },
      Port: { type: "object", properties: { protocol: { type: "string" } } },
    }
  );
  const paths = collectPropertyPaths(s);
  assert.ok(paths.has("wslc.portMappings"));
  assert.ok(paths.has("wslc.portMappings.protocol"));
  assert.ok(!paths.has("wslc.portMappings[].protocol"));
});

test("collectPropertyPaths follows anyOf branches (the Option<T> shape)", () => {
  const s = schema(
    { seatbelt: { anyOf: [{ $ref: "#/definitions/Seatbelt" }, { type: "null" }] } },
    { Seatbelt: { type: "object", properties: { guiAccess: { type: "boolean" } } } }
  );
  const paths = collectPropertyPaths(s);
  assert.ok(paths.has("seatbelt.guiAccess"));
});

test("collectPropertyPaths terminates on a self-referential schema", () => {
  const s = schema(
    { node: { $ref: "#/definitions/Node" } },
    {
      Node: {
        type: "object",
        properties: { child: { $ref: "#/definitions/Node" }, name: { type: "string" } },
      },
    }
  );
  const paths = collectPropertyPaths(s);
  assert.ok(paths.has("node.name"));
});

test("collectPropertyPaths ignores an unresolvable $ref", () => {
  const s = schema({ a: { $ref: "#/definitions/Missing" } });
  assert.ok(collectPropertyPaths(s).has("a"));
});

// --- collectDeclaredAvailability ------------------------------------------------

test("collectDeclaredAvailability records every path a shared type is reachable from", () => {
  const s = schema(
    {
      seatbelt: { $ref: "#/definitions/Seatbelt" },
      experimental: { $ref: "#/definitions/Experimental" },
    },
    {
      Seatbelt: {
        type: "object",
        properties: { guiAccess: { type: "boolean", [SINCE_KEY]: "0.7" } },
      },
      Experimental: {
        type: "object",
        properties: { seatbelt: { $ref: "#/definitions/Seatbelt" } },
      },
    }
  );
  const declared = collectDeclaredAvailability(s);
  assert.strictEqual(declared.length, 1);
  assert.deepStrictEqual(declared[0].paths.sort(), [
    "experimental.seatbelt.guiAccess",
    "seatbelt.guiAccess",
  ]);
});

test("collectDeclaredAvailability ignores unannotated properties", () => {
  const s = schema({ a: { type: "string" }, b: { type: "string", [SINCE_KEY]: "0.7" } });
  const declared = collectDeclaredAvailability(s);
  assert.deepStrictEqual(
    declared.map((d) => d.property),
    ["b"]
  );
});

// --- since -----------------------------------------------------------------

test("a since that matches the derived first appearance passes", () => {
  const v06 = schema({ old: { type: "string" } });
  const v07 = schema({ old: { type: "string" }, seatbelt: { type: "string" } });
  const dev = schema({
    old: { type: "string" },
    seatbelt: { type: "string", [SINCE_KEY]: "0.7" },
  });
  const { errors, checked } = run(dev, timelineOf(v06, v07, dev));
  assert.deepStrictEqual(errors, []);
  assert.strictEqual(checked, 1);
});

test("a since that disagrees with the derived first appearance fails", () => {
  const v06 = schema({ seatbelt: { type: "string" } });
  const v07 = schema({ seatbelt: { type: "string" } });
  const dev = schema({ seatbelt: { type: "string", [SINCE_KEY]: "0.7" } });
  const { errors } = run(dev, timelineOf(v06, v07, dev));
  assert.strictEqual(errors.length, 1);
  assert.match(errors[0], /first appears in the 0\.6 schema/);
});

test("a since on a field absent from every schema fails", () => {
  const v06 = schema({});
  const v07 = schema({});
  const dev = schema({ ghost: { type: "string", [SINCE_KEY]: "0.7" } });
  // Deliberately hand the gate a timeline whose dev entry lacks the field, to
  // model a schema that advertises a range for something unreachable.
  const timeline = timelineOf(v06, v07, schema({}));
  const { errors } = run(dev, timeline);
  assert.strictEqual(errors.length, 1);
  assert.match(errors[0], /appears in none of the/);
});

test("a nested since is checked at its full path", () => {
  const bare = schema(
    { processContainer: { $ref: "#/definitions/PC" } },
    { PC: { type: "object", properties: { leastPrivilege: { type: "boolean" } } } }
  );
  const dev = schema(
    { processContainer: { $ref: "#/definitions/PC" } },
    {
      PC: {
        type: "object",
        properties: {
          leastPrivilege: { type: "boolean" },
          captureDenials: { type: "object", [SINCE_KEY]: "0.8" },
        },
      },
    }
  );
  const { errors } = run(dev, timelineOf(bare, bare, dev));
  assert.deepStrictEqual(errors, []);
});

// --- fail-closed on the open experimental block ----------------------------

test(`an availability range under 'experimental' is refused rather than silently skipped`, () => {
  const dev = schema(
    { experimental: { $ref: "#/definitions/Exp" } },
    { Exp: { type: "object", properties: { wslc: { type: "object", [SINCE_KEY]: "0.8" } } } }
  );
  const { errors } = run(dev, timelineOf(schema({}), schema({}), dev));
  assert.strictEqual(errors.length, 1);
  assert.match(errors[0], /validated vacuously/);
});

test("an availability range on a state-aware discriminator is refused", () => {
  // `phase` / `sandboxId` / `correlationVector` are carried by 0.6 state-aware
  // requests but only entered the schema at 0.8, so schema presence would
  // approve `since: 0.8` and reject every lifecycle request ever sent.
  for (const field of ["phase", "sandboxId", "correlationVector"]) {
    const dev = schema({ [field]: { type: "string", [SINCE_KEY]: "0.8" } });
    const { errors } = run(dev, timelineOf(schema({}), schema({}), dev));
    assert.strictEqual(errors.length, 1, `${field}: ${errors.join("; ")}`);
    assert.match(errors[0], /state-aware requests declaring 0\.6/);
  }
});

test("every underivable root carries an explanation", () => {
  assert.ok(UNDERIVABLE_ROOTS.length >= 4);
  for (const root of UNDERIVABLE_ROOTS) {
    assert.ok(typeof root.path === "string" && root.path.length > 0);
    assert.ok(typeof root.why === "string" && root.why.length > 0);
  }
});

test("an availability range on a type shared with the experimental subtree is refused", () => {
  // This is the leak the rule exists for: annotating a field inside a struct
  // reachable from `experimental` would constrain the permissive surface too.
  const dev = schema(
    {
      seatbelt: { $ref: "#/definitions/Seatbelt" },
      experimental: { $ref: "#/definitions/Exp" },
    },
    {
      Seatbelt: {
        type: "object",
        properties: { guiAccess: { type: "boolean", [SINCE_KEY]: "0.7" } },
      },
      Exp: { type: "object", properties: { seatbelt: { $ref: "#/definitions/Seatbelt" } } },
    }
  );
  const { errors } = run(dev, timelineOf(schema({}), schema({}), dev));
  assert.strictEqual(errors.length, 1);
  assert.match(errors[0], /move it to the containing field/);
});

// --- until -----------------------------------------------------------------

test("an until naming a version the field existed in passes", () => {
  const v06 = schema({ defaultPolicy: { type: "string" } });
  const v07 = schema({ defaultPolicy: { type: "string" } });
  // Retired fields deliberately stay in the dev schema: one dev schema has to
  // validate configs declaring every supported version.
  const dev = schema({ defaultPolicy: { type: "string", [UNTIL_KEY]: "0.7" } });
  const { errors, checked } = run(dev, timelineOf(v06, v07, dev));
  assert.deepStrictEqual(errors, []);
  assert.strictEqual(checked, 1);
});

test("an until naming a version the field never existed in fails", () => {
  const v06 = schema({});
  const v07 = schema({});
  const dev = schema({ egress: { type: "string", [UNTIL_KEY]: "0.7" } });
  const { errors } = run(dev, timelineOf(v06, v07, dev));
  assert.strictEqual(errors.length, 1);
  assert.match(errors[0], /does not exist in the 0\.7 schema/);
});

test("an until naming a version outside the timeline fails", () => {
  const dev = schema({ a: { type: "string", [UNTIL_KEY]: "1.4" } });
  const { errors } = run(dev, timelineOf(schema({ a: {} }), schema({ a: {} }), dev));
  assert.strictEqual(errors.length, 1);
  assert.match(errors[0], /not a version this gate has a schema for/);
});

// --- combined / malformed --------------------------------------------------

test("an empty availability range (since newer than until) fails", () => {
  const v = schema({ a: { type: "string" } });
  const dev = schema({ a: { type: "string", [SINCE_KEY]: "0.6", [UNTIL_KEY]: "0.6" } });
  const ok = run(dev, timelineOf(v, v, dev));
  assert.deepStrictEqual(ok.errors, []);

  const bad = schema({ a: { type: "string", [SINCE_KEY]: "0.8", [UNTIL_KEY]: "0.6" } });
  const { errors } = run(bad, timelineOf(schema({}), schema({}), bad));
  assert.ok(errors.some((e) => /empty availability range/.test(e)), errors.join("\n"));
});

test("a malformed bound is reported and stops further checks for that field", () => {
  const dev = schema({ a: { type: "string", [SINCE_KEY]: "0.8.0-alpha" } });
  const { errors } = run(dev, timelineOf(schema({}), schema({}), dev));
  assert.strictEqual(errors.length, 1);
  assert.match(errors[0], /not a major\.minor version/);
});

test("no declared ranges is not an error", () => {
  const dev = schema({ a: { type: "string" } });
  const { errors, checked } = run(dev, timelineOf(dev, dev, dev));
  assert.deepStrictEqual(errors, []);
  assert.strictEqual(checked, 0);
});

test("exceeding the traversal depth budget fails loudly instead of skipping", () => {
  // Returning silently at the depth cut-off would drop every declaration below
  // it from the checked set — the gate would pass by not looking.
  const definitions = {};
  const depth = MAX_DEPTH + 5;
  for (let i = 0; i < depth; i++) {
    definitions[`N${i}`] = {
      type: "object",
      properties: { next: { $ref: `#/definitions/N${i + 1}` } },
    };
  }
  definitions[`N${depth}`] = {
    type: "object",
    properties: { leaf: { type: "string", [SINCE_KEY]: "0.8" } },
  };
  const deep = schema({ root: { $ref: "#/definitions/N0" } }, definitions);

  assert.throws(() => collectPropertyPaths(deep), DepthExceeded);
});
