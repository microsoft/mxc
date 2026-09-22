// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

const assert = require("node:assert/strict");
const { test } = require("node:test");
const {
  assertDirectionalNetworkOnly,
  contractsWithTypeScriptOracles,
  formatFailure,
  stableSchemaVersion,
  validateDispatchRoots,
  validatePublishedRegistry,
  validateStableHistory,
} = require("../check-contract-codegen.js");

const roots = ["OneShotRequest", "WindowsSandboxProvisionRequest",
  "IsolationSessionProvisionRequest", "WslcProvisionRequest", "StartRequest",
  "ExecRequest", "StopRequest", "DeprovisionRequest"];
const v0_9Roots = ["OneShotRequest", "IsolationSessionProvisionRequest",
  "WslcProvisionRequest", "StartRequest", "ExecRequest", "StopRequest",
  "DeprovisionRequest"];
const removed = ["defaultPolicy", "enforcementMode", "allowedHosts",
  "blockedHosts", "allowLocalNetwork", "proxy"];

function schema(requestRoots = roots) {
  return {
    allOf: requestRoots.map(root => ({ $ref: `#/definitions/${root}` })),
    definitions: Object.fromEntries(requestRoots.map(root => [root, {
      type: "object",
      properties: {
        network: { $ref: "#/definitions/Network" },
        process: { type: "string", default: 'echo "network.proxy"' },
      },
    }]).concat([
      ["Network", { properties: { egress: { $ref: "#/definitions/Egress" } } }],
      ["Egress", { properties: { default: { enum: ["allow", "deny"] } } }],
      ["UnreachableLegacy", { properties: { proxy: {} } }],
    ])),
  };
}

test("exact versions dispatch precisely their expected request roots", () => {
  assert.deepEqual(
    [...validateDispatchRoots(schema(v0_9Roots), "0.9.0-alpha").values()],
    v0_9Roots
  );
  assert.deepEqual(
    [...validateDispatchRoots(schema(), "0.10.0-alpha").values()],
    roots
  );

  const missing = schema(v0_9Roots);
  missing.allOf.pop();
  assert.throws(
    () => validateDispatchRoots(missing, "0.9.0-alpha"),
    /missing dispatched roots: DeprovisionRequest/
  );

  const unexpected = schema(v0_9Roots);
  unexpected.definitions.UnknownRequest = { type: "object" };
  unexpected.allOf.push({ $ref: "#/definitions/UnknownRequest" });
  assert.throws(
    () => validateDispatchRoots(unexpected, "0.9.0-alpha"),
    /unexpected dispatched roots: UnknownRequest/
  );
});

test("published exact contracts with TypeScript oracles are regenerated", () => {
  const selected = contractsWithTypeScriptOracles([
    { version: "0.8.0-alpha", status: "published", typescriptPath: null },
    {
      version: "0.9.0-alpha",
      status: "published",
      schemaPath: "schemas/stable/mxc-config.schema.0.9.0-alpha.json",
      typescriptPath: "sdk/node/src/generated/v0_9_0_alpha/wire.ts",
    },
    {
      version: "0.10.0-alpha",
      status: "development",
      schemaPath: "schemas/dev/mxc-config.schema.0.10.0-alpha.json",
      typescriptPath: "sdk/node/src/generated/v0_10_0_alpha/wire.ts",
    },
  ]);
  assert.deepEqual(
    selected.map(contract => contract.version),
    ["0.9.0-alpha", "0.10.0-alpha"]
  );

  assert.throws(
    () => contractsWithTypeScriptOracles([
      { version: "0.9.0-alpha", schemaPath: "v0.9.json", typescriptPath: null },
      {
        version: "0.10.0-alpha",
        schemaPath: "v0.10.json",
        typescriptPath: "v0.10.ts",
      },
    ]),
    /0\.9\.0-alpha has no TypeScript oracle path/
  );
  assert.throws(
    () => contractsWithTypeScriptOracles([
      {
        version: "0.9.0-alpha",
        schemaPath: "v0.9.json",
        typescriptPath: "v0.9.ts",
      },
    ]),
    /0\.10\.0-alpha is absent from the registry/
  );
  assert.throws(
    () => contractsWithTypeScriptOracles([
      {
        version: "0.9.0-alpha",
        schemaPath: "v0.9.json",
        typescriptPath: "v0.9.ts",
      },
      {
        version: "0.10.0-alpha",
        schemaPath: "v0.10.json",
        typescriptPath: "v0.10.ts",
      },
      {
        version: "0.11.0-alpha",
        schemaPath: "v0.11.json",
        typescriptPath: "v0.11.ts",
      },
    ]),
    /0\.11\.0-alpha has no expected request-root set/
  );
});

test("every removed property is rejected from every exact request root", () => {
  for (const root of roots) {
    for (const name of removed) {
      const value = schema();
      value.definitions[root].properties.network = {
        allOf: [{ $ref: "#/definitions/HiddenLegacy" }],
      };
      value.definitions.HiddenLegacy = { properties: { [name]: { type: "string" } } };
      assert.throws(() => assertDirectionalNetworkOnly(value), new RegExp(`${root}.*${name}`));
    }
  }
});

test("recursive references preserve network context and terminate", () => {
  const value = schema();
  value.definitions.Network.allOf = [{ $ref: "#/definitions/Network" }];
  assert.doesNotThrow(() => assertDirectionalNetworkOnly(value));
  value.definitions.Network.properties.proxy = {};
  assert.throws(() => assertDirectionalNetworkOnly(value), /network.proxy/);
});

test("data strings and unreachable legacy definitions do not authorize fields", () => {
  assert.doesNotThrow(() => assertDirectionalNetworkOnly(schema()));
});

test("missing roots and dangling or external references fail closed", () => {
  const value = schema();
  delete value.definitions.ExecRequest;
  assert.throws(() => assertDirectionalNetworkOnly(value), /Missing exact request root/);
  for (const reference of ["#/definitions/Absent", "https://example.com/unknown"]) {
    const broken = schema();
    broken.definitions.Network.$ref = reference;
    assert.throws(() => assertDirectionalNetworkOnly(broken), /Unresolved schema reference/);
  }
});

test("stable schema history allows initial publication", () => {
  const base = new Map([
    ["schemas/stable/mxc-config.schema.0.8.0-alpha.json", "{\"v\":1}\r\n"],
  ]);
  const unchanged = new Map([
    ["schemas/stable/mxc-config.schema.0.8.0-alpha.json", "{\"v\":1}\n"],
    ["schemas/stable/mxc-config.schema.0.9.0-alpha.json", "{\"v\":2}\n"],
  ]);
  assert.deepEqual(validateStableHistory(base, unchanged), []);
});

test("stable schema history rejects mutation and removal", () => {
  const base = new Map([
    ["schemas/stable/mxc-config.schema.0.8.0-alpha.json", "{\"v\":1}\r\n"],
  ]);

  assert.match(
    validateStableHistory(
      base,
      new Map([
        ["schemas/stable/mxc-config.schema.0.8.0-alpha.json", "{\"v\":2}\n"],
      ])
    ).join("\n"),
    /changed after publication/
  );
  assert.match(
    validateStableHistory(base, new Map()).join("\n"),
    /was removed/
  );
});

test("CLI failures use the normal contract-codegen diagnostic", () => {
  const output = formatFailure(new Error("could not parse stable schema"));
  assert.equal(
    output,
    "Contract codegen check FAILED:\n  - could not parse stable schema"
  );
  assert.doesNotMatch(output, /\n\s+at /);
});

test("published registry covers every supported stable schema", () => {
  const path = "schemas/stable/mxc-config.schema.0.9.0-alpha.json";
  const schemaId = "https://example.test/0.9.0-alpha";
  const stable = new Map([
    [path, JSON.stringify({ $id: schemaId })],
  ]);
  const published = [
    {
      version: "0.9.0-alpha",
      status: "published",
      schemaPath: path,
      schemaId,
    },
    {
      version: "0.10.0-alpha",
      status: "development",
      schemaPath: "schemas/dev/mxc-config.schema.0.10.0-alpha.json",
      schemaId: "development",
    },
  ];
  assert.deepEqual(
    validatePublishedRegistry(published, stable, "0.6.0-alpha"),
    []
  );
  assert.match(
    validatePublishedRegistry([], stable, "0.6.0-alpha").join("\n"),
    /absent from the registry/
  );
  assert.match(
    validatePublishedRegistry(
      [{ ...published[0], status: "development" }, published[1]],
      stable,
      "0.6.0-alpha"
    ).join("\n"),
    /not published/
  );
});

test("retired stable schemas do not require exact registry entries", () => {
  const retired = new Map([
    [
      "schemas/stable/mxc-config.schema.0.5.0-alpha.json",
      JSON.stringify({ $id: "retired" }),
    ],
  ]);
  const development = [{
    version: "0.10.0-alpha",
    status: "development",
    schemaPath: "schemas/dev/mxc-config.schema.0.10.0-alpha.json",
    schemaId: "development",
  }];
  assert.deepEqual(
    validatePublishedRegistry(development, retired, "0.6.0-alpha"),
    []
  );
  assert.equal(
    stableSchemaVersion(
      "schemas/stable/mxc-config.schema.0.9.0-alpha.json"
    ),
    "0.9.0-alpha"
  );
});
