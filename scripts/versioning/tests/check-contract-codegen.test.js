// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

const assert = require("node:assert/strict");
const {
  mkdtempSync,
  mkdirSync,
  rmSync,
  writeFileSync,
} = require("node:fs");
const os = require("node:os");
const { join } = require("node:path");
const { test } = require("node:test");
const {
  assertDirectionalNetworkOnly,
  contractsWithGeneratedArtifacts,
  formatFailure,
  stableSchemaVersion,
  validateDispatchRoots,
  validateFixtures,
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

function contract(version, requestRoots, overrides = {}) {
  return {
    version,
    status: version === "0.10.0-alpha" ? "development" : "published",
    schemaPath: `${version}.schema.json`,
    typescriptPath: `${version}.wire.ts`,
    generatesArtifacts: true,
    requestRoots: requestRoots.map((schemaDefinition) => ({
      fixtureDirectory: schemaDefinition
        .replace(/Request$/, "")
        .replace(/([a-z])([A-Z])/g, "$1_$2")
        .toLowerCase(),
      schemaDefinition,
    })),
    ...overrides,
  };
}

test("exact versions dispatch precisely their expected request roots", () => {
  const v0_9 = contract("0.9.0-alpha", v0_9Roots);
  const v0_10 = contract("0.10.0-alpha", roots);
  assert.deepEqual(
    [...validateDispatchRoots(schema(v0_9Roots), v0_9).values()],
    v0_9Roots
  );
  assert.deepEqual(
    [...validateDispatchRoots(schema(), v0_10).values()],
    roots
  );

  const missing = schema(v0_9Roots);
  missing.allOf.pop();
  assert.throws(
    () => validateDispatchRoots(missing, v0_9),
    /missing dispatched roots: DeprovisionRequest/
  );

  const unexpected = schema(v0_9Roots);
  unexpected.definitions.UnknownRequest = { type: "object" };
  unexpected.allOf.push({ $ref: "#/definitions/UnknownRequest" });
  assert.throws(
    () => validateDispatchRoots(unexpected, v0_9),
    /unexpected dispatched roots: UnknownRequest/
  );
});

test("registry selects exact contracts with generated artifacts", () => {
  const selected = contractsWithGeneratedArtifacts([
    contract("0.8.0-alpha", [], {
      typescriptPath: null,
      generatesArtifacts: false,
    }),
    contract("0.9.0-alpha", v0_9Roots),
    contract("0.10.0-alpha", roots),
  ]);
  assert.deepEqual(
    selected.map(contract => contract.version),
    ["0.9.0-alpha", "0.10.0-alpha"]
  );

  assert.throws(
    () => contractsWithGeneratedArtifacts([
      contract("0.9.0-alpha", v0_9Roots, { typescriptPath: null }),
      contract("0.10.0-alpha", roots),
    ]),
    /0\.9\.0-alpha has no TypeScript oracle path/
  );
  assert.throws(
    () => contractsWithGeneratedArtifacts([
      contract("0.9.0-alpha", v0_9Roots, { schemaPath: "" }),
    ]),
    /exact contract 0\.9\.0-alpha has no schema path/
  );
  assert.throws(
    () => contractsWithGeneratedArtifacts([
      contract("0.9.0-alpha", v0_9Roots, { generatesArtifacts: false }),
    ]),
    /non-renderable exact contract 0\.9\.0-alpha has a TypeScript oracle path/
  );
  assert.throws(
    () => contractsWithGeneratedArtifacts([
      contract("0.8.0-alpha", ["OneShotRequest"], {
        typescriptPath: null,
        generatesArtifacts: false,
      }),
    ]),
    /non-renderable exact contract 0\.8\.0-alpha has request-root metadata/
  );
  assert.throws(
    () => contractsWithGeneratedArtifacts([
      {
        ...contract("0.9.0-alpha", ["OneShotRequest"]),
        requestRoots: [
          {
            fixtureDirectory: "one_shot",
            schemaDefinition: "OneShotRequest",
          },
          {
            fixtureDirectory: "alternate_one_shot",
            schemaDefinition: "OneShotRequest",
          },
        ],
      },
    ]),
    /repeats schema root OneShotRequest/
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
      assert.throws(
        () => assertDirectionalNetworkOnly(value, roots),
        new RegExp(`${root}.*${name}`)
      );
    }
  }
});

test("recursive references preserve network context and terminate", () => {
  const value = schema();
  value.definitions.Network.allOf = [{ $ref: "#/definitions/Network" }];
  assert.doesNotThrow(() => assertDirectionalNetworkOnly(value, roots));
  value.definitions.Network.properties.proxy = {};
  assert.throws(() => assertDirectionalNetworkOnly(value, roots), /network.proxy/);
});

test("data strings and unreachable legacy definitions do not authorize fields", () => {
  assert.doesNotThrow(() => assertDirectionalNetworkOnly(schema(), roots));
});

test("missing roots and dangling or external references fail closed", () => {
  const value = schema();
  delete value.definitions.ExecRequest;
  assert.throws(
    () => assertDirectionalNetworkOnly(value, roots),
    /Missing exact request root/
  );
  for (const reference of ["#/definitions/Absent", "https://example.com/unknown"]) {
    const broken = schema();
    broken.definitions.Network.$ref = reference;
    assert.throws(
      () => assertDirectionalNetworkOnly(broken, roots),
      /Unresolved schema reference/
    );
  }
});

test("fixture validation does not require an unregistered exec root", () => {
  const fixtureRoot = mkdtempSync(join(os.tmpdir(), "mxc-no-exec-fixtures-"));
  try {
    const oneShot = schema(["OneShotRequest"]);
    oneShot.definitions.OneShotRequest = {
      type: "object",
      required: ["process"],
      additionalProperties: false,
      properties: {
        process: { type: "string" },
      },
    };
    for (const kind of ["valid", "invalid"]) {
      mkdirSync(join(fixtureRoot, "one_shot", kind), { recursive: true });
    }
    writeFileSync(
      join(fixtureRoot, "one_shot", "valid", "minimal.json"),
      JSON.stringify({ process: "echo hello" })
    );
    writeFileSync(
      join(fixtureRoot, "one_shot", "invalid", "missing_process.json"),
      JSON.stringify({})
    );

    assert.doesNotThrow(() =>
      validateFixtures(
        oneShot,
        fixtureRoot,
        new Map([["one_shot", "OneShotRequest"]])
      )
    );
  } finally {
    rmSync(fixtureRoot, { recursive: true, force: true });
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
