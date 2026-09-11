// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

const assert = require("node:assert/strict");
const { test } = require("node:test");
const { assertDirectionalNetworkOnly } = require("../check-contract-codegen.js");

const roots = ["OneShotRequest", "WindowsSandboxProvisionRequest",
  "IsolationSessionProvisionRequest", "WslcProvisionRequest", "StartRequest",
  "ExecRequest", "StopRequest", "DeprovisionRequest"];
const removed = ["defaultPolicy", "enforcementMode", "allowedHosts",
  "blockedHosts", "allowLocalNetwork", "proxy"];

function schema() {
  return {
    definitions: Object.fromEntries(roots.map(root => [root, {
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
