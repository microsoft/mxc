// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

const assert = require("node:assert/strict");
const { test } = require("node:test");
const {
  parseContractRegistry,
  requestRootsForContract,
} = require("../lib/contract-registry.js");

function contract(version = "0.10.0-alpha") {
  return {
    version,
    status: "development",
    schemaId: `https://example.test/${version}`,
    schemaPath: `schemas/${version}.json`,
    typescriptPath: `generated/${version}.ts`,
    generatesArtifacts: true,
    requestRoots: [{
      fixtureDirectory: "one_shot",
      schemaDefinition: "OneShotRequest",
    }],
  };
}

test("registry parsing indexes valid descriptors", () => {
  const first = contract("0.9.0-alpha");
  const second = contract();
  const { registry, byVersion } = parseContractRegistry(
    JSON.stringify([first, second]),
    "test registry"
  );
  assert.equal(registry.length, 2);
  assert.deepEqual(byVersion.get(second.version), second);
  assert.deepEqual(
    [...requestRootsForContract(first)],
    [["one_shot", "OneShotRequest"]]
  );
});

test("registry parsing rejects invalid top-level values", () => {
  assert.throws(
    () => parseContractRegistry("{}", "test registry"),
    /returned no registered contracts/
  );
  assert.throws(
    () => parseContractRegistry("{", "test registry"),
    /returned invalid JSON/
  );
});

test("registry parsing rejects duplicate versions", () => {
  assert.throws(
    () =>
      parseContractRegistry(
        JSON.stringify([contract(), contract()]),
        "test registry"
      ),
    /repeats version 0\.10\.0-alpha/
  );
});

test("request-root parsing rejects duplicate metadata", () => {
  const duplicate = contract();
  duplicate.requestRoots.push({
    fixtureDirectory: "alternate",
    schemaDefinition: "OneShotRequest",
  });
  assert.throws(
    () => requestRootsForContract(duplicate),
    /repeats schema root OneShotRequest/
  );
});
