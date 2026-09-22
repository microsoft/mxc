// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

const assert = require("node:assert/strict");
const { test } = require("node:test");
const {
  parseContractRegistry,
  requestRootsForContract,
  validateSdkMajorTargets,
} = require("../lib/contract-registry.js");

function contract(version = "1.1.0-alpha", status = "development") {
  return {
    version,
    status,
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

function publishedContract(version) {
  return contract(version, "published");
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
    /repeats version 1\.1\.0-alpha/
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

test("SDK targets may remain empty before the first stable major line", () => {
  assert.doesNotThrow(() =>
    validateSdkMajorTargets({}, [
      contract("0.9.0-alpha"),
      contract("1.1.0-alpha"),
    ])
  );
});

test("SDK targets select the latest exact Rust contract in each major", () => {
  const registry = [
    publishedContract("1.0.0"),
    publishedContract("1.1.0"),
  ];
  assert.doesNotThrow(() =>
    validateSdkMajorTargets({ "1": "1.1.0" }, registry)
  );
  assert.throws(
    () => validateSdkMajorTargets({ "1": "1.0.0" }, registry),
    /latest published stable major 1 exact contract is 1\.1\.0/
  );
});

test("development contracts do not advance stable SDK targets", () => {
  const registry = [
    publishedContract("1.0.0"),
    contract("1.1.0-alpha"),
    contract("1.1.0+build.1", "published"),
  ];
  assert.doesNotThrow(() =>
    validateSdkMajorTargets({ "1": "1.0.0" }, registry)
  );
});

test("development-only major lines do not require an SDK target", () => {
  assert.doesNotThrow(() =>
    validateSdkMajorTargets({}, [contract("1.0.0-alpha")])
  );
});

test("every published stable major line has an SDK target", () => {
  assert.throws(
    () => validateSdkMajorTargets({}, [publishedContract("1.0.0")]),
    /published stable major 1 exact contracts have no SDK target/
  );
});

test("SDK targets reject malformed, prerelease, and cross-major values", () => {
  const registry = [
    publishedContract("1.0.0"),
    publishedContract("2.0.0"),
  ];
  assert.throws(
    () =>
      validateSdkMajorTargets(
        { "01": "1.0.0", "1": "1.0.0", "2": "2.0.0" },
        registry
      ),
    /not a canonical positive major/
  );
  assert.throws(
    () =>
      validateSdkMajorTargets(
        { "1": "1.0.0-alpha", "2": "2.0.0" },
        registry
      ),
    /must identify an exact stable contract/
  );
  assert.throws(
    () =>
      validateSdkMajorTargets(
        { "1": "2.0.0", "2": "2.0.0" },
        registry
      ),
    /which is not in major 1/
  );
});

test("SDK targets reject a stable-looking development contract", () => {
  assert.throws(
    () => validateSdkMajorTargets({ "1": "1.0.0" }, [contract("1.0.0")]),
    /must identify a published exact stable contract/
  );
});
