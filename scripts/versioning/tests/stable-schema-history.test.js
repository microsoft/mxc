// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

const test = require("node:test");
const assert = require("node:assert/strict");
const {
  validateStableHistory,
} = require("../lib/stable-schema-history");

const stable = (version, body = version) => [
  `mxc-config.schema.${version}.json`,
  body,
];

function input(overrides = {}) {
  return {
    baseFiles: new Map([stable("0.6.0-alpha"), stable("0.7.0-alpha")]),
    currentFiles: new Map([stable("0.6.0-alpha"), stable("0.7.0-alpha")]),
    baseSchemaVersion: {
      stableLatest: "0.7.0-alpha",
      maxSupported: "0.8.0-alpha",
      devSchemaFile: "0.8.0-dev",
    },
    currentSchemaVersion: {
      stableLatest: "0.7.0-alpha",
      maxSupported: "0.8.0-alpha",
      devSchemaFile: "0.8.0-dev",
    },
    baseDevSchemaContent: "dev",
    currentDevSchemaContent: "dev",
    baseStabilityContent: "manifest",
    currentStabilityContent: "manifest",
    ...overrides,
  };
}

test("unchanged released schemas pass", () => {
  assert.deepEqual(validateStableHistory(input()).errors, []);
});

test("modifying or deleting a released schema fails", () => {
  const currentFiles = new Map([
    stable("0.6.0-alpha", "changed"),
  ]);
  const { errors } = validateStableHistory(input({ currentFiles }));
  assert.ok(errors.some((error) => error.includes("was modified")));
  assert.ok(errors.some((error) => error.includes("was deleted")));
});

test("one generated release with frozen inputs passes", () => {
  const currentFiles = new Map([
    stable("0.6.0-alpha"),
    stable("0.7.0-alpha"),
    stable("0.8.0-alpha"),
  ]);
  const currentSchemaVersion = {
    stableLatest: "0.8.0-alpha",
    maxSupported: "0.8.0-alpha",
    devSchemaFile: "0.8.0-dev",
  };
  const result = validateStableHistory(
    input({ currentFiles, currentSchemaVersion })
  );
  assert.deepEqual(result.errors, []);
  assert.equal(result.newVersion.raw, "0.8.0-alpha");
});

test("a release cannot advance or modify its dev inputs", () => {
  const currentFiles = new Map([
    stable("0.6.0-alpha"),
    stable("0.7.0-alpha"),
    stable("0.8.0-alpha"),
  ]);
  const currentSchemaVersion = {
    stableLatest: "0.8.0-alpha",
    maxSupported: "0.9.0-alpha",
    devSchemaFile: "0.9.0-dev",
  };
  const { errors } = validateStableHistory(
    input({
      currentFiles,
      currentSchemaVersion,
      currentDevSchemaContent: "new dev",
      currentStabilityContent: "new manifest",
    })
  );
  assert.ok(errors.some((error) => error.includes("maxSupported")));
  assert.ok(errors.some((error) => error.includes("devSchemaFile")));
  assert.ok(errors.some((error) => error.includes("dev schema")));
  assert.ok(errors.some((error) => error.includes("config-stability.json")));
});

test("stableLatest cannot move without exactly one new stable schema", () => {
  const changedLatest = {
    stableLatest: "0.8.0-alpha",
    maxSupported: "0.8.0-alpha",
    devSchemaFile: "0.8.0-dev",
  };
  const noFile = validateStableHistory(
    input({ currentSchemaVersion: changedLatest })
  );
  assert.ok(noFile.errors.some((error) => error.includes("without adding")));

  const twoFiles = new Map([
    stable("0.6.0-alpha"),
    stable("0.7.0-alpha"),
    stable("0.8.0-alpha"),
    stable("0.9.0-alpha"),
  ]);
  const multiple = validateStableHistory(
    input({ currentFiles: twoFiles, currentSchemaVersion: changedLatest })
  );
  assert.ok(multiple.errors.some((error) => error.includes("only one")));
});
