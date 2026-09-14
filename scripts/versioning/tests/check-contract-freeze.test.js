// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

const assert = require("node:assert/strict");
const { test } = require("node:test");
const {
  schemaSha256,
  safeRepoPath,
  sha256,
  validatePublishedHistory,
} = require("../check-contract-freeze.js");

function registry(contracts) {
  return { formatVersion: 1, contracts };
}

function published(overrides = {}) {
  return {
    version: "0.8.0-alpha",
    rustVariant: "V0_8_0Alpha",
    rustModule: "v0_8_0_alpha",
    status: "published",
    schemaId: "schema-id",
    schemaPath: "schema-path",
    typescriptPath: null,
    contractModulePath: "contract-path",
    adapterPath: "adapter-path",
    builderPath: "builder-path",
    fixturePath: "fixture-path",
    schemaSha256: "a".repeat(64),
    ...overrides,
  };
}

test("published identities remain immutable", () => {
  const base = registry([published()]);
  assert.deepEqual(validatePublishedHistory(base, registry([published()])), []);

  for (const [field, value] of [
    ["status", "development"],
    ["schemaPath", "different"],
    ["adapterPath", "different"],
    ["builderPath", "different"],
    ["schemaSha256", "b".repeat(64)],
  ]) {
    assert.match(
      validatePublishedHistory(
        base,
        registry([published({ [field]: value })])
      ).join("\n"),
      new RegExp(field)
    );
  }
});

test("published contracts cannot be removed", () => {
  assert.match(
    validatePublishedHistory(registry([published()]), registry([])).join("\n"),
    /was removed/
  );
});

test("newly published contracts are allowed", () => {
  const development = published({
    version: "0.9.0-alpha",
    status: "development",
    schemaSha256: null,
  });
  const nowPublished = { ...development, status: "published", schemaSha256: "b".repeat(64) };
  assert.deepEqual(
    validatePublishedHistory(
      registry([published(), development]),
      registry([published(), nowPublished])
    ),
    []
  );
});

test("schema digests use SHA-256 bytes", () => {
  assert.equal(
    sha256(Buffer.from("mxc")),
    "4dc8d53a340db8381d67e04176b4dad8da2aa83e64afd48801da568b7a98a454"
  );
  assert.equal(schemaSha256(Buffer.from("a\r\nb\r\n")), sha256(Buffer.from("a\nb\n")));
});

test("registered paths cannot escape the repository", () => {
  assert.equal(safeRepoPath("../outside"), null);
  assert.equal(safeRepoPath(""), null);
  assert.ok(safeRepoPath("schemas/contract-registry.generated.json"));
});
