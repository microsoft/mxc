// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

const test = require("node:test");
const assert = require("node:assert/strict");
const { requestedBaseRef } = require("../lib/git-base");

test("explicit base ref wins", () => {
  assert.equal(
    requestedBaseRef(["--base-ref", "origin/feature"], {
      MXC_VERSIONING_BASE_REF: "origin/main",
    }),
    "origin/feature"
  );
});

test("environment base ref is used", () => {
  assert.equal(
    requestedBaseRef([], { MXC_VERSIONING_BASE_REF: "origin/main" }),
    "origin/main"
  );
});

test("GitHub Actions fails closed without a base ref", () => {
  assert.throws(
    () => requestedBaseRef([], { GITHUB_ACTIONS: "true" }),
    /required in GitHub Actions/
  );
});

test("local callers may use resolver fallbacks", () => {
  assert.equal(requestedBaseRef([], {}), null);
});
