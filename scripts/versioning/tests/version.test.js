// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

const test = require("node:test");
const assert = require("node:assert/strict");
const {
  compareVersions,
  parseMajorMinor,
  parseVersion,
} = require("../lib/version");

test("strict SemVer parsing accepts prerelease and build metadata", () => {
  assert.ok(parseVersion("0.8.0-alpha.1+build.7"));
  assert.ok(parseVersion("1.0.0"));
  assert.ok(parseMajorMinor("0.8"));
});

test("strict SemVer parsing rejects leading zeroes and malformed identifiers", () => {
  for (const version of [
    "01.8.0",
    "0.08.0",
    "0.8.00",
    "0.8.0-01",
    "0.8.0-alpha_1",
    "0.8",
    "9007199254740992.0.0",
    `1.0.0-${"a".repeat(251)}`,
  ]) {
    assert.equal(parseVersion(version), null, version);
  }
  assert.equal(parseMajorMinor("0.08"), null);
});

test("build metadata does not affect version precedence", () => {
  assert.equal(
    compareVersions(
      parseVersion("0.8.0-alpha+build.1"),
      parseVersion("0.8.0-alpha+build.2")
    ),
    0
  );
});
