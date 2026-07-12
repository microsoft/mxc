// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

const test = require("node:test");
const assert = require("node:assert/strict");
const {
  evaluateSupportedRange,
  validateGeneratedStableFloor,
  validateMinHistory,
  validatePreFloorDevLine,
} = require("../lib/supported-range-contract");

function evaluate(overrides = {}) {
  return evaluateSupportedRange({
    previousVersion: "0.8.0-alpha",
    newVersion: "0.9.0-alpha",
    minVersion: "0.8.0-alpha",
    generatedStableFloor: "0.8.0-alpha",
    breaks: [],
    ...overrides,
  });
}

test("the first generated stable line must advance the floor", () => {
  const failed = evaluate({
    previousVersion: "0.7.0-alpha",
    newVersion: "0.8.0-alpha",
    minVersion: "0.6.0-alpha",
  });
  assert.ok(failed.errors.some((error) => error.includes("advance min")));

  const passed = evaluate({
    previousVersion: "0.7.0-alpha",
    newVersion: "0.8.0-alpha",
    minVersion: "0.8.0-alpha",
  });
  assert.deepEqual(passed.errors, []);
  assert.equal(passed.mode, "legacy-boundary");
});

test("the first generated stable release cannot skip the declared floor", () => {
  const result = evaluate({
    previousVersion: "0.7.0-alpha",
    newVersion: "0.9.0-alpha",
    minVersion: "0.9.0-alpha",
  });
  assert.ok(
    result.errors.some((error) => error.includes("must be exactly"))
  );
});

test("the generated stable floor is immutable once introduced", () => {
  assert.deepEqual(
    validateGeneratedStableFloor(undefined, "0.8.0-alpha"),
    []
  );
  assert.deepEqual(
    validateGeneratedStableFloor("0.8.0-alpha", "0.8.0-alpha"),
    []
  );
  assert.ok(
    validateGeneratedStableFloor("0.8.0-alpha", "0.9.0-alpha")[0].includes(
      "immutable"
    )
  );
});

test("the supported floor cannot move backward", () => {
  assert.deepEqual(
    validateMinHistory("0.8.0-alpha", "0.9.0-alpha"),
    []
  );
  assert.deepEqual(
    validateMinHistory("0.8.1-alpha", "0.8.0-alpha"),
    []
  );
  assert.ok(
    validateMinHistory("0.9.0-alpha", "0.8.0-alpha")[0].includes(
      "cannot move backward"
    )
  );
});

test("the dev line cannot skip an unreleased generated floor", () => {
  assert.deepEqual(
    validatePreFloorDevLine(
      "0.7.0-alpha",
      "0.8.0-alpha",
      "0.8.0-alpha"
    ),
    []
  );
  assert.ok(
    validatePreFloorDevLine(
      "0.7.0-alpha",
      "0.9.0-alpha",
      "0.8.0-alpha"
    )[0].includes("must remain")
  );
  assert.deepEqual(
    validatePreFloorDevLine(
      "0.8.0-alpha",
      "0.9.0-alpha",
      "0.8.0-alpha"
    ),
    []
  );
});

test("additive generated releases may retain the old floor", () => {
  assert.deepEqual(evaluate().errors, []);
});

test("breaking generated releases must advance the floor", () => {
  const failed = evaluate({ breaks: ["$.value: property removed"] });
  assert.ok(failed.errors.some((error) => error.includes("advance min")));

  const passed = evaluate({
    minVersion: "0.9.0-alpha",
    breaks: ["$.value: property removed"],
  });
  assert.deepEqual(passed.errors, []);
});

test("breaking changes cannot use a patch or prerelease-only bump", () => {
  const result = evaluate({
    previousVersion: "0.8.0-alpha",
    newVersion: "0.8.1-alpha",
    minVersion: "0.8.1-alpha",
    breaks: ["$.value: property removed"],
  });
  assert.ok(
    result.errors.some((error) => error.includes("compares only major.minor"))
  );
});
