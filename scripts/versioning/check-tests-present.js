#!/usr/bin/env node
// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

// Guards the guard: fail when there are no test files to run.
//
// `node --test tests/*.test.js` exits 0 when the pattern matches nothing, so
// renaming or moving the tests directory would leave the versioning job green
// while executing nothing at all. Every other gate in this directory is only as
// trustworthy as its tests actually running, so this runs ahead of them.
//
//   node scripts/versioning/check-tests-present.js

const { readdirSync, existsSync } = require("fs");
const { join, resolve } = require("path");

const testsDir = resolve(__dirname, "tests");

if (!existsSync(testsDir)) {
  console.error(
    `Test presence check FAILED: ${join("scripts", "versioning", "tests")} does not exist.`
  );
  process.exit(1);
}

// Read the entry types, not just the names. A *directory* named `foo.test.js`
// matches the suffix but runs nothing, so a name-only check would report the
// tests are present while `node --test` still executes nothing -- exactly the
// silent pass this script exists to prevent.
const files = readdirSync(testsDir, { withFileTypes: true })
  .filter((entry) => entry.isFile() && entry.name.endsWith(".test.js"))
  .map((entry) => entry.name);

if (files.length === 0) {
  console.error(
    "Test presence check FAILED: no *.test.js files found; the test step " +
      "would report success without executing anything."
  );
  process.exit(1);
}

console.log(`Test presence OK: ${files.length} test file(s).`);
