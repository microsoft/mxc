// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

const test = require("node:test");
const assert = require("node:assert/strict");
const { spawnSync } = require("child_process");
const { copyFileSync, mkdirSync, mkdtempSync, rmSync, writeFileSync } = require("fs");
const { join, resolve } = require("path");
const { tmpdir } = require("os");

const SCRIPT = resolve(__dirname, "..", "check-tests-present.js");

// The script resolves its tests directory relative to its own location, so it is
// copied into a scratch layout and run as a real process. That also exercises
// the exit code, which is the only thing CI actually reads.
function runAgainst(populate) {
  const dir = mkdtempSync(join(tmpdir(), "check-tests-present-"));
  try {
    copyFileSync(SCRIPT, join(dir, "check-tests-present.js"));
    populate(dir);
    const result = spawnSync(process.execPath, [join(dir, "check-tests-present.js")], {
      encoding: "utf8",
    });
    return { status: result.status, output: `${result.stdout}${result.stderr}` };
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
}

test("the presence check passes when a real test file exists", () => {
  const { status, output } = runAgainst((dir) => {
    mkdirSync(join(dir, "tests"));
    writeFileSync(join(dir, "tests", "a.test.js"), "// test\n");
  });
  assert.equal(status, 0, output);
  assert.match(output, /Test presence OK: 1 test file\(s\)\./);
});

test("the presence check fails when the tests directory is missing or empty", () => {
  const missing = runAgainst(() => {});
  assert.equal(missing.status, 1, missing.output);
  assert.match(missing.output, /does not exist/);

  const empty = runAgainst((dir) => mkdirSync(join(dir, "tests")));
  assert.equal(empty.status, 1, empty.output);
  assert.match(empty.output, /no \*\.test\.js files found/);
});

test("a directory named like a test file does not satisfy the presence check", () => {
  // `readdirSync` returns entry names, so a suffix-only check would count a
  // directory called `foo.test.js` as a test -- reporting that tests are present
  // while `node --test` still executes nothing, which is the exact silent pass
  // this script exists to prevent.
  const { status, output } = runAgainst((dir) => {
    mkdirSync(join(dir, "tests", "placeholder.test.js"), { recursive: true });
  });
  assert.equal(status, 1, output);
  assert.match(output, /no \*\.test\.js files found/);
});

test("a real test file is still found alongside such a directory", () => {
  const { status, output } = runAgainst((dir) => {
    mkdirSync(join(dir, "tests", "placeholder.test.js"), { recursive: true });
    writeFileSync(join(dir, "tests", "real.test.js"), "// test\n");
  });
  assert.equal(status, 0, output);
  assert.match(output, /Test presence OK: 1 test file\(s\)\./);
});
