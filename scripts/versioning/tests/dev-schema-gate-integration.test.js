// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

// End-to-end coverage for the dev-schema compatibility gate.
//
// The gate is only meaningful as a process: resolve the pull request base, read
// both dev schemas out of git, compare them, and exit non-zero. Unit-testing the
// pieces would miss exactly the bypasses that matter, so these tests drive the
// real CLI against throwaway repositories and assert on its exit code.

const test = require("node:test");
const assert = require("node:assert/strict");
const { execFileSync, spawnSync } = require("child_process");
const { mkdtempSync, rmSync, writeFileSync, mkdirSync, cpSync } = require("fs");
const { tmpdir } = require("os");
const { join, resolve } = require("path");

const scriptsDir = resolve(__dirname, "..");
const gateRelative = "scripts/versioning/check-dev-schema-compat.js";

function git(cwd, args) {
  return execFileSync("git", args, { cwd, encoding: "utf8" }).trim();
}

const DEV_LINE = "0.8.0-dev";

const schemaWith = (properties) => ({
  $schema: "http://json-schema.org/draft-07/schema#",
  type: "object",
  additionalProperties: false,
  properties,
});

function writeVersions(dir, devSchemaFile) {
  writeFileSync(
    join(dir, "schemas", "schema-version.json"),
    `${JSON.stringify({ devSchemaFile }, null, 2)}\n`
  );
}

function writeSchema(dir, devSchemaFile, schema) {
  writeFileSync(
    join(dir, "schemas", "dev", `mxc-config.schema.${devSchemaFile}.json`),
    `${JSON.stringify(schema, null, 2)}\n`
  );
}

// A repository that contains a real copy of the gate and its libraries, a base
// commit on `main`, and a `topic` branch to run the gate from.
function scratchRepo(baseSchema, devLine = DEV_LINE) {
  const dir = mkdtempSync(join(tmpdir(), "dev-schema-gate-"));
  git(dir, ["init", "-q", "-b", "main"]);
  git(dir, ["config", "user.email", "test@example.com"]);
  git(dir, ["config", "user.name", "Test"]);
  mkdirSync(join(dir, "schemas", "dev"), { recursive: true });
  mkdirSync(join(dir, "scripts"), { recursive: true });
  cpSync(scriptsDir, join(dir, "scripts", "versioning"), { recursive: true });
  rmSync(join(dir, "scripts", "versioning", "node_modules"), {
    recursive: true,
    force: true,
  });
  writeVersions(dir, devLine);
  writeSchema(dir, devLine, baseSchema);
  git(dir, ["add", "-A"]);
  git(dir, ["commit", "-q", "-m", "base"]);
  git(dir, ["checkout", "-q", "-b", "topic"]);
  return dir;
}

function runGate(dir) {
  return spawnSync(process.execPath, [join(dir, gateRelative), "--base-ref", "main"], {
    cwd: dir,
    encoding: "utf8",
  });
}

function commit(dir, message) {
  git(dir, ["add", "-A"]);
  git(dir, ["commit", "-q", "-m", message]);
}

test("an unchanged dev schema passes", (t) => {
  const dir = scratchRepo(schemaWith({ keep: { type: "string" } }));
  t.after(() => rmSync(dir, { recursive: true, force: true }));
  const result = runGate(dir);
  assert.equal(result.status, 0, result.stderr);
  assert.match(result.stdout, /no breaking change/);
});

test("adding a property passes", (t) => {
  const dir = scratchRepo(schemaWith({ keep: { type: "string" } }));
  t.after(() => rmSync(dir, { recursive: true, force: true }));
  writeSchema(
    dir,
    DEV_LINE,
    schemaWith({ keep: { type: "string" }, added: { type: "number" } })
  );
  commit(dir, "add a property");
  const result = runGate(dir);
  assert.equal(result.status, 0, result.stderr);
});

// The shape of PR #676: delete a stable field and regenerate everything around
// it. Every other gate in this directory passes on that change.
test("removing a property is blocked and the property is named", (t) => {
  const dir = scratchRepo(
    schemaWith({ keep: { type: "string" }, doomed: { type: "string" } })
  );
  t.after(() => rmSync(dir, { recursive: true, force: true }));
  writeSchema(dir, DEV_LINE, schemaWith({ keep: { type: "string" } }));
  commit(dir, "remove a property");
  const result = runGate(dir);
  assert.equal(result.status, 1, result.stdout);
  assert.match(result.stderr, /doomed/);
});

test("narrowing a property type is blocked", (t) => {
  const dir = scratchRepo(schemaWith({ value: {} }));
  t.after(() => rmSync(dir, { recursive: true, force: true }));
  writeSchema(dir, DEV_LINE, schemaWith({ value: { type: "string" } }));
  commit(dir, "narrow a type");
  const result = runGate(dir);
  assert.equal(result.status, 1, result.stdout);
});

// Reading both sides at the BASE path, or skipping the comparison outright,
// would let a pull request disable the gate by editing one line of
// schema-version.json.
test("opening a new dev line does not disable the gate", (t) => {
  const dir = scratchRepo(
    schemaWith({ keep: { type: "string" }, doomed: { type: "string" } })
  );
  t.after(() => rmSync(dir, { recursive: true, force: true }));
  writeVersions(dir, "0.9.0-dev");
  writeSchema(dir, "0.9.0-dev", schemaWith({ keep: { type: "string" } }));
  commit(dir, "open a new dev line while dropping a property");
  const result = runGate(dir);
  assert.equal(result.status, 1, result.stdout);
  assert.match(result.stderr, /doomed/);
  assert.match(result.stderr, /0\.8\.0-dev -> 0\.9\.0-dev/);
});

test("a compatible new dev line passes and reports the move", (t) => {
  const dir = scratchRepo(schemaWith({ keep: { type: "string" } }));
  t.after(() => rmSync(dir, { recursive: true, force: true }));
  writeVersions(dir, "0.9.0-dev");
  writeSchema(dir, "0.9.0-dev", schemaWith({ keep: { type: "string" } }));
  commit(dir, "open a new dev line");
  const result = runGate(dir);
  assert.equal(result.status, 0, result.stderr);
  assert.match(result.stdout, /0\.8\.0-dev -> 0\.9\.0-dev/);
});

test("a missing dev schema at HEAD fails rather than passing vacuously", (t) => {
  const dir = scratchRepo(schemaWith({ keep: { type: "string" } }));
  t.after(() => rmSync(dir, { recursive: true, force: true }));
  writeVersions(dir, "0.9.0-dev");
  commit(dir, "point at a dev line that does not exist");
  const result = runGate(dir);
  assert.equal(result.status, 1, result.stdout);
  assert.match(result.stderr, /missing at HEAD/);
});

test("an unparsable dev schema fails with the file named", (t) => {
  const dir = scratchRepo(schemaWith({ keep: { type: "string" } }));
  t.after(() => rmSync(dir, { recursive: true, force: true }));
  writeFileSync(
    join(dir, "schemas", "dev", `mxc-config.schema.${DEV_LINE}.json`),
    "{ not json"
  );
  commit(dir, "corrupt the dev schema");
  const result = runGate(dir);
  assert.equal(result.status, 1, result.stdout);
  assert.match(result.stderr, /not valid JSON/);
});
