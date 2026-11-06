// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

"use strict";

const { readFileSync } = require("node:fs");
const { spawnSync } = require("node:child_process");
const { join } = require("node:path");
const { test } = require("node:test");
const assert = require("node:assert/strict");
const Ajv = require("ajv");

const root = join(__dirname, "..", "..", "..");
const schema = JSON.parse(readFileSync(join(root, "schemas", "dev", "mxc-config.schema.1.1.0-alpha.json"), "utf8"));
const cases = JSON.parse(readFileSync(join(root, "src", "mxc-sdk", "tests", "mxc_contract", "v1_1_0_alpha", "image_reference_cases.json"), "utf8"));

test("MicroVM schema matches the registry-reference contract on both creation paths", () => {
  const validate = new Ajv({ allErrors: true, strict: false }).compile(schema);
  for (const { image, valid } of cases) {
    for (const provision of [false, true]) {
      const request = {
        version: "1.1.0-alpha",
        containment: "microvm",
        microvm: { image },
        ...(provision ? { phase: "provision" } : { process: { commandLine: "echo" } }),
      };
      assert.equal(validate(request), valid, `${provision ? "provision" : "create-and-run"}: ${JSON.stringify(image)} ${JSON.stringify(validate.errors)}`);
    }
  }
});

test("MicroVM schema handles long image references without excessive backtracking", () => {
  // A separate process bounds a stuck synchronous regex, not normal validation latency.
  const result = spawnSync(process.execPath, ["-e", `
    const assert = require("node:assert/strict");
    const { readFileSync } = require("node:fs");
    const Ajv = require("ajv");
    const schema = JSON.parse(readFileSync(process.argv[1], "utf8"));
    const validate = new Ajv({ allErrors: true, strict: false }).compile(schema);
    const dotted = "a.".repeat(512 * 1024);
    for (const [image, valid] of [
      [dotted, false],
      [dotted + "/", false],
      [dotted + "/repo", true],
      [dotted + "/repo\\n", false],
    ]) {
      for (const provision of [false, true]) {
        const request = {
          version: "1.1.0-alpha",
          containment: "microvm",
          microvm: { image },
          ...(provision ? { phase: "provision" } : { process: { commandLine: "echo" } }),
        };
        assert.equal(validate(request), valid, provision ? "provision" : "create-and-run");
      }
    }
  `, join(root, "schemas", "dev", "mxc-config.schema.1.1.0-alpha.json")], {
    cwd: __dirname,
    encoding: "utf8",
    timeout: 30_000,
  });
  assert.ifError(result.error);
  assert.equal(result.status, 0, result.stdout + result.stderr);
});
