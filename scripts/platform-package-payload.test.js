// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.
//
//   node --test scripts/platform-package-payload.test.js

const { test } = require("node:test");
const assert = require("node:assert");
const { payloadFiles } = require("./platform-package-payload.js");

function fakeManifest(files) {
  return { readFileSync: () => JSON.stringify({ files }) };
}

test("returns the build-artifact files in manifest order", () => {
  const r = payloadFiles(
    "m",
    fakeManifest(["wxc-exec.exe", "bin/kernel.elf", "snapshots/kernel.vmem", "README.md"]),
  );
  assert.deepStrictEqual(r, ["wxc-exec.exe", "bin/kernel.elf", "snapshots/kernel.vmem"]);
});

test("excludes README.md (tracked, not a build artifact)", () => {
  const r = payloadFiles("m", fakeManifest(["wxc-exec.exe", "README.md"]));
  assert.deepStrictEqual(r, ["wxc-exec.exe"]);
});

test("tolerates a missing/empty files array", () => {
  assert.deepStrictEqual(payloadFiles("m", { readFileSync: () => "{}" }), []);
});

test("ignores non-string entries", () => {
  const r = payloadFiles("m", { readFileSync: () => JSON.stringify({ files: ["a.exe", 5, null] }) });
  assert.deepStrictEqual(r, ["a.exe"]);
});
