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

test("rejects a missing or empty files array", () => {
  assert.throws(
    () => payloadFiles("m", { readFileSync: () => "{}" }),
    /files must be a non-empty array/,
  );
  assert.throws(
    () => payloadFiles("m", fakeManifest([])),
    /files must be a non-empty array/,
  );
});

test("rejects non-string or empty entries", () => {
  assert.throws(
    () => payloadFiles("m", fakeManifest(["a.exe", 5, null])),
    /files entries must be non-empty strings/,
  );
  assert.throws(
    () => payloadFiles("m", fakeManifest(["a.exe", ""])),
    /files entries must be non-empty strings/,
  );
});

test("rejects a files array with no build artifacts", () => {
  assert.throws(
    () => payloadFiles("m", fakeManifest(["README.md"])),
    /files must include at least one build artifact/,
  );
});
