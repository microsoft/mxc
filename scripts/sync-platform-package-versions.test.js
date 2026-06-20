// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

// Unit tests for the platform-package version-sync logic. Runs against hermetic
// temp-dir fixtures so it never touches the real working tree.
//
//   node --test scripts/sync-platform-package-versions.test.js

const { test } = require("node:test");
const assert = require("node:assert");
const fs = require("fs");
const os = require("os");
const path = require("path");

const {
  syncPlatformPackageVersions,
} = require("./sync-platform-package-versions.js");

/**
 * Build a temp repo fixture: sdk/package.json at `metaVersion` plus one
 * sdk/platform-packages/<name>/package.json per entry in `packages`
 * ({ name, version }). Extra raw dirs/files can be created via `extras`.
 */
function makeFixture(metaVersion, packages, extras = {}) {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), "sync-ver-"));
  const ppDir = path.join(root, "sdk", "platform-packages");
  fs.mkdirSync(ppDir, { recursive: true });
  fs.writeFileSync(
    path.join(root, "sdk", "package.json"),
    JSON.stringify({ name: "@microsoft/mxc-sdk", version: metaVersion }, null, 2) + "\n",
  );
  for (const p of packages) {
    const dir = path.join(ppDir, p.dir);
    fs.mkdirSync(dir, { recursive: true });
    if (p.omitManifest) continue;
    fs.writeFileSync(
      path.join(dir, "package.json"),
      JSON.stringify({ name: `@microsoft/mxc-sdk-${p.dir}`, version: p.version }, null, 2) + "\n",
    );
  }
  for (const [rel, contents] of Object.entries(extras)) {
    const full = path.join(ppDir, rel);
    fs.mkdirSync(path.dirname(full), { recursive: true });
    fs.writeFileSync(full, contents);
  }
  return root;
}

function readVersion(root, dir) {
  const p = path.join(root, "sdk", "platform-packages", dir, "package.json");
  return JSON.parse(fs.readFileSync(p, "utf8")).version;
}

function cleanup(root) {
  fs.rmSync(root, { recursive: true, force: true });
}

test("aligned packages: check passes, no drift, no writes", () => {
  const root = makeFixture("0.7.0", [
    { dir: "win32-x64", version: "0.7.0" },
    { dir: "linux-x64", version: "0.7.0" },
  ]);
  try {
    const r = syncPlatformPackageVersions({ repoRoot: root, check: true });
    assert.strictEqual(r.ok, true);
    assert.deepStrictEqual(r.drifted, []);
    assert.strictEqual(r.checked, 2);
    assert.strictEqual(r.errors.length, 0);
  } finally {
    cleanup(root);
  }
});

test("drift in check mode: ok=false, drift listed, file unchanged", () => {
  const root = makeFixture("0.7.0", [
    { dir: "win32-x64", version: "0.6.0" },
    { dir: "linux-x64", version: "0.7.0" },
  ]);
  try {
    const r = syncPlatformPackageVersions({ repoRoot: root, check: true });
    assert.strictEqual(r.ok, false);
    assert.deepStrictEqual(r.drifted, ["@microsoft/mxc-sdk-win32-x64"]);
    assert.deepStrictEqual(r.stamped, []);
    // check mode must not write
    assert.strictEqual(readVersion(root, "win32-x64"), "0.6.0");
  } finally {
    cleanup(root);
  }
});

test("drift in stamp mode: rewrites drifted package to meta version", () => {
  const root = makeFixture("0.7.0", [
    { dir: "win32-x64", version: "0.6.0" },
    { dir: "linux-arm64", version: "0.7.0" },
  ]);
  try {
    const r = syncPlatformPackageVersions({ repoRoot: root, check: false });
    assert.strictEqual(r.ok, true);
    assert.deepStrictEqual(r.stamped, ["@microsoft/mxc-sdk-win32-x64"]);
    assert.strictEqual(readVersion(root, "win32-x64"), "0.7.0");
    assert.strictEqual(readVersion(root, "linux-arm64"), "0.7.0");
  } finally {
    cleanup(root);
  }
});

test("non-platform directories are ignored", () => {
  const root = makeFixture(
    "0.7.0",
    [{ dir: "win32-x64", version: "0.7.0" }],
    { "node_modules/.keep": "x", ".git/HEAD": "ref: refs/heads/x" },
  );
  try {
    const r = syncPlatformPackageVersions({ repoRoot: root, check: true });
    assert.strictEqual(r.ok, true);
    assert.strictEqual(r.checked, 1);
    assert.strictEqual(r.errors.length, 0);
  } finally {
    cleanup(root);
  }
});

test("a dir without our package.json is skipped (not a platform package)", () => {
  // Filesystem is the source of truth: only dirs whose package.json names an
  // @microsoft/mxc-sdk-* package count. A dir without one is ignored, and the
  // real platform package is still stamped.
  const root = makeFixture(
    "0.7.0",
    [
      { dir: "win32-x64", version: "0.6.0" }, // real package, drifts → stamped
      { dir: "tooling", omitManifest: true }, // not a platform package → ignored
    ],
    {},
    { optionalDependencies: { "@microsoft/mxc-sdk-win32-x64": "0.7.0" } },
  );
  try {
    const r = syncPlatformPackageVersions({ repoRoot: root, check: false });
    assert.strictEqual(r.ok, true);
    assert.deepStrictEqual(r.errors, []);
    assert.deepStrictEqual(r.stamped, ["@microsoft/mxc-sdk-win32-x64"]);
    assert.strictEqual(r.checked, 1);
    assert.strictEqual(readVersion(root, "win32-x64"), "0.7.0");
  } finally {
    cleanup(root);
  }
});

test("a foreign package.json (not @microsoft/mxc-sdk-*) is skipped", () => {
  const root = makeFixture(
    "0.7.0",
    [{ dir: "win32-x64", version: "0.7.0" }],
    { "vendor/package.json": JSON.stringify({ name: "some-vendor-lib", version: "1.2.3" }) },
  );
  try {
    const r = syncPlatformPackageVersions({ repoRoot: root, check: true });
    assert.strictEqual(r.ok, true);
    assert.strictEqual(r.checked, 1);
    assert.deepStrictEqual(r.errors, []);
  } finally {
    cleanup(root);
  }
});

test("invalid meta version is rejected before any work", () => {
  const root = makeFixture("v0.7", [{ dir: "win32-x64", version: "0.7.0" }]);
  try {
    const r = syncPlatformPackageVersions({ repoRoot: root, check: true });
    assert.strictEqual(r.ok, false);
    assert.ok(r.errors.some((e) => e.includes("not a valid semver")));
  } finally {
    cleanup(root);
  }
});

test("invalid platform package version is an error (not stamped over)", () => {
  const root = makeFixture("0.7.0", [
    { dir: "win32-x64", version: "0.7..0" },
  ]);
  try {
    const r = syncPlatformPackageVersions({ repoRoot: root, check: false });
    assert.strictEqual(r.ok, false);
    assert.ok(r.errors.some((e) => e.includes("not a valid semver")));
    assert.deepStrictEqual(r.stamped, []);
  } finally {
    cleanup(root);
  }
});

test("prerelease meta version stamps cleanly", () => {
  const root = makeFixture("0.8.0-alpha", [
    { dir: "darwin-arm64", version: "0.7.0" },
  ]);
  try {
    const r = syncPlatformPackageVersions({ repoRoot: root, check: false });
    assert.strictEqual(r.ok, true);
    assert.strictEqual(readVersion(root, "darwin-arm64"), "0.8.0-alpha");
  } finally {
    cleanup(root);
  }
});
