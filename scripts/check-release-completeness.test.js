// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.
//
//   node --test scripts/check-release-completeness.test.js

const { test } = require("node:test");
const assert = require("node:assert");
const { join } = require("node:path");
const { checkReleaseCompleteness } = require("./check-release-completeness.js");

const META = "meta/package.json";
const PKGS = "platform-packages";
const TARS = "tarballs";

// Build an injectable fake filesystem.
//   platformPackages: { <dir>: { name, version, files? } | null }  (null = dir w/o package.json)
//   optionalDependencies: meta optionalDependencies map
//   tarballs: string[] of files in the tarball dir
//   payloadOnDisk: { <dir>: string[] } payload files staged on disk in that pkg dir
//   malformed: string[] of dirs whose package.json is unparseable
function fixture({
  optionalDependencies = {},
  platformPackages = {},
  tarballs = [],
  payloadOnDisk = {},
  malformed = [],
}) {
  const files = new Map();
  files.set(META, JSON.stringify({ optionalDependencies }));
  for (const [dir, pkg] of Object.entries(platformPackages)) {
    if (pkg !== null) files.set(join(PKGS, dir, "package.json"), JSON.stringify(pkg));
  }
  for (const dir of malformed) {
    files.set(join(PKGS, dir, "package.json"), "{ this is not valid json");
  }
  for (const [dir, payload] of Object.entries(payloadOnDisk)) {
    for (const f of payload) files.set(join(PKGS, dir, f), "<binary>");
  }
  return {
    metaPkgPath: META,
    platformPackagesDir: PKGS,
    tarballDir: TARS,
    readFileSync: (p) => {
      if (!files.has(p)) throw new Error(`ENOENT ${p}`);
      return files.get(p);
    },
    existsSync: (p) => p === PKGS || p === TARS || files.has(p),
    readdirSync: (p) => {
      if (p === PKGS) return [...Object.keys(platformPackages), ...malformed];
      if (p === TARS) return tarballs;
      return [];
    },
  };
}

const PLATFORM_PACKAGES = {
  "win32-x64": { name: "@microsoft/mxc-sdk-win32-x64", version: "0.7.0" },
  "linux-x64": { name: "@microsoft/mxc-sdk-linux-x64", version: "0.7.0" },
};
const OPT = {
  "@microsoft/mxc-sdk-win32-x64": "0.7.0",
  "@microsoft/mxc-sdk-linux-x64": "0.7.0",
};

test("ok when every on-disk package is pinned and packed with no extras", () => {
  const r = checkReleaseCompleteness(
    fixture({
      optionalDependencies: OPT,
      platformPackages: PLATFORM_PACKAGES,
      tarballs: [
        "microsoft-mxc-sdk-win32-x64-0.7.0.tgz",
        "microsoft-mxc-sdk-linux-x64-0.7.0.tgz",
      ],
    }),
  );
  assert.strictEqual(r.ok, true);
  assert.strictEqual(r.expected, 2);
});

test("fails (empty) when there are no platform packages on disk", () => {
  const r = checkReleaseCompleteness(
    fixture({ optionalDependencies: {}, platformPackages: {}, tarballs: [] }),
  );
  assert.strictEqual(r.ok, false);
  assert.strictEqual(r.expected, 0);
});

test("fails when an expected platform tarball is missing", () => {
  const r = checkReleaseCompleteness(
    fixture({
      optionalDependencies: OPT,
      platformPackages: PLATFORM_PACKAGES,
      tarballs: ["microsoft-mxc-sdk-win32-x64-0.7.0.tgz"],
    }),
  );
  assert.strictEqual(r.ok, false);
  assert.deepStrictEqual(r.missing, ["microsoft-mxc-sdk-linux-x64-0.7.0.tgz"]);
});

test("fails when ANY stray tarball is present (including non-mxc)", () => {
  const r = checkReleaseCompleteness(
    fixture({
      optionalDependencies: { "@microsoft/mxc-sdk-win32-x64": "0.7.0" },
      platformPackages: {
        "win32-x64": { name: "@microsoft/mxc-sdk-win32-x64", version: "0.7.0" },
      },
      tarballs: [
        "microsoft-mxc-sdk-win32-x64-0.7.0.tgz",
        "some-other-lib-1.0.0.tgz", // must be rejected, not ignored
      ],
    }),
  );
  assert.strictEqual(r.ok, false);
  assert.deepStrictEqual(r.extra, ["some-other-lib-1.0.0.tgz"]);
});

test("fails when meta pins the wrong version for an on-disk package", () => {
  const r = checkReleaseCompleteness(
    fixture({
      optionalDependencies: { "@microsoft/mxc-sdk-win32-x64": "0.8.0" },
      platformPackages: {
        "win32-x64": { name: "@microsoft/mxc-sdk-win32-x64", version: "0.7.0" },
      },
      tarballs: ["microsoft-mxc-sdk-win32-x64-0.7.0.tgz"],
    }),
  );
  assert.strictEqual(r.ok, false);
  assert.strictEqual(r.pinIssues.length, 1);
});

test("fails when meta is missing a pin for an on-disk package", () => {
  const r = checkReleaseCompleteness(
    fixture({
      optionalDependencies: {}, // win32 not pinned at all
      platformPackages: {
        "win32-x64": { name: "@microsoft/mxc-sdk-win32-x64", version: "0.7.0" },
      },
      tarballs: ["microsoft-mxc-sdk-win32-x64-0.7.0.tgz"],
    }),
  );
  assert.strictEqual(r.ok, false);
  assert.strictEqual(r.pinIssues.length, 1);
});

test("fails when meta pins a zombie package with no on-disk source", () => {
  const r = checkReleaseCompleteness(
    fixture({
      optionalDependencies: {
        "@microsoft/mxc-sdk-win32-x64": "0.7.0",
        "@microsoft/mxc-sdk-darwin-x64": "0.7.0", // no on-disk dir
      },
      platformPackages: {
        "win32-x64": { name: "@microsoft/mxc-sdk-win32-x64", version: "0.7.0" },
      },
      tarballs: ["microsoft-mxc-sdk-win32-x64-0.7.0.tgz"],
    }),
  );
  assert.strictEqual(r.ok, false);
  assert.ok(r.pinIssues.some((p) => p.includes("darwin-x64")));
});

test("ignores non-tgz files in the tarball dir", () => {
  const r = checkReleaseCompleteness(
    fixture({
      optionalDependencies: { "@microsoft/mxc-sdk-win32-x64": "0.7.0" },
      platformPackages: {
        "win32-x64": { name: "@microsoft/mxc-sdk-win32-x64", version: "0.7.0" },
      },
      tarballs: ["microsoft-mxc-sdk-win32-x64-0.7.0.tgz", "README.md"],
    }),
  );
  assert.strictEqual(r.ok, true);
});

test("skips platform-package dirs without a package.json", () => {
  const r = checkReleaseCompleteness(
    fixture({
      optionalDependencies: { "@microsoft/mxc-sdk-win32-x64": "0.7.0" },
      platformPackages: {
        "win32-x64": { name: "@microsoft/mxc-sdk-win32-x64", version: "0.7.0" },
        "node_modules": null, // stray dir, no package.json
      },
      tarballs: ["microsoft-mxc-sdk-win32-x64-0.7.0.tgz"],
    }),
  );
  assert.strictEqual(r.ok, true);
  assert.strictEqual(r.expected, 1);
});

test("rejects a NESTED stray .tgz (recursive scan, round-3 P1-2)", () => {
  // Model a tarball dir with a top-level expected tarball and a nested stray
  // one under a subdir; the recursive walk must surface the nested file.
  const metaJson = JSON.stringify({
    optionalDependencies: { "@microsoft/mxc-sdk-win32-x64": "0.7.0" },
  });
  const pkgJson = JSON.stringify({ name: "@microsoft/mxc-sdk-win32-x64", version: "0.7.0" });
  const tree = {
    [TARS]: ["microsoft-mxc-sdk-win32-x64-0.7.0.tgz", "evil"],
    [join(TARS, "evil")]: ["smuggled-1.0.0.tgz"],
    [PKGS]: ["win32-x64"],
  };
  const dirs = new Set([TARS, join(TARS, "evil"), PKGS]);
  const r = checkReleaseCompleteness({
    metaPkgPath: META,
    platformPackagesDir: PKGS,
    tarballDir: TARS,
    readFileSync: (p) => {
      if (p === META) return metaJson;
      if (p === join(PKGS, "win32-x64", "package.json")) return pkgJson;
      throw new Error(`ENOENT ${p}`);
    },
    existsSync: (p) => dirs.has(p) || p === join(PKGS, "win32-x64", "package.json"),
    readdirSync: (p) => tree[p] ?? [],
    statSync: (p) => ({ isDirectory: () => dirs.has(p) }),
  });
  assert.strictEqual(r.ok, false);
  assert.deepStrictEqual(r.extra, ["evil/smuggled-1.0.0.tgz"]);
});

test("ok when a package with a files[] payload has every payload file staged on disk (F2)", () => {
  const r = checkReleaseCompleteness(
    fixture({
      optionalDependencies: { "@microsoft/mxc-sdk-win32-x64": "0.7.0" },
      platformPackages: {
        "win32-x64": {
          name: "@microsoft/mxc-sdk-win32-x64",
          version: "0.7.0",
          files: ["wxc-exec.exe", "nanvixd.exe", "bin/kernel.elf", "README.md"],
        },
      },
      payloadOnDisk: { "win32-x64": ["wxc-exec.exe", "nanvixd.exe", "bin/kernel.elf"] },
      tarballs: ["microsoft-mxc-sdk-win32-x64-0.7.0.tgz"],
    }),
  );
  assert.strictEqual(r.ok, true);
  assert.deepStrictEqual(r.payloadMissing, []);
});

test("fails when an allowlisted payload file is not staged on disk (F2 — silent npm-pack omission)", () => {
  const r = checkReleaseCompleteness(
    fixture({
      optionalDependencies: { "@microsoft/mxc-sdk-win32-x64": "0.7.0" },
      platformPackages: {
        "win32-x64": {
          name: "@microsoft/mxc-sdk-win32-x64",
          version: "0.7.0",
          // The win32-x64 manifest requires the micro-VM payload.
          files: ["wxc-exec.exe", "nanvixd.exe", "bin/kernel.elf", "README.md"],
        },
      },
      // Only the primary executor was staged (e.g. an official build that copies
      // signPattern but not the micro-VM payload); nanvixd.exe + kernel.elf absent.
      payloadOnDisk: { "win32-x64": ["wxc-exec.exe"] },
      tarballs: ["microsoft-mxc-sdk-win32-x64-0.7.0.tgz"],
    }),
  );
  assert.strictEqual(r.ok, false);
  assert.deepStrictEqual(r.payloadMissing, ["win32-x64/nanvixd.exe", "win32-x64/bin/kernel.elf"]);
});

test("fails (does NOT silently skip) when a platform manifest is malformed (F3)", () => {
  const r = checkReleaseCompleteness(
    fixture({
      optionalDependencies: { "@microsoft/mxc-sdk-win32-x64": "0.7.0" },
      platformPackages: {
        "win32-x64": { name: "@microsoft/mxc-sdk-win32-x64", version: "0.7.0" },
      },
      malformed: ["linux-x64"], // corrupt package.json must not be dropped
      tarballs: ["microsoft-mxc-sdk-win32-x64-0.7.0.tgz"],
    }),
  );
  assert.strictEqual(r.ok, false);
  assert.deepStrictEqual(r.malformed, ["linux-x64/package.json"]);
});

