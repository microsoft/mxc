// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

const test = require("node:test");
const assert = require("node:assert/strict");
const { execFileSync, spawnSync } = require("child_process");
const { mkdirSync, mkdtempSync, rmSync, writeFileSync } = require("fs");
const { tmpdir } = require("os");
const { dirname, join, resolve } = require("path");

const SCRIPT = resolve(__dirname, "..", "check-package-lock-integrity.js");
const SHA512 = `sha512-${Buffer.alloc(64).toString("base64")}`;
const SHA1 = `sha1-${Buffer.alloc(20).toString("base64")}`;

function writeJson(path, value) {
  mkdirSync(dirname(path), { recursive: true });
  writeFileSync(path, `${JSON.stringify(value, null, 2)}\n`);
}

function packageLock(packages) {
  return {
    name: "test",
    lockfileVersion: 3,
    packages: {
      "": {},
      ...packages,
    },
  };
}

function runInRepo(populate) {
  const repo = mkdtempSync(join(tmpdir(), "package-lock-integrity-"));
  try {
    execFileSync("git", ["init", "--quiet", repo]);
    execFileSync("git", ["-C", repo, "config", "core.autocrlf", "false"]);
    populate(repo);
    const result = spawnSync(process.execPath, [SCRIPT], {
      cwd: repo,
      encoding: "utf8",
    });
    return {
      status: result.status,
      output: `${result.stdout}${result.stderr}`,
    };
  } finally {
    rmSync(repo, { recursive: true, force: true });
  }
}

function track(repo, ...paths) {
  execFileSync("git", ["-C", repo, "add", "--", ...paths]);
}

test("accepts npmjs SHA-512 artifacts and repository-relative dependencies", () => {
  const result = runInRepo((repo) => {
    mkdirSync(join(repo, "packages", "library"), { recursive: true });
    mkdirSync(join(repo, "packages", "app", "local-package"), {
      recursive: true,
    });
    mkdirSync(join(repo, "sdk", "node"), { recursive: true });
    writeJson(
      join(repo, "packages", "app", "package-lock.json"),
      packageLock({
        "node_modules/remote": {
          resolved: "https://registry.npmjs.org/remote/-/remote-1.0.0.tgz",
          integrity: SHA512,
        },
        "node_modules/local": {
          resolved: "file:../library",
        },
        "node_modules/library-link": {
          resolved: "../library",
          link: true,
        },
        "node_modules/local-without-dot": {
          resolved: "file:local-package",
        },
        "node_modules/relative": {
          resolved: "../../sdk/node",
        },
        "node_modules/bundled": {
          version: "1.0.0",
          inBundle: true,
        },
        "../library": {
          name: "library",
          version: "1.0.0",
        },
      })
    );
    track(repo, "packages/app/package-lock.json");
  });

  assert.equal(result.status, 0, result.output);
  assert.match(result.output, /OK: 1 tracked lockfile\(s\)/);
});

test("rejects non-npmjs sources and weak or missing integrity", () => {
  const result = runInRepo((repo) => {
    writeJson(
      join(repo, "packages", "app", "package-lock.json"),
      packageLock({
        "node_modules/internal": {
          resolved:
            "https://ms-feed-25.pkgs.visualstudio.com/1es-public/_packaging/npm-public/npm/registry/internal/-/internal-1.0.0.tgz",
          integrity: SHA512,
        },
        "node_modules/other-registry": {
          resolved: "https://packages.example.com/other-1.0.0.tgz",
          integrity: SHA512,
        },
        "node_modules/git": {
          resolved: "git+ssh://git@example.com/package.git",
        },
        "node_modules/sha1": {
          resolved: "https://registry.npmjs.org/sha1/-/sha1-1.0.0.tgz",
          integrity: SHA1,
        },
        "node_modules/missing": {
          resolved: "https://registry.npmjs.org/missing/-/missing-1.0.0.tgz",
        },
        "node_modules/outside": {
          resolved: "file:../../../outside",
        },
        "node_modules/drive-relative": {
          resolved: "file:C:outside",
        },
        "node_modules/home-relative": {
          resolved: "file:~/outside",
        },
        "node_modules/hosted-git-shorthand": {
          resolved: "owner/repo",
        },
        "node_modules/no-resolved": {
          integrity: SHA512,
        },
      })
    );
    track(repo, "packages/app/package-lock.json");
  });

  assert.equal(result.status, 1, result.output);
  assert.match(result.output, /lacks a valid SHA-512 hash/);
  assert.match(
    result.output,
    /must use https:\/\/registry\.npmjs\.org or resolve within the repository/
  );
  assert.match(result.output, /npmjs artifact lacks a SHA-512 hash/);
  for (const packageName of [
    "outside",
    "drive-relative",
    "home-relative",
    "hosted-git-shorthand",
  ]) {
    assert.match(
      result.output,
      new RegExp(
        String.raw`\$\["packages"\]\["node_modules/${packageName}"\]\["resolved"\]`
      )
    );
  }
  assert.match(
    result.output,
    /\$\["packages"\]\["node_modules\/no-resolved"\]\["resolved"\]: installed package must declare/
  );
});

test("ignores untracked package locks", () => {
  const result = runInRepo((repo) => {
    writeJson(
      join(repo, "package-lock.json"),
      packageLock({
        "node_modules/remote": {
          resolved: "https://registry.npmjs.org/remote/-/remote-1.0.0.tgz",
          integrity: SHA512,
        },
      })
    );
    writeJson(
      join(repo, "untracked", "package-lock.json"),
      packageLock({
        "node_modules/internal": {
          resolved:
            "https://ms-feed-25.pkgs.visualstudio.com/feed/package.tgz",
          integrity: SHA1,
        },
      })
    );
    track(repo, "package-lock.json");
  });

  assert.equal(result.status, 0, result.output);
  assert.match(result.output, /OK: 1 tracked lockfile\(s\)/);
});
