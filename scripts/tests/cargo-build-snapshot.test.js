// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

const test = require("node:test");
const assert = require("node:assert/strict");
const { spawnSync } = require("node:child_process");
const {
  mkdirSync, mkdtempSync, readFileSync, rmSync, statSync, utimesSync, writeFileSync,
} = require("node:fs");
const { tmpdir } = require("node:os");
const { join, resolve } = require("node:path");

const root = resolve(__dirname, "..", "..");
const helper = join(root, "scripts", "ci", "cargo-build-snapshot.ps1");

function run(command, args, cwd, env = process.env) {
  const result = spawnSync(command, args, {
    cwd, env, encoding: "utf8", timeout: 60_000,
  });
  assert.ifError(result.error);
  assert.equal(result.status, 0, result.stdout + result.stderr);
  return result.stdout + result.stderr;
}

test("restoring a shared build preserves Cargo freshness after a fresh source checkout", () => {
  const scratch = mkdtempSync(join(tmpdir(), "mxc-cargo-snapshot-"));
  const repository = join(scratch, "repository");
  const source = join(repository, "src");
  const library = join(source, "src", "lib.rs");
  const gitHead = join(repository, ".git", "HEAD");
  const archive = join(scratch, "build.tar");
  mkdirSync(join(source, "src"), { recursive: true });
  writeFileSync(join(source, "Cargo.toml"),
    '[package]\nname = "snapshot-fixture"\nversion = "0.1.0"\nedition = "2021"\n');
  writeFileSync(library, "pub fn answer() -> u32 { 42 }\n");
  writeFileSync(join(source, "build.rs"),
    'fn main() {\n' +
    '    println!("cargo:rerun-if-changed=build.rs");\n' +
    '    println!("cargo:rerun-if-changed=../.git/HEAD");\n' +
    '}\n');
  const env = { ...process.env, CARGO_TARGET_DIR: join(source, "target") };
  try {
    run("git", ["init", "--quiet"], repository);
    const host = run("rustc", ["-vV"], source).match(/^host: (\S+)/m)[1];
    const build = ["build", "--offline", "--release", "--target", host, "-vv"];
    assert.match(run("cargo", build, source, env), /Compiling snapshot-fixture/);
    run("git", ["add", "."], repository);
    const before = statSync(library).mtimeMs;
    const headBefore = statSync(gitHead).mtimeMs;
    run("pwsh", ["-NoProfile", "-File", helper, "-Mode", "Save",
      "-Archive", archive, "-Target", host, "-RepositoryRoot", repository], root);
    rmSync(join(source, "target"), { recursive: true, force: true });
    const later = new Date(Date.now() + 10_000);
    utimesSync(library, later, later);
    utimesSync(gitHead, later, later);
    run("pwsh", ["-NoProfile", "-File", helper, "-Mode", "Restore",
      "-Archive", archive, "-Target", host, "-RepositoryRoot", repository], root);
    assert.ok(Math.abs(statSync(library).mtimeMs - before) < 1,
      "source timestamps must survive transfer, not force a rebuild");
    const output = run("cargo", build, source, env);
    assert.match(output, /Fresh snapshot-fixture/);
    assert.doesNotMatch(output, /Compiling snapshot-fixture/);
    assert.ok(Math.abs(statSync(gitHead).mtimeMs - headBefore) < 1,
      "matching Git build inputs must keep their producing timestamps");
    assert.equal(readFileSync(library, "utf8"), "pub fn answer() -> u32 { 42 }\n");
    const changedHead = "ref: refs/heads/different-checkout\n";
    writeFileSync(gitHead, changedHead);
    const rejected = spawnSync("pwsh", ["-NoProfile", "-File", helper, "-Mode", "Restore",
      "-Archive", archive, "-Target", host, "-RepositoryRoot", repository], {
      cwd: root, encoding: "utf8", timeout: 30_000,
    });
    assert.ifError(rejected.error);
    assert.notEqual(rejected.status, 0);
    assert.match(rejected.stdout + rejected.stderr, /snapshot Git input differs/);
    assert.equal(readFileSync(gitHead, "utf8"), changedHead,
      "restoring a snapshot must never overwrite Git history or references");
  } finally {
    rmSync(scratch, { recursive: true, force: true });
  }
});
