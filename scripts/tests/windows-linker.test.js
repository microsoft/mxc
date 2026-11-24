// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

const test = require("node:test");
const assert = require("node:assert/strict");
const { spawnSync } = require("node:child_process");
const { existsSync, mkdtempSync, readFileSync, rmSync, writeFileSync } = require("node:fs");
const { tmpdir } = require("node:os");
const { join, resolve } = require("node:path");

const root = resolve(__dirname, "..", "..");
const source = join(root, "src");

function run(command, args, cwd = source) {
  const result = spawnSync(command, args, {
    cwd, encoding: "utf8", timeout: 60_000,
  });
  assert.ifError(result.error);
  assert.equal(result.status, 0, result.stdout + result.stderr);
  return result.stdout + result.stderr;
}

test("the pinned Windows linker produces interoperable DLLs, executables, and PDBs", () => {
  const directory = mkdtempSync(join(tmpdir(), "mxc-windows-linker-"));
  try {
    const hostTriple = run("rustc", ["-vV"]).match(/^host: (\S+)/m)[1];
    const target = process.env.MXC_RUST_TEST_TARGET || hostTriple;
    const sysroot = run("rustc", ["--print", "sysroot"]).trim();
    const environment = join(directory, "github-env");
    const setup = join(root, ".github", "actions", "setup-windows-linker", "setup.ps1");
    run("pwsh", ["-NoProfile", "-File", setup, "-Target", target,
      "-EnvironmentFile", environment], root);
    const entry = readFileSync(environment, "utf8").trim();
    const key = "CARGO_TARGET_" + target.toUpperCase().replaceAll("-", "_") + "_LINKER=";
    assert.ok(entry.startsWith(key), entry);
    const linker = entry.slice(key.length);
    assert.ok(existsSync(linker));
    assert.equal(linker.toLowerCase(),
      join(sysroot, "lib", "rustlib", hostTriple, "bin", "rust-lld.exe").toLowerCase(),
      "linker selection must use src/rust-toolchain.toml even when invoked from the repository root");
    const common = ["--edition=2021", "--target", target,
      "-C", `linker=${linker}`, "-C", "opt-level=3", "-C", "debuginfo=2",
      "-C", "split-debuginfo=packed"];
    const library = join(directory, "library.rs");
    writeFileSync(library, '#[no_mangle]\npub extern "C" fn answer() -> u32 { 42 }\n');
    run("rustc", [...common, "--crate-name", "mxc_link_fixture", "--crate-type", "cdylib",
      library, "-o", join(directory, "mxc_link_fixture.dll")]);
    const program = join(directory, "program.rs");
    writeFileSync(program,
      '#[link(name = "mxc_link_fixture.dll")]\n' +
      'extern "C" { fn answer() -> u32; }\n' +
      'fn main() { assert_eq!(unsafe { answer() }, 42); println!("DLL interop passed"); }\n');
    const executable = join(directory, "program.exe");
    run("rustc", [...common, program, "-L", `native=${directory}`, "-o", executable]);
    assert.match(run(executable, [], directory), /DLL interop passed/);
    assert.ok(existsSync(join(directory, "mxc_link_fixture.pdb")), "DLL debug symbols are required");
    assert.ok(existsSync(join(directory, "program.pdb")), "executable debug symbols are required");
  } finally {
    rmSync(directory, { recursive: true, force: true });
  }
});
