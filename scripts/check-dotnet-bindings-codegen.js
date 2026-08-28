#!/usr/bin/env node
// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

// Generation check for the C# P/Invoke layer. The generated file
// (NativeMethods.g.cs) is NOT committed — it is produced at build time by the
// GenerateNativeBindings MSBuild target (and by `cargo build -p mxc_ffi
// --features dotnetsdk`). This gate rebuilds the FFI with codegen enabled and
// asserts the bindings are produced and expose the expected entry points, so a
// broken/renamed C ABI is caught in CI even though nothing is committed. Run
// from the repository root:
//
//   node scripts/check-dotnet-bindings-codegen.js

const { readFileSync, existsSync, readdirSync, rmSync, statSync } = require("fs");
const { join } = require("path");
const { execFileSync } = require("child_process");
const { scanBuildRs } = require("./versioning/lib/build-rs-inputs");

const repoRoot = join(__dirname, "..");
const generated = join(
  repoRoot,
  "sdk",
  "dotnet",
  "Microsoft.Mxc.Sdk",
  "Native",
  "NativeMethods.g.cs"
);

function listFiles(directory) {
  return readdirSync(directory).flatMap((name) => {
    const path = join(directory, name);
    if (statSync(path).isDirectory()) {
      return ["bin", "obj", "runtimes"].includes(name) ? [] : listFiles(path);
    }
    return [path];
  });
}

// Derive the required set from every hand-written managed call site. This
// avoids a curated smoke-test list drifting behind a newly consumed native
// entry point. The generated file is excluded because it is the output under
// test.
const managedSource = join(repoRoot, "sdk", "dotnet", "Microsoft.Mxc.Sdk");
const REQUIRED_ENTRY_POINTS = [
  ...new Set(
    listFiles(managedSource)
      .filter((path) => path.endsWith(".cs") && path !== generated)
      .flatMap((path) => [
        ...readFileSync(path, "utf8").matchAll(/NativeMethods\.(mxc_\w+)/g),
      ])
      .map((match) => match[1])
  ),
].sort();
if (REQUIRED_ENTRY_POINTS.length === 0) {
  console.error("ERROR: found no NativeMethods.mxc_* call sites in the C# SDK");
  process.exit(1);
}

// Remove any stale copy so we prove codegen actually (re)produces it.
if (existsSync(generated)) {
  rmSync(generated);
}

try {
  execFileSync("cargo", ["build", "-p", "mxc_ffi", "--features", "dotnetsdk"], {
    cwd: join(repoRoot, "src"),
    stdio: "inherit",
  });
} catch (e) {
  console.error(
    `ERROR: 'cargo build -p mxc_ffi --features dotnetsdk' failed: ${e.message}`
  );
  process.exit(1);
}

if (!existsSync(generated)) {
  console.error(
    `ERROR: binding generation did not produce the expected file:\n  ${generated}`
  );
  process.exit(1);
}

const content = readFileSync(generated, "utf8");
const missing = REQUIRED_ENTRY_POINTS.filter(
  (name) => !content.includes(`EntryPoint = "${name}"`)
);
if (missing.length > 0) {
  console.error(
    "ERROR: generated C# bindings are missing expected entry point(s): " +
      missing.join(", ")
  );
  process.exit(1);
}

// build.rs names the same set of Rust sources twice: once for csbindgen to
// read, and once as `cargo:rerun-if-changed`. Emitting any `rerun-if-changed`
// replaces cargo's default "re-run when any package file changed" with exactly
// the declared set, so a csbindgen input missing from that set leaves the build
// script un-run and the bindings stale while the crate itself recompiles.
const buildRs = readFileSync(
  join(repoRoot, "src", "ffi", "mxc_ffi", "build.rs"),
  "utf8"
);

const { csbindgenInputs, unparseable, declaredInputs } = scanBuildRs(buildRs);

if (csbindgenInputs.length === 0 && unparseable.length === 0) {
  console.error(
    "ERROR: found no `.input_extern_file(...)` calls in src/ffi/mxc_ffi/build.rs.\n" +
      "  The parity check cannot be trusted; has the codegen setup changed?"
  );
  process.exit(1);
}

if (unparseable.length > 0) {
  console.error(
    "ERROR: could not read the argument of some `.input_extern_file(...)` call(s)\n" +
      "in src/ffi/mxc_ffi/build.rs, so this gate cannot prove the\n" +
      "`rerun-if-changed` list covers them:\n" +
      unparseable.map((s) => `  - .input_extern_file(${s}`).join("\n") +
      "\n\nUse a plain string literal, or teach this check the new form."
  );
  process.exit(1);
}

if (declaredInputs.length === 0) {
  console.error(
    "ERROR: found no `cargo:rerun-if-changed=` lines in src/ffi/mxc_ffi/build.rs.\n" +
      "  Without them cargo re-runs the build script on any change to the crate,\n" +
      "  which this check assumes is not the case."
  );
  process.exit(1);
}

const notDeclared = csbindgenInputs.filter(
  (rel) => !declaredInputs.includes(rel)
);
if (notDeclared.length > 0) {
  console.error(
    "ERROR: Rust source(s) read by csbindgen are not declared as\n" +
      "`cargo:rerun-if-changed`, so editing one leaves the generated bindings\n" +
      "stale:\n" +
      notDeclared.map((p) => `  - ${p}`).join("\n") +
      "\n\nAdd each to the `rerun-if-changed` list in\n" +
      "  src/ffi/mxc_ffi/build.rs"
  );
  process.exit(1);
}

console.log(
  `C# bindings codegen OK: generated every one of ${REQUIRED_ENTRY_POINTS.length} managed entry points; ` +
    `${csbindgenInputs.length} csbindgen source(s) all declared as rerun-if-changed`
);
