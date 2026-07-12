#!/usr/bin/env node
// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

// Drift gate for the generated C# P/Invoke layer. Rebuilds `mxc_ffi` (whose
// build.rs regenerates NativeMethods.g.cs via csbindgen) and fails if the
// committed file changed — i.e. the checked-in bindings drifted from the Rust
// FFI. Run from the repository root:
//
//   node scripts/check-csharp-bindings-codegen.js

const { readFileSync, existsSync } = require("fs");
const { join } = require("path");
const { execFileSync } = require("child_process");

const repoRoot = join(__dirname, "..");
const generated = join(
  repoRoot,
  "csharp",
  "Microsoft.Mxc.Sdk",
  "Native",
  "NativeMethods.g.cs"
);

function read(path) {
  return existsSync(path) ? readFileSync(path, "utf8") : null;
}

const before = read(generated);

try {
  // build.rs regenerates the C# file as a side effect of building the crate.
  execFileSync("cargo", ["build", "-p", "mxc_ffi"], {
    cwd: join(repoRoot, "src"),
    stdio: "inherit",
  });
} catch (e) {
  console.error(`ERROR: 'cargo build -p mxc_ffi' failed: ${e.message}`);
  process.exit(1);
}

const after = read(generated);

if (after === null) {
  console.error(`ERROR: expected generated file not found: ${generated}`);
  process.exit(1);
}

if (before !== after) {
  console.error(
    "ERROR: generated C# bindings are out of date. Rebuild `mxc_ffi` and commit\n" +
      "       csharp/Microsoft.Mxc.Sdk/Native/NativeMethods.g.cs."
  );
  process.exit(1);
}

console.log("C# bindings codegen OK: NativeMethods.g.cs is up to date");
