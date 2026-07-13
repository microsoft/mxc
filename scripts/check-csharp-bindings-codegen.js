#!/usr/bin/env node
// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

// Generation check for the C# P/Invoke layer. The generated file
// (NativeMethods.g.cs) is NOT committed — it is produced at build time by the
// GenerateNativeBindings MSBuild target (and by `cargo build -p mxc_ffi
// --features csharpsdk`). This gate rebuilds the FFI with codegen enabled and
// asserts the bindings are produced and expose the expected entry points, so a
// broken/renamed C ABI is caught in CI even though nothing is committed. Run
// from the repository root:
//
//   node scripts/check-csharp-bindings-codegen.js

const { readFileSync, existsSync, rmSync } = require("fs");
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

// The extern entry points the C# SDK P/Invokes; the generated file must expose
// each one. Keep in sync with the `#[no_mangle] extern "C"` fns in
// src/ffi/mxc_ffi/src/lib.rs.
const REQUIRED_ENTRY_POINTS = [
  "mxc_run",
  "mxc_run_result_free",
  "mxc_string_free",
  "mxc_version",
];

// Remove any stale copy so we prove codegen actually (re)produces it.
if (existsSync(generated)) {
  rmSync(generated);
}

try {
  execFileSync("cargo", ["build", "-p", "mxc_ffi", "--features", "csharpsdk"], {
    cwd: join(repoRoot, "src"),
    stdio: "inherit",
  });
} catch (e) {
  console.error(
    `ERROR: 'cargo build -p mxc_ffi --features csharpsdk' failed: ${e.message}`
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

console.log(
  `C# bindings codegen OK: generated with ${REQUIRED_ENTRY_POINTS.length} expected entry points`
);
