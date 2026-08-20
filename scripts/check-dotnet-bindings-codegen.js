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

const { readFileSync, existsSync, rmSync } = require("fs");
const { join } = require("path");
const { execFileSync } = require("child_process");

const repoRoot = join(__dirname, "..");
const generated = join(
  repoRoot,
  "sdk",
  "dotnet",
  "Microsoft.Mxc.Sdk",
  "Native",
  "NativeMethods.g.cs"
);

// A smoke-test subset of the extern entry points the C# SDK P/Invokes — not the
// whole set, which is larger. The compiler is the real backstop: csbindgen emits
// a binding only for a fn carrying `#[no_mangle]` or `#[export_name]`, and takes
// the `EntryPoint` from whichever of the two determines the export. So renaming
// a fn, removing it, or dropping that attribute makes the generated method
// change or disappear, and the hand-written call sites stop compiling.
//
// Keep in sync with the `#[no_mangle] extern "C"` fns in src/ffi/mxc_ffi/src/.
const REQUIRED_ENTRY_POINTS = [
  "mxc_run",
  "mxc_run_result_free",
  "mxc_error_detail_free",
  "mxc_string_free",
  "mxc_version",
  "mxc_telemetry_get_consent",
  "mxc_telemetry_request_consent",
  "mxc_telemetry_withdraw_consent",
  "mxc_telemetry_get_consent_status",
  "mxc_telemetry_needs_consent_prompt",
  "mxc_telemetry_get_policy",
  "mxc_spawn",
  "mxc_sandbox_take_stdin",
  "mxc_sandbox_take_stdout",
  "mxc_sandbox_take_stderr",
  "mxc_stream_read",
  "mxc_stream_write",
  "mxc_stream_flush",
  "mxc_sandbox_id",
  "mxc_sandbox_output_metadata_json",
  "mxc_sandbox_try_wait",
  "mxc_sandbox_wait",
  "mxc_sandbox_kill",
  "mxc_sandbox_free",
  "mxc_read_stream_free",
  "mxc_write_stream_free",
  "mxc_state_aware",
  "mxc_state_aware_exec",
  "mxc_state_aware_result_free",
];

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

// The same set of Rust sources is named twice: once for csbindgen to read, and
// once as the MSBuild target's incremental `Inputs`. MSBuild skips the target
// when its output is newer than every declared input, so a file missing from
// the second list means an incremental C# build can compile against stale
// declarations — and cargo's own `rerun-if-changed` never gets consulted,
// because the target never runs. A clean CI build always regenerates and so
// cannot catch it.
//
// This is not hypothetical: adding `error_detail.rs` to build.rs without adding
// it to the csproj is exactly how the lists drifted once already.
const CRATE_REL_ROOT = "ffi/mxc_ffi";
const buildRs = readFileSync(
  join(repoRoot, "src", "ffi", "mxc_ffi", "build.rs"),
  "utf8"
);
const csproj = readFileSync(
  join(
    repoRoot,
    "sdk",
    "dotnet",
    "Microsoft.Mxc.Sdk",
    "Microsoft.Mxc.Sdk.csproj"
  ),
  "utf8"
);

// Enumerate every call site, then parse each one — rather than matching only
// the shape we expect. A regex that skips what it cannot read would let an
// unrecognised-but-live input (a trailing comma, a `const` argument, a call
// split across lines) pass unnoticed while the four literal calls keep the
// zero-call guard quiet. Anything unparseable fails the gate instead.
const callSites = [...buildRs.matchAll(/\.input_extern_file\s*\(/g)];
if (callSites.length === 0) {
  console.error(
    "ERROR: found no `.input_extern_file(...)` calls in src/ffi/mxc_ffi/build.rs.\n" +
      "  The parity check cannot be trusted; has the codegen setup changed?"
  );
  process.exit(1);
}

const csbindgenInputs = [];
const unparseable = [];
for (const site of callSites) {
  const rest = buildRs.slice(site.index + site[0].length);
  // Only a plain string literal, optionally followed by a trailing comma and
  // whitespace, is understood. Anything else is reported, not skipped.
  const literal = rest.match(/^\s*"([^"]+)"\s*,?\s*\)/);
  if (literal) {
    csbindgenInputs.push(literal[1]);
  } else {
    unparseable.push(rest.split("\n")[0].trim().slice(0, 60));
  }
}
if (unparseable.length > 0) {
  console.error(
    "ERROR: could not read the argument of some `.input_extern_file(...)` call(s)\n" +
      "in src/ffi/mxc_ffi/build.rs, so this gate cannot prove the MSBuild inputs\n" +
      "cover them:\n" +
      unparseable.map((s) => `  - .input_extern_file(${s}`).join("\n") +
      "\n\nUse a plain string literal, or teach this check the new form."
  );
  process.exit(1);
}

// Scope to the owning target's opening tag — attributes live there, and
// matching only `<Target …>` cannot bleed into child elements. The lookahead
// finds `Name` wherever it sits among the attributes: requiring it first would
// make legal, behaviour-preserving XML reordering look like a missing target.
// `\b` keeps `<TargetFramework>` from matching.
const target = csproj.match(
  /<Target\b(?=[^>]*\bName="GenerateNativeBindings")[^>]*>/
);
if (!target) {
  console.error(
    "ERROR: could not find the `GenerateNativeBindings` target in the csproj."
  );
  process.exit(1);
}
const inputsAttr = target[0].match(/Inputs="([^"]*)"/);
if (!inputsAttr) {
  console.error(
    "ERROR: the `GenerateNativeBindings` target declares no `Inputs` attribute,\n" +
      "  so MSBuild cannot know when to regenerate the bindings."
  );
  process.exit(1);
}

// build.rs paths are crate-relative ("src/lib.rs"); the csproj spells them from
// the repo's src dir ("$(MxcSrcDir)/ffi/mxc_ffi/src/lib.rs"). Compare on the
// crate-rooted tail so the check tolerates how the csproj roots itself but
// still rejects the same filename under a different crate.
const declaredInputs = inputsAttr[1]
  .split(";")
  .map((p) => p.trim().replace(/\\/g, "/"))
  .filter(Boolean);
const notDeclared = csbindgenInputs.filter((rel) => {
  const expected = `${CRATE_REL_ROOT}/${rel}`;
  return !declaredInputs.some((declared) => declared.endsWith(expected));
});
if (notDeclared.length > 0) {
  console.error(
    "ERROR: Rust source(s) read by csbindgen are missing from the C# project's\n" +
      "MSBuild `Inputs`, so an incremental build can skip regeneration and use\n" +
      "stale bindings:\n" +
      notDeclared.map((p) => `  - ${CRATE_REL_ROOT}/${p}`).join("\n") +
      "\n\nAdd each to the GenerateNativeBindings `Inputs` in\n" +
      "  sdk/dotnet/Microsoft.Mxc.Sdk/Microsoft.Mxc.Sdk.csproj"
  );
  process.exit(1);
}

console.log(
  `C# bindings codegen OK: generated with ${REQUIRED_ENTRY_POINTS.length} expected entry points; ` +
    `${csbindgenInputs.length} csbindgen source(s) all declared as MSBuild inputs`
);
