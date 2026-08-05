#!/usr/bin/env node
// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

// Validates that the telemetry policy-state wire strings agree across every
// language binding. The Rust `PolicyState::as_str()` in wxc_common is the
// single source of truth; the C# `TelemetryPolicyState` mapping and the
// TypeScript `TelemetryPolicyState` union must cover exactly the same set.
//
// Without this gate the three mappings drift silently: a new Rust variant
// would be parsed as `Blocked` by the other bindings (they fail closed, which
// is safe but wrong), and a stale binding string would never be reported at
// all. Run from the repository root:
//
//   node scripts/check-telemetry-policy-parity.js

const { readFileSync } = require("fs");
const { join } = require("path");

const repoRoot = join(__dirname, "..");

const rustPath = join(
  repoRoot,
  "src",
  "core",
  "wxc_common",
  "src",
  "telemetry",
  "policy.rs"
);
const csharpPath = join(
  repoRoot,
  "sdk",
  "dotnet",
  "Microsoft.Mxc.Sdk",
  "MxcTelemetry.cs"
);
const tsPath = join(repoRoot, "sdk", "node", "src", "telemetry.ts");

const errors = [];

// --- Rust: the source of truth -------------------------------------------
// `PolicyState::Unrestricted => "unrestricted",` inside `fn as_str`.
const rustSrc = readFileSync(rustPath, "utf8");
const asStrBody = rustSrc.match(
  /fn as_str\(&self\)\s*->\s*&'static str\s*\{[\s\S]*?match self \{([\s\S]*?)\n\s*\}/
);
if (!asStrBody) {
  console.error("ERROR: could not find `PolicyState::as_str` in policy.rs");
  process.exit(1);
}
const rustStates = new Map(); // wire string -> Rust variant
for (const m of asStrBody[1].matchAll(
  /PolicyState::(\w+)\s*=>\s*"([a-z-]+)"/g
)) {
  rustStates.set(m[2], m[1]);
}

if (rustStates.size === 0) {
  console.error("ERROR: parsed zero policy states from policy.rs");
  process.exit(1);
}

// --- C#: the ParsePolicyState switch --------------------------------------
// Every state except the fail-closed default must appear as a literal arm;
// the default arm is what maps everything else (including `"blocked"`) to
// Blocked. The default may return Blocked directly or through the helper
// that records an actionable diagnostic before failing closed.
const csharpSrc = readFileSync(csharpPath, "utf8");
const parseBody = csharpSrc.match(
  /ParsePolicyState\(string\? value\) => value switch\s*\{([\s\S]*?)\};/
);
if (!parseBody) {
  console.error("ERROR: could not find `ParsePolicyState` in MxcTelemetry.cs");
  process.exit(1);
}
const csharpStates = new Set();
for (const m of parseBody[1].matchAll(/"([a-z-]+)"\s*=>/g)) {
  csharpStates.add(m[1]);
}
const csharpDefault = /_\s*=>\s*(?:TelemetryPolicyState\.Blocked|UnrecognizedPolicyState\(value\))/.test(
  parseBody[1]
);
if (!csharpDefault) {
  errors.push(
    "C# ParsePolicyState must fail closed with a direct Blocked result or the UnrecognizedPolicyState helper"
  );
}
if (/UnrecognizedPolicyState\(value\)/.test(parseBody[1])) {
  const helperBody = csharpSrc.match(
    /UnrecognizedPolicyState\(string\? value\)\s*\{([\s\S]*?)\n\s*\}/
  );
  if (!helperBody || !/return\s+TelemetryPolicyState\.Blocked\s*;/.test(helperBody[1])) {
    errors.push(
      "C# UnrecognizedPolicyState must return TelemetryPolicyState.Blocked"
    );
  }
}
// The default arm covers "blocked", so treat it as handled.
csharpStates.add("blocked");

// --- TypeScript: the exported union ---------------------------------------
const tsSrc = readFileSync(tsPath, "utf8");
const unionMatch = tsSrc.match(
  /export type TelemetryPolicyState\s*=\s*([^;]+);/
);
if (!unionMatch) {
  console.error(
    "ERROR: could not find `export type TelemetryPolicyState` in telemetry.ts"
  );
  process.exit(1);
}
const tsStates = new Set();
for (const m of unionMatch[1].matchAll(/'([a-z-]+)'/g)) {
  tsStates.add(m[1]);
}

// --- Compare ---------------------------------------------------------------
for (const [wire, variant] of rustStates) {
  if (!csharpStates.has(wire)) {
    errors.push(
      `C# ParsePolicyState does not handle '${wire}' (Rust PolicyState::${variant})`
    );
  }
  if (!tsStates.has(wire)) {
    errors.push(
      `TypeScript TelemetryPolicyState union is missing '${wire}' (Rust PolicyState::${variant})`
    );
  }
}
for (const wire of csharpStates) {
  if (!rustStates.has(wire)) {
    errors.push(
      `C# ParsePolicyState handles '${wire}' with no matching Rust PolicyState variant`
    );
  }
}
for (const wire of tsStates) {
  if (!rustStates.has(wire)) {
    errors.push(
      `TypeScript TelemetryPolicyState has '${wire}' with no matching Rust PolicyState variant`
    );
  }
}

if (errors.length > 0) {
  console.error("ERROR: telemetry policy-state parity check failed:");
  for (const e of errors) {
    console.error(`  - ${e}`);
  }
  console.error(
    "\nThe Rust `PolicyState::as_str()` in src/core/wxc_common/src/telemetry/policy.rs " +
      "is the source of truth. Update the C# and TypeScript bindings to match."
  );
  process.exit(1);
}

console.log(
  `Telemetry policy parity OK: ${rustStates.size} states match across Rust, C#, and TypeScript ` +
    `(${[...rustStates.keys()].sort().join(", ")})`
);
