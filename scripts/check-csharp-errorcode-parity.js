#!/usr/bin/env node
// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

// Validates that the C# `ErrorCode` enum matches the native FFI `MXC_STATUS_*`
// constants one-for-one (name and value). Run from the repository root:
//
//   node scripts/check-csharp-errorcode-parity.js

const { readFileSync } = require("fs");
const { join } = require("path");

const repoRoot = join(__dirname, "..");

const rustPath = join(repoRoot, "src", "ffi", "mxc_ffi", "src", "lib.rs");
const csharpPath = join(
  repoRoot,
  "csharp",
  "Microsoft.Mxc.Sdk",
  "ErrorCode.cs"
);

function screamingToPascal(name) {
  return name
    .split("_")
    .map((part) => part.charAt(0).toUpperCase() + part.slice(1).toLowerCase())
    .join("");
}

// Rust: `pub const MXC_STATUS_MALFORMED_REQUEST: i32 = 1;`
const rustSrc = readFileSync(rustPath, "utf8");
const rustCodes = new Map(); // PascalName -> value
for (const m of rustSrc.matchAll(
  /pub const MXC_STATUS_(\w+):\s*i32\s*=\s*(\d+);/g
)) {
  rustCodes.set(screamingToPascal(m[1]), Number(m[2]));
}

// C#: `MalformedRequest = 1,` inside the ErrorCode enum.
const csharpSrc = readFileSync(csharpPath, "utf8");
const enumBody = csharpSrc.match(/enum ErrorCode\s*\{([\s\S]*?)\}/);
if (!enumBody) {
  console.error("ERROR: could not find `enum ErrorCode` in ErrorCode.cs");
  process.exit(1);
}
const csharpCodes = new Map();
for (const m of enumBody[1].matchAll(/^\s*(\w+)\s*=\s*(\d+)\s*,/gm)) {
  csharpCodes.set(m[1], Number(m[2]));
}

if (rustCodes.size === 0 || csharpCodes.size === 0) {
  console.error(
    `ERROR: parsed ${rustCodes.size} Rust and ${csharpCodes.size} C# codes; expected non-zero for both`
  );
  process.exit(1);
}

const errors = [];
for (const [name, value] of rustCodes) {
  if (!csharpCodes.has(name)) {
    errors.push(`C# ErrorCode is missing '${name}' (native value ${value})`);
  } else if (csharpCodes.get(name) !== value) {
    errors.push(
      `Value mismatch for '${name}': native ${value} vs C# ${csharpCodes.get(name)}`
    );
  }
}
for (const [name, value] of csharpCodes) {
  if (!rustCodes.has(name)) {
    errors.push(
      `C# ErrorCode has '${name}' (${value}) with no matching native MXC_STATUS_* constant`
    );
  }
}

if (errors.length > 0) {
  console.error("ERROR: C# ErrorCode / native MXC_STATUS_* parity check failed:");
  for (const e of errors) {
    console.error(`  - ${e}`);
  }
  process.exit(1);
}

console.log(
  `ErrorCode parity OK: ${rustCodes.size} codes match between native FFI and C#`
);
