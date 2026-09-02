#!/usr/bin/env node
// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

// Validates telemetry policy, consent-result, and status-reason wire strings
// across the Rust implementation and the Node and C# bindings.
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
const rustConsentProtocolPath = join(
  repoRoot,
  "src",
  "core",
  "wxc_common",
  "src",
  "telemetry",
  "consent_protocol.rs"
);
const csharpPath = join(
  repoRoot,
  "sdk",
  "dotnet",
  "Microsoft.Mxc.Sdk",
  "MxcTelemetry.cs"
);
const tsPath = join(
  repoRoot,
  "sdk",
  "node",
  "src",
  "telemetry.ts"
);

const errors = [];

// --- Rust: the source of truth -------------------------------------------
// `PolicyState::Unrestricted => "unrestricted",` inside `fn as_str`.
const rustSrc = readFileSync(rustPath, "utf8");
const rustConsentProtocolSrc = readFileSync(rustConsentProtocolPath, "utf8");
const asStrBody = rustSrc.match(
  /fn as_str\(&self\)\s*->\s*&'static str\s*\{[\s\S]*?match self \{([\s\S]*?)\n\s*\}/
);
if (!asStrBody) {
  console.error("ERROR: could not find `PolicyState::as_str` in policy.rs");
  process.exit(1);
}
const rustStates = new Map(); // wire string -> Rust variant
for (const m of asStrBody[1].matchAll(
  /PolicyState::(\w+)\s*=>\s*"([^"]+)"/g
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
  /ParsePolicyState\s*\(([^)]*)\)\s*=>\s*value\s+switch\s*\{([\s\S]*?)\};/
);
if (!parseBody) {
  console.error("ERROR: could not find `ParsePolicyState` in MxcTelemetry.cs");
  process.exit(1);
}
if (
  !/\bvalue\b/.test(parseBody[1]) ||
  !/\boperation\b/.test(parseBody[1])
) {
  console.error(
    "ERROR: `ParsePolicyState` must accept both value and operation parameters"
  );
  process.exit(1);
}
const csharpStates = new Set();
const csharpMappings = new Map(); // wire string -> C# enum variant
for (const m of parseBody[2].matchAll(
  /"([^"]+)"\s*=>\s*TelemetryPolicyState\.(\w+)/g
)) {
  csharpStates.add(m[1]);
  csharpMappings.set(m[1], m[2]);
}
const unrecognizedHelperCall =
  /UnrecognizedPolicyState\s*\(\s*value\s*,\s*operation\s*\)/;
const csharpDefault =
  /_\s*=>\s*TelemetryPolicyState\.Blocked\b/.test(parseBody[2]) ||
  /_\s*=>\s*UnrecognizedPolicyState\s*\(\s*value\s*,\s*operation\s*\)/.test(
    parseBody[2]
  );
if (!csharpDefault) {
  errors.push(
    "C# ParsePolicyState must fail closed with a direct Blocked result or the UnrecognizedPolicyState helper"
  );
}
if (unrecognizedHelperCall.test(parseBody[2])) {
  const helperBody = csharpSrc.match(
    /UnrecognizedPolicyState\s*\(([^)]*)\)\s*\{([\s\S]*?)\n\s*\}/
  );
  if (
    !helperBody ||
    !/\bvalue\b/.test(helperBody[1]) ||
    !/\boperation\b/.test(helperBody[1]) ||
    !/return\s+TelemetryPolicyState\.Blocked\s*;/.test(helperBody[2])
  ) {
    errors.push(
      "C# UnrecognizedPolicyState must return TelemetryPolicyState.Blocked"
    );
  }
}
// The default arm covers "blocked", so treat it as handled.
if (!csharpMappings.has("blocked")) {
  csharpStates.add("blocked");
  csharpMappings.set("blocked", "Blocked");
}

// --- TypeScript: the exported union ---------------------------------------
const tsSrc = readFileSync(tsPath, "utf8");
const unionMatch = tsSrc.match(
  /export type TelemetryPolicyState\s*=\s*([^;]+);/
);
if (!unionMatch) {
  console.error(
    "ERROR: could not find `TelemetryPolicyState` in telemetry.ts"
  );
  process.exit(1);
}
const tsStates = new Set();
for (const m of unionMatch[1].matchAll(/["']([^"']+)["']/g)) {
  tsStates.add(m[1]);
}

function parseTypeScriptUnion(name) {
  const match = tsSrc.match(new RegExp(`export type ${name}\\s*=\\s*([^;]+);`));
  if (!match) {
    console.error(`ERROR: could not find TypeScript \`${name}\``);
    process.exit(1);
  }
  return new Set([...match[1].matchAll(/["']([^"']+)["']/g)].map((item) => item[1]));
}

function parseRustEnum(name, rename) {
  const match = rustConsentProtocolSrc.match(
    new RegExp(`enum\\s+${name}\\s*\\{([\\s\\S]*?)\\n\\}`)
  );
  if (!match) {
    console.error(`ERROR: could not find Rust enum \`${name}\``);
    process.exit(1);
  }
  return new Set(
    [...match[1].matchAll(/^\s*([A-Z][A-Za-z0-9_]*)\s*,/gm)].map((item) => {
      const kebab = item[1].replace(/([a-z0-9])([A-Z])/g, "$1-$2").toLowerCase();
      return rename === "camelCase"
        ? kebab.replace(/-([a-z])/g, (_, letter) => letter.toUpperCase())
        : kebab;
    })
  );
}

function compareSets(label, expected, actual) {
  for (const wire of expected) {
    if (!actual.has(wire)) {
      errors.push(`${label} is missing '${wire}'`);
    }
  }
  for (const wire of actual) {
    if (!expected.has(wire)) {
      errors.push(`${label} has '${wire}' with no matching Rust variant`);
    }
  }
}

function expectedVariant(wire) {
  return wire
    .split("-")
    .map((part) => part.charAt(0).toUpperCase() + part.slice(1))
    .join("");
}

function parseCsharpSwitch(functionName, enumName) {
  const body = csharpSrc.match(
    new RegExp(
      `private\\s+static\\s+[\\w?<>]+\\s+${functionName}\\s*\\([^)]*\\)[\\s\\S]*?` +
      `(?:=>\\s*value|return\\s+value\\.GetString\\(\\))\\s+switch\\s*\\{([\\s\\S]*?)\\};`
    )
  );
  if (!body) {
    console.error(`ERROR: could not find \`${functionName}\` in MxcTelemetry.cs`);
    process.exit(1);
  }
  const mappings = new Map();
  const arm = new RegExp(`"([^"]+)"\\s*=>\\s*${enumName}\\.(\\w+)`, "g");
  for (const match of body[1].matchAll(arm)) {
    mappings.set(match[1], match[2]);
  }
  if (!/(?:_|var\s+\w+)\s*=>\s*\w*Unrecognized\w*\(/.test(body[1])) {
    errors.push(`${functionName} must route unknown wire values to a fail-closed sentinel helper`);
  }
  return mappings;
}

function compareMappings(label, expected, actual) {
  for (const wire of expected) {
    const actualVariant = actual.get(wire);
    const variant = expectedVariant(wire);
    if (actualVariant === undefined) {
      errors.push(`C# ${label} does not handle '${wire}'`);
    } else if (actualVariant !== variant) {
      errors.push(`C# ${label} maps '${wire}' to ${actualVariant}, expected ${variant}`);
    }
  }
  for (const wire of actual.keys()) {
    if (!expected.has(wire)) {
      errors.push(`C# ${label} handles '${wire}' with no matching TypeScript API value`);
    }
  }
}

function functionReturnsSentinel(functionName, sentinel) {
  const declaration = new RegExp(
    `private\\s+static\\s+[\\w?<>]+\\s+${functionName}\\s*\\(`
  ).exec(csharpSrc);
  if (declaration === null) {
    console.error(`ERROR: could not find \`${functionName}\` in MxcTelemetry.cs`);
    process.exit(1);
  }
  const start = declaration.index;
  const nextFunction = csharpSrc.indexOf("\n    private static ", start + 1);
  const body = csharpSrc.slice(start, nextFunction < 0 ? undefined : nextFunction);
  return body.includes(`return ${sentinel};`);
}

const terminalConsentResults = parseRustEnum("ConsentResult", "camelCase");
terminalConsentResults.delete("status");
terminalConsentResults.delete("presentationRequired");
compareSets(
  "TypeScript TelemetryConsentResult",
  terminalConsentResults,
  parseTypeScriptUnion("TelemetryConsentResult")
);
const consentResultMappings = parseCsharpSwitch(
  "ParseConsentActionResult",
  "TelemetryConsentActionResult"
);
compareMappings(
  "ParseConsentActionResult",
  terminalConsentResults,
  consentResultMappings
);
if (!functionReturnsSentinel(
  "UnrecognizedConsentActionResult",
  "TelemetryConsentActionResult.Unknown"
)) {
  errors.push("C# unknown consent action results must return TelemetryConsentActionResult.Unknown");
}

const consentReasons = parseRustEnum("StatusReason", "kebab-case");
compareSets(
  "TypeScript TelemetryConsentStatusReason",
  consentReasons,
  parseTypeScriptUnion("TelemetryConsentStatusReason")
);
const reasonMappings = parseCsharpSwitch(
  "ParseConsentStatusReason",
  "TelemetryConsentStatusReason"
);
compareMappings("ParseConsentStatusReason", consentReasons, reasonMappings);
if (!functionReturnsSentinel(
  "UnrecognizedConsentStatusReason",
  "TelemetryConsentStatusReason.Unknown"
)) {
  errors.push("C# unknown consent status reasons must return TelemetryConsentStatusReason.Unknown");
}

// --- Compare ---------------------------------------------------------------
for (const [wire, variant] of rustStates) {
  if (!csharpStates.has(wire)) {
    errors.push(
      `C# ParsePolicyState does not handle '${wire}' (Rust PolicyState::${variant})`
    );
  }
  const csharpVariant = csharpMappings.get(wire);
  if (csharpVariant !== undefined && csharpVariant !== variant) {
    errors.push(
      `C# ParsePolicyState maps '${wire}' to TelemetryPolicyState.${csharpVariant}, expected TelemetryPolicyState.${variant}`
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
  console.error("ERROR: telemetry wire parity check failed:");
  for (const e of errors) {
    console.error(`  - ${e}`);
  }
  console.error(
    "\nUpdate the C# mappings to match the Rust policy strings and " +
      "TypeScript consent API contract."
  );
  process.exit(1);
}

console.log(
  `Telemetry wire parity OK: ${rustStates.size} policy states, ` +
    `${terminalConsentResults.size} terminal results, and ${consentReasons.size} status reasons match`
);
