#!/usr/bin/env node
// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

const { readFileSync } = require("fs");
const { join } = require("path");

const root = join(__dirname, "..");
const protocol = readFileSync(
  join(root, "src", "core", "wxc_common", "src", "telemetry", "consent_protocol.rs"),
  "utf8"
);
const policy = readFileSync(
  join(root, "src", "core", "wxc_common", "src", "telemetry", "policy.rs"),
  "utf8"
);
const csharp = readFileSync(
  join(root, "sdk", "dotnet", "Microsoft.Mxc.Sdk", "MxcTelemetry.cs"),
  "utf8"
);
const typescript = readFileSync(
  join(root, "sdk", "node", "src", "telemetry.ts"),
  "utf8"
);
const errors = [];

function requiredMatch(source, expression, label) {
  const match = source.match(expression);
  if (!match) {
    console.error(`ERROR: could not parse ${label}`);
    process.exit(1);
  }
  return match;
}

function rustWireName(variant, rename) {
  const kebab = variant.replace(/([a-z0-9])([A-Z])/g, "$1-$2").toLowerCase();
  return rename === "camelCase"
    ? kebab.replace(/-([a-z])/g, (_, letter) => letter.toUpperCase())
    : kebab;
}

function rustEnum(name) {
  const match = requiredMatch(
    protocol,
    new RegExp(
      `#\\[serde\\(rename_all = "([^"]+)"(?:,[^\\]]*)?\\)\\]\\s*` +
      `pub\\(super\\)\\s+enum\\s+${name}\\s*\\{([\\s\\S]*?)\\n\\}`
    ),
    `Rust enum ${name}`
  );
  if (!["camelCase", "kebab-case"].includes(match[1])) {
    console.error(`ERROR: unsupported serde rename '${match[1]}' on ${name}`);
    process.exit(1);
  }
  return new Set(
    [...match[2].matchAll(/^\s*([A-Z][A-Za-z0-9_]*)\s*,/gm)]
      .map((item) => rustWireName(item[1], match[1]))
  );
}

function policyStates() {
  const body = requiredMatch(
    policy,
    /fn as_str\(&self\)\s*->\s*&'static str\s*\{[\s\S]*?match self \{([\s\S]*?)\n\s*\}/,
    "PolicyState::as_str"
  )[1];
  return new Map(
    [...body.matchAll(/PolicyState::(\w+)\s*=>\s*"([^"]+)"/g)]
      .map((item) => [item[2], item[1]])
  );
}

function typescriptValues(name) {
  const body = requiredMatch(
    typescript,
    new RegExp(`const ${name}\\s*=\\s*\\[([\\s\\S]*?)\\]\\s*as const`),
    `TypeScript literal set ${name}`
  )[1];
  return new Set([...body.matchAll(/["']([^"']+)["']/g)].map((item) => item[1]));
}

function csharpSwitch(functionName, enumName) {
  const body = requiredMatch(
    csharp,
    new RegExp(
      `private\\s+static\\s+[\\w?<>]+\\s+${functionName}\\s*\\([^)]*\\)[\\s\\S]*?` +
      `(?:=>\\s*value|return\\s+value\\.GetString\\(\\))\\s+switch\\s*\\{([\\s\\S]*?)\\};`
    ),
    `C# ${functionName}`
  )[1];
  return new Map(
    [...body.matchAll(new RegExp(`"([^"]+)"\\s*=>\\s*${enumName}\\.(\\w+)`, "g"))]
      .map((item) => [item[1], item[2]])
  );
}

function csharpStatusReasons() {
  const body = requiredMatch(
    csharp,
    /private\s+static\s+bool\s+IsKnownConsentStatusReason\s*\([^)]*\)[\s\S]*?return\s+value\.GetString\(\)\s+switch\s*\{([\s\S]*?)\};/,
    "C# IsKnownConsentStatusReason"
  )[1];
  return new Set([...body.matchAll(/"([^"]+)"/g)].map((item) => item[1]));
}

function functionBody(name) {
  const start = requiredMatch(
    csharp,
    new RegExp(`private\\s+static\\s+[\\w?<>]+\\s+${name}\\s*\\(`),
    `C# ${name}`
  ).index;
  const end = csharp.indexOf("\n    private static ", start + 1);
  return csharp.slice(start, end < 0 ? undefined : end);
}

function compareSets(label, expected, actual) {
  for (const value of expected) {
    if (!actual.has(value)) errors.push(`${label} is missing '${value}'`);
  }
  for (const value of actual) {
    if (!expected.has(value)) errors.push(`${label} has unexpected '${value}'`);
  }
}

function expectedVariant(wire) {
  return wire
    .replace(/-([a-z])/g, (_, letter) => letter.toUpperCase())
    .replace(/^./, (letter) => letter.toUpperCase());
}

function compareMappings(label, expected, actual) {
  for (const wire of expected) {
    const variant = actual.get(wire);
    if (variant === undefined) {
      errors.push(`${label} does not handle '${wire}'`);
    } else if (variant !== expectedVariant(wire)) {
      errors.push(`${label} maps '${wire}' to ${variant}`);
    }
  }
  for (const wire of actual.keys()) {
    if (!expected.has(wire)) errors.push(`${label} handles unexpected '${wire}'`);
  }
}

const runtimePolicy = policyStates();
const protocolPolicy = rustEnum("PolicyState");
compareSets("Rust consent protocol policy", new Set(runtimePolicy.keys()), protocolPolicy);
compareSets("TypeScript policy", protocolPolicy, typescriptValues("TELEMETRY_POLICY_STATES"));
const csharpPolicy = csharpSwitch("ParsePolicyState", "TelemetryPolicyState");
csharpPolicy.set("blocked", "Blocked");
compareMappings("C# ParsePolicyState", protocolPolicy, csharpPolicy);

const consentStates = rustEnum("ConsentState");
compareSets("TypeScript consent state", consentStates, typescriptValues("TELEMETRY_CONSENT_STATES"));
compareMappings(
  "C# ParseConsentState",
  consentStates,
  csharpSwitch("ParseConsentState", "TelemetryConsentState")
);

const terminalResults = rustEnum("ConsentResult");
terminalResults.delete("status");
terminalResults.delete("presentationRequired");
compareSets(
  "TypeScript consent result",
  terminalResults,
  typescriptValues("TELEMETRY_CONSENT_RESULTS")
);
compareMappings(
  "C# ParseConsentActionResult",
  terminalResults,
  csharpSwitch("ParseConsentActionResult", "TelemetryConsentActionResult")
);

const statusReasons = rustEnum("StatusReason");
compareSets(
  "TypeScript private status reason",
  statusReasons,
  typescriptValues("CONSENT_STATUS_REASONS")
);
compareSets("C# private status reason", statusReasons, csharpStatusReasons());

for (const [name, sentinel] of [
  ["UnrecognizedConsentState", "return TelemetryConsentState.Undetermined;"],
  ["UnrecognizedConsentActionResult", "return TelemetryConsentActionResult.Unknown;"],
  ["ReportUnrecognizedConsentStatusReason", "return false;"],
  ["UnrecognizedPolicyState", "return TelemetryPolicyState.Blocked;"],
]) {
  if (!functionBody(name).includes(sentinel)) {
    errors.push(`C# ${name} must contain '${sentinel}'`);
  }
}

if (errors.length > 0) {
  console.error("ERROR: telemetry wire parity check failed:");
  for (const error of errors) console.error(`  - ${error}`);
  process.exit(1);
}

console.log(
  `Telemetry wire parity OK: ${protocolPolicy.size} policy states, ` +
  `${consentStates.size} consent states, ${terminalResults.size} terminal results, ` +
  `and ${statusReasons.size} private status reasons match`
);
