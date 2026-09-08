#!/usr/bin/env node
// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

// Static drift gate for the Rust surfaces represented by closed managed enums
// and tagged request types. Runtime parsers remain fail-closed; this check makes
// newly added Rust variants fail CI before a host happens to emit one.

const { readFileSync } = require("fs");
const { join } = require("path");

const root = join(__dirname, "..");
const errors = [];
const read = (...parts) => readFileSync(join(root, ...parts), "utf8");

function enumBody(source, enumName, language) {
  const pattern =
    language === "rust"
      ? new RegExp(`\\b(?:pub\\s+)?enum\\s+${enumName}\\s*\\{`)
      : new RegExp(`\\b(?:public|internal)\\s+enum\\s+${enumName}\\s*\\{`);
  const match = pattern.exec(source);
  if (!match) throw new Error(`could not find ${language} enum ${enumName}`);
  let depth = 1;
  let cursor = match.index + match[0].length;
  for (; cursor < source.length && depth > 0; cursor++) {
    if (source[cursor] === "{") depth++;
    if (source[cursor] === "}") depth--;
  }
  if (depth !== 0) throw new Error(`unterminated ${language} enum ${enumName}`);
  return source.slice(match.index + match[0].length, cursor - 1);
}

function enumMembers(source, enumName, language) {
  const body = enumBody(source, enumName, language)
    .replace(/\/\/\/.*$/gm, "")
    .replace(/\/\/.*$/gm, "");
  const segments = [];
  let start = 0;
  let depth = 0;
  for (let index = 0; index <= body.length; index++) {
    const character = body[index];
    if (character === "(" || character === "{" || character === "[") depth++;
    if (character === ")" || character === "}" || character === "]") depth--;
    if ((character === "," && depth === 0) || index === body.length) {
      const segment = body.slice(start, index).trim();
      if (segment) segments.push(segment);
      start = index + 1;
    }
  }

  return segments.map((original) => {
    const segment = original.replace(/#\[[\s\S]*?\]\s*/g, "").trim();
    const match = /^(\w+)(?:\s*=\s*[\s\S]+|\s*\([\s\S]*\)|\s*\{[\s\S]*\})?$/.exec(
      segment
    );
    if (!match) {
      throw new Error(
        `could not parse ${language} enum ${enumName} member: ${original}`
      );
    }
    return { name: match[1], source: original };
  });
}

function enumVariants(source, enumName, language) {
  return enumMembers(source, enumName, language).map((member) => member.name);
}

function compare(label, actual, expected) {
  const actualSorted = [...new Set(actual)].sort();
  const expectedSorted = [...new Set(expected)].sort();
  if (JSON.stringify(actualSorted) !== JSON.stringify(expectedSorted)) {
    errors.push(
      `${label}: managed [${actualSorted.join(", ")}], Rust [${expectedSorted.join(", ")}]`
    );
  }
}

function namedBody(source, kind, name) {
  const match = new RegExp(`\\b${kind}\\s+${name}\\b[^\\{]*\\{`).exec(source);
  if (!match) throw new Error(`could not find ${kind} ${name}`);
  let depth = 1;
  let cursor = match.index + match[0].length;
  for (; cursor < source.length && depth > 0; cursor++) {
    if (source[cursor] === "{") depth++;
    if (source[cursor] === "}") depth--;
  }
  if (depth !== 0) throw new Error(`unterminated ${kind} ${name}`);
  return source.slice(match.index + match[0].length, cursor - 1);
}

const snakeToCamel = (value) =>
  value.replace(/_([a-z])/g, (_, letter) => letter.toUpperCase());

function skipWhitespace(source, cursor) {
  while (cursor < source.length && /\s/.test(source[cursor])) cursor++;
  return cursor;
}

function attributeEnd(source, start, marker) {
  let depth = 1;
  let quote = null;
  let escaped = false;
  for (let cursor = start + marker.length; cursor < source.length; cursor++) {
    const character = source[cursor];
    if (quote !== null) {
      if (escaped) {
        escaped = false;
      } else if (character === "\\") {
        escaped = true;
      } else if (character === quote) {
        quote = null;
      }
      continue;
    }
    if (character === '"' || character === "'") {
      quote = character;
    } else if (character === "[") {
      depth++;
    } else if (character === "]" && --depth === 0) {
      return cursor + 1;
    }
  }
  return -1;
}

function attributedDeclarations(body, marker, declarationPattern) {
  const declarations = [];
  let cursor = 0;
  while (cursor < body.length) {
    cursor = skipWhitespace(body, cursor);
    const attributesStart = cursor;
    while (body.startsWith(marker, cursor)) {
      const end = attributeEnd(body, cursor, marker);
      if (end === -1) {
        cursor = body.length;
        break;
      }
      cursor = skipWhitespace(body, end);
    }
    if (cursor >= body.length) break;

    declarationPattern.lastIndex = cursor;
    const match = declarationPattern.exec(body);
    if (match) {
      declarations.push({
        attributes: body.slice(attributesStart, cursor),
        name: match[1],
      });
      cursor = declarationPattern.lastIndex;
    } else {
      // Advance unconditionally, including when attributes were just consumed
      // (a non-public attributed member reaches here). Every path through this
      // loop must move the cursor, or the gate would spin instead of failing.
      cursor++;
    }
  }
  return declarations;
}

function rustFieldsFromBody(body) {
  return attributedDeclarations(
    body,
    "#[",
    /(?:pub(?:\([^)]*\))?\s+)?(\w+)\s*:/y
  ).map(({ attributes, name }) => {
    const renamed = /\brename\s*=\s*"([^"]+)"/.exec(attributes);
    return renamed?.[1] ?? snakeToCamel(name);
  });
}

function rustStructFields(source, name) {
  return rustFieldsFromBody(namedBody(source, "struct", name));
}

function rustVariantFields(source, enumName, variantName) {
  const body = enumBody(source, enumName, "rust");
  const match = new RegExp(`\\b${variantName}\\s*\\{`).exec(body);
  if (!match) throw new Error(`could not find ${enumName}::${variantName}`);
  let depth = 1;
  let cursor = match.index + match[0].length;
  for (; cursor < body.length && depth > 0; cursor++) {
    if (body[cursor] === "{") depth++;
    if (body[cursor] === "}") depth--;
  }
  if (depth !== 0) throw new Error(`unterminated ${enumName}::${variantName}`);
  return rustFieldsFromBody(
    body.slice(match.index + match[0].length, cursor - 1)
  );
}

function managedJsonFields(source, className) {
  const body = namedBody(source, "class", className);
  return attributedDeclarations(
    body,
    "[",
    /public\s+(?:required\s+)?[\w<>,?.\[\]\s]+\s+(\w+)\s*\{/y
  )
    .filter(
      ({ attributes }) =>
        !/\[\s*JsonIgnore(?:Attribute)?(?:\s*\]|\s*\()/.test(attributes)
    )
    .map(({ attributes, name }) => {
      const renamed = /JsonPropertyName\("([^"]+)"\)/.exec(attributes);
      return renamed?.[1] ?? camelCase(name);
    });
}

// `legacyManagedOnly` lists managed JSON fields that intentionally have no Rust
// counterpart because they are deprecated compatibility aliases. They must stay
// serializable so legacy JSON round-trips, but the managed request path strips
// them before the native layer sees them.
function compareStructFields(
  label,
  rustSource,
  rustName,
  managedSource,
  managedName,
  legacyManagedOnly = []
) {
  compare(
    `${label} fields`,
    managedJsonFields(managedSource, managedName).filter(
      (field) => !legacyManagedOnly.includes(field)
    ),
    rustStructFields(rustSource, rustName)
  );
}

const rustPolicy = read("src", "core", "mxc_engine", "src", "policy.rs");
const rustNetworkPolicy = read(
  "src",
  "core",
  "mxc_engine",
  "src",
  "policy",
  "network.rs"
);
const rustBindingRequest = read(
  "src",
  "ffi",
  "mxc_ffi",
  "src",
  "request.rs"
);
const managedRequest = read(
  "sdk",
  "dotnet",
  "Microsoft.Mxc.Sdk",
  "SandboxRequest.cs"
);
const managedPolicy = read(
  "sdk",
  "dotnet",
  "Microsoft.Mxc.Sdk",
  "SandboxPolicy.cs"
);
const rustOneShot = enumVariants(rustPolicy, "Containment", "rust").filter(
  (variant) => variant !== "IsolationSession"
);
const bindingContainment = enumMembers(
  rustBindingRequest,
  "RequestContainment",
  "rust"
);
compare(
  "Rust SDK vs binding containment variants",
  bindingContainment.map((member) => member.name),
  rustOneShot
);
compareStructFields(
  "one-shot request",
  rustBindingRequest,
  "RequestSpec",
  managedRequest,
  "SandboxRequest"
);
compare(
  "process-container request fields",
  managedJsonFields(managedRequest, "ProcessContainerContainment"),
  rustVariantFields(rustBindingRequest, "RequestContainment", "ProcessContainer")
);
compare(
  "WSLC request fields",
  managedJsonFields(managedRequest, "WslcContainment"),
  rustVariantFields(rustBindingRequest, "RequestContainment", "Wslc")
);
compareStructFields(
  "process-container UI",
  rustBindingRequest,
  "ProcessContainerUiSpec",
  managedRequest,
  "ProcessContainerUiPolicy"
);
compareStructFields(
  "process-container network",
  rustBindingRequest,
  "ProcessContainerNetworkSpec",
  managedRequest,
  "ProcessContainerNetworkPolicy"
);
compareStructFields(
  "WSLC port mapping",
  rustBindingRequest,
  "WslcPortMappingSpec",
  managedRequest,
  "WslcPortMapping"
);

for (const [
  label,
  rustSource,
  rustName,
  managedName,
  legacyManagedOnly,
] of [
  // `captureDenials` is an obsolete managed-only alias (MXC0001, removed in
  // 1.0). Rust only accepts it under `containment.captureDenials`, and
  // MxcSandbox.PrepareRequest strips it from the policy before serialization.
  ["sandbox policy", rustPolicy, "SandboxPolicy", "SandboxPolicy", ["captureDenials"]],
  ["filesystem policy", rustPolicy, "FilesystemSection", "FilesystemPolicy"],
  ["UI policy", rustPolicy, "UiSection", "UiPolicy"],
  ["network policy", rustNetworkPolicy, "NetworkSection", "NetworkPolicy"],
  ["network peer", rustNetworkPolicy, "NetworkPeerSection", "NetworkPeerPolicy"],
  ["network port", rustNetworkPolicy, "NetworkPortSection", "NetworkPortPolicy"],
  ["network rule", rustNetworkPolicy, "NetworkRuleSection", "NetworkRulePolicy"],
  ["network egress", rustNetworkPolicy, "NetworkEgressSection", "NetworkEgressPolicy"],
  ["network ingress", rustNetworkPolicy, "NetworkIngressSection", "NetworkIngressPolicy"],
  ["network runtime config", rustNetworkPolicy, "RuntimeConfigSection", "NetworkRuntimeConfig"],
]) {
  compareStructFields(
    label,
    rustSource,
    rustName,
    managedPolicy,
    managedName,
    legacyManagedOnly
  );
}
const managedOneShot = [
  ...managedRequest.matchAll(
    /\[JsonDerivedType\(typeof\(\w+\),\s*"([^"]+)"\)\]/g
  ),
].map((match) => match[1]);
const camelCase = (value) => value[0].toLowerCase() + value.slice(1);
compare(
  "one-shot containment discriminators",
  managedOneShot,
  bindingContainment.map((member) => {
    const renamed = /#\[serde\([^]]*\brename\s*=\s*"([^"]+)"/s.exec(
      member.source
    );
    return renamed?.[1] ?? camelCase(member.name);
  })
);

const rustProbeFull = read("src", "core", "mxc_engine", "src", "probe.rs");
const rustProbe = rustProbeFull.split("#[cfg(test)]")[0];
const rustModels = read("src", "core", "wxc_common", "src", "models.rs");
const managedDiscovery = read(
  "sdk",
  "dotnet",
  "Microsoft.Mxc.Sdk",
  "PlatformDiscovery.cs"
);
const managedSandbox = read(
  "sdk",
  "dotnet",
  "Microsoft.Mxc.Sdk",
  "MxcSandbox.cs"
);

const discoveredRustBackends = [
  ...rustProbe.matchAll(/ContainmentBackend::(\w+)\.wire_name\(\)/g),
].map((match) => match[1]);
const rustWireNames = new Map(
  [
    ...rustModels.matchAll(
      /ContainmentBackend::(\w+)\s*=>\s*"([^"]+)"/g
    ),
  ].map((match) => [match[1], match[2]])
);
const managedBackendCases = [
  ...managedSandbox.matchAll(
    /"([^"]+)"\s*=>\s*ContainmentBackend\.(\w+)/g
  ),
].map((match) => [match[2], match[1]]);
compare(
  "discovery backend enum",
  enumVariants(managedDiscovery, "ContainmentBackend", "csharp").filter(
    (variant) => variant !== "Unknown"
  ),
  discoveredRustBackends
);
for (const variant of discoveredRustBackends) {
  const expectedWire = rustWireNames.get(variant);
  const actualWire = managedBackendCases.find(([name]) => name === variant)?.[1];
  if (actualWire !== expectedWire) {
    errors.push(
      `discovery backend ${variant}: managed wire "${actualWire}", Rust wire "${expectedWire}"`
    );
  }
}

compare(
  "backend capability enum",
  enumVariants(managedDiscovery, "BackendCapability", "csharp").filter(
    (variant) => variant !== "Unknown"
  ),
  enumVariants(rustProbe, "BackendCapability", "rust")
);
const rustCapabilityMembers = enumMembers(
  rustProbe,
  "BackendCapability",
  "rust"
);
const rustCapabilities = rustCapabilityMembers.map((member) => member.name);
for (const member of rustCapabilityMembers) {
  const variant = member.name;
  const renamed = /#\[serde\([^]]*\brename\s*=\s*"([^"]+)"/s.exec(member.source);
  const wire = renamed?.[1] ?? camelCase(variant);
  if (
    !new RegExp(
      `"${wire}"\\s*=>\\s*BackendCapability\\.${variant}\\b`
    ).test(managedSandbox)
  ) {
    errors.push(`backend capability ${variant} (${wire}) has no managed parser case`);
  }
}

const tierMatch = /const CANONICAL_TIERS:[^=]+=\s*\[([^\]]+)\]/s.exec(
  rustProbeFull
);
if (!tierMatch) {
  errors.push("probe.rs: could not find CANONICAL_TIERS");
} else {
  const rustTiers = [...tierMatch[1].matchAll(/"([^"]+)"/g)].map(
    (match) => match[1]
  );
  const managedTiers = [
    ...managedSandbox.matchAll(/"([^"]+)"\s*=>\s*IsolationTier\.\w+/g),
  ].map((match) => match[1]);
  compare("isolation-tier wire names", managedTiers, rustTiers);
}

const rustStateAware = read(
  "src",
  "core",
  "mxc_engine",
  "src",
  "state_aware.rs"
).split("#[cfg(test)]")[0];
const stateAwareMatch = /matches!\(\s*backend,\s*([\s\S]*?)\)\s*&&/.exec(
  rustStateAware
);
if (!stateAwareMatch) {
  errors.push("state_aware.rs: could not find experimental backend registry");
} else {
  const rustBackends = [
    ...stateAwareMatch[1].matchAll(/ContainmentBackend::(\w+)/g),
  ].map((match) => match[1]);
  const managedStateAware = read(
    "sdk",
    "dotnet",
    "Microsoft.Mxc.Sdk",
    "StateAwareTypes.cs"
  );
  compare(
    "state-aware containment enum",
    enumVariants(managedStateAware, "StateAwareContainment", "csharp"),
    rustBackends
  );
}

const rustDispatch = read(
  "src",
  "core",
  "wxc_common",
  "src",
  "state_aware_dispatch.rs"
);
const managedLifecycle = read(
  "sdk",
  "dotnet",
  "Microsoft.Mxc.Sdk",
  "MxcLifecycle.cs"
);
const rustPrefixBody = namedBody(rustDispatch, "fn", "backend_from_prefix");
const managedPrefixBody = namedBody(managedLifecycle, "StateAwareContainment", "ContainmentForId");
const rustPrefixes = [
  ...rustPrefixBody.matchAll(/"([^"]+)"\s*=>\s*Ok\(ContainmentBackend::(\w+)\)/g),
].map((match) => `${match[1]}:${match[2]}`);
const managedPrefixes = [
  ...managedPrefixBody.matchAll(/"([^"]+)"\s*=>\s*StateAwareContainment\.(\w+)/g),
].map((match) => `${match[1]}:${match[2]}`);
compare("state-aware sandbox-id prefixes", managedPrefixes, rustPrefixes);

if (errors.length > 0) {
  console.error("C# API parity FAILED:");
  for (const error of errors) console.error(`  - ${error}`);
  process.exit(1);
}

console.log(
  `C# API parity OK: request/policy fields, sandbox-id prefixes, ` +
    `${rustOneShot.length} one-shot backends, ` +
    `${new Set(discoveredRustBackends).size} discovery backends, ` +
    `${rustCapabilities.length} capabilities`
);
