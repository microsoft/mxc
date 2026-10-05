#!/usr/bin/env node
// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

// Static drift gate for the Rust/exact-contract surfaces represented by closed
// managed enums and tagged request types. Runtime parsers remain fail-closed;
// this check makes newly added exact-contract fields or Rust variants fail CI
// before a host happens to emit one.

const { readFileSync } = require("fs");
const { join } = require("path");

const root = join(__dirname, "..");
const errors = [];
const read = (...parts) => readFileSync(join(root, ...parts), "utf8");
const camelCase = (value) => value[0].toLowerCase() + value.slice(1);

function compare(label, actual, expected) {
  const actualSorted = [...new Set(actual)].sort();
  const expectedSorted = [...new Set(expected)].sort();
  if (JSON.stringify(actualSorted) !== JSON.stringify(expectedSorted)) {
    errors.push(
      `${label}: managed [${actualSorted.join(", ")}], expected [${expectedSorted.join(", ")}]`
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
      cursor++;
    }
  }
  return declarations;
}

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

  return segments
    .filter(
      (original) =>
        language !== "rust" ||
        !/#\[\s*cfg\s*\(\s*test\s*\)\s*\]/.test(original)
    )
    .map((original) => {
      const segment = original.replace(/#\[[\s\S]*?\]\s*/g, "").trim();
      const match =
        /^(\w+)(?:\s*=\s*[\s\S]+|\s*\([\s\S]*\)|\s*\{[\s\S]*\})?$/.exec(
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

function managedDerivedTypes(source, baseType) {
  return [
    ...source.matchAll(
      new RegExp(`public\\s+sealed\\s+class\\s+(\\w+)\\s*:\\s*${baseType}\\b`, "g")
    ),
  ].map((match) => match[1]);
}

function managedJsonFields(source, className) {
  const body = namedBody(source, "class", className);
  return attributedDeclarations(
    body,
    "[",
    /public\s+(?:required\s+)?[\w<>,?.\[\]\s]+\s+(\w+)\s*\{/y
  )
    .filter(({ attributes }) => {
      const ignored = /\[\s*JsonIgnore(?:Attribute)?\s*(?:\(\s*([^)]*)\s*\))?\s*\]/.exec(
        attributes
      );
      if (!ignored) return true;
      const arguments = ignored[1]?.trim();
      return (
        arguments !== undefined &&
        arguments !== "" &&
        !/\bCondition\s*=\s*JsonIgnoreCondition\.Always\b/.test(arguments)
      );
    })
    .map(({ attributes, name }) => {
      const renamed = /JsonPropertyName\("([^"]+)"\)/.exec(attributes);
      return renamed?.[1] ?? camelCase(name);
    });
}

compare(
  "managed JSON field extractor",
  managedJsonFields(
    `class Example {
      [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
      [JsonPropertyName("before")]
      public string? Before { get; set; }
      [JsonPropertyName("after")]
      [JsonIgnore(Condition = JsonIgnoreCondition.Never)]
      public string? After { get; set; }
      [JsonIgnore(Condition = JsonIgnoreCondition.Always)]
      [JsonPropertyName("excluded")]
      public string Excluded { get; set; }
      public string DefaultName { get; set; }
    }`,
    "Example"
  ),
  ["before", "after", "defaultName"]
);

function schemaDefinition(schema, name) {
  const definition = schema.definitions?.[name];
  if (!definition) throw new Error(`could not find schema definition ${name}`);
  return definition;
}

function schemaProperties(schema, name) {
  return Object.keys(schemaDefinition(schema, name).properties ?? {});
}

function schemaEnumStrings(schema, name) {
  const definition = schemaDefinition(schema, name);
  if (Array.isArray(definition.oneOf)) {
    return definition.oneOf.flatMap((branch) => branch.enum ?? []);
  }
  return definition.enum ?? [];
}

const exactV1 = JSON.parse(
  read("schemas", "stable", "mxc-config.schema.1.0.0.json")
);
const managedRequest = read(
  "sdk",
  "dotnet",
  "Microsoft.Mxc.Sdk",
  "V1",
  "ContainerRequest.cs"
);
const managedPolicy = read(
  "sdk",
  "dotnet",
  "Microsoft.Mxc.Sdk",
  "V1",
  "ContainerRequestSections.cs"
);
const generatedWire = read(
  "sdk",
  "dotnet",
  "Microsoft.Mxc.Sdk",
  "Generated",
  "MxcConfigV1_0_0.g.cs"
);

const managedContainmentWire = new Map([
  ["Process", "process"],
  ["ProcessContainer", "processcontainer"],
  ["Lxc", "lxc"],
  ["Bubblewrap", "bubblewrap"],
  ["Seatbelt", "seatbelt"],
  ["IsolationSession", "isolation_session"],
  ["Wslc", "wslc"],
]);
const managedOneShotContainments = managedDerivedTypes(
  managedRequest,
  "Containment"
).map((name) => {
  const wire = managedContainmentWire.get(name);
  if (!wire) {
    errors.push(`managed containment ${name} has no exact v1 wire mapping`);
  }
  return wire;
});
compare(
  "exact v1 one-shot containment values",
  managedOneShotContainments.filter(Boolean),
  schemaEnumStrings(exactV1, "OneShotContainment")
);
compare(
  "generated exact one-shot request fields",
  managedJsonFields(generatedWire, "OneShotRequest"),
  schemaProperties(exactV1, "OneShotRequest")
);
compare(
  "process-container exact fields",
  managedJsonFields(generatedWire, "ProcessContainer"),
  schemaProperties(exactV1, "ProcessContainer")
);
compare(
  "process-container authoring fields",
  managedJsonFields(managedRequest, "ProcessContainer"),
  // The request writer fixes this native-only field to the SDK default.
  schemaProperties(exactV1, "ProcessContainer").filter((field) => field !== "leastPrivilege")
);
compare(
  "process-container UI exact fields",
  managedJsonFields(managedRequest, "ProcessContainerUiPolicy"),
  schemaProperties(exactV1, "ProcessContainerUi")
);
compare(
  "process-container filesystem exact fields",
  managedJsonFields(managedRequest, "ProcessContainerFilesystemPolicy"),
  schemaProperties(exactV1, "ProcessContainerFilesystem")
);
compare(
  "process-container network exact fields",
  managedJsonFields(managedRequest, "ProcessContainerNetworkPolicy"),
  schemaProperties(exactV1, "ProcessContainerNetwork")
);
compare(
  "capture-denials exact fields",
  managedJsonFields(managedPolicy, "CaptureDenialsPolicy"),
  schemaProperties(exactV1, "CaptureDenials")
);
compare(
  "WSLC one-shot exact fields",
  managedJsonFields(managedRequest, "Wslc"),
  schemaProperties(exactV1, "OneShotWslc").filter((field) => field !== "targetOs")
);
compare(
  "WSLC port-mapping exact fields",
  managedJsonFields(managedRequest, "WslcPortMapping"),
  schemaProperties(exactV1, "PortMapping").filter((field) => field !== "protocol")
);
compare("LXC exact fields", managedJsonFields(managedRequest, "Lxc"), schemaProperties(exactV1, "Lxc"));
compare("Seatbelt exact fields", managedJsonFields(managedRequest, "Seatbelt"), schemaProperties(exactV1, "Seatbelt"));
compare(
  "container request fields handled by exact writer",
  managedJsonFields(managedRequest, "ContainerRequest"),
  ["command", "filesystem", "network", "ui", "timeoutMs", "containment",
    "containerName", "workingDirectory", "environment", "inheritDefaultEnv"]
);
const managedOptions = read(
  "sdk", "dotnet", "Microsoft.Mxc.Sdk", "V1", "ExecutionOptions.cs"
);
for (const [name, fields] of [
  ["RunOptions", ["experimental", "telemetry"]],
  ["SpawnOptions", ["experimental", "telemetry"]],
  ["SpawnWithPtyOptions", ["experimental", "telemetry", "size"]],
]) {
  compare(`${name} invocation fields`, managedJsonFields(managedOptions, name), fields);
}
compare(
  "filesystem policy exact fields plus lifecycle compatibility",
  managedJsonFields(managedPolicy, "FilesystemPolicy"),
  [...schemaProperties(exactV1, "Filesystem"), "clearPolicyOnExit"]
);
compare(
  "network policy exact fields plus runtime config authoring",
  managedJsonFields(managedPolicy, "NetworkPolicy"),
  [...schemaProperties(exactV1, "Network"), "runtimeConfig"]
);
compare("network peer exact fields", managedJsonFields(managedPolicy, "NetworkPeerPolicy"), schemaProperties(exactV1, "NetworkPeer"));
compare("network port exact fields", managedJsonFields(managedPolicy, "NetworkPortPolicy"), schemaProperties(exactV1, "NetworkPort"));
compare("network rule exact fields", managedJsonFields(managedPolicy, "NetworkRulePolicy"), schemaProperties(exactV1, "NetworkRule"));
compare("network egress exact fields", managedJsonFields(managedPolicy, "NetworkEgressPolicy"), schemaProperties(exactV1, "NetworkEgress"));
compare("network ingress exact fields", managedJsonFields(managedPolicy, "NetworkIngressPolicy"), schemaProperties(exactV1, "NetworkIngress"));
compare("network runtime config exact fields", managedJsonFields(managedPolicy, "NetworkRuntimeConfig"), schemaProperties(exactV1, "RuntimeConfig"));
compare("telemetry config exact fields", managedJsonFields(managedPolicy, "TelemetryConfig"), schemaProperties(exactV1, "Telemetry"));
compare(
  "UI policy exact writer source fields",
  managedJsonFields(managedPolicy, "UiPolicy"),
  ["disable", "clipboard", "allowInputInjection"]
);

const rustProbeFull = read("src", "core", "mxc_engine", "src", "probe.rs");
const rustProbe = rustProbeFull.split("#[cfg(test)]")[0];
const rustModels = read("src", "core", "wxc_common", "src", "models.rs");
const managedDiscovery = read(
  "sdk",
  "dotnet",
  "Microsoft.Mxc.Sdk",
  "V1",
  "PlatformDiscovery.cs"
);
const managedSandbox = read(
  "sdk",
  "dotnet",
  "Microsoft.Mxc.Sdk",
  "V1",
  "MxcPlatform.cs"
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
const runStateAwareBody = namedBody(rustStateAware, "fn", "run_state_aware");
const rustBackends = [
  ...runStateAwareBody.matchAll(/ContainmentBackend::(\w+)\s*=>/g),
]
  .map((match) => match[1])
  .filter((backend) => backend !== "WindowsSandbox");
if (rustBackends.length === 0) {
  errors.push("state_aware.rs: could not find state-aware backend dispatch");
} else {
  const managedStateAware = read(
    "sdk",
    "dotnet",
    "Microsoft.Mxc.Sdk",
    "V1",
    "LifecycleTypes.cs"
  );
  compare(
    "state-aware containment enum",
    enumVariants(managedStateAware, "LifecycleContainmentKind", "csharp"),
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
  "V1",
  "MxcLifecycle.cs"
);
const rustPrefixBody = namedBody(rustDispatch, "fn", "backend_from_prefix");
const rustPrefixes = [
  ...rustPrefixBody.matchAll(/"([^"]+)"\s*=>\s*Ok\(ContainmentBackend::(\w+)\)/g),
]
  .filter((match) => match[2] !== "WindowsSandbox")
  .map((match) => `${match[1]}:${match[2]}`);
function managedIdPrefixes(source) {
  return [
    ...namedBody(source, "LifecycleContainmentKind", "ContainmentForId")
      .matchAll(/"([^"]+)"\s*=>\s*LifecycleContainmentKind\.(\w+)/g),
  ].map((match) => `${match[1]}:${match[2]}`);
}
compare(
  "state-aware sandbox-id prefix extractor",
  managedIdPrefixes(
    `class Example {
      static LifecycleContainmentKind ContainmentForId(ContainerId id) {
        return id switch { "iso" => LifecycleContainmentKind.IsolationSession };
      }
      static LifecycleContainmentKind Other(string id) {
        return id switch { "unrelated" => LifecycleContainmentKind.Wslc };
      }
    }`
  ),
  ["iso:IsolationSession"]
);
const managedPrefixes = managedIdPrefixes(managedLifecycle);
compare("state-aware sandbox-id prefixes", managedPrefixes, rustPrefixes);

if (errors.length > 0) {
  console.error("C# API parity FAILED:");
  for (const error of errors) console.error(`  - ${error}`);
  process.exit(1);
}

console.log(
  `C# API parity OK: exact v1 request/policy fields, sandbox-id prefixes, ` +
    `${schemaEnumStrings(exactV1, "OneShotContainment").length} one-shot backends, ` +
    `${new Set(discoveredRustBackends).size} discovery backends, ` +
    `${rustCapabilities.length} capabilities`
);
