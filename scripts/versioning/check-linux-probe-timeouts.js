#!/usr/bin/env node
// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

// Linux probe-timeout parity gate: the TypeScript SDK kills `lxc-exec
// --available-backends` after its own backstop, and a probe killed there is
// reported as an unsupported host. The native walk runs its three probes
// sequentially, so the backstop has to exceed their sum -- otherwise raising a
// Rust timeout silently turns slow-but-working hosts into unsupported ones.
// TypeScript cannot import a Rust constant, so this gate is what stops
// `NATIVE_PROBE_WORST_CASE_MS` from drifting away from that sum.
//
// Run from anywhere:
//   node scripts/versioning/check-linux-probe-timeouts.js

const { readFileSync } = require("fs");
const { join } = require("path");

const repoRoot = join(__dirname, "..", "..");
const errors = [];

// Each Rust term of the native worst case, and the file that owns it.
const RUST_TERMS = [
  {
    label: "bwrap --version probe",
    file: join(repoRoot, "src", "backends", "bubblewrap", "common", "src", "bwrap_version.rs"),
    constant: "BWRAP_VERSION_TIMEOUT",
  },
  {
    label: "proxy-enforcement dependency walk",
    file: join(repoRoot, "src", "backends", "bubblewrap", "common", "src", "proxy_network.rs"),
    constant: "PRE_FLIGHT_BUDGET",
  },
  {
    label: "lxc availability probe",
    file: join(repoRoot, "src", "backends", "lxc", "common", "src", "availability.rs"),
    constant: "PROBE_TIMEOUT",
  },
];

const PLATFORM_TS = join(repoRoot, "sdk", "node", "src", "platform.ts");

function read(path) {
  try {
    return readFileSync(path, "utf8");
  } catch (e) {
    errors.push(`could not read ${path}: ${e.message}`);
    return null;
  }
}

/** Milliseconds in `const <name>: Duration = Duration::from_secs(N);` (or `_millis`). */
function rustDurationMs(source, constant, file) {
  const pattern = new RegExp(
    `const\\s+${constant}\\s*:\\s*Duration\\s*=\\s*Duration::from_(secs|millis)\\(\\s*(\\d+)\\s*\\)`
  );
  const match = pattern.exec(source);
  if (!match) {
    errors.push(`${file}: could not find \`const ${constant}: Duration = Duration::from_secs(..)\``);
    return null;
  }
  const value = Number(match[2]);
  return match[1] === "secs" ? value * 1000 : value;
}

let nativeTotalMs = 0;
const breakdown = [];
for (const term of RUST_TERMS) {
  const source = read(term.file);
  if (source === null) continue;
  const ms = rustDurationMs(source, term.constant, term.file);
  if (ms === null) continue;
  nativeTotalMs += ms;
  breakdown.push(`${term.constant}=${ms}ms (${term.label})`);
}

const platform = read(PLATFORM_TS);
if (platform !== null) {
  const mirrored = /const\s+NATIVE_PROBE_WORST_CASE_MS\s*=\s*([^;]+);/.exec(platform);
  const backstop = /const\s+LINUX_PROBE_TIMEOUT_MS\s*=\s*([^;]+);/.exec(platform);

  if (!mirrored) {
    errors.push(`${PLATFORM_TS}: could not find \`const NATIVE_PROBE_WORST_CASE_MS = ..\``);
  } else {
    // The expression is a sum of numeric literals, so evaluating it needs no
    // parser -- but reject anything else rather than eval an arbitrary string.
    const expression = mirrored[1].trim();
    if (!/^[\d_\s+]+$/.test(expression)) {
      errors.push(
        `${PLATFORM_TS}: NATIVE_PROBE_WORST_CASE_MS must be a sum of numeric literals, got \`${expression}\``
      );
    } else {
      const declared = expression
        .split("+")
        .reduce((sum, part) => sum + Number(part.replace(/_/g, "").trim()), 0);
      if (declared !== nativeTotalMs) {
        errors.push(
          `NATIVE_PROBE_WORST_CASE_MS is ${declared}ms but the Rust constants now sum to ${nativeTotalMs}ms ` +
            `[${breakdown.join(", ")}]. Update sdk/node/src/platform.ts.`
        );
      }
    }
  }

  if (!backstop) {
    errors.push(`${PLATFORM_TS}: could not find \`const LINUX_PROBE_TIMEOUT_MS = ..\``);
  } else if (!backstop[1].includes("NATIVE_PROBE_WORST_CASE_MS")) {
    errors.push(
      `${PLATFORM_TS}: LINUX_PROBE_TIMEOUT_MS must be derived from NATIVE_PROBE_WORST_CASE_MS, got \`${backstop[1].trim()}\``
    );
  }
}

if (errors.length > 0) {
  console.error("Linux probe-timeout parity check FAILED:");
  for (const error of errors) console.error("  - " + error);
  process.exit(1);
}

console.log(
  `Linux probe-timeout parity OK: native worst case ${nativeTotalMs}ms [${breakdown.join(", ")}]; ` +
    `the SDK backstop is derived from it.`
);
