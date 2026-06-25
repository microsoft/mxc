#!/usr/bin/env node
// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.
//
// Single source of truth for "which built files make up a platform package's
// shipped payload". Reads the package manifest's `files` allowlist so the CI
// upload/verify lists and the package contents can never drift apart.
//
//   node scripts/platform-package-payload.js <path-to-platform-package.json>
//
// Prints one payload file (relative path, e.g. `bin/kernel.elf`) per line.
// `README.md` is excluded: it is a tracked/generated package file, not a build
// artifact produced into the Rust target dir.

const fs = require("fs");

const NON_ARTIFACT_FILES = new Set(["README.md"]);

/**
 * @param {string} manifestPath path to a platform-package package.json
 * @param {{ readFileSync?: Function }} [io]
 * @returns {string[]} build-artifact payload files (relative paths)
 */
function payloadFiles(manifestPath, { readFileSync = fs.readFileSync } = {}) {
  const pkg = JSON.parse(readFileSync(manifestPath, "utf8"));
  const files = Array.isArray(pkg.files) ? pkg.files : [];
  return files.filter((f) => typeof f === "string" && !NON_ARTIFACT_FILES.has(f));
}

module.exports = { payloadFiles, NON_ARTIFACT_FILES };

if (require.main === module) {
  const manifestPath = process.argv[2];
  if (!manifestPath) {
    console.error("usage: platform-package-payload.js <platform-package.json>");
    process.exit(2);
  }
  for (const f of payloadFiles(manifestPath)) {
    console.log(f);
  }
}
