#!/usr/bin/env node
// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.
//
// Non-failing install-time check. The SDK delivers its native sandbox binary
// through an optional per-platform package (@microsoft/mxc-sdk-<os>-<arch>);
// npm silently ignores a failed/skipped optional install (registry hiccup,
// `--omit=optional`, an offline mirror, or an as-yet-unpublished platform
// package), which would otherwise only surface as an error at first spawn.
//
// This script WARNS (it never fails the install — always exits 0) when the
// host's platform package is absent or the host is an unsupported target.
//
// The decision logic is the exported pure `evaluate()` (injectable for tests);
// the CLI tail performs the real I/O and always exits 0.

const path = require("path");
const fs = require("fs");

// (platform, arch) tuples MXC ships a native binary for — must match
// SUPPORTED_TUPLES in src/platform.ts. 32-bit / other archs are intentionally
// NOT supported.
const SUPPORTED_TUPLES = new Set([
  "win32-x64",
  "win32-arm64",
  "linux-x64",
  "linux-arm64",
  "darwin-arm64",
  "darwin-x64",
]);

function sdkArch(arch) {
  return arch === "arm64" ? "arm64" : arch === "x64" ? "x64" : arch;
}

function executableBinaryName(platform) {
  if (platform === "linux") return "lxc-exec";
  if (platform === "darwin") return "mxc-exec-mac";
  return "wxc-exec.exe";
}

/**
 * Decide what (if anything) to warn about. Pure with respect to process state —
 * all I/O is injected — so it can be unit-tested across installed / missing /
 * unsupported scenarios.
 *
 * @param {{ platform: string, arch: string,
 *           resolve: (id: string) => string,
 *           existsSync: (p: string) => boolean,
 *           scriptDir: string }} deps
 * @returns {{ action: 'ok'|'warn'|'unsupported', message?: string, pkgName?: string }}
 */
function evaluate({ platform, arch, resolve, existsSync, scriptDir }) {
  const tuple = `${platform}-${sdkArch(arch)}`;

  // Unsupported (platform, arch) — e.g. a 32-bit or other non-shipped arch. Do
  // NOT synthesize a package name that 404s; explain the host isn't supported.
  if (!SUPPORTED_TUPLES.has(tuple)) {
    return {
      action: "unsupported",
      message:
        `\nwarning (@microsoft/mxc-sdk): this host (${tuple}) is not a supported\n` +
        `  MXC target. Native binaries ship for win32/linux (x64, arm64) and\n` +
        `  macOS (x64, arm64) only. The SDK will throw when it spawns a sandbox\n` +
        `  unless you build from source or set MXC_BIN_DIR to a directory whose\n` +
        `  <arch> subdirectory holds a compatible binary\n` +
        `  (i.e. $MXC_BIN_DIR/<x64|arm64>/${executableBinaryName(platform)}).\n`,
    };
  }

  const pkgName = `@microsoft/mxc-sdk-${tuple}`;
  const binName = executableBinaryName(platform);

  // 1. Installed as an optional dependency. Verify the native binary is
  //    actually present — a resolvable package.json with a missing/partial
  //    binary (interrupted or corrupt optional install) must not pass as "ok",
  //    or the failure only surfaces as an opaque throw at first spawn.
  try {
    const pkgDir = path.dirname(resolve(`${pkgName}/package.json`));
    if (existsSync(path.join(pkgDir, binName))) {
      return { action: "ok", pkgName };
    }
    return {
      action: "warn",
      pkgName,
      message:
        `\nwarning (@microsoft/mxc-sdk): ${pkgName} is installed but its native\n` +
        `  binary (${binName}) is missing — the optional install may have been\n` +
        `  interrupted or corrupted. The SDK will throw when it spawns a sandbox.\n` +
        `  Reinstall the package ("npm install ${pkgName}") or set MXC_BIN_DIR so\n` +
        `  $MXC_BIN_DIR/<x64|arm64>/${binName} is the binary.\n`,
    };
  } catch {
    // not installed; continue
  }

  // 2. Monorepo dev layout — the binary resolves from the sibling staged dir.
  //    We deliberately do NOT require the binary here: in a dev checkout the
  //    Rust artifacts are built separately, so warning on every `npm install`
  //    before a build would be pure noise.
  try {
    const devDir = path.join(scriptDir, "..", "platform-packages", tuple);
    if (existsSync(path.join(devDir, "package.json"))) {
      return { action: "ok", pkgName };
    }
  } catch {
    // ignore — treat as "not present"
  }

  // 3. Genuinely missing.
  return {
    action: "warn",
    pkgName,
    message:
      `\nwarning (@microsoft/mxc-sdk): ${pkgName} was not installed.\n` +
      `  The SDK needs this optional package for its native sandbox binary on\n` +
      `  this host. If it was skipped (e.g. --omit=optional, an offline mirror,\n` +
      `  or a transient registry error), the SDK will throw when it spawns a\n` +
      `  sandbox. Reinstall with the package present ("npm install ${pkgName}")\n` +
      `  or set MXC_BIN_DIR so $MXC_BIN_DIR/<x64|arm64>/${executableBinaryName(platform)}\n` +
      `  is the binary.\n`,
  };
}

module.exports = { evaluate, runPostinstall, SUPPORTED_TUPLES };

/**
 * Install-time entrypoint seam: runs {@link evaluate}, emits any warning via the
 * injected `error` sink, and NEVER throws (a postinstall must not fail the
 * install). Returns the evaluation result so callers/tests can assert on it.
 * All I/O is injected so the warn / unsupported / ok paths are unit-testable
 * without spawning a real `npm install`.
 *
 * @param {{ platform: string, arch: string, resolve: (id: string) => string,
 *           existsSync: (p: string) => boolean, scriptDir: string,
 *           error?: (msg: string) => void }} deps
 * @returns {{ action: 'ok'|'warn'|'unsupported', message?: string, pkgName?: string }}
 */
function runPostinstall({ platform, arch, resolve, existsSync, scriptDir, error }) {
  try {
    const result = evaluate({ platform, arch, resolve, existsSync, scriptDir });
    if (result.message && error) {
      error(result.message);
    }
    return result;
  } catch {
    // never fail the install
    return { action: "ok" };
  }
}

// CLI — never fails the install for any reason (always exits 0). Uses
// console.error (synchronous) so the warning isn't dropped by process.exit.
if (require.main === module) {
  runPostinstall({
    platform: process.platform,
    arch: process.arch,
    resolve: (id) => require.resolve(id),
    existsSync: (p) => fs.existsSync(p),
    scriptDir: __dirname,
    error: (msg) => console.error(msg),
  });
  process.exit(0);
}
