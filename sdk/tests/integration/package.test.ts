// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

import { describe, it } from 'node:test';
import assert from 'node:assert';
import fs from 'fs';
import os from 'os';
import path from 'path';
import { createRequire } from 'node:module';
import {
  getSdkBinDir,
  getPlatformPackageName,
  EXPECTED_WINDOWS_BINARIES,
  EXPECTED_LINUX_BINARIES,
  EXPECTED_MACOS_BINARIES,
  ALL_KNOWN_BINARIES,
  TEST_ONLY_BINARIES,
  platformName,
} from './test-helpers.js';

const require = createRequire(import.meta.url);

const expectedBinaries: Record<string, string[]> = {
  win32: EXPECTED_WINDOWS_BINARIES,
  linux: EXPECTED_LINUX_BINARIES,
  darwin: EXPECTED_MACOS_BINARIES,
};

// Files that legitimately sit beside the binaries in a platform package.
const ALLOWED_NON_BINARY_FILES = ['package.json', 'README.md', 'LICENSE.md'];

describe('per-platform package binaries (#512)', () => {
  // After #512 the native executor + sandbox helpers ship in the host's
  // per-platform package (@microsoft/mxc-sdk-<os>-<arch>) at its root — not in
  // a bin/<arch> subdir of the meta package.
  const binDir = getSdkBinDir();
  const platform = os.platform();
  const osName = platformName();
  const expected = expectedBinaries[platform] ?? [];

  it(`resolves the platform package directory (${getPlatformPackageName()})`, () => {
    assert.ok(fs.existsSync(binDir), `Platform package directory not found: ${binDir}`);
  });

  for (const binary of expected) {
    it(`includes ${binary}`, () => {
      assert.ok(
        fs.existsSync(path.join(binDir, binary)),
        `Expected binary not found: ${path.join(binDir, binary)}`,
      );
    });
  }

  it(`has all ${osName} binaries present`, () => {
    if (expected.length === 0) return;
    const missing = expected.filter((b) => !fs.existsSync(path.join(binDir, b)));
    assert.deepStrictEqual(missing, [], `Missing binaries in ${binDir}: ${missing.join(', ')}`);
  });

  it('does not ship dev/test-only proxy binaries', () => {
    const present = TEST_ONLY_BINARIES.filter((b) => fs.existsSync(path.join(binDir, b)));
    assert.deepStrictEqual(
      present,
      [],
      `Test-only binaries must not ship in the platform package: ${present.join(', ')}`,
    );
  });

  it('contains no unexpected files', () => {
    if (!fs.existsSync(binDir)) return;
    const actual = fs
      .readdirSync(binDir)
      .filter((f) => fs.statSync(path.join(binDir, f)).isFile());
    const unexpected = actual.filter(
      (f) => !ALL_KNOWN_BINARIES.includes(f) && !ALLOWED_NON_BINARY_FILES.includes(f),
    );
    assert.deepStrictEqual(
      unexpected,
      [],
      `Unexpected files in ${binDir} — add expected binaries to test-helpers.ts: ${unexpected.join(', ')}`,
    );
  });
});

describe('meta package ships no native binaries (#512)', () => {
  it('the installed @microsoft/mxc-sdk has no bin/ directory', () => {
    const metaRoot = path.dirname(require.resolve('@microsoft/mxc-sdk/package.json'));
    const binPath = path.join(metaRoot, 'bin');
    assert.ok(
      !fs.existsSync(binPath),
      `Meta package must not ship a bin/ directory, but found: ${binPath}`,
    );
  });
});
