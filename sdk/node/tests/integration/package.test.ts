// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

import { describe, it } from 'node:test';
import assert from 'node:assert';
import fs from 'fs';
import os from 'os';
import path from 'path';
import {
  getSdkBinDir,
  EXPECTED_WINDOWS_BINARIES,
  EXPECTED_LINUX_BINARIES,
  EXPECTED_MACOS_PACKAGE_FILES,
  ALL_KNOWN_PACKAGE_FILES,
  getSeatbeltBuildType,
  platformName,
} from './test-helpers.js';

const expectedFiles: Record<string, string[]> = {
  win32: EXPECTED_WINDOWS_BINARIES,
  linux: EXPECTED_LINUX_BINARIES,
  darwin: EXPECTED_MACOS_PACKAGE_FILES,
};

describe('SDK package binaries', () => {
  const binDir = getSdkBinDir();
  const platform = os.platform();
  const osName = platformName();
  const expected = expectedFiles[platform] ?? [];

  it('should have a bin directory for the current architecture', () => {
    assert.ok(
      fs.existsSync(binDir),
      `SDK bin directory not found: ${binDir}`,
    );
  });

  for (const file of expected) {
    it(`should include ${file}`, () => {
      const fullPath = path.join(binDir, file);
      assert.ok(
        fs.existsSync(fullPath),
        `Expected package file not found: ${fullPath}`,
      );
    });
  }

  it(`should have all ${osName} package files present`, () => {
    if (expected.length === 0) {
      // No binary expectations for this platform — skip
      return;
    }
    const missing = expected.filter(b => !fs.existsSync(path.join(binDir, b)));
    assert.deepStrictEqual(
      missing, [],
      `Missing binaries in ${binDir}: ${missing.join(', ')}`,
    );
  });

  it('should identify the packaged Seatbelt build type', {
    skip: platform !== 'darwin',
  }, () => {
    const buildType = getSeatbeltBuildType();
    assert.ok(
      buildType === 'debug' || buildType === 'release',
      'Expected a valid mxc-exec-mac build-type marker',
    );
  });

  it('should not contain unexpected files', () => {
    if (!fs.existsSync(binDir)) {
      return;
    }
    const actual = fs.readdirSync(binDir).filter(f => {
      const stat = fs.statSync(path.join(binDir, f));
      return stat.isFile();
    });
    // The npm package bundles files for all platforms in the same arch
    // directory, so allow any known entry regardless of current OS.
    const unexpected = actual.filter(f => !ALL_KNOWN_PACKAGE_FILES.includes(f));
    assert.deepStrictEqual(
      unexpected, [],
      `Unexpected files in ${binDir} — add them to the expected lists in test-helpers.ts: ${unexpected.join(', ')}`,
    );
  });
});
