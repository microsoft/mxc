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
  ALL_KNOWN_BINARIES,
  platformName,
} from './test-helpers';

const expectedBinaries: Record<string, string[]> = {
  win32: EXPECTED_WINDOWS_BINARIES,
  linux: EXPECTED_LINUX_BINARIES,
};

describe('SDK package binaries', () => {
  const binDir = getSdkBinDir();
  const platform = os.platform();
  const osName = platformName();
  const expected = expectedBinaries[platform] ?? [];

  it('should have a bin directory for the current architecture', () => {
    assert.ok(
      fs.existsSync(binDir),
      `SDK bin directory not found: ${binDir}`,
    );
  });

  for (const binary of expected) {
    it(`should include ${binary}`, () => {
      const fullPath = path.join(binDir, binary);
      assert.ok(
        fs.existsSync(fullPath),
        `Expected binary not found: ${fullPath}`,
      );
    });
  }

  it(`should have all ${osName} binaries present`, () => {
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

  it('should not contain unexpected binaries', () => {
    if (!fs.existsSync(binDir)) {
      return;
    }
    const actual = fs.readdirSync(binDir).filter(f => {
      const stat = fs.statSync(path.join(binDir, f));
      return stat.isFile();
    });
    // The npm package bundles binaries for all platforms in the same arch
    // directory, so allow any known binary regardless of current OS.
    const unexpected = actual.filter(f => !ALL_KNOWN_BINARIES.includes(f));
    assert.deepStrictEqual(
      unexpected, [],
      `Unexpected binaries in ${binDir} — add them to the expected lists in test-helpers.ts: ${unexpected.join(', ')}`,
    );
  });
});
