// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

import { describe, it } from 'node:test';
import assert from 'node:assert';
import { sdk } from './test-helpers.js';

describe('Platform support', () => {
  it('should report platform support information', () => {
    const support = sdk.getPlatformSupport();
    assert.ok(typeof support.isSupported === 'boolean', 'isSupported should be a boolean');
    assert.ok(Array.isArray(support.availableMethods), 'availableMethods should be an array');
  });

  describe('In-process creation options', () => {
    const request = {
      command: 'cmd.exe /c echo test',
      network: { egress: { default: 'deny' as const } },
      ui: { disable: true },
      timeoutMs: 30000,
    };

    it('rejects unsupported dry-run before dispatching a synchronous operation', () => {
      for (const operation of [sdk.spawn, sdk.run]) {
        assert.throws(
          () => operation(request, { dryRun: true } as never),
          /does not support dryRun/,
        );
      }
    });

    it('rejects unsupported dry-run before dispatching an asynchronous operation', async () => {
      for (const operation of [sdk.spawnAsync, sdk.runAsync]) {
        await assert.rejects(
          operation(request, { dryRun: true } as never),
          /does not support dryRun/,
        );
      }
    });
  });
});
