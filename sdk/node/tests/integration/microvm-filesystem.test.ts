// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

import { it } from 'node:test';
import assert from 'node:assert';
import { sdk } from './test-helpers.js';

it('rejects MicroVM through the in-process streaming API', () => {
  const config = {
    version: '0.9.0-alpha',
    containment: 'microvm' as const,
    process: {
      commandLine: "print('unreachable')",
      timeout: 30000,
    },
  };

  assert.throws(
    () => sdk.spawnSandboxFromConfig(config, { experimental: true }),
    /containment 'microvm' is not supported by the in-process Node SDK/,
  );
});
