// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

import assert from 'node:assert';
import { describe, it } from 'node:test';
import { probeSandboxSupport } from '@microsoft/mxc-sdk';

describe('probeSandboxSupport integration', () => {
  it('rejects a non-ProcessContainer config', {
    skip: process.platform !== 'win32',
  }, () => {
    assert.throws(
      () => probeSandboxSupport({
        version: '0.9.0-alpha',
        containment: 'wslc',
        process: { commandLine: 'echo hi' },
        wslc: { image: 'alpine:latest' },
      }),
      /supports only ProcessContainer containment; got wslc/,
    );
  });
});
