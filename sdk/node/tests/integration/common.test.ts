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
});
