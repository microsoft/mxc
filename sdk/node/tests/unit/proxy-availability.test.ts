// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

import { test } from 'node:test';
import assert from 'node:assert';
import { evaluateProxyAvailability } from '../integration/proxy-availability.js';

test('available when the proxy binary is present', () => {
  const r = evaluateProxyAvailability({
    binary: 'unix-test-proxy',
    dir: '/bin',
    env: {},
    existsSync: () => true,
  });
  assert.strictEqual(r, true);
});

test('skips (false) when absent and not required', () => {
  const r = evaluateProxyAvailability({
    binary: 'unix-test-proxy',
    dir: '/bin',
    env: {},
    existsSync: () => false,
  });
  assert.strictEqual(r, false);
});

test('skips (false) when no source dir is resolved and not required', () => {
  const r = evaluateProxyAvailability({
    binary: 'unix-test-proxy',
    dir: null,
    env: {},
    existsSync: () => true,
  });
  assert.strictEqual(r, false);
});

test('throws when absent but MXC_REQUIRE_PROXY_TESTS is set', () => {
  assert.throws(
    () =>
      evaluateProxyAvailability({
        binary: 'wxc-test-proxy.exe',
        dir: '/bin',
        env: { MXC_REQUIRE_PROXY_TESTS: '1' },
        existsSync: () => false,
      }),
    /MXC_REQUIRE_PROXY_TESTS is set/,
  );
});

test('throws when no dir resolved but MXC_REQUIRE_PROXY_TESTS is set', () => {
  assert.throws(
    () =>
      evaluateProxyAvailability({
        binary: 'wxc-test-proxy.exe',
        dir: null,
        env: { MXC_REQUIRE_PROXY_TESTS: '1' },
        existsSync: () => true,
      }),
    /no MXC_TEST_PROXY_DIR/,
  );
});

test('present-and-required does not throw', () => {
  const r = evaluateProxyAvailability({
    binary: 'wxc-test-proxy.exe',
    dir: '/bin',
    env: { MXC_REQUIRE_PROXY_TESTS: '1' },
    existsSync: () => true,
  });
  assert.strictEqual(r, true);
});
