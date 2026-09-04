// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

import assert from 'node:assert/strict';
import { existsSync } from 'node:fs';
import { createRequire } from 'node:module';
import { dirname, join } from 'node:path';
import { platform } from 'node:process';
import { fileURLToPath } from 'node:url';
import { describe, it } from 'node:test';

import {
  MxcError,
  getAvailableBackends,
  getPlatformSupport,
  getVersion,
  deprovisionSandbox,
  deprovisionSandboxSync,
  execAttachedSandbox,
  execAttachedSandboxSync,
  provisionSandbox,
  provisionSandboxSync,
  runSandbox,
  runSandboxSync,
  startSandbox,
  startSandboxSync,
  stopSandbox,
  stopSandboxSync,
} from '../src/index.js';

const prototypeRoot = join(dirname(fileURLToPath(import.meta.url)), '..', '..');
const libraryName = platform === 'win32'
  ? 'mxc_ffi.dll'
  : platform === 'darwin'
    ? 'libmxc_ffi.dylib'
    : 'libmxc_ffi.so';
const realLibrary = join(prototypeRoot, '..', '..', '..', 'src', 'target', 'debug', libraryName);

if (!existsSync(realLibrary)) {
  throw new Error(`Expected generated Diplomat library at ${realLibrary}`);
}
process.env.MXC_FFI_LIBRARY = realLibrary;
const nativeAddon = createRequire(import.meta.url)(
  join(prototypeRoot, 'build', 'Debug', 'mxc_node_ffi.node'),
);

describe('generated Diplomat mxc_ffi ABI', () => {
  it('calls Version and Discover through the real library', () => {
    assert.match(getVersion(), /^\d+\.\d+\.\d+/);
    assert.ok(Array.isArray(getAvailableBackends()));
    assert.ok(getPlatformSupport().availableMethods.length > 0);
  });

  it('converts malformed Run through generated error accessors', () => {
    assert.throws(
      () => runSandboxSync('{'),
      (error: unknown) => error instanceof MxcError &&
        error.code === 'malformed_request' &&
        error.message.length > 0,
    );
  });

  it('uses the same generated malformed-Run call through the async API', async () => {
    await assert.rejects(
      runSandbox('{'),
      (error: unknown) => error instanceof MxcError &&
        error.code === 'malformed_request' &&
        error.message.length > 0,
    );
  });

  for (const operation of [
    ['provision', provisionSandboxSync, provisionSandbox],
    ['start', startSandboxSync, startSandbox],
    ['stop', stopSandboxSync, stopSandbox],
    ['deprovision', deprovisionSandboxSync, deprovisionSandbox],
  ] as const) {
    it(`maps malformed ${operation[0]} requests consistently for sync and async APIs`, async () => {
      assert.throws(
        () => operation[1]('{', { dryRun: true, experimental: true }),
        (error: unknown) => error instanceof MxcError && error.code === 'malformed_request',
      );
      await assert.rejects(
        operation[2]('{', { dryRun: true, experimental: true }),
        (error: unknown) => error instanceof MxcError && error.code === 'malformed_request',
      );
    });
  }

  it('maps malformed ExecAttached requests consistently for sync and async APIs', async () => {
    assert.throws(
      () => execAttachedSandboxSync('{', { experimental: true }),
      (error: unknown) => error instanceof MxcError && error.code === 'malformed_request',
    );
    await assert.rejects(
      execAttachedSandbox('{', { experimental: true }),
      (error: unknown) => error instanceof MxcError && error.code === 'malformed_request',
    );
  });

  it('throws TypeError for direct-addon request and state-aware flag conversion failures', () => {
    assert.throws(
      () => nativeAddon.runSandboxSync(Symbol('not-json')),
      TypeError,
    );
    assert.throws(
      () => nativeAddon.provisionSandboxSync(42, true, true),
      { name: 'TypeError', message: /State-aware request must be a JSON string/ },
    );
    assert.throws(
      () => nativeAddon.provisionSandboxSync('{}', 'true', true),
      { name: 'TypeError', message: /dryRun must be a boolean/ },
    );
    assert.throws(
      () => nativeAddon.execAttachedSandboxSync('{}', 'true'),
      { name: 'TypeError', message: /experimental must be a boolean/ },
    );
  });
});
