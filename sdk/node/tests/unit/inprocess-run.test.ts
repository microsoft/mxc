// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

import assert from 'node:assert';
import { afterEach, describe, it } from 'node:test';
import * as rootSdk from '../../src/index.js';
import * as v1Sdk from '../../src/v1.js';
import { _setBindingRunAsyncImplementation } from '../../src/bindings/run.js';
import type { RequestSpec } from '../../src/bindings/request.js';

const { MxcError } = rootSdk;
const { spawnSandboxAsync } = v1Sdk;

afterEach(() => _setBindingRunAsyncImplementation());

describe('public SDK namespace exports', () => {
  it('keeps typed authoring and lifecycle functions in V1', () => {
    for (const name of [
      'createConfigFromPolicy',
      'spawnSandbox',
      'spawnSandboxAsync',
      'buildSandboxPayload',
      'getAvailableToolsPolicy',
      'getUserProfilePolicy',
      'getTemporaryFilesPolicy',
      'provisionSandbox',
      'startSandbox',
      'execInSandbox',
      'execInSandboxAsync',
      'stopSandbox',
      'deprovisionSandbox',
    ] as const) {
      assert.strictEqual(typeof v1Sdk[name], 'function', name);
      assert.strictEqual(Object.hasOwn(rootSdk, name), false, name);
    }
  });

  it('keeps raw config, discovery, errors, and process handles at the root', () => {
    for (const name of [
      'spawnSandboxFromConfig',
      'getPlatformSupport',
      'probeSandboxSupport',
      'MxcError',
      'MxcSandboxProcess',
    ] as const) {
      assert.strictEqual(typeof rootSdk[name], 'function', name);
      assert.strictEqual(Object.hasOwn(v1Sdk, name), false, name);
    }
  });
});

describe('in-process async run routing', () => {
  it('uses the V1 binding policy without caller-supplied schema version', async () => {
    let bindingRequest: RequestSpec | undefined;
    _setBindingRunAsyncImplementation(async (request) => {
      bindingRequest = request;
      return {
        stdout: 'out',
        stderr: 'err',
        exitCode: 7,
        timedOut: false,
        warnings: [],
      };
    });

    const result = await spawnSandboxAsync(
      'echo hello',
      {},
      { experimental: true, inheritDefaultEnv: true },
      'C:\\work',
      'sample',
    );

    assert.deepStrictEqual(result, { stdout: 'out', stderr: 'err', exitCode: 7 });
    assert.ok(!('version' in bindingRequest!.policy));
    assert.strictEqual(bindingRequest?.command, 'echo hello');
    assert.strictEqual(bindingRequest?.containerName, 'sample');
    assert.strictEqual(bindingRequest?.workingDirectory, 'C:\\work');
    assert.deepStrictEqual(bindingRequest?.environment, {});
    assert.strictEqual(bindingRequest?.inheritDefaultEnv, true);
  });

  it('rejects executor-only options instead of falling back', async () => {
    for (const options of [
      { usePty: true },
      { dryRun: true },
      { skipPlatformCheck: true },
      { executablePath: 'wxc-exec.exe' },
      { signal: new AbortController().signal },
    ]) {
      await assert.rejects(
        spawnSandboxAsync('echo hello', {}, options),
        /does not support executor-only option/,
      );
    }
  });

  it('surfaces buffered diagnostics', async () => {
    _setBindingRunAsyncImplementation(async () => ({
      stdout: '',
      stderr: 'native stderr',
      exitCode: 0,
      timedOut: false,
      warnings: ['policy was relaxed'],
      outputMetadata: {
        captureDenials: { kind: 'captureDenials', outputPath: 'denials.json' },
      },
    }));

    const result = await spawnSandboxAsync('echo hello', {});
    assert.match(result.stderr, /native stderr/);
    assert.match(result.stderr, /policy was relaxed/);
    assert.match(result.stderr, /denials\.json/);
  });

  it('maps native timeouts to the public error', async () => {
    _setBindingRunAsyncImplementation(async () => ({
      stdout: '',
      stderr: '',
      exitCode: -1,
      timedOut: true,
      warnings: [],
    }));

    await assert.rejects(
      spawnSandboxAsync('echo hello', {}),
      (error: unknown) =>
        error instanceof MxcError
        && error.code === 'backend_error'
        && error.details?.timedOut === true,
    );
  });

  it('preserves typed native errors', async () => {
    _setBindingRunAsyncImplementation(async () => {
      throw new MxcError('unsupported_containment', 'LXC is executor-only');
    });

    await assert.rejects(
      spawnSandboxAsync('echo hello', {}),
      (error: unknown) =>
        error instanceof MxcError
        && error.code === 'unsupported_containment'
        && error.message === 'LXC is executor-only',
    );
  });

  it('wraps binding invocation failures as backend errors', async () => {
    _setBindingRunAsyncImplementation(async () => {
      throw new Error('native invocation failed');
    });

    await assert.rejects(
      spawnSandboxAsync('echo hello', {}),
      (error: unknown) =>
        error instanceof MxcError
        && error.code === 'backend_error'
        && error.message === 'native invocation failed',
    );
  });
});
