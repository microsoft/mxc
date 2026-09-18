// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

import assert from 'node:assert';
import { afterEach, describe, it } from 'node:test';
import { MxcError } from '../../src/errors.js';
import { spawnSandboxAsync } from '../../src/sandbox.js';
import { _setBindingRunAsyncImplementation } from '../../src/bindings/run.js';
import type { RequestSpec } from '../../src/bindings/request.js';
import type { SandboxPolicy } from '../../src/types.js';

afterEach(() => _setBindingRunAsyncImplementation());

describe('in-process async run routing', () => {
  it('converts the existing config flow at the native boundary', async () => {
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
      { version: '0.9.0-alpha' },
      { experimental: true, inheritDefaultEnv: true },
      'C:\\work',
      'sample',
    );

    assert.deepStrictEqual(result, { stdout: 'out', stderr: 'err', exitCode: 7 });
    assert.strictEqual(bindingRequest?.policy.version, '0.9.0-alpha');
    assert.strictEqual(bindingRequest?.command, 'echo hello');
    assert.strictEqual(bindingRequest?.containerName, 'sample');
    assert.strictEqual(bindingRequest?.workingDirectory, 'C:\\work');
    assert.deepStrictEqual(bindingRequest?.environment, {});
    assert.strictEqual(bindingRequest?.inheritDefaultEnv, true);
    assert.strictEqual(bindingRequest?.experimental, true);
  });

  it('rejects executor-only options instead of falling back', async () => {
    const policy = { version: '0.9.0-alpha' };
    for (const options of [
      { usePty: true },
      { dryRun: true },
      { skipPlatformCheck: true },
      { executablePath: 'wxc-exec.exe' },
      { signal: new AbortController().signal },
    ]) {
      await assert.rejects(
        spawnSandboxAsync('echo hello', policy, options),
        /does not support executor-only option/,
      );
    }
  });

  it('rejects an explicitly authored network enforcement mode', async () => {
    const policy = {
      version: '0.8.0-alpha',
      network: { enforcementMode: 'firewall' },
    } as SandboxPolicy & { network: { enforcementMode: 'firewall' } };

    await assert.rejects(
      spawnSandboxAsync('echo hello', policy),
      (error: unknown) =>
        error instanceof MxcError
        && error.code === 'malformed_request'
        && error.message.includes('network.enforcementMode'),
    );
  });

  it('lets the native builder derive legacy network enforcement', async () => {
    let bindingRequest: RequestSpec | undefined;
    _setBindingRunAsyncImplementation(async (request) => {
      bindingRequest = request;
      return {
        stdout: '',
        stderr: '',
        exitCode: 0,
        timedOut: false,
        warnings: [],
      };
    });

    await spawnSandboxAsync('echo hello', {
      version: '0.8.0-alpha',
      network: { allowOutbound: true, allowedHosts: ['example.com'] },
    });

    assert.strictEqual(bindingRequest?.policy.network?.allowOutbound, true);
    assert.deepStrictEqual(
      bindingRequest?.policy.network?.allowedHosts,
      ['example.com'],
    );
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

    const result = await spawnSandboxAsync('echo hello', { version: '0.9.0-alpha' });
    assert.strictEqual(
      result.stderr,
      'native stderr\npolicy was relaxed\n'
        + '{"kind":"captureDenials","outputPath":"denials.json"}\n',
    );
  });

  it('rejects timed-out execution', async () => {
    _setBindingRunAsyncImplementation(async () => ({
      stdout: '',
      stderr: '',
      exitCode: -1,
      timedOut: true,
      warnings: [],
    }));

    await assert.rejects(
      spawnSandboxAsync('sleep 30', { version: '0.9.0-alpha', timeoutMs: 1 }),
      (error: unknown) =>
        error instanceof MxcError
        && error.code === 'backend_error'
        && error.message.includes('timed out'),
    );
  });

  it('preserves typed native errors', async () => {
    _setBindingRunAsyncImplementation(async () => {
      throw new MxcError('unsupported_containment', 'LXC is executor-only');
    });

    await assert.rejects(
      spawnSandboxAsync('echo hello', { version: '0.9.0-alpha' }),
      (error: unknown) =>
        error instanceof MxcError
        && error.code === 'unsupported_containment'
        && error.message === 'LXC is executor-only',
    );
  });

  it('wraps Koffi invocation failures as backend errors', async () => {
    _setBindingRunAsyncImplementation(async () => {
      throw new Error('native invocation failed');
    });

    await assert.rejects(
      spawnSandboxAsync('echo hello', { version: '0.9.0-alpha' }),
      (error: unknown) =>
        error instanceof MxcError
        && error.code === 'backend_error'
        && error.message === 'native invocation failed',
    );
  });

  it('rejects testing-only policy instead of falling back', async () => {
    await assert.rejects(
      spawnSandboxAsync('echo hello', {
        version: '0.8.0-alpha',
        network: { proxy: { builtinTestServer: true } },
      }),
      /not supported by the in-process Node SDK/,
    );
  });
});
