// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

import assert from 'node:assert';
import { afterEach, describe, it } from 'node:test';
import { MxcError } from '../../src/errors.js';
import { spawnSandboxAsync } from '../../src/sandbox.js';
import { _setBindingRunAsyncImplementation } from '../../src/bindings/run.js';
import type { RequestSpec } from '../../src/bindings/request.js';

afterEach(() => _setBindingRunAsyncImplementation());

describe('in-process async run routing', () => {
  it('uses the version-free v1 binding policy', async () => {
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
});
