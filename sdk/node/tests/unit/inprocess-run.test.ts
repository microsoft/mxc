// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

import assert from 'node:assert';
import { afterEach, describe, it } from 'node:test';
import * as rootSdk from '../../src/index.js';
import * as v1Sdk from '../../src/v1.js';
import { _setSpawnBindingSandboxWithPtyImplementation } from '../../src/bindings/pty.js';
import { _setBindingRunAsyncImplementation } from '../../src/bindings/run.js';
import type { OneShotRequest } from '../../src/generated/v1_0_0/wire.js';
import type { MxcPtyProcess } from '../../src/mxc-pty-process.js';

const { MxcError } = rootSdk;
const { spawnSandboxAsync, spawnWithPty } = v1Sdk;

afterEach(() => {
  _setBindingRunAsyncImplementation();
  _setSpawnBindingSandboxWithPtyImplementation();
});

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
  it('routes PTY containment through the SDK-owned exact request', async () => {
    let bindingRequest: OneShotRequest | undefined;
    let bindingRows = 0;
    let bindingColumns = 0;
    _setSpawnBindingSandboxWithPtyImplementation(
      async (request, _experimental, rows, columns) => {
        bindingRequest = request;
        bindingRows = rows;
        bindingColumns = columns;
        return {} as MxcPtyProcess;
      },
    );

    const config = v1Sdk.createConfigFromPolicy({}, 'isolation_session');
    config.process!.commandLine = 'cmd.exe';
    await spawnWithPty(config, { rows: 30, columns: 100 });

    assert.strictEqual(bindingRequest?.containment, 'isolation_session');
    assert.strictEqual(bindingRequest?.ui, undefined);
    assert.strictEqual(bindingRows, 30);
    assert.strictEqual(bindingColumns, 100);
  });

  it('routes ProcessContainer PTY requests and terminal size to the native binding', async () => {
    let bindingRequest: OneShotRequest | undefined;
    let bindingRows = 0;
    let bindingColumns = 0;
    _setSpawnBindingSandboxWithPtyImplementation(
      async (request, _experimental, rows, columns) => {
        bindingRequest = request;
        bindingRows = rows;
        bindingColumns = columns;
        return {} as MxcPtyProcess;
      },
    );

    const config = v1Sdk.createConfigFromPolicy({}, 'processcontainer');
    config.process!.commandLine = 'cmd.exe /c echo pty';
    await spawnWithPty(config, { rows: 42, columns: 132 });

    assert.strictEqual(bindingRequest?.containment, 'processcontainer');
    assert.strictEqual(bindingRequest?.process.commandLine, 'cmd.exe /c echo pty');
    assert.strictEqual(bindingRows, 42);
    assert.strictEqual(bindingColumns, 132);
  });

  it('uses the SDK-owned exact v1 one-shot request', async () => {
    let bindingRequest: OneShotRequest | undefined;
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
      { inheritDefaultEnv: true },
      'C:\\work',
      'sample',
    );

    assert.deepStrictEqual(result, { stdout: 'out', stderr: 'err', exitCode: 7 });
    assert.strictEqual(bindingRequest?.version, '1.0.0');
    assert.strictEqual(bindingRequest?.process.commandLine, 'echo hello');
    assert.strictEqual(bindingRequest?.containerId, 'sample');
    assert.strictEqual(bindingRequest?.process.cwd, 'C:\\work');
    assert.strictEqual(bindingRequest?.process.inheritDefaultEnv, true);
  });

  it('rejects executor-only options instead of falling back', async () => {
    for (const options of [
      { usePty: true },
      { dryRun: true },
      { skipPlatformCheck: true },
      { executablePath: 'wxc-exec.exe' },
      { signal: new AbortController().signal },
      { experimental: true },
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
