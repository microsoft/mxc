// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

import assert from 'node:assert';
import { afterEach, describe, it } from 'node:test';
import * as rootSdk from '../../src/index.js';
import * as v1Sdk from '../../src/v1.js';
import {
  _setBindingRunAsyncImplementation,
  _setBindingRunImplementation,
} from '../../src/bindings/run.js';
import { _setBindingSandboxProcessFactories } from '../../src/bindings/streaming.js';
import {
  MxcSandboxProcess,
  type NativeLifecycleDriver,
} from '../../src/sandbox-process.js';
import type { OneShotRequest } from '../../src/generated/v1_0_0/wire.js';

const { MxcError } = rootSdk;
const { run, runAsync, spawn, spawnAsync } = v1Sdk;

afterEach(() => {
  _setBindingRunImplementation();
  _setBindingRunAsyncImplementation();
  _setBindingSandboxProcessFactories();
});

describe('public SDK namespace exports', () => {
  it('keeps V1 operations and types in the versioned entry point', () => {
    for (const name of [
      'spawn',
      'spawnAsync',
      'run',
      'runAsync',
      'provisionSandbox',
      'startSandbox',
      'execInSandbox',
      'execInSandboxAsync',
      'stopSandbox',
      'deprovisionSandbox',
      'MxcProcess',
    ] as const) {
      assert.strictEqual(typeof v1Sdk[name], 'function', name);
      assert.strictEqual(Object.hasOwn(rootSdk, name), false, name);
    }
  });

  it('does not expose replaced one-shot APIs or process wrappers', () => {
    for (const name of [
      'createConfigFromPolicy',
      'spawnSandbox',
      'spawnSandboxAsync',
      'spawnSandboxFromConfig',
      'MxcSandboxProcess',
    ] as const) {
      assert.strictEqual(Object.hasOwn(rootSdk, name), false, name);
      assert.strictEqual(Object.hasOwn(v1Sdk, name), false, name);
    }

    for (const name of ['getPlatformSupport', 'probeSandboxSupport', 'MxcError'] as const) {
      assert.strictEqual(typeof rootSdk[name], 'function', name);
      assert.strictEqual(Object.hasOwn(v1Sdk, name), false, name);
    }
  });
});

describe('in-process asynchronous run routing', () => {
  it('uses the SDK-owned exact v1 one-shot request synchronously', () => {
    let bindingRequest: OneShotRequest | undefined;
    _setBindingRunImplementation((request) => {
      bindingRequest = request;
      return {
        stdout: 'sync output',
        stderr: '',
        exitCode: 0,
        timedOut: false,
        warnings: [],
      };
    });

    const result = run({
      policy: {},
      command: 'echo sync',
      containerName: 'sync-sample',
    });

    assert.strictEqual(result.stdout, 'sync output');
    assert.strictEqual(bindingRequest?.version, '1.0.0');
    assert.strictEqual(bindingRequest?.process.commandLine, 'echo sync');
    assert.strictEqual(bindingRequest?.containerId, 'sync-sample');
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

    it('routes spawn and spawnAsync through the native process bindings', async () => {
      let syncRequest: OneShotRequest | undefined;
      let asyncRequest: OneShotRequest | undefined;
      const createProcess = () => {
        const driver: NativeLifecycleDriver = {
          id: 17,
          standardInput: null,
          standardOutput: null,
          standardError: null,
          poll: () => ({ exitCode: 0, running: false, timedOut: false }),
          wait: async () => ({ exitCode: 0, timedOut: false }),
          warnings: () => [],
          outputMetadata: () => undefined,
          kill: () => {},
          killForTimeout: () => {},
          free: async () => {},
        };
        return new MxcSandboxProcess(driver);
      };
      _setBindingSandboxProcessFactories(
        (request) => {
          syncRequest = request;
          return createProcess();
        },
        async (request) => {
          asyncRequest = request;
          return createProcess();
        },
      );

      const syncProcess = spawn({ policy: {}, command: 'echo sync spawn' });
      const asyncProcess = await spawnAsync({ policy: {}, command: 'echo async spawn' });

      assert.ok(syncProcess instanceof v1Sdk.MxcProcess);
      assert.ok(asyncProcess instanceof v1Sdk.MxcProcess);
      assert.strictEqual(syncRequest?.process.commandLine, 'echo sync spawn');
      assert.strictEqual(syncRequest?.version, '1.0.0');
      assert.strictEqual(asyncRequest?.process.commandLine, 'echo async spawn');
      assert.strictEqual(asyncRequest?.version, '1.0.0');
      await Promise.all([syncProcess.waitAsync(), asyncProcess.waitAsync()]);
    });

    const result = await runAsync({
      policy: {},
      command: 'echo hello',
      workingDirectory: 'C:\\work',
      environment: { SAMPLE: 'value' },
      inheritDefaultEnvironment: true,
      containerName: 'sample',
    });

    assert.deepStrictEqual(result, {
      stdout: 'out',
      stderr: 'err',
      exitCode: 7,
      timedOut: false,
      warnings: [],
    });
    assert.strictEqual(bindingRequest?.version, '1.0.0');
    assert.strictEqual(bindingRequest?.process.commandLine, 'echo hello');
    assert.strictEqual(bindingRequest?.containerId, 'sample');
    assert.strictEqual(bindingRequest?.process.cwd, 'C:\\work');
    assert.deepStrictEqual(bindingRequest?.process.env, ['SAMPLE=value']);
    assert.strictEqual(bindingRequest?.process.inheritDefaultEnv, true);
  });

  it('rejects invalid requests at the SDK boundary', async () => {
    await assert.rejects(
      runAsync({ policy: {}, command: '' }),
      /command must be a non-empty string/,
    );
    await assert.rejects(
      runAsync({ policy: null as never, command: 'echo hello' }),
      /policy must be an object/,
    );
  });

  it('preserves buffered diagnostics and metadata', async () => {
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

    const result = await runAsync({ policy: {}, command: 'echo hello' });
    assert.match(result.stderr, /native stderr/);
    assert.deepStrictEqual(result.warnings, ['policy was relaxed']);
    assert.deepStrictEqual(result.outputMetadata, {
      captureDenials: { kind: 'captureDenials', outputPath: 'denials.json' },
    });
  });

  it('preserves timeout results and typed native errors', async () => {
    _setBindingRunAsyncImplementation(async () => ({
      stdout: '',
      stderr: '',
      exitCode: -1,
      timedOut: true,
      warnings: [],
    }));

    const timedOut = await runAsync({ policy: {}, command: 'echo hello' });
    assert.strictEqual(timedOut.timedOut, true);
    assert.strictEqual(timedOut.exitCode, -1);

    _setBindingRunAsyncImplementation(async () => {
      throw new MxcError('unsupported_containment', 'backend unavailable');
    });

    await assert.rejects(
      runAsync({ policy: {}, command: 'echo hello' }),
      (error: unknown) =>
        error instanceof MxcError
        && error.code === 'unsupported_containment'
        && error.message === 'backend unavailable',
    );
  });

  it('wraps binding invocation failures as backend errors', async () => {
    _setBindingRunAsyncImplementation(async () => {
      throw new Error('native invocation failed');
    });

    await assert.rejects(
      runAsync({ policy: {}, command: 'echo hello' }),
      (error: unknown) =>
        error instanceof MxcError
        && error.code === 'backend_error'
        && error.message === 'native invocation failed',
    );
  });
});
