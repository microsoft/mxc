// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

import assert from 'node:assert';
import { afterEach, describe, it } from 'node:test';
import * as rootSdk from '../../src/index.js';
import * as v1Sdk from '../../src/v1/index.js';
import {
  _setBindingRunAsyncImplementation,
} from '../../src/bindings/run.js';
import { _setBindingSandboxProcessFactories } from '../../src/bindings/streaming.js';
import {
  MxcProcess,
  type NativeLifecycleDriver,
} from '../../src/v1/container-process.js';
import type { OneShotRequest } from '../../src/generated/v1_0_0/wire.js';

const { MxcError } = v1Sdk;
const { run, spawn } = v1Sdk;

afterEach(() => {
  _setBindingRunAsyncImplementation();
  _setBindingSandboxProcessFactories();
});

describe('public SDK namespace exports', () => {
  it('keeps V1 operations and types in the versioned entry point', () => {
    for (const name of [
      'spawn',
      'run',
      'provisionContainer',
      'startContainer',
      'spawnInContainer',
      'runInContainer',
      'stopContainer',
      'deprovisionContainer',
      'MxcProcess',
    ] as const) {
      assert.strictEqual(typeof v1Sdk[name], 'function', name);
      assert.strictEqual(Object.hasOwn(rootSdk, name), false, name);
    }
  });

  it('does not expose replaced one-shot APIs or legacy process wrappers', () => {
    for (const name of [
      'createConfigFromRequest',
      'runAsync',
      'spawnAsync',
      'runInContainerAsync',
      'spawnInContainerAsync',
      'spawnSandbox',
      'spawnSandboxAsync',
      'spawnSandboxFromConfig',
    ] as const) {
      assert.strictEqual(Object.hasOwn(rootSdk, name), false, name);
      assert.strictEqual(Object.hasOwn(v1Sdk, name), false, name);
    }
    assert.strictEqual(Object.hasOwn(v1Sdk, 'MxcSandboxProcess'), false);
    assert.strictEqual(typeof v1Sdk.MxcProcess.prototype.wait, 'function');
    assert.strictEqual(Object.hasOwn(v1Sdk.MxcProcess.prototype, 'waitAsync'), false);

    for (const name of [
      'getPlatformSupport', 'getAvailableBackends', 'probe', 'MxcError',
      'getTelemetryConsentStatus', 'requestTelemetryConsent', 'withdrawTelemetryConsent',
    ] as const) {
      assert.strictEqual(typeof v1Sdk[name], 'function', name);
      assert.strictEqual(Object.hasOwn(rootSdk, name), false, name);
    }
    for (const name of [
      'queryTelemetryConsentAsync',
      'getTelemetryConsentStatusAsync',
      'requestTelemetryConsentAsync',
      'withdrawTelemetryConsentAsync',
    ]) {
      assert.strictEqual(Object.hasOwn(v1Sdk, name), false, name);
    }
    assert.deepStrictEqual(Object.keys(rootSdk), []);
  });
});

describe('in-process asynchronous run routing', () => {
  it('rejects any supplied dryRun option before native execution', async () => {
    for (const dryRun of [true, false, undefined]) {
      const options = { dryRun } as never;
      await assert.rejects(run({ command: 'echo hello' }, options), /does not support dryRun/);
      await assert.rejects(spawn({ command: 'echo hello' }, options), /does not support dryRun/);
      await assert.rejects(
        v1Sdk.spawnWithPty({ command: 'echo hello' }, options),
        /does not support dryRun/,
      );
    }
  });

  it('rejects malformed creation telemetry before native execution', async () => {
    for (const telemetry of [null, true, [], { enabled: 'true' }, { ignored: true }]) {
      const options = { telemetry } as never;
      await assert.rejects(run({ command: 'echo hello' }, options), /telemetry must contain/);
      await assert.rejects(spawn({ command: 'echo hello' }, options), /telemetry must contain/);
      await assert.rejects(
        v1Sdk.spawnWithPty({ command: 'echo hello' }, options),
        /telemetry must contain/,
      );
    }
  });

  it('uses the SDK-owned exact v1 one-shot request', async () => {
    let bindingRequest: OneShotRequest | undefined;
    let bindingExperimental = false;
    _setBindingRunAsyncImplementation(async (request, experimental) => {
      bindingRequest = request;
      bindingExperimental = experimental;
      return {
        stdout: 'out',
        stderr: 'err',
        exitCode: 7,
        timedOut: false,
        warnings: [],
      };
    });

    const result = await run({
      command: 'echo hello',
      workingDirectory: 'C:\\work',
      environment: { SAMPLE: 'value' },
      inheritDefaultEnvironment: true,
      containerName: 'sample',
    }, { experimental: true, telemetry: { enabled: false } });

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
    assert.strictEqual(bindingExperimental, true);
    assert.deepStrictEqual(bindingRequest?.telemetry, { enabled: false });
  });

  it('routes spawn through the asynchronous native process binding with options', async () => {
    let bindingRequest: OneShotRequest | undefined;
    let bindingExperimental = false;
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
      return new MxcProcess(driver);
    };
    _setBindingSandboxProcessFactories(
      () => assert.fail('the public V1 API must not use the synchronous binding'),
      async (request, experimental) => {
        bindingRequest = request;
        bindingExperimental = experimental;
        return createProcess();
      },
    );

    const processHandle = await spawn(
      { command: 'echo spawn' },
      { experimental: true, telemetry: { enabled: true } },
    );

    assert.ok(processHandle instanceof v1Sdk.MxcProcess);
    assert.strictEqual(bindingRequest?.process.commandLine, 'echo spawn');
    assert.strictEqual(bindingRequest?.version, '1.0.0');
    assert.strictEqual(bindingExperimental, true);
    assert.deepStrictEqual(bindingRequest?.telemetry, { enabled: true });
    await processHandle.wait();
  });

  it('rejects invalid requests at the SDK boundary', async () => {
    await assert.rejects(
      run({ command: '' }),
      /command must be a non-empty string/,
    );
    await assert.rejects(
      run({ command: null as never }),
      /command must be a non-empty string/,
    );
  });

  it('preserves captured stderr verbatim while returning diagnostics separately', async () => {
    const nativeResult = {
      stdout: '',
      stderr: 'native stderr',
      exitCode: 0,
      timedOut: false,
      warnings: ['policy was relaxed'],
      outputMetadata: {
        captureDenials: {
          type: 'captureDenials', outputPath: 'denials.json', exitCode: 0,
          totalDenials: 3, deniedResourcesTruncated: false,
        },
      },
    } as const;
    _setBindingRunAsyncImplementation(async () => ({
      ...nativeResult, warnings: [...nativeResult.warnings],
    }));

    const result = await run({ command: 'echo hello' });
    assert.strictEqual(result.stderr, nativeResult.stderr);
    assert.deepStrictEqual(result.warnings, ['policy was relaxed']);
    assert.deepStrictEqual(result.outputMetadata, nativeResult.outputMetadata);
  });

  it('does not manufacture stderr when a workload emits none', async () => {
    _setBindingRunAsyncImplementation(async () => ({
      stdout: '', stderr: '', exitCode: 0, timedOut: false, warnings: ['warning'],
    }));
    assert.strictEqual((await run({ command: 'echo hello' })).stderr, '');
  });

  it('preserves timeout results and typed native errors', async () => {
    _setBindingRunAsyncImplementation(async () => ({
      stdout: '',
      stderr: '',
      exitCode: -1,
      timedOut: true,
      warnings: [],
    }));

    const timedOut = await run({ command: 'echo hello' });
    assert.strictEqual(timedOut.timedOut, true);
    assert.strictEqual(timedOut.exitCode, -1);

    _setBindingRunAsyncImplementation(async () => {
      throw new MxcError('unsupported_containment', 'backend unavailable');
    });

    await assert.rejects(
      run({ command: 'echo hello' }),
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
      run({ command: 'echo hello' }),
      (error: unknown) =>
        error instanceof MxcError
        && error.code === 'backend_error'
        && error.message === 'native invocation failed',
    );
  });
});
