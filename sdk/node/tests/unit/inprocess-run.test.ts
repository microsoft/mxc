// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

import assert from 'node:assert';
import { afterEach, describe, it } from 'node:test';
import { MxcError } from '../../src/errors.js';
import { createConfigFromPolicy, spawnSandboxAsync, spawnSandboxAsyncWithReport } from '../../src/sandbox.js';
import { _setBindingRunAsyncImplementation } from '../../src/bindings/run.js';
import type { RequestSpec } from '../../src/bindings/request.js';
import type { SandboxPolicy } from '../../src/types.js';

afterEach(() => _setBindingRunAsyncImplementation());

describe('in-process async run routing', () => {
  it('preserves the legacy config object when policy controls are omitted', { skip: process.platform !== 'win32' }, () => {
    for (const version of ['0.9.0-alpha', '0.10.0-alpha']) {
      for (const processContainer of [undefined, {}]) {
        const config = createConfigFromPolicy({ version, processContainer });
        assert.deepStrictEqual(Object.keys(config.processContainer ?? {}), [
          'leastPrivilege', 'capabilities', 'ui', 'filesystem', 'network',
        ]);
      }
    }
    const opted = createConfigFromPolicy({
      version: '0.10.0-alpha',
      processContainer: { policyEnforcement: {} },
    });
    assert.strictEqual(Object.hasOwn(opted.processContainer ?? {}, 'policyEnforcement'), true);
    assert.deepStrictEqual(opted.processContainer?.policyEnforcement, {});
  });

  it('snapshots getter-backed policy controls without changing the attempt limit', { skip: process.platform !== 'win32' }, async () => {
    for (const ownGetter of [false, true]) {
      let reads = 0;
      let modeReads = 0;
      class Controls {
        get mode() { modeReads++; return 'mutate' as const; }
        get maxAttempts() { return ++reads === 1 ? 1 : 64; }
      }
      const controls = new Controls();
      if (ownGetter) {
        Object.defineProperty(controls, 'maxAttempts', {
          enumerable: true,
          get: () => ++reads === 1 ? 1 : 64,
        });
      }
      let bindingRequest: RequestSpec | undefined;
      _setBindingRunAsyncImplementation(async (request) => {
        bindingRequest = request;
        return { stdout: '', stderr: '', exitCode: 0, timedOut: false, warnings: [] };
      });
      await spawnSandboxAsync('unused', {
        version: '0.10.0-alpha',
        processContainer: { policyEnforcement: controls },
      }, { experimental: true });
      if (bindingRequest?.containment.type !== 'processContainer') assert.fail('wrong containment');
      assert.deepStrictEqual(bindingRequest.containment.policyEnforcement, { mode: 'mutate', maxAttempts: 1 });
      assert.strictEqual(reads, 1);
      assert.strictEqual(modeReads, 1);
    }
  });

  it('rejects malformed policy-control shapes before projection or native execution', { skip: process.platform !== 'win32' }, async () => {
    let nativeCalls = 0;
    _setBindingRunAsyncImplementation(async () => {
      nativeCalls++;
      return { stdout: '', stderr: '', exitCode: 0, timedOut: false, warnings: [] };
    });
    for (const policyEnforcement of [
      false, true, 0, '', [], ['mutate', 1], null,
      { mode: 'mutate', maxAttempts: 1, typo: true },
      { mode: false }, { mode: null }, { maxAttempts: null },
    ]) {
      const policy = { version: '0.10.0-alpha', processContainer: { policyEnforcement } };
      const malformed = (error: unknown) =>
        error instanceof MxcError && error.code === 'malformed_request';
      // Reflect exercises untyped JavaScript callers without changing public TypeScript types.
      assert.throws(() => Reflect.apply(createConfigFromPolicy, undefined, [policy]), malformed);
      await assert.rejects(Reflect.apply(spawnSandboxAsync, undefined, ['unused', policy]), malformed);
    }
    assert.strictEqual(nativeCalls, 0);
  });

  it('forwards policy controls and retains creation metadata', { skip: process.platform !== 'win32' }, async () => {
    let bindingRequest: RequestSpec | undefined;
    const metadata = { policyEnforcement: {
      reportVersion: 1, requestedMode: 'mutate', modeApplied: false,
      availability: 'unavailable', termination: 'ignored', environmentCreated: false,
      originalPolicyHash: 'same', effectivePolicyHash: 'same', attempts: [],
    } };
    _setBindingRunAsyncImplementation(async (request) => {
      bindingRequest = request;
      return { stdout: '', stderr: '', exitCode: 0, timedOut: false, warnings: [], outputMetadata: metadata };
    });
    const result = await spawnSandboxAsyncWithReport('echo unused', {
      version: '0.10.0-alpha',
      processContainer: { policyEnforcement: { mode: 'mutate', maxAttempts: 8 } },
    }, { experimental: true });
    assert.deepStrictEqual(bindingRequest?.containment.type, 'processContainer');
    if (bindingRequest?.containment.type !== 'processContainer') assert.fail('wrong native containment');
    assert.deepStrictEqual(bindingRequest.containment.policyEnforcement, { mode: 'mutate', maxAttempts: 8 });
    assert.deepStrictEqual(result.outputMetadata, metadata);
  });

  it('retains the policy journal when buffered execution times out', { skip: process.platform !== 'win32' }, async () => {
    const policyEnforcement = {
      reportVersion: 1, requestedMode: 'mutate', modeApplied: true,
      availability: 'available', termination: 'created', environmentCreated: true,
      originalPolicyHash: 'before', effectivePolicyHash: 'after', attempts: [],
    };
    _setBindingRunAsyncImplementation(async () => ({
      stdout: '', stderr: '', exitCode: -1, timedOut: true,
      warnings: ['timed out; additionally capture sealing failed'],
      outputMetadata: { policyEnforcement },
    }));
    await assert.rejects(
      spawnSandboxAsync('unused', {
        version: '0.10.0-alpha',
        processContainer: { policyEnforcement: { mode: 'mutate' } },
      }, { experimental: true }),
      (error: unknown) => error instanceof MxcError
        && error.details?.policyEnforcement === policyEnforcement
        && JSON.stringify(error.details?.warnings) === JSON.stringify(['timed out; additionally capture sealing failed']),
    );
  });

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

    const result: Record<string, string | number> = await spawnSandboxAsync(
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

  it('preserves authored outbound intent for native legacy validation', async () => {
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
    assert.deepStrictEqual(result, {
      stdout: '',
      stderr: 'native stderr\npolicy was relaxed\n'
        + '{"kind":"captureDenials","outputPath":"denials.json"}\n',
      exitCode: 0,
    });
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

  it('exposes capture metadata only through the additive reporting API', async () => {
    const metadata = { captureDenials: { kind: 'captureDenials', outputPath: 'denials.json' } };
    let calls = 0;
    _setBindingRunAsyncImplementation(async (request) => {
      calls++;
      assert.strictEqual(JSON.stringify(request).includes('policyEnforcement'), false);
      return {
        stdout: 'once', stderr: '', exitCode: 0, timedOut: false, warnings: [],
        outputMetadata: metadata,
      };
    });
    const result = await spawnSandboxAsyncWithReport('unused', { version: '0.9.0-alpha' });
    assert.strictEqual(result.stdout, 'once');
    assert.deepStrictEqual(result.outputMetadata, metadata);
    assert.strictEqual(calls, 1);
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
