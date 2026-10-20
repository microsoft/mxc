// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

import assert from 'node:assert';
import { afterEach, describe, it } from 'node:test';
import {
  _errorCodeForNativeStatus,
  _setBindingRunLibraryLoader,
  runOneShotJsonAsync,
} from '../../src/bindings/run.js';
import { nativeStatusError, parseExecutionMetadata } from '../../src/bindings/native-error.js';
import { MxcError } from '../../src/v1/errors.js';
import type { CaptureDenialsResult, CaptureDenialsError, ExecutionMetadata } from '../../src/v1/index.js';

afterEach(() => _setBindingRunLibraryLoader());

describe('native execution metadata decoding', () => {
  const captureDenials: CaptureDenialsResult = {
    type: 'captureDenials',
    outputPath: 'denials.json',
    exitCode: -1,
    totalDenials: 3,
    deniedResourcesTruncated: false,
    etlPath: 'trace.etl',
  };
  const captureDenialsError: CaptureDenialsError = {
    message: 'finalization failed',
    etlPath: 'retained.etl',
  };

  it('decodes named capture results and errors without changing native fields', () => {
    const metadata: ExecutionMetadata = { captureDenials, captureDenialsError };
    const decoded = parseExecutionMetadata(JSON.stringify(metadata));
    assert.deepStrictEqual(decoded, metadata);
    assert.strictEqual(decoded?.captureDenials?.outputPath, 'denials.json');
    assert.strictEqual(decoded?.captureDenialsError?.etlPath, 'retained.etl');
  });

  it('preserves absent metadata and optional retained traces', () => {
    assert.strictEqual(parseExecutionMetadata(undefined), undefined);
    assert.deepStrictEqual(parseExecutionMetadata('{}'), {});
    const { etlPath, ...withoutTrace } = captureDenials;
    assert.deepStrictEqual(
      parseExecutionMetadata(JSON.stringify({ captureDenials: withoutTrace })),
      { captureDenials: withoutTrace },
    );
  });

  it('rejects malformed metadata with typed backend errors', () => {
    for (const json of [
      '{', 'null', '[]', '42',
      JSON.stringify({ captureDenials: {} }),
      JSON.stringify({ captureDenials: { ...captureDenials, totalDenials: -1 } }),
      JSON.stringify({ captureDenials: { ...captureDenials, exitCode: 1.5 } }),
      JSON.stringify({ captureDenials: { ...captureDenials, deniedResourcesTruncated: 'false' } }),
      JSON.stringify({ captureDenials: { ...captureDenials, etlPath: 1 } }),
      JSON.stringify({ captureDenialsError: { message: 'failure' } }),
    ]) {
      assert.throws(() => parseExecutionMetadata(json), (error: unknown) =>
        error instanceof MxcError && error.code === 'backend_error');
    }
  });
});

describe('native run binding', () => {
  function installLibrary(events: string[], supportsMutation: boolean): void {
    _setBindingRunLibraryLoader((() => ({
      path: 'fake-mxc',
      version: () => 'test',
      handle: {
        unload: () => events.push('unload'),
        func: (symbol: string) => {
          events.push(`bind:${symbol}`);
          if (symbol === 'mxc_run_result_free') {
            return () => events.push('free-result');
          }
          if (symbol === 'mxc_run_with_policy_mutation_json' && !supportsMutation) {
            throw new Error(`Cannot find function '${symbol}'`);
          }
          const invoke = (_request: string, experimental: number, result: object) => {
            assert.strictEqual(experimental, 0);
            events.push(`call:${symbol}`);
            Object.assign(result, {
              status: 0, exitCode: 0, timedOut: 0, error: {},
              stdout: Buffer.from('workload\0'), stderr: null, outputMetadata: null,
              warnings: symbol === 'mxc_run_with_policy_mutation_json'
                ? Buffer.from('["Policy mutation: restricted egress"]\0') : null,
            });
            return 0;
          };
          return Object.assign(invoke, {
            async: (
              request: string,
              experimental: number,
              result: object,
              complete: (error: Error | null, status: number) => void,
            ) => queueMicrotask(() => complete(null, invoke(request, experimental, result))),
          });
        },
      },
    })) as never);
  }

  it('uses dedicated mutation exports and the existing warnings/result ownership', async () => {
    const events: string[] = [];
    installLibrary(events, true);
    const request = {
      version: '1.0.0' as const,
      process: { commandLine: 'not executed by this fake' },
    };
    const strict = await runOneShotJsonAsync(request);
    const mutated = await runOneShotJsonAsync(request, false, true);
    assert.deepStrictEqual(strict.warnings, []);
    assert.deepStrictEqual(mutated.warnings, ['Policy mutation: restricted egress']);
    assert.strictEqual(mutated.stdout, 'workload');
    assert.strictEqual(mutated.stderr, '');
    assert.deepStrictEqual(events, [
      'bind:mxc_run_json', 'bind:mxc_run_result_free', 'call:mxc_run_json',
      'free-result', 'unload',
      'bind:mxc_run_with_policy_mutation_json', 'bind:mxc_run_result_free',
      'call:mxc_run_with_policy_mutation_json', 'free-result',
    ]);
  });

  it('retains the native mutation module across calls without retaining policy in JavaScript', async () => {
    const events: string[] = [];
    installLibrary(events, true);
    const request = {
      version: '1.0.0' as const,
      process: { commandLine: 'not executed by this fake' },
    };
    await runOneShotJsonAsync(request, false, true);
    await runOneShotJsonAsync(request);
    await runOneShotJsonAsync(request, false, true);
    assert.strictEqual(events.filter((event) => event === 'bind:mxc_run_with_policy_mutation_json').length, 1);
    assert.strictEqual(events.filter((event) => event === 'call:mxc_run_with_policy_mutation_json').length, 2);
    assert.strictEqual(events.filter((event) => event === 'free-result').length, 3);
    assert.strictEqual(events.filter((event) => event === 'unload').length, 1);
  });
  it('leaves strict calls usable on old libraries and never silently falls back', async () => {
    const events: string[] = [];
    installLibrary(events, false);
    const request = {
      version: '1.0.0' as const,
      process: { commandLine: 'not executed by this fake' },
    };
    await runOneShotJsonAsync(request);
    events.length = 0;
    await assert.rejects(runOneShotJsonAsync(request, false, true), (error: unknown) =>
      error instanceof MxcError && error.code === 'backend_unavailable'
        && error.message.includes('mxc_run_with_policy_mutation_json'));
    assert.deepStrictEqual(events, ['bind:mxc_run_with_policy_mutation_json', 'unload']);
  });

  it('preserves creation-policy text after native message storage is released', () => {
    const message = [
      'CreateProcessSecurityEnvironment failed (HRESULT = 0x800704EC)',
      'Returned constraints: 2 (non-exhaustive).',
      'Resource 1: "C:\\\\work"',
      'Resource 2: "C:\\\\\u65e5\u672c"',
      'required=18446744073709551615.',
    ].join('\n');
    const storage = Buffer.from(`${message}\0`, 'utf8');
    const error = nativeStatusError(12, { message: storage });
    storage.fill(0);
    assert.strictEqual(error.code, 'backend_error');
    assert.strictEqual(error.message, message);
    assert.deepStrictEqual(error.details, { ffiStatus: 12 });
    assert.strictEqual(error.operation, undefined);
    assert.strictEqual(error.nativeCode, undefined);
  });

  it('maps SDK status codes', () => {
    assert.strictEqual(_errorCodeForNativeStatus(1), 'malformed_request');
    assert.strictEqual(_errorCodeForNativeStatus(2), 'unsupported_containment');
    assert.strictEqual(_errorCodeForNativeStatus(4), 'backend_unavailable');
    assert.strictEqual(_errorCodeForNativeStatus(11), 'policy_validation');
    assert.strictEqual(_errorCodeForNativeStatus(12), 'backend_error');
  });

  it('maps FFI contract failures without inventing new public codes', () => {
    assert.strictEqual(_errorCodeForNativeStatus(100), 'malformed_request');
    assert.strictEqual(_errorCodeForNativeStatus(101), 'malformed_request');
    assert.strictEqual(_errorCodeForNativeStatus(102), 'backend_error');
    assert.strictEqual(_errorCodeForNativeStatus(103), 'backend_error');
    assert.strictEqual(_errorCodeForNativeStatus(999), 'backend_error');
  });
});
