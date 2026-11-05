// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

import assert from 'node:assert';
import { mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import * as path from 'node:path';
import { describe, it } from 'node:test';
import koffi from 'koffi';
import { _errorCodeForNativeStatus } from '../../src/bindings/run.js';
import {
  AbiErrorDetailType,
  createAbiErrorDetail,
  parseExecutionMetadata,
  type AbiErrorDetail,
} from '../../src/bindings/native-error.js';
import { MxcError } from '../../src/v1/errors.js';
import { run } from '../../src/v1/container.js';
import { runJson, policyFailuresFromError, serializePolicyFailures } from '../../src/v1/dev/index.js';
import type { CaptureDenialsResult, CaptureDenialsError, ExecutionMetadata } from '../../src/v1/index.js';

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
  it('marshals Dev feedback separately and frees owned error JSON through its result exactly once', async (t) => {
    const report = { formatVersion: 1, results: [] };
    const detailsJson = Buffer.from(JSON.stringify({
      policyFailures: report, backendDetail: { retained: true },
    }) + '\0');
    interface Result {
      status: number;
      exitCode: number;
      timedOut: number;
      stdout: unknown;
      stderr: unknown;
      error: AbiErrorDetail;
      outputMetadata: unknown;
      warnings: unknown;
    }
    const calls: Array<{ symbol: string; args: unknown[] }> = [];
    let freed = 0;
    let unloaded = 0;
    const directory = mkdtempSync('.mxc-node-binding-');
    const filename = process.platform === 'win32' ? 'mxc_ffi.dll'
      : process.platform === 'darwin' ? 'libmxc_ffi.dylib' : 'libmxc_ffi.so';
    const oldFfiDir = process.env.MXC_FFI_DIR;
    writeFileSync(path.join(directory, filename), '');
    process.env.MXC_FFI_DIR = path.resolve(directory);
    const load = t.mock.method(koffi, 'load', () => ({
      func(symbol: string, _result?: unknown, parameters?: unknown[]) {
        if (symbol === 'const char *mxc_version(void)') return () => 'unit-fixture';
        if (symbol === 'mxc_run_result_free') {
          return (result: Result) => {
            freed += 1;
            Object.assign(result.error, createAbiErrorDetail());
          };
        }
        assert.ok(symbol === 'mxc_run_json' || symbol === 'mxc_run_with_policy_failures_json', symbol);
        const withFeedback = symbol === 'mxc_run_with_policy_failures_json';
        assert.strictEqual(parameters?.length, withFeedback ? 4 : 3);
        if (withFeedback) assert.strictEqual(parameters?.[2], 'const char *');
        const nativeRun = (...args: unknown[]) => {
          assert.strictEqual(args.length, withFeedback ? 4 : 3);
          const result = args[withFeedback ? 3 : 2] as Result;
          assert.deepStrictEqual(result.error, createAbiErrorDetail());
          calls.push({ symbol, args: args.slice(0, -1) });
          const status = calls.length === 1 ? 11 : 0;
          Object.assign(result, {
            status, exitCode: status ? -1 : 7, timedOut: 0,
            stdout: null, stderr: null, outputMetadata: null,
            warnings: status ? null : Buffer.from('["ordinary warning"]\0'),
            error: status ? {
              message: Buffer.from('creation blocked\0'),
              operation: Buffer.from('CreateProcess\0'),
              nativeCode: Buffer.from('0x80070005\0'),
              remediation: Buffer.from('Inspect the structured result.\0'),
              detailsJson,
            } : createAbiErrorDetail(),
          });
          return status;
        };
        return Object.assign(nativeRun, {
          async(...args: unknown[]) {
            const completion = args.pop() as (error: Error | null, status: number) => void;
            queueMicrotask(() => completion(null, nativeRun(...args)));
          },
        });
      },
      unload() { unloaded += 1; },
    }));
    try {
      const pointerSize = koffi.sizeof('void *');
      assert.strictEqual(koffi.offsetof(AbiErrorDetailType, 'detailsJson'), 4 * pointerSize);
      assert.strictEqual(koffi.sizeof(AbiErrorDetailType), 5 * pointerSize);
      const json = ' { "version":"1.1.0-alpha","process":{"commandLine":"echo"} } ';
      let refusal: unknown;
      await assert.rejects(runJson(json), (error: unknown) => {
        refusal = error;
        assert.ok(error instanceof MxcError);
        assert.strictEqual(error.code, 'policy_validation');
        assert.strictEqual(error.message, 'creation blocked');
        assert.strictEqual(error.operation, 'CreateProcess');
        assert.strictEqual(error.nativeCode, '0x80070005');
        assert.strictEqual(error.remediation, 'Inspect the structured result.');
        assert.deepStrictEqual(error.details, {
          ffiStatus: 11, policyFailures: report, backendDetail: { retained: true },
        });
        return true;
      });
      assert.strictEqual(calls.length, 1);
      assert.strictEqual(freed, 1);
      const feedback = policyFailuresFromError(refusal);
      assert.deepStrictEqual(feedback, report, 'decoded feedback survives the native result free');
      const output = await runJson(json, { experimental: true, policyFailures: feedback });
      assert.deepStrictEqual(output, {
        stdout: '', stderr: '', exitCode: 7, timedOut: false, warnings: ['ordinary warning'],
      });
      await run({ command: 'echo', containerName: 'strict-native-unit' });
      assert.deepStrictEqual(calls.slice(0, 2), [
        { symbol: 'mxc_run_with_policy_failures_json', args: [json, 0, null] },
        { symbol: 'mxc_run_with_policy_failures_json', args: [json, 1, serializePolicyFailures(report)] },
      ]);
      assert.strictEqual(calls[2].symbol, 'mxc_run_json');
      assert.strictEqual(calls[2].args.length, 2);
      assert.strictEqual(calls[2].args[1], 0);
      assert.strictEqual(freed, 3);
      assert.strictEqual(unloaded, 3);
    } finally {
      load.mock.restore();
      if (oldFfiDir === undefined) delete process.env.MXC_FFI_DIR;
      else process.env.MXC_FFI_DIR = oldFfiDir;
      rmSync(directory, { recursive: true, force: true });
    }
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
