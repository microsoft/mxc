// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

import assert from 'node:assert';
import { mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import * as path from 'node:path';
import { describe, it, type TestContext } from 'node:test';
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
import {
  runJson, preparePolicyJson, policyFailuresFromError, serializePolicyFailures,
  type PolicyFailures, type PreparedPolicyRequest,
} from '../../src/v1/dev/index.js';
import { getStreamingNative } from '../../src/bindings/streaming.js';
import type { CaptureDenialsResult, CaptureDenialsError, ExecutionMetadata } from '../../src/v1/index.js';

function mockNativeLibrary(
  t: TestContext,
  bind: (symbol: string, result: unknown, parameters?: unknown[]) => unknown,
  loadFailure?: Error,
) {
  const directory = mkdtempSync('.mxc-node-binding-');
  const filename = process.platform === 'win32' ? 'mxc_ffi.dll'
    : process.platform === 'darwin' ? 'libmxc_ffi.dylib' : 'libmxc_ffi.so';
  const oldFfiDir = process.env.MXC_FFI_DIR;
  writeFileSync(path.join(directory, filename), '');
  process.env.MXC_FFI_DIR = path.resolve(directory);
  let unloadCount = 0;
  const load = t.mock.method(koffi, 'load', () => {
    if (loadFailure !== undefined) throw loadFailure;
    return {
      func(symbol: string, result: unknown, parameters?: unknown[]) {
        if (symbol === 'const char *mxc_version(void)') return () => 'unit-fixture';
        return bind(symbol, result, parameters);
      },
      unload() { unloadCount += 1; },
    };
  });
  return {
    get unloadCount() { return unloadCount; },
    dispose() {
      load.mock.restore();
      if (oldFfiDir === undefined) delete process.env.MXC_FFI_DIR;
      else process.env.MXC_FFI_DIR = oldFfiDir;
      rmSync(directory, { recursive: true, force: true });
    },
  };
}

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
  it('keeps Dev creation strict and frees owned error JSON through its result exactly once', async (t) => {
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
    const fixture = mockNativeLibrary(t, (symbol, _result, parameters) => {
      if (symbol === 'mxc_run_result_free') {
        return (result: Result) => {
          freed += 1;
          Object.assign(result.error, createAbiErrorDetail());
        };
      }
      assert.strictEqual(symbol, 'mxc_run_json');
      assert.strictEqual(parameters?.length, 3);
      const nativeRun = (...args: unknown[]) => {
        assert.strictEqual(args.length, 3);
        const result = args[2] as Result;
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
    });
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
      const failures = policyFailuresFromError(refusal);
      assert.deepStrictEqual(failures, report, 'decoded policy failures survive the native result free');
      const output = await runJson(json, { experimental: true });
      assert.deepStrictEqual(output, {
        stdout: '', stderr: '', exitCode: 7, timedOut: false, warnings: ['ordinary warning'],
      });
      await run({ command: 'echo', containerName: 'strict-native-unit' });
      assert.deepStrictEqual(calls.slice(0, 2), [
        { symbol: 'mxc_run_json', args: [json, 0] },
        { symbol: 'mxc_run_json', args: [json, 1] },
      ]);
      assert.strictEqual(calls[2].symbol, 'mxc_run_json');
      assert.strictEqual(calls[2].args.length, 2);
      assert.strictEqual(calls[2].args[1], 0);
      assert.strictEqual(freed, 3);
      assert.strictEqual(fixture.unloadCount, 3);
    } finally {
      fixture.dispose();
    }
  });

  it('prepares through Koffi async with separate inputs and owned output/error allocations', async (t) => {
    const requestJson = ' { "version":"1.1.0-alpha","process":{"commandLine":"echo"} } ';
    const failures: PolicyFailures = {
      formatVersion: 1,
      results: [{
        version: 0xffff_ffff, minimumReaderVersion: 1, outcome: 0xffff_ffff,
        details: [{
          failureClass: 2, failureReason: 2, requiredAction: 2, resourceKind: 1,
          valueKind: 1, flags: 0xffff_ffff,
          requestedValue: '18446744073709551615', requiredValue: '9007199254740993',
          resource: [0xd800, 0],
        }],
      }],
    };
    const candidate: PreparedPolicyRequest = {
      requestJson: '{"version":"1.1.0-alpha","filesystem":{"deniedPaths":["C:\\\\private"]},'
        + '"process":{"commandLine":"echo"}}',
      changes: [{ operation: 'add', path: '/filesystem', before: null, after: {
        deniedPaths: ['C:\\private'],
      } }],
    };
    const payload = Buffer.from(JSON.stringify(candidate) + '\0');
    const diagnostic = Buffer.from('{"private":"SUCCESS_DIAGNOSTIC"}\0');
    const calls: unknown[][] = [];
    const freedStrings: unknown[] = [];
    const freedErrors: AbiErrorDetail[] = [];
    let complete: (() => void) | undefined;
    const fixture = mockNativeLibrary(t, (symbol, result, parameters) => {
      if (symbol === 'mxc_string_free') {
        assert.deepStrictEqual(parameters, ['void *']);
        return (pointer: unknown) => {
          assert.strictEqual(fixture.unloadCount, 0);
          assert.strictEqual(pointer, payload);
          freedStrings.push(pointer);
          payload.fill(0);
        };
      }
      if (symbol === 'mxc_error_detail_free') {
        return (error: AbiErrorDetail) => {
          assert.strictEqual(fixture.unloadCount, 0);
          freedErrors.push({ ...error });
          diagnostic.fill(0);
          Object.assign(error, createAbiErrorDetail());
        };
      }
      assert.strictEqual(symbol, 'mxc_prepare_policy_json');
      assert.strictEqual(result, 'int32_t');
      assert.strictEqual(parameters?.length, 5);
      assert.deepStrictEqual(parameters?.slice(0, 3), ['const char *', 'const char *', 'int32_t']);
      assert.strictEqual(koffi.sizeof(parameters![3] as string), koffi.sizeof('void *'));
      return Object.assign(() => assert.fail('preparation must not call the synchronous binding'), {
        async(...args: unknown[]) {
          assert.strictEqual(args.length, 6);
          calls.push(args.slice(0, 3));
          const out = args[3] as unknown[];
          const error = args[4] as AbiErrorDetail;
          const completion = args[5] as (failure: Error | null, status: number) => void;
          assert.strictEqual(out.length, 1);
          assert.strictEqual(out[0], null);
          assert.deepStrictEqual(error, createAbiErrorDetail());
          complete = () => {
            out[0] = payload;
            error.detailsJson = diagnostic;
            completion(null, 0);
          };
        },
      });
    });
    try {
      const before = JSON.stringify(failures);
      let settled = false;
      const pending = preparePolicyJson(requestJson, failures, { experimental: true })
        .then((value) => { settled = true; return value; });
      await new Promise<void>((resolve) => setImmediate(resolve));
      assert.strictEqual(settled, false, 'the event loop remains available while native work is pending');
      assert.deepStrictEqual(calls, [[requestJson, serializePolicyFailures(failures), 1]]);
      assert.strictEqual(freedErrors.length, 0);
      assert.strictEqual(freedStrings.length, 0);
      assert.strictEqual(fixture.unloadCount, 0);
      assert.ok(complete);
      complete();
      assert.deepStrictEqual(await pending, candidate, 'copied JSON survives native frees');
      assert.strictEqual(JSON.stringify(failures), before);
      assert.strictEqual(freedStrings.length, 1);
      assert.strictEqual(freedErrors.length, 1);
      assert.strictEqual(freedErrors[0].detailsJson, diagnostic);
      assert.strictEqual(fixture.unloadCount, 1);
    } finally {
      fixture.dispose();
    }
  });

  it('cleans preparation allocations on native, decoding, callback and scheduling failures', async (t) => {
    const marker = 'PREPARATION_MALFORMED_RESULT_PRIVATE';
    const failures: PolicyFailures = { formatVersion: 1, results: [] };
    let mode = '';
    let output: Buffer | null = null;
    let diagnostic: Buffer | null = null;
    const freeOrder: string[] = [];
    const fixture = mockNativeLibrary(t, (symbol) => {
      if (symbol === 'mxc_string_free') {
        return (pointer: unknown) => {
          assert.strictEqual(pointer, output);
          freeOrder.push('string');
          output?.fill(0);
        };
      }
      if (symbol === 'mxc_error_detail_free') {
        return (error: AbiErrorDetail) => {
          assert.strictEqual(error.detailsJson, diagnostic);
          freeOrder.push('error');
          diagnostic?.fill(0);
          Object.assign(error, createAbiErrorDetail());
        };
      }
      assert.strictEqual(symbol, 'mxc_prepare_policy_json');
      if (mode === 'missing-symbol') throw new Error('missing symbol: mxc_prepare_policy_json');
      return Object.assign(() => assert.fail('synchronous preparation must not run'), {
        async(
          _request: string, _policyFailures: string, experimental: number, out: unknown[],
          error: AbiErrorDetail, completion: (failure: Error | null, status: number) => void,
        ) {
          assert.strictEqual(experimental, 0);
          output = mode === 'no-output' ? null : Buffer.from((mode === 'oversized-result'
            ? ' '.repeat(32 * 1024 * 1024 + 1) : `{${marker}`) + '\0');
          diagnostic = Buffer.from((mode === 'malformed-error' ? `{${marker}`
            : JSON.stringify({ policyFailures: failures, otherDetail: 'retained' })) + '\0');
          out[0] = output;
          Object.assign(error, {
            message: Buffer.from('Policy preparation refused.\0'),
            operation: Buffer.from('prepare_policy_json\0'),
            nativeCode: Buffer.from('0x800704EC\0'),
            detailsJson: diagnostic,
          });
          if (mode === 'scheduling') throw new Error(marker);
          queueMicrotask(() => completion(mode === 'callback' ? new Error(marker) : null,
            mode === 'native' || mode === 'malformed-error' ? 11 : 0));
        },
      });
    });
    try {
      for (mode of [
        'native', 'malformed-error', 'no-output', 'malformed-result', 'oversized-result',
        'callback', 'scheduling', 'missing-symbol',
      ]) {
        freeOrder.length = 0;
        output = null;
        diagnostic = null;
        const priorUnloads = fixture.unloadCount;
        await assert.rejects(preparePolicyJson('{}', failures), (error: unknown) => {
          assert.ok(error instanceof MxcError);
          assert.strictEqual(error.code, mode === 'native' ? 'policy_validation' : 'backend_error');
          if (mode === 'missing-symbol') {
            assert.match(error.message, /mxc_prepare_policy_json/);
            assert.match(error.remediation ?? '', /SDK version, operating system, and architecture/);
          } else {
            assert.strictEqual([error.message, error.stack, String(error)].join('\n').includes(marker), false);
          }
          if (mode === 'native') {
            assert.strictEqual(error.operation, 'prepare_policy_json');
            assert.strictEqual(error.nativeCode, '0x800704EC');
            assert.deepStrictEqual(error.details, {
              policyFailures: failures, otherDetail: 'retained', ffiStatus: 11,
            });
          }
          return true;
        });
        assert.deepStrictEqual(freeOrder, mode === 'missing-symbol' ? []
          : mode === 'no-output' ? ['error'] : ['string', 'error']);
        assert.strictEqual(fixture.unloadCount, priorUnloads + 1);
      }
    } finally {
      fixture.dispose();
    }
  });

  it('preserves native library load diagnostics with actionable remediation', async (t) => {
    const diagnostic = 'incompatible native binary';
    const fixture = mockNativeLibrary(
      t,
      () => assert.fail('native functions must not be bound after a load failure'),
      new Error(diagnostic),
    );
    try {
      await assert.rejects(preparePolicyJson('{}', { formatVersion: 1, results: [] }),
        (error: unknown) => {
          assert.ok(error instanceof MxcError);
          assert.strictEqual(error.code, 'backend_error');
          assert.match(error.message, new RegExp(diagnostic));
          assert.match(error.remediation ?? '', /SDK version, operating system, and architecture/);
          assert.strictEqual(error.operation, undefined);
          assert.strictEqual(error.nativeCode, undefined);
          assert.strictEqual(error.details, undefined);
          return true;
        });
      assert.strictEqual(fixture.unloadCount, 0);
    } finally {
      fixture.dispose();
    }
  });

  it('binds strict Dev spawn without requiring an execution-time policy-failure symbol', async (t) => {
    const symbols: string[] = [];
    const calls: unknown[][] = [];
    const fixture = mockNativeLibrary(t, (symbol, _result, parameters) => {
      symbols.push(symbol);
      if (symbol === 'mxc_spawn_json') {
        assert.strictEqual(parameters?.length, 4);
        return Object.assign(() => assert.fail('raw spawn must be asynchronous'), {
          async(...args: unknown[]) {
            const completion = args.pop() as (error: Error | null, status: number) => void;
            calls.push(args.slice(0, 2));
            queueMicrotask(() => completion(null, 0));
          },
        });
      }
      return Object.assign(() => {}, { async() {} });
    });
    try {
      const native = getStreamingNative();
      for (const experimental of [0, 1]) {
        await new Promise<void>((resolve, reject) => {
          native.spawn('{"process":{"commandLine":"echo"}}', experimental, [null], createAbiErrorDetail(),
            (error) => error === null ? resolve() : reject(error));
        });
      }
      assert.deepStrictEqual(calls.map((args) => args[1]), [0, 1]);
      assert.ok(symbols.includes('mxc_spawn_json'));
      assert.strictEqual(symbols.some((symbol) => symbol.includes('policy_failures')), false);
    } finally {
      fixture.dispose();
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
