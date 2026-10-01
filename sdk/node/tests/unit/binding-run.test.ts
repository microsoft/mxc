// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

import assert from 'node:assert';
import { describe, it } from 'node:test';
import { _errorCodeForNativeStatus } from '../../src/bindings/run.js';
import { nativeStatusError, parseExecutionMetadata } from '../../src/bindings/native-error.js';
import { MxcError } from '../../src/v1/errors.js';
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
