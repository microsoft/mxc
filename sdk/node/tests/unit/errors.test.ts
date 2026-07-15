// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

import { describe, it } from 'node:test';
import assert from 'node:assert';
import { ErrorCode, MxcError, mxcErrorFromCode } from '../../src/errors.js';

const codes: ErrorCode[] = [
  'malformed_request',
  'unsupported_containment',
  'unsupported_phase',
  'backend_unavailable',
  'malformed_id',
  'stale_id',
  'not_provisioned',
  'not_started',
  'already_started',
  'already_stopped',
  'policy_validation',
  'backend_error',
];

describe('MxcError', () => {
  for (const code of codes) {
    it(`constructs with code='${code}', extends Error, exposes message and code`, () => {
      const err = new MxcError(code, 'boom');
      assert.strictEqual(err.code, code);
      assert.strictEqual(err.message, 'boom');
      assert.strictEqual(err.name, 'MxcError');
      assert.ok(err instanceof MxcError);
      assert.ok(err instanceof Error);
    });
  }

  it('round-trips details', () => {
    const err = new MxcError('backend_error', 'boom', { hresult: '0x80004005' });
    assert.deepStrictEqual(err.details, { hresult: '0x80004005' });
  });

  it('omits details when not supplied', () => {
    const err = new MxcError('stale_id', 'boom');
    assert.strictEqual(err.details, undefined);
  });
});

describe('mxcErrorFromCode', () => {
  for (const code of codes) {
    it(`maps '${code}' to MxcError with that code`, () => {
      const err = mxcErrorFromCode(code, 'boom');
      assert.ok(err instanceof MxcError);
      assert.strictEqual(err.code, code);
      assert.strictEqual(err.message, 'boom');
    });
  }

  it('passes details through to the constructed instance', () => {
    const err = mxcErrorFromCode('backend_error', 'boom', { hresult: '0x80004005' });
    assert.ok(err instanceof MxcError);
    assert.deepStrictEqual(err.details, { hresult: '0x80004005' });
  });

  it('returns an MxcError carrying the unknown code verbatim', () => {
    const err = mxcErrorFromCode('not_a_real_code', 'boom');
    assert.ok(err instanceof MxcError);
    assert.strictEqual(err.code, 'not_a_real_code');
  });
});
