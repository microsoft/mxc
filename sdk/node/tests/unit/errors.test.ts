// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

import { describe, it } from 'node:test';
import assert from 'node:assert';
import { ErrorCode, MxcError, mxcErrorFromCode, mxcErrorFromEnvelope } from '../../src/errors.js';

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

describe('MxcError structured fields', () => {
  // The positional signature predates the object form. Any consumer still
  // calling it must keep compiling and behaving identically -- this is the
  // non-breaking guarantee for the overload.
  it('still accepts the legacy positional form', () => {
    const err = new MxcError('backend_error', 'boom', { hresult: '0x80004005' });
    assert.strictEqual(err.code, 'backend_error');
    assert.strictEqual(err.message, 'boom');
    assert.deepStrictEqual(err.details, { hresult: '0x80004005' });
    assert.strictEqual(err.operation, undefined);
    assert.strictEqual(err.nativeCode, undefined);
    assert.strictEqual(err.remediation, undefined);
    assert.ok(err instanceof MxcError);
    assert.ok(err instanceof Error);
  });

  // `ConstructorParameters` resolves to the LAST overload. Keeping the
  // positional signature last preserves the pre-existing type-level result.
  it('keeps ConstructorParameters resolving to the positional form', () => {
    const args: ConstructorParameters<typeof MxcError> = ['stale_id', 'boom'];
    const err = new MxcError(...args);
    assert.strictEqual(err.code, 'stale_id');
  });

  it('accepts the object form and exposes every field', () => {
    const err = new MxcError({
      code: 'stale_id',
      message: 'agent user not found',
      operation: 'IsoSessionOps.StopSessionAsync',
      nativeCode: '0x80070490',
      remediation: 'Re-provision the sandbox.',
      details: { phase: 'stop' },
    });
    assert.strictEqual(err.code, 'stale_id');
    assert.strictEqual(err.message, 'agent user not found');
    assert.strictEqual(err.operation, 'IsoSessionOps.StopSessionAsync');
    assert.strictEqual(err.nativeCode, '0x80070490');
    assert.strictEqual(err.remediation, 'Re-provision the sandbox.');
    assert.deepStrictEqual(err.details, { phase: 'stop' });
    assert.ok(err instanceof MxcError);
    assert.ok(err instanceof Error);
    assert.strictEqual(err.name, 'MxcError');
  });

  it('leaves structured fields undefined when the object omits them', () => {
    const err = new MxcError({ code: 'policy_validation', message: 'bad policy' });
    assert.strictEqual(err.operation, undefined);
    assert.strictEqual(err.nativeCode, undefined);
    assert.strictEqual(err.remediation, undefined);
    assert.strictEqual(err.details, undefined);
  });

  // The overload discriminates on `typeof === 'string'`, so a nullish
  // argument takes the object branch. Without a guard it fails inside
  // `super()` with a TypeError naming `message`, which tells the reader
  // nothing about what actually went wrong.
  for (const bad of [undefined, null]) {
    it(`rejects ${String(bad)} with a message naming the real problem`, () => {
      assert.throws(
        () => new (MxcError as unknown as new (arg: unknown) => MxcError)(bad),
        (err: unknown) => {
          assert.ok(err instanceof TypeError, `expected TypeError, got ${String(err)}`);
          assert.match(err.message, /MxcError: expected an error code string or a field object/);
          assert.match(err.message, new RegExp(String(bad)));
          return true;
        },
      );
    });
  }

  // `message` was an unchecked `as string`. Omitting it yields an empty
  // string (the `Error` constructor ignores an undefined message), not the
  // literal text "undefined".
  it('yields an empty message when the positional message is omitted', () => {
    const err = new (MxcError as unknown as new (code: string) => MxcError)('stale_id');
    assert.strictEqual(err.code, 'stale_id');
    assert.strictEqual(err.message, '');
  });
});

describe('mxcErrorFromEnvelope', () => {
  it('maps every field off the wire envelope', () => {
    const err = mxcErrorFromEnvelope({
      code: 'backend_error',
      message: 'the operation failed',
      operation: 'IsoSessionOps.AddUserAsync',
      nativeCode: '0x80004005',
      remediation: 'Check the host configuration.',
      details: { extra: true },
    });
    assert.ok(err instanceof MxcError);
    assert.strictEqual(err.code, 'backend_error');
    assert.strictEqual(err.message, 'the operation failed');
    assert.strictEqual(err.operation, 'IsoSessionOps.AddUserAsync');
    assert.strictEqual(err.nativeCode, '0x80004005');
    assert.strictEqual(err.remediation, 'Check the host configuration.');
    assert.deepStrictEqual(err.details, { extra: true });
  });

  it('omits fields the wire envelope did not carry', () => {
    const err = mxcErrorFromEnvelope({ code: 'policy_validation', message: 'bad policy' });
    assert.strictEqual(err.operation, undefined);
    assert.strictEqual(err.nativeCode, undefined);
    assert.strictEqual(err.remediation, undefined);
    assert.strictEqual(err.details, undefined);
  });

  it('passes an unknown wire code through verbatim', () => {
    const err = mxcErrorFromEnvelope({ code: 'not_a_real_code', message: 'boom' });
    assert.ok(err instanceof MxcError);
    assert.strictEqual(err.code, 'not_a_real_code');
  });

  for (const code of codes) {
    it(`maps '${code}' from an envelope`, () => {
      const err = mxcErrorFromEnvelope({ code, message: 'boom' });
      assert.strictEqual(err.code, code);
    });
  }
});
