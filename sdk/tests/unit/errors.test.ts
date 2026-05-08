// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

import { describe, it } from 'node:test';
import assert from 'node:assert';
import {
  ErrorCode,
  MxcError,
  MxcMalformedRequestError,
  MxcUnsupportedContainmentError,
  MxcUnsupportedPhaseError,
  MxcBackendUnavailableError,
  MxcMalformedIdError,
  MxcStaleIdError,
  MxcNotProvisionedError,
  MxcNotStartedError,
  MxcAlreadyStartedError,
  MxcAlreadyStoppedError,
  MxcPolicyValidationError,
  MxcBackendError,
  mxcErrorFromCode,
} from '../../src/errors.js';

interface ErrorCase {
  cls: new (message: string, details?: Record<string, unknown>) => MxcError;
  code: ErrorCode;
  className: string;
}

const cases: ErrorCase[] = [
  { cls: MxcMalformedRequestError, code: 'malformed_request', className: 'MxcMalformedRequestError' },
  { cls: MxcUnsupportedContainmentError, code: 'unsupported_containment', className: 'MxcUnsupportedContainmentError' },
  { cls: MxcUnsupportedPhaseError, code: 'unsupported_phase', className: 'MxcUnsupportedPhaseError' },
  { cls: MxcBackendUnavailableError, code: 'backend_unavailable', className: 'MxcBackendUnavailableError' },
  { cls: MxcMalformedIdError, code: 'malformed_id', className: 'MxcMalformedIdError' },
  { cls: MxcStaleIdError, code: 'stale_id', className: 'MxcStaleIdError' },
  { cls: MxcNotProvisionedError, code: 'not_provisioned', className: 'MxcNotProvisionedError' },
  { cls: MxcNotStartedError, code: 'not_started', className: 'MxcNotStartedError' },
  { cls: MxcAlreadyStartedError, code: 'already_started', className: 'MxcAlreadyStartedError' },
  { cls: MxcAlreadyStoppedError, code: 'already_stopped', className: 'MxcAlreadyStoppedError' },
  { cls: MxcPolicyValidationError, code: 'policy_validation', className: 'MxcPolicyValidationError' },
  { cls: MxcBackendError, code: 'backend_error', className: 'MxcBackendError' },
];

describe('MxcError class hierarchy', () => {
  for (const { cls, code, className } of cases) {
    it(`${className} sets code='${code}', extends MxcError and Error`, () => {
      const err = new cls('boom');
      assert.strictEqual(err.code, code);
      assert.strictEqual(err.message, 'boom');
      assert.strictEqual(err.name, className);
      assert.ok(err instanceof MxcError);
      assert.ok(err instanceof Error);
      assert.ok(err instanceof cls);
    });

    it(`${className} round-trips details`, () => {
      const err = new cls('boom', { hresult: '0x80004005' });
      assert.deepStrictEqual(err.details, { hresult: '0x80004005' });
    });

    it(`${className} omits details when not supplied`, () => {
      const err = new cls('boom');
      assert.strictEqual(err.details, undefined);
    });
  }

  it('discriminates between subclasses by instanceof', () => {
    const stale: MxcError = new MxcStaleIdError('expired');
    assert.ok(stale instanceof MxcStaleIdError);
    assert.ok(!(stale instanceof MxcBackendError));
  });
});

describe('mxcErrorFromCode', () => {
  for (const { cls, code, className } of cases) {
    it(`maps '${code}' to ${className}`, () => {
      const err = mxcErrorFromCode(code, 'boom');
      assert.ok(err instanceof cls);
      assert.strictEqual(err.code, code);
      assert.strictEqual(err.message, 'boom');
    });
  }

  it('passes details through to the constructed instance', () => {
    const err = mxcErrorFromCode('backend_error', 'boom', { hresult: '0x80004005' });
    assert.ok(err instanceof MxcBackendError);
    assert.deepStrictEqual(err.details, { hresult: '0x80004005' });
  });

  it('returns the base MxcError for unknown codes', () => {
    const err = mxcErrorFromCode('not_a_real_code', 'boom');
    assert.ok(err instanceof MxcError);
    for (const { cls } of cases) {
      assert.ok(!(err instanceof cls), `unexpected match for ${cls.name}`);
    }
  });
});
