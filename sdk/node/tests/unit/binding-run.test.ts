// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

import assert from 'node:assert';
import { describe, it } from 'node:test';
import { _errorCodeForNativeStatus } from '../../src/bindings/run.js';
import { nativeStatusError } from '../../src/bindings/native-error.js';
import { getPolicyEnforcementReport, type PolicyEnforcementReport } from '../../src/policy-enforcement.js';

describe('native run binding', () => {
  it('owns generic structured details independently of native storage', () => {
    const payload = { diagnostic: { value: '9007199254740993', phases: ['prepare', 'launch'] } };
    const storage = Buffer.from(`${JSON.stringify(payload)}\0`);
    const error = nativeStatusError(12, {
      message: Buffer.from('generic failure\0'),
      detailsJson: storage,
    });
    storage.fill(0);
    assert.deepStrictEqual(error.details, { ...payload, ffiStatus: 12 });
    assert.strictEqual(error.code, 'backend_error');
    assert.strictEqual(error.message, 'generic failure');
  });

  it('preserves owned policy details and uint64 strings across the native boundary', () => {
    const report: PolicyEnforcementReport = {
      reportVersion: 1, requestedMode: 'mutate', modeApplied: true,
      availability: 'available', termination: 'unrepairable', environmentCreated: false,
      originalPolicyHash: 'before', effectivePolicyHash: 'after',
      attempts: [{
        attempt: 1, hresult: '0x800704EC',
        result: {
          version: 1, outcome: { code: 3, name: 'blocked' },
          details: [{
            failureClass: { code: 999 }, failureReason: { code: 999 },
            requiredAction: { code: 999 }, resourceKind: { code: 0 }, valueKind: { code: 999 },
            requestedValue: '18446744073709551615', requiredValue: '9007199254740993',
            flags: 0, resourceOffsetChars: 0, resourceCharsWritten: 0, resourceCharsRequired: 0,
          }],
          detailsCapacity: 64, detailsCount: 1,
          resourceCapacityChars: 32768, resourceCharsWritten: 0, resourceCharsRequired: 0,
        },
      }],
    };
    const detail = Buffer.from(`${JSON.stringify({ policyEnforcement: report })}\0`);
    const error = nativeStatusError(11, {
      message: Buffer.from('blocked\0'),
      operation: Buffer.from('CreateProcessSecurityEnvironment2\0'),
      nativeCode: Buffer.from('0x800704EC\0'),
      detailsJson: detail,
    });
    assert.strictEqual(error.code, 'policy_validation');
    assert.strictEqual(error.operation, 'CreateProcessSecurityEnvironment2');
    assert.strictEqual(error.nativeCode, '0x800704EC');
    assert.deepStrictEqual(getPolicyEnforcementReport(error.details), report);
    assert.strictEqual(error.details?.ffiStatus, 11);
    assert.strictEqual(getPolicyEnforcementReport({}), undefined);
    assert.throws(() => getPolicyEnforcementReport({ policyEnforcement: {} }), TypeError);
    assert.throws(() => getPolicyEnforcementReport({
      policyEnforcement: { ...report, reportVersion: 99 },
    }), TypeError);
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
