// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

import assert from 'node:assert';
import { describe, it } from 'node:test';
import { MxcError } from '@microsoft/mxc-sdk/v1';
import {
  isolationSessionFeatureSkipReason,
  stateAwareRuntimeUnavailable,
} from './test-helpers.js';

describe('state-aware integration skip classification', () => {
  it('distinguishes missing native features from missing host runtime', () => {
    for (const code of ['backend_unavailable', 'unsupported_phase'] as const) {
      const error = new MxcError(code, 'feature unavailable');
      assert.match(isolationSessionFeatureSkipReason(error)!, /lacks the isolation_session feature/);
      assert.strictEqual(stateAwareRuntimeUnavailable(error), true);
    }

    const addUser = new MxcError({
      code: 'backend_error',
      message: 'AddUser is unavailable',
      operation: 'IsoSessionOps.AddUserAsync2',
      remediation: 'Enable Feature_AgentSessionsBaseSupport',
    });
    assert.match(isolationSessionFeatureSkipReason(addUser)!, /runtime unavailable/);
    assert.strictEqual(stateAwareRuntimeUnavailable(addUser), true);
  });

  it('propagates API-backed and unrelated failures instead of skipping', () => {
    for (const error of [
      new MxcError({
        code: 'backend_unavailable',
        message: 'host API unavailable',
        operation: 'IsoSessionOps.CreateAsync',
      }),
      new MxcError({
        code: 'unsupported_phase',
        message: 'API rejected phase',
        operation: 'IsoSessionOps.CreateAsync',
      }),
      new MxcError({
        code: 'backend_error',
        message: 'AddUser failed for another reason',
        operation: 'IsoSessionOps.AddUserAsync2',
      }),
      new MxcError('policy_validation', 'invalid policy'),
      new Error('transport failure'),
    ]) {
      assert.strictEqual(isolationSessionFeatureSkipReason(error), undefined);
      assert.strictEqual(stateAwareRuntimeUnavailable(error), false);
    }
  });
});
