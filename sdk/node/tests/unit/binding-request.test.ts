// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

import assert from 'node:assert';
import { describe, it } from 'node:test';
import {
  bindingRequestUnsupportedReason,
  prepareBindingSandboxRequest,
} from '../../src/bindings/request.js';

describe('mxc_ffi binding request', () => {
  it('builds the same typed request shape as the .NET binding', () => {
    const request = prepareBindingSandboxRequest({
      script: 'echo hello',
      policy: {
        version: '0.9.0-alpha',
        filesystem: { readonlyPaths: ['C:\\input'] },
        network: { egress: { default: 'deny' } },
        runtimeConfig: { networkProxy: 'http://127.0.0.1:8080' },
        telemetry: { enabled: false },
      },
      workingDirectory: 'C:\\work',
      containerName: 'sample',
      environment: { SET: 'value', OMIT: undefined },
      experimental: true,
    });

    assert.deepStrictEqual(request, {
      policy: {
        version: '0.9.0-alpha',
        filesystem: { readonlyPaths: ['C:\\input'] },
        network: {
          egress: { default: 'deny' },
          runtimeConfig: { networkProxy: 'http://127.0.0.1:8080' },
        },
        telemetry: { enabled: false },
      },
      command: 'echo hello',
      containment: { type: 'process' },
      containerName: 'sample',
      workingDirectory: 'C:\\work',
      environment: { SET: 'value' },
      experimental: true,
    });
  });

  it('preserves explicit false and empty collections', () => {
    const request = prepareBindingSandboxRequest({
      script: 'echo hello',
      policy: {
        version: '0.9.0-alpha',
        network: { allowOutbound: false, allowedHosts: [] },
      },
    });

    assert.strictEqual(request.policy.network!.allowOutbound, false);
    assert.deepStrictEqual(request.policy.network!.allowedHosts, []);
    assert.strictEqual(request.experimental, false);
  });

  it('moves ProcessContainer-specific policy onto tagged containment', () => {
    const request = prepareBindingSandboxRequest({
      script: 'echo hello',
      policy: {
        version: '0.9.0-alpha',
        processContainer: { network: { allowedProxyPeer: 'proxy' } },
      },
    });

    assert.deepStrictEqual(request.containment, {
      type: 'processContainer',
      network: { allowedProxyPeer: 'proxy' },
    });
    assert.strictEqual('processContainer' in request.policy, false);
  });

  it('identifies testing-only policy that requires the executor path', () => {
    assert.strictEqual(bindingRequestUnsupportedReason({
      version: '0.9.0-alpha',
      processContainer: { network: { allowedProxyPeer: 'proxy' } },
    }), null);
    assert.match(bindingRequestUnsupportedReason({
      version: '0.9.0-alpha',
      network: { proxy: { builtinTestServer: true } },
    })!, /testing-feature/);
  });
});
