// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

import assert from 'node:assert';
import { describe, it } from 'node:test';
import {
  inProcessUnsupportedReason,
  serializeNativeRunRequest,
} from '../../src/native-request.js';

describe('native run request adapter', () => {
  it('serializes the existing policy and invocation shape', () => {
    const json = serializeNativeRunRequest({
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

    assert.deepStrictEqual(JSON.parse(json), {
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
    const request = JSON.parse(serializeNativeRunRequest({
      script: 'echo hello',
      policy: {
        version: '0.9.0-alpha',
        network: { allowOutbound: false, allowedHosts: [] },
      },
    }));

    assert.strictEqual(request.policy.network.allowOutbound, false);
    assert.deepStrictEqual(request.policy.network.allowedHosts, []);
    assert.strictEqual(request.experimental, false);
  });

  it('identifies policies that require the executor path', () => {
    assert.match(inProcessUnsupportedReason({
      version: '0.9.0-alpha',
      processContainer: { network: { allowedProxyPeer: 'proxy' } },
    })!, /processContainer/);
    assert.match(inProcessUnsupportedReason({
      version: '0.9.0-alpha',
      network: { proxy: { builtinTestServer: true } },
    })!, /testing-feature/);
  });
});
