// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

// Driven only by the repository's offline trusted-TLS SDK fixture selector.
import assert from 'node:assert/strict';
import { writeFileSync } from 'node:fs';
import * as dev from '@microsoft/mxc-sdk/v1/dev';
import { MxcError } from '@microsoft/mxc-sdk/v1';

const mode = process.env.MXC_W365_TEST_SDK_MODE;
assert.ok(mode, 'requires offline W365 SDK fixture selector');
assert.equal(process.env.W365A_CONTROLPLANE_URL, 'localhost');
assert.ok(process.env.MXC_W365_TEST_CA);
const id = 'w365:11111111-1111-1111-1111-111111111111:22222222-2222-2222-2222-222222222222';
const provision = {
  version: '1.1.0-alpha', phase: 'provision', containment: 'w365_agents',
  w365Agents: { provision: { poolId: '11111111-1111-1111-1111-111111111111', userType: 'Local' } },
};
const options = { experimental: true };
const request = (phase) => JSON.stringify({
  version: '1.1.0-alpha', phase, sandboxId: id,
  ...(phase === 'exec' ? { process: { commandLine: 'echo must-not-run' } } : {}),
});
switch (mode) {
  case 'validate': {
    await assert.rejects(dev.provisionContainerJson(JSON.stringify(provision)), { code: 'backend_unavailable' });
    await dev.validateProvisionJson(JSON.stringify(provision), options);
    await dev.validateStopJson(request('stop'), options);
    await dev.validateDeprovisionJson(request('deprovision'), options);
    await assert.rejects(dev.provisionContainerJson(JSON.stringify({ ...provision, filesystem: {} }), options));
    await assert.rejects(dev.startContainerJson(request('start'), options), { code: 'backend_unavailable' });
    await assert.rejects(dev.spawnInContainerJson(request('exec'), options));
    await assert.rejects(dev.runInContainerJson(request('exec'), options));
    await assert.rejects(dev.spawnInContainerWithPtyJson(request('exec'), options));
    await assert.rejects(dev.runJson(JSON.stringify({
      version: '1.1.0-alpha', containment: 'w365_agents', process: { commandLine: 'echo must-not-run' },
    }), options));
    break;
  }
  case 'provision':
    assert.equal(JSON.parse(await dev.provisionContainerJson(JSON.stringify(provision), options)).result.sandboxId, id);
    break;
  case 'stop':
  case 'cleanup': {
    const response = mode === 'stop'
      ? await dev.stopContainerJson(request('stop'), options)
      : await dev.deprovisionContainerJson(request('deprovision'), options);
    const { metadata } = JSON.parse(response).result;
    assert.equal(metadata.releaseRequested, true);
    assert.equal(metadata.restartable, false);
    break;
  }
  case 'uncertain-release':
  case 'rejected':
  case 'http-error':
  case 'unknown':
    if (mode === 'unknown') delete provision.w365Agents.provision.userType;
    await assert.rejects(
      mode === 'uncertain-release'
        ? dev.deprovisionContainerJson(request('deprovision'), options)
        : dev.provisionContainerJson(JSON.stringify(provision), options),
      (error) => {
        assert.ok(error instanceof MxcError);
        assert.equal(error.code, 'backend_error');
        assert.equal(error.details.possiblySucceeded, true);
        assert.equal(error.details.requestId, 'fixture-request');
        assert.ok(error.details.clientRequestId);
        if (mode === 'unknown') assert.equal(error.details.sandboxId, undefined);
        else assert.equal(error.details.sandboxId, id);
        if (mode === 'uncertain-release') assert.equal(error.details.httpStatus, 408);
        if (mode === 'http-error') {
          assert.equal(error.details.httpStatus, 500);
          assert.equal(error.details.code, 'provision_timeout');
        }
        return true;
      },
    );
    break;
  default:
    throw new Error(`Unknown SDK fixture mode: ${mode}`);
}
writeFileSync(process.env.MXC_W365_TEST_SDK_MARKER, mode);
