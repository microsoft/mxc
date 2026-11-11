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
    await dev.validateStartJson(request('start'), options);
    await dev.validateProcessJson(request('exec'), options);
    await assert.rejects(dev.spawnInContainerWithPtyJson(request('exec'), options));
    await assert.rejects(dev.runJson(JSON.stringify({
      version: '1.1.0-alpha', containment: 'w365_agents', process: { commandLine: 'echo must-not-run' },
    }), options));
    break;
  }
  case 'ready':
    assert.equal(JSON.parse(await dev.startContainerJson(request('start'), options)).result.metadata.status, 'Ready');
    break;
  case 'capture': {
    const result = await dev.runInContainerJson(request('exec'), options);
    assert.equal(result.exitCode, 7);
    assert.equal(result.timedOut, false);
    assert.equal(result.stdout, 'fixture-out');
    assert.equal(result.stderr, 'fixture-err');
    break;
  }
  case 'pipe': {
    const process = await dev.spawnInContainerJson(request('exec'), options);
    process.standardInput?.end();
    let stdout = '';
    let stderr = '';
    const out = process.standardOutput;
    const err = process.standardError;
    out.on('data', chunk => { stdout += chunk.toString(); });
    err.on('data', chunk => { stderr += chunk.toString(); });
    try {
      assert.equal((await process.wait()).exitCode, 7);
      await Promise.all([out, err].map(stream =>
        stream.readableEnded ? Promise.resolve() : new Promise((resolve, reject) => {
          stream.once('end', resolve);
          stream.once('error', reject);
        })));
      assert.equal(stdout, 'fixture-out');
      assert.equal(stderr, 'fixture-err');
    } finally { process.dispose(); }
    break;
  }
  case 'exec-error':
    await assert.rejects(dev.runInContainerJson(request('exec'), options), error => {
      assert.ok(error instanceof MxcError);
      assert.equal(error.details.code, 'remote_exec_error');
      assert.equal(error.details.possiblySucceeded, true);
      return true;
    });
    break;
  case 'spawn-error':
    await assert.rejects(dev.spawnInContainerJson(request('exec'), options), error => {
      assert.ok(error instanceof MxcError);
      assert.equal(error.details.code, 'auth_denied');
      assert.equal(error.details.possiblySucceeded, false);
      assert.equal(error.details.httpStatus, 403);
      assert.equal(error.details.sandboxId, id);
      return true;
    });
    break;
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
