// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

import assert from 'node:assert/strict';
import { it } from 'node:test';
import { getAvailableBackends, MxcError } from '@microsoft/mxc-sdk/v1';
import * as dev from '@microsoft/mxc-sdk/v1/dev';

const enabled = process.platform === 'win32' && process.arch === 'x64'
  && process.env.MXC_ENABLE_NVX_TESTS === '1';
const options = { experimental: true };
const image = 'mcr.microsoft.com/azurelinux/base/core:3.0';

it('V1.Dev NVX JSON lifecycle capture, live streams and overflow recovery',
  { skip: !enabled, timeout: 600_000 }, async () => {
    assert.ok(
      getAvailableBackends().some(backend => backend.backend === 'microvm'),
      'the packaged NVX runtime must be discoverable on the MicroVM validation host',
    );
    const request = (commandLine: string) => JSON.stringify({
      version: '1.1.0-alpha', containment: 'microvm', microvm: { image },
      process: { commandLine, timeout: 30000 },
    });
    const oneShot = await dev.runJson(request("printf 'NVX_ONESHOT\\n'"), options);
    assert.equal(oneShot.exitCode, 0);
    assert.match(oneShot.stdout, /NVX_ONESHOT/);
    const provision = JSON.stringify({
      version: '1.1.0-alpha', phase: 'provision', containment: 'microvm', microvm: { image },
    });
    const reply = (json: string) => JSON.parse(json).result as Record<string, unknown>;
    const sandboxId = reply(await dev.provisionContainerJson(provision, options)).sandboxId;
    assert.ok(typeof sandboxId === 'string' && sandboxId.length > 0);
    const phase = (name: string) => JSON.stringify({ version: '1.0.0', phase: name, sandboxId });
    const exec = (commandLine: string, timeout = 30000) => JSON.stringify({
      version: '1.1.0-alpha', phase: 'exec', sandboxId, process: { commandLine, timeout },
    });
    let started = false;
    try {
      const startResponse = await dev.startContainerJson(phase('start'), options);
      started = true;
      assert.deepEqual(reply(startResponse), {});
      const captured = await dev.runInContainerJson(exec("printf 'NVX_CAPTURE\\n'; printf 'NVX_ERROR\\n' >&2"), options);
      assert.equal(captured.exitCode, 0);
      assert.match(captured.stdout, /NVX_CAPTURE/);
      assert.match(captured.stderr, /NVX_ERROR/);
      const proc = await dev.spawnInContainerJson(exec("printf 'NVX_LIVE_OUT\\n'; printf 'NVX_LIVE_ERR\\n' >&2; sleep 3"), options);
      try {
        assert.ok(proc.standardOutput && proc.standardError);
        const until = (stream: NodeJS.ReadableStream, marker: string) => new Promise<string>((resolve, reject) => {
          let text = '';
          stream.on('data', chunk => {
            text += String(chunk);
            if (text.includes(marker)) resolve(text);
          });
          stream.once('error', reject);
        });
        const output = Promise.all([
          until(proc.standardOutput, 'NVX_LIVE_OUT'), until(proc.standardError, 'NVX_LIVE_ERR'),
        ]);
        const exit = proc.wait();
        const winner = await Promise.race([output.then(() => 'output'), exit.then(() => 'exit')]);
        assert.equal(winner, 'output', 'both streams must deliver data before exit');
        const [stdout, stderr] = await output;
        assert.match(stdout, /NVX_LIVE_OUT/);
        assert.match(stderr, /NVX_LIVE_ERR/);
        assert.equal((await exit).exitCode, 0);
      } finally { proc.dispose(); }
      await assert.rejects(dev.runInContainerJson(exec(
        'head -c 33554432 /dev/zero; head -c 33554433 /dev/zero >&2', 0), options),
      (error: unknown) => error instanceof MxcError && error.code === 'backend_error');
      const reused = await dev.runInContainerJson(exec("printf 'REUSE_OK\\n'"), options);
      assert.equal(reused.exitCode, 0);
      assert.match(reused.stdout, /REUSE_OK/);
    } finally {
      try { if (started) await dev.stopContainerJson(phase('stop'), options); }
      finally { assert.deepEqual(reply(await dev.deprovisionContainerJson(phase('deprovision'), options)), {}); }
    }
  });
