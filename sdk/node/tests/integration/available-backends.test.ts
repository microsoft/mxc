// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

import assert from 'node:assert/strict';
import test from 'node:test';
import { Worker } from 'node:worker_threads';
import {
  createConfigFromPolicy,
  getAvailableBackends,
} from '@microsoft/mxc-sdk';
import {
  debugSpawnOptions,
  spawnFromConfigAsync,
} from './test-helpers.js';

const expectLinuxDiscovery =
  process.env.MXC_EXPECT_LINUX_BACKEND_DISCOVERY === '1';
const expectBubblewrapLaunchability =
  process.env.MXC_EXPECT_BWRAP_LAUNCHABILITY === '1';
const isRoot = process.getuid?.() === 0;

type DiscoveredBackend = {
  backend: string;
  capabilities: unknown[];
  warnings: unknown[];
};

function assertBackendShape(
  backends: unknown,
): asserts backends is DiscoveredBackend[] {
  assert.ok(Array.isArray(backends));
  for (const backend of backends) {
    assert.ok(typeof backend === 'object' && backend !== null);
    assert.strictEqual(typeof backend.backend, 'string');
    assert.ok(Array.isArray(backend.capabilities));
    assert.ok(Array.isArray(backend.warnings));
  }
}

function assertPreparedBackends(backends: DiscoveredBackend[]): void {
  if (expectLinuxDiscovery) {
    assert.ok(
      backends.some((backend) => backend.backend === 'lxc'),
      'the prepared package-CI host must report its installed LXC backend',
    );
  }

  if (expectBubblewrapLaunchability) {
    assert.ok(
      backends.some((backend) => backend.backend === 'bubblewrap'),
      'the namespace-prepared host must report Bubblewrap',
    );
  }
}

async function discoverBackendsInWorker(): Promise<DiscoveredBackend[]> {
  const worker = new Worker(
    new URL('./available-backends-worker.js', import.meta.url),
  );
  let workerResult: unknown;

  try {
    await new Promise<void>((resolve, reject) => {
      worker.once('message', (value: unknown) => {
        workerResult = value;
      });
      worker.once('error', reject);
      worker.once('exit', (code) => {
        if (code !== 0) {
          reject(new Error(`backend discovery worker exited with code ${code}`));
          return;
        }
        if (workerResult === undefined) {
          reject(new Error('backend discovery worker exited without a result'));
          return;
        }
        resolve();
      });
    });
  } finally {
    if (worker.threadId !== -1) {
      await worker.terminate();
    }
  }

  assert.ok(typeof workerResult === 'object' && workerResult !== null);
  assert.ok('isMainThread' in workerResult);
  assert.strictEqual(workerResult.isMainThread, false);
  assert.ok('backends' in workerResult);
  assertBackendShape(workerResult.backends);
  return workerResult.backends;
}

test('installed package discovers Linux backends as an unprivileged user', (t) => {
  if (process.platform !== 'linux') {
    assert.strictEqual(
      expectLinuxDiscovery,
      false,
      'MXC_EXPECT_LINUX_BACKEND_DISCOVERY requires a Linux host',
    );
    assert.strictEqual(
      expectBubblewrapLaunchability,
      false,
      'MXC_EXPECT_BWRAP_LAUNCHABILITY requires a Linux host',
    );
    t.skip('Linux-only installed-package backend discovery');
    return;
  }
  if (isRoot && !expectLinuxDiscovery && !expectBubblewrapLaunchability) {
    t.skip('the dedicated pre-sudo package check covers unprivileged discovery');
    return;
  }

  delete process.env.MXC_FFI_DIR;
  assert.notStrictEqual(
    process.getuid?.(),
    0,
    'installed-package discovery must run as a non-root user',
  );

  const backends = getAvailableBackends();
  assertBackendShape(backends);
  assertPreparedBackends(backends);
});

test('installed package discovers backends in a worker isolate', async () => {
  delete process.env.MXC_FFI_DIR;

  const backends = await discoverBackendsInWorker();
  assertPreparedBackends(backends);
});

test('an advertised Bubblewrap backend performs a real package launch', async (t) => {
  if (process.platform !== 'linux') {
    t.skip('Linux-only Bubblewrap launchability check');
    return;
  }
  if (isRoot && !expectLinuxDiscovery && !expectBubblewrapLaunchability) {
    t.skip('the dedicated pre-sudo package check covers unprivileged launchability');
    return;
  }

  delete process.env.MXC_FFI_DIR;
  const backends = getAvailableBackends();
  const bubblewrap = backends.find((backend) => backend.backend === 'bubblewrap');
  if (!bubblewrap) {
    assert.strictEqual(
      expectBubblewrapLaunchability,
      false,
      'Bubblewrap is required when the host declares namespace launchability',
    );
    t.skip('Bubblewrap is not launchable for this unprivileged user');
    return;
  }

  const config = createConfigFromPolicy(
    { version: '0.7.0-alpha' },
    'bubblewrap',
    'available-backends-launchability',
  );
  config.process!.commandLine = 'exit 0';
  config.process!.cwd = '/';
  config.process!.env = ['PATH=/usr/bin:/bin'];
  config.network = {
    defaultPolicy: 'allow',
    allowLocalNetwork: true,
  };

  const result = await spawnFromConfigAsync(config, debugSpawnOptions);
  assert.strictEqual(result.exitCode, 0, result.stderr);
});
