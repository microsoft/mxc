// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

// End-to-end coverage for the native Node WSLC state-aware lifecycle.
//
// Prerequisites:
//   - Windows 11 with WSL2 and the WSLC runtime installed
//   - mxc_ffi.dll built with the wslc feature
//   - wslcsdk.dll and wxc-wslc-daemon.exe staged with mxc_ffi.dll
//   - alpine:latest already in the daemon session cache, since these provision
//     with the default isolated posture, which refuses a registry pull
//     (MXC_WSLC_TEST_IMAGE selects another image)
//
// Opt in with MXC_ENABLE_WSLC_TESTS=1.

import assert from 'node:assert/strict';
import os from 'node:os';
import { describe, it } from 'node:test';
import {
  MxcError,
} from '@microsoft/mxc-sdk/v1';
import {
  deprovisionContainer,
  spawnInContainer,
  runInContainer,
  provisionContainer,
  startContainer,
  stopContainer,
  type ContainerId,
} from '@microsoft/mxc-sdk/v1';
import { safeDeprovision } from './test-helpers.js';

const wslcImage = process.env.MXC_WSLC_TEST_IMAGE ?? 'alpine:latest';

// WSLC tests require a Windows machine with WSL2 and WSLC SDK installed.
// Opt-in via MXC_ENABLE_WSLC_TESTS=1 since most CI agents lack the runtime.
const isWslcAvailable =
  os.platform() === 'win32' && process.env.MXC_ENABLE_WSLC_TESTS === '1';

function collect(
  stream: NodeJS.ReadableStream | null,
  onChunk?: (chunk: string) => void,
): Promise<string> {
  if (stream === null) {
    return Promise.resolve('');
  }

  return new Promise((resolve, reject) => {
    const chunks: Buffer[] = [];
    stream.on('data', (chunk: Buffer | string) => {
      const buffer = Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk);
      chunks.push(buffer);
      onChunk?.(buffer.toString('utf8'));
    });
    stream.once('end', () => resolve(Buffer.concat(chunks).toString('utf8')));
    stream.once('error', reject);
  });
}

describe('WSLC state-aware lifecycle E2E', {
  skip: !isWslcAvailable
    ? 'WSLC tests require MXC_ENABLE_WSLC_TESTS=1 on Windows with WSL2 and WSLC SDK'
    : undefined,
}, () => {
  it(
    'preserves lifecycle, streaming, timeout, and stale-id behavior',
    { timeout: 180_000 },
    async () => {
      const { containerId } = await provisionContainer({ containment: 'wslc', image: wslcImage });
      let started = false;
      let provisioned = true;

      try {
        assert.match(containerId, /^wslc:[0-9a-f]{32}$/);
        await startContainer(containerId);
        started = true;

        const marker = `NODE_WSLC_WARM_${Date.now()}`;
        const writeResult = await runInContainer(containerId, { command: `printf '${marker}' > /tmp/mxc-node-wslc-marker` });
        assert.equal(writeResult.exitCode, 0);

        const readResult = await runInContainer(containerId, { command: 'cat /tmp/mxc-node-wslc-marker' });
        assert.equal(readResult.exitCode, 0);
        assert.equal(readResult.stdout, marker);
        assert.equal(readResult.stderr, '');

        const buffered = await runInContainer(containerId, { command: "printf 'NODE_WSLC_STDOUT\\n'; printf 'NODE_WSLC_STDERR\\n' >&2; exit 7" });
        assert.equal(buffered.exitCode, 7);
        assert.match(buffered.stdout, /NODE_WSLC_STDOUT/);
        assert.match(buffered.stderr, /NODE_WSLC_STDERR/);

        let firstChunkAt: number | undefined;
        const streamed = await spawnInContainer(containerId, { command: 'echo NODE_WSLC_STREAM_FIRST; sleep 2; ' +
              'echo NODE_WSLC_STREAM_LAST; echo NODE_WSLC_STREAM_ERR >&2' });
        try {
          assert.equal(
            streamed.standardInput,
            null,
            'WSLC must explicitly expose no stdin',
          );
          const stdoutPromise = collect(streamed.standardOutput, (chunk) => {
            if (
              firstChunkAt === undefined &&
              chunk.includes('NODE_WSLC_STREAM_FIRST')
            ) {
              firstChunkAt = performance.now();
            }
          });
          const stderrPromise = collect(streamed.standardError);
          const [result, stdout, stderr] = await Promise.all([
            streamed.wait(),
            stdoutPromise,
            stderrPromise,
          ]);
          const streamEnd = performance.now();

          assert.equal(result.exitCode, 0);
          assert.equal(result.timedOut, false);
          assert.match(stdout, /NODE_WSLC_STREAM_FIRST/);
          assert.match(stdout, /NODE_WSLC_STREAM_LAST/);
          assert.match(stderr, /NODE_WSLC_STREAM_ERR/);
          assert.ok(firstChunkAt !== undefined, 'first output was never observed');
          assert.ok(
            streamEnd - firstChunkAt >= 1_000,
            'first and last output arrived together instead of incrementally',
          );
        } finally {
          streamed.dispose();
        }

        const timeoutStart = performance.now();
        const timed = await spawnInContainer(containerId, { command: 'sleep 10',
timeoutMs: 750 });
        try {
          const result = await timed.wait();
          assert.equal(result.timedOut, true);
          const timeoutElapsed = performance.now() - timeoutStart;
          assert.ok(
            timeoutElapsed < 70_000,
            `timeout confirmation took ${Math.round(timeoutElapsed)} ms`,
          );
        } finally {
          timed.dispose();
        }

        await stopContainer(containerId);
        started = false;
        await deprovisionContainer(containerId);
        provisioned = false;

        await assert.rejects(
          () => startContainer(containerId),
          (error: unknown) =>
            error instanceof MxcError && error.code === 'not_provisioned',
        );
      } finally {
        if (started) {
          try {
            await stopContainer(containerId);
          } catch (error) {
            console.error(`Cleanup stop failed for ${containerId}: ${error}`);
          }
        }
        if (provisioned) {
          await safeDeprovision(containerId);
        }
      }
    },
  );
});
