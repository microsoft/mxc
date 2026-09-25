// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

// End-to-end coverage for the native Node WSLC state-aware lifecycle.
//
// Prerequisites:
//   - Windows 11 with WSL2 and the WSLC runtime installed
//   - mxc_ffi.dll built with the wslc feature
//   - wslcsdk.dll and wxc-wslc-daemon.exe staged with mxc_ffi.dll
//   - alpine:latest pre-pulled, or MXC_WSLC_TEST_IMAGE set to another image
//
// Opt in with MXC_ENABLE_WSLC_TESTS=1.

import assert from 'node:assert/strict';
import os from 'node:os';
import { describe, it } from 'node:test';
import {
  MxcError,
  deprovisionSandbox,
  execInSandbox,
  execInSandboxAsync,
  provisionSandbox,
  startSandbox,
  stopSandbox,
  type ExecResult,
  type SandboxId,
} from '@microsoft/mxc-sdk';
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

async function execAfterCancellation(
  sandboxId: SandboxId<'wslc'>,
): Promise<ExecResult> {
  const deadline = Date.now() + 15_000;
  let lastError: unknown;

  while (Date.now() < deadline) {
    try {
      return await execInSandboxAsync(sandboxId, {
        process: { commandLine: 'echo NODE_WSLC_AFTER_CANCEL' },
      });
    } catch (error) {
      lastError = error;
      if (!(error instanceof MxcError) || error.code !== 'backend_error') {
        throw error;
      }
      await new Promise((resolve) => setTimeout(resolve, 500));
    }
  }

  throw lastError ?? new Error('sandbox did not become reusable after cancellation');
}

describe('WSLC state-aware lifecycle E2E', {
  skip: !isWslcAvailable
    ? 'WSLC tests require MXC_ENABLE_WSLC_TESTS=1 on Windows with WSL2 and WSLC SDK'
    : undefined,
}, () => {
  it(
    'preserves lifecycle, streaming, timeout, cancellation, and stale-id behavior',
    { timeout: 180_000 },
    async () => {
      const { sandboxId } = await provisionSandbox('wslc', { image: wslcImage });
      let started = false;
      let provisioned = true;

      try {
        assert.match(sandboxId, /^wslc:[0-9a-f]{32}$/);
        await startSandbox(sandboxId);
        started = true;

        const marker = `NODE_WSLC_WARM_${Date.now()}`;
        const writeResult = await execInSandboxAsync(sandboxId, {
          process: {
            commandLine: `printf '${marker}' > /tmp/mxc-node-wslc-marker`,
          },
        });
        assert.equal(writeResult.exitCode, 0);

        const readResult = await execInSandboxAsync(sandboxId, {
          process: { commandLine: 'cat /tmp/mxc-node-wslc-marker' },
        });
        assert.equal(readResult.exitCode, 0);
        assert.equal(readResult.stdout, marker);
        assert.equal(readResult.stderr, '');

        const buffered = await execInSandboxAsync(sandboxId, {
          process: {
            commandLine:
              "printf 'NODE_WSLC_STDOUT\\n'; printf 'NODE_WSLC_STDERR\\n' >&2; exit 7",
          },
        });
        assert.equal(buffered.exitCode, 7);
        assert.match(buffered.stdout, /NODE_WSLC_STDOUT/);
        assert.match(buffered.stderr, /NODE_WSLC_STDERR/);

        let firstChunkAt: number | undefined;
        const streamed = execInSandbox(sandboxId, {
          process: {
            commandLine:
              'echo NODE_WSLC_STREAM_FIRST; sleep 2; ' +
              'echo NODE_WSLC_STREAM_LAST; echo NODE_WSLC_STREAM_ERR >&2',
          },
        });
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
            streamed.waitAsync(),
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
        const timed = execInSandbox(sandboxId, {
          process: { commandLine: 'sleep 10', timeout: 750 },
        });
        try {
          const result = await timed.waitAsync();
          assert.equal(result.timedOut, true);
          const timeoutElapsed = performance.now() - timeoutStart;
          assert.ok(
            timeoutElapsed < 70_000,
            `timeout confirmation took ${Math.round(timeoutElapsed)} ms`,
          );
        } finally {
          timed.dispose();
        }

        const controller = new AbortController();
        const reason = new Error('NODE_WSLC_ABORT_EXPECTED');
        const cancelTimer = setTimeout(() => controller.abort(reason), 750);
        try {
          await assert.rejects(
            execInSandboxAsync(
              sandboxId,
              { process: { commandLine: 'sleep 10' } },
              { signal: controller.signal },
            ),
            (error: unknown) =>
              error === reason ||
              (error instanceof Error && error.message === reason.message),
          );
        } finally {
          clearTimeout(cancelTimer);
        }

        const afterCancel = await execAfterCancellation(sandboxId);
        assert.equal(afterCancel.exitCode, 0);
        assert.match(afterCancel.stdout, /NODE_WSLC_AFTER_CANCEL/);

        await stopSandbox(sandboxId);
        started = false;
        await deprovisionSandbox(sandboxId);
        provisioned = false;

        await assert.rejects(
          () => startSandbox(sandboxId),
          (error: unknown) =>
            error instanceof MxcError && error.code === 'not_provisioned',
        );
      } finally {
        if (started) {
          try {
            await stopSandbox(sandboxId);
          } catch (error) {
            console.error(`Cleanup stop failed for ${sandboxId}: ${error}`);
          }
        }
        if (provisioned) {
          await safeDeprovision(sandboxId);
        }
      }
    },
  );
});
