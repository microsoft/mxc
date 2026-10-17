// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

import type { Readable } from 'node:stream';
import type { MxcProcess, WaitResult } from './container-process.js';

function collectStream(stream: Readable | null): {
  result: Promise<string>;
  closeForTimeout: () => void;
} {
  if (stream === null) {
    return { result: Promise.resolve(''), closeForTimeout: () => {} };
  }

  let timedOut = false;
  const chunks: Buffer[] = [];
  let resolveResult!: (value: string) => void;
  const collect = (chunk: Buffer | string) => {
    chunks.push(Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk));
  };
  const result = new Promise<string>((resolve, reject) => {
    resolveResult = resolve;
    stream.on('data', collect);
    stream.once('end', () => resolve(Buffer.concat(chunks).toString('utf8')));
    stream.once('error', reject);
    stream.once('close', () => {
      if (timedOut) {
        resolve(Buffer.concat(chunks).toString('utf8'));
      } else if (!stream.readableEnded) {
        reject(new Error('captured output closed before EOF'));
      }
    });
  });
  return {
    result,
    closeForTimeout: () => {
      timedOut = true;
      stream.pause();
      if (stream.readableLength > 0) stream.read(stream.readableLength);
      stream.off('data', collect);
      resolveResult(Buffer.concat(chunks).toString('utf8'));
      stream.destroy();
    },
  };
}

/** Capture both streams concurrently, stopping reads after a process timeout. */
export async function captureProcessOutput(
  proc: MxcProcess,
): Promise<{ result: WaitResult; stdout: string; stderr: string }> {
  const stdout = collectStream(proc.standardOutput);
  const stderr = collectStream(proc.standardError);
  const reads = Promise.all([stdout.result, stderr.result]);
  try {
    const wait = proc.wait();
    const readFailure = new Promise<never>((_, reject) => {
      void reads.catch(reject);
    });
    const result = await Promise.race([wait, readFailure]);
    if (result.timedOut) {
      stdout.closeForTimeout();
      stderr.closeForTimeout();
    }
    const [out, err] = await reads;
    return { result, stdout: out, stderr: err };
  } catch (error) {
    stdout.closeForTimeout();
    stderr.closeForTimeout();
    await Promise.allSettled([reads]);
    throw error;
  }
}
