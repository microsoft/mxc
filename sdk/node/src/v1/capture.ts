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

  let settled = false;
  const chunks: Buffer[] = [];
  let settle!: (error?: Error) => void;
  const collect = (chunk: Buffer | string) => {
    chunks.push(Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk));
  };
  const result = new Promise<string>((resolve, reject) => {
    const onEnd = () => settle();
    const onError = (error: Error) => settle(error);
    const onClose = () => settle(stream.readableEnded
      ? undefined : new Error('captured output closed before EOF'));
    settle = (error) => {
      if (settled) return;
      settled = true;
      stream.off('data', collect);
      stream.off('end', onEnd);
      stream.off('close', onClose);
      // MxcProcess still handles errors from delayed native reads.
      stream.off('error', onError);
      if (error !== undefined) {
        chunks.length = 0;
        reject(error);
      } else {
        const text = Buffer.concat(chunks).toString('utf8');
        chunks.length = 0;
        resolve(text);
      }
    };
    stream.on('data', collect);
    stream.once('end', onEnd);
    stream.once('error', onError);
    stream.once('close', onClose);
  });
  return {
    result,
    closeForTimeout: () => {
      if (!settled) {
        stream.pause();
        if (stream.readableLength > 0) stream.read(stream.readableLength);
        settle();
      }
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
