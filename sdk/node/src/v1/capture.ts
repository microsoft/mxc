// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

import type { Readable } from 'node:stream';
import type { MxcProcess, WaitResult } from './container-process.js';

const MAX_CAPTURED_OUTPUT_BYTES = 1024 * 1024;

interface CapturedStream {
  text: string;
  truncated: boolean;
}

function collectStream(stream: Readable | null): {
  result: Promise<CapturedStream>;
  closeForTimeout: () => void;
} {
  if (stream === null) {
    return {
      result: Promise.resolve({ text: '', truncated: false }),
      closeForTimeout: () => {},
    };
  }

  let settled = false;
  const buffer = Buffer.alloc(MAX_CAPTURED_OUTPUT_BYTES);
  let length = 0;
  let truncated = false;
  let settle!: (error?: Error) => void;
  const collect = (chunk: Buffer | string) => {
    const bytes = Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk);
    const retained = Math.min(bytes.length, MAX_CAPTURED_OUTPUT_BYTES - length);
    bytes.copy(buffer, length, 0, retained);
    length += retained;
    truncated ||= retained < bytes.length;
  };
  const result = new Promise<CapturedStream>((resolve, reject) => {
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
        reject(error);
      } else {
        resolve({ text: buffer.subarray(0, length).toString('utf8'), truncated });
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
): Promise<{ result: WaitResult; stdout: string; stderr: string; warnings: string[] }> {
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
    const warnings: string[] = [];
    for (const [stream, output] of [['stdout', out], ['stderr', err]] as const) {
      if (output.truncated) {
        warnings.push(
          `${stream} capture truncated at ${MAX_CAPTURED_OUTPUT_BYTES} bytes; use streaming APIs for complete output`,
        );
      }
    }
    return { result, stdout: out.text, stderr: err.text, warnings };
  } catch (error) {
    stdout.closeForTimeout();
    stderr.closeForTimeout();
    await Promise.allSettled([reads]);
    throw error;
  }
}
