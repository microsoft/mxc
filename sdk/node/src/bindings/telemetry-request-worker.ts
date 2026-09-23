// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

// Main-thread bridge for the blocking native consent presenter callback.

import { Worker } from 'node:worker_threads';
import { MxcError, type MxcErrorFields } from '../errors.js';
import { TELEMETRY_CONSENT_PRESENTER_ERROR } from './telemetry.js';

export interface TelemetryRequestWorkerData {
  locale?: string;
  decisionShared: SharedArrayBuffer;
}

export type TelemetryRequestWorkerMessage =
  | { kind: 'payload'; payload: string }
  | { kind: 'present'; promptJson: string }
  | { kind: 'error'; error: MxcErrorFields };

export interface BindingTelemetryWorkerLike {
  on(event: 'message', listener: (message: TelemetryRequestWorkerMessage) => void): this;
  on(event: 'error', listener: (error: Error) => void): this;
  on(event: 'exit', listener: (code: number) => void): this;
}

type WorkerFactory = (data: TelemetryRequestWorkerData) => BindingTelemetryWorkerLike;

const defaultWorkerFactory: WorkerFactory = (data) => new Worker(
  new URL('./telemetry-request-worker-entry.js', import.meta.url),
  { workerData: data, execArgv: [] },
);

let workerFactory = defaultWorkerFactory;

export function _setBindingTelemetryWorkerFactory(factory?: WorkerFactory): void {
  workerFactory = factory ?? defaultWorkerFactory;
}

function serializeUnknownError(error: unknown): Error {
  return error instanceof Error ? error : new Error(String(error));
}

export function runTelemetryConsentRequestAsync(
  locale: string | undefined,
  presenter: (promptJson: string, signal: AbortSignal) => number | Promise<number>,
): Promise<string> {
  const decision = new Int32Array(new SharedArrayBuffer(Int32Array.BYTES_PER_ELEMENT * 2));
  return new Promise((resolve, reject) => {
    const worker = workerFactory({
      locale,
      decisionShared: decision.buffer as SharedArrayBuffer,
    });
    let settled = false;
    let presenterAbort: AbortController | null = null;
    let presenterError: Error | undefined;
    let decisionWritten = false;

    const writeDecision = (code: number): void => {
      if (decisionWritten) {
        return;
      }
      decisionWritten = true;
      Atomics.store(decision, 1, code);
      Atomics.store(decision, 0, 1);
      Atomics.notify(decision, 0);
    };

    const finish = (action: () => void) => {
      if (settled) {
        return;
      }
      settled = true;
      presenterAbort?.abort();
      if (!decisionWritten) {
        writeDecision(TELEMETRY_CONSENT_PRESENTER_ERROR);
      }
      action();
    };

    worker.on('message', (message) => {
      if (message.kind === 'present') {
        presenterAbort = new AbortController();
        void (async () => {
          try {
            const code = await presenter(message.promptJson, presenterAbort.signal);
            if (!Number.isSafeInteger(code)) {
              throw new Error(`consent presenter returned invalid decision '${String(code)}'`);
            }
            writeDecision(code);
          } catch (error) {
            presenterError = serializeUnknownError(error);
            writeDecision(TELEMETRY_CONSENT_PRESENTER_ERROR);
          }
        })();
        return;
      }
      if (message.kind === 'payload') {
        finish(() => {
          if (presenterError) {
            reject(presenterError);
          } else {
            resolve(message.payload);
          }
        });
        return;
      }
      if (message.kind === 'error') {
        finish(() => reject(presenterError ?? new MxcError(message.error)));
        return;
      }
      finish(() => reject(new Error('telemetry request worker returned an unexpected message')));
    });
    worker.on('error', (error) => finish(() => reject(error)));
    worker.on('exit', (code) => finish(() => reject(presenterError ?? new MxcError({
      code: 'backend_error',
      message: `telemetry worker exited before returning a result (code ${code})`,
    }))));
  });
}
