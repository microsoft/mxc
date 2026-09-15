// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

import { Worker } from 'node:worker_threads';
import { MxcError, type MxcErrorFields } from '../errors.js';
import {
  TELEMETRY_CONSENT_PRESENTER_ERROR,
  type TelemetryConsentSnapshot,
} from './telemetry.js';

export interface TelemetryQueryWorkerData {
  operation: 'query';
}

export interface TelemetryWithdrawWorkerData {
  operation: 'withdraw';
}

export interface TelemetryRequestWorkerData {
  operation: 'request';
  locale?: string;
  decisionShared: SharedArrayBuffer;
}

export type TelemetryWorkerData =
  | TelemetryQueryWorkerData
  | TelemetryWithdrawWorkerData
  | TelemetryRequestWorkerData;

export type TelemetryWorkerMessage =
  | { kind: 'snapshot'; snapshot: TelemetryConsentSnapshot }
  | { kind: 'payload'; payload: string }
  | { kind: 'present'; promptJson: string }
  | { kind: 'error'; error: MxcErrorFields };

export interface BindingTelemetryWorkerLike {
  on(event: 'message', listener: (message: TelemetryWorkerMessage) => void): this;
  on(event: 'error', listener: (error: Error) => void): this;
  on(event: 'exit', listener: (code: number) => void): this;
}

type WorkerFactory = (data: TelemetryWorkerData) => BindingTelemetryWorkerLike;

const defaultWorkerFactory: WorkerFactory = (data) => new Worker(
  new URL('./telemetry-worker-entry.js', import.meta.url),
  { workerData: data, execArgv: [] },
);

let workerFactory = defaultWorkerFactory;

export function _setBindingTelemetryWorkerFactory(factory?: WorkerFactory): void {
  workerFactory = factory ?? defaultWorkerFactory;
}

function serializeUnknownError(error: unknown): Error {
  return error instanceof Error ? error : new Error(String(error));
}

function runTelemetryWorker<T>(
  data: TelemetryWorkerData,
  handleMessage: (
    message: TelemetryWorkerMessage,
    finish: (action: () => void) => void,
    resolve: (value: T) => void,
    reject: (reason?: unknown) => void,
  ) => void,
): Promise<T> {
  return new Promise((resolve, reject) => {
    const worker = workerFactory(data);
    let settled = false;
    const finish = (action: () => void) => {
      if (settled) {
        return;
      }
      settled = true;
      action();
    };

    worker.on('message', (message) => handleMessage(message, finish, resolve, reject));
    worker.on('error', (error) => finish(() => reject(error)));
    worker.on('exit', (code) => finish(() => reject(new MxcError({
      code: 'backend_error',
      message: `mxc_telemetry worker exited before returning a result (code ${code})`,
    }))));
  });
}

export function runTelemetryConsentQueryAsync(): Promise<TelemetryConsentSnapshot> {
  return runTelemetryWorker({ operation: 'query' }, (message, finish, resolve, reject) => {
    if (message.kind === 'snapshot') {
      finish(() => resolve(message.snapshot));
      return;
    }
    if (message.kind === 'error') {
      finish(() => reject(new MxcError(message.error)));
      return;
    }
    finish(() => reject(new Error('telemetry query worker returned an unexpected message')));
  });
}

export function runTelemetryConsentWithdrawAsync(): Promise<string> {
  return runTelemetryWorker({ operation: 'withdraw' }, (message, finish, resolve, reject) => {
    if (message.kind === 'payload') {
      finish(() => resolve(message.payload));
      return;
    }
    if (message.kind === 'error') {
      finish(() => reject(new MxcError(message.error)));
      return;
    }
    finish(() => reject(new Error('telemetry withdrawal worker returned an unexpected message')));
  });
}

export function runTelemetryConsentRequestAsync(
  locale: string | undefined,
  presenter: (promptJson: string, signal: AbortSignal) => number | Promise<number>,
): Promise<string> {
  const decision = new Int32Array(new SharedArrayBuffer(Int32Array.BYTES_PER_ELEMENT * 2));
  return new Promise((resolve, reject) => {
    const worker = workerFactory({
      operation: 'request',
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
      message: `mxc_telemetry worker exited before returning a result (code ${code})`,
    }))));
  });
}
