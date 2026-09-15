// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

// Main-thread bridge for state-aware lifecycle calls that block in the native
// runtime. Running them in a worker keeps Node's event loop responsive.

import { Worker } from 'node:worker_threads';
import { MxcError, type MxcErrorFields } from '../errors.js';
import type { BindingStateAwareRequest } from './state-aware.js';

export interface BindingStateAwareWorkerData {
  request: BindingStateAwareRequest;
}

export type BindingStateAwareWorkerMessage =
  | { ok: true; responseJson: string }
  | { ok: false; error: MxcErrorFields };

export interface BindingStateAwareWorkerLike {
  on(event: 'message', listener: (message: BindingStateAwareWorkerMessage) => void): this;
  on(event: 'error', listener: (error: Error) => void): this;
  on(event: 'exit', listener: (code: number) => void): this;
}

type WorkerFactory = (data: BindingStateAwareWorkerData) => BindingStateAwareWorkerLike;

const defaultWorkerFactory: WorkerFactory = (data) => new Worker(
  new URL('./state-aware-worker-entry.js', import.meta.url),
  { workerData: data, execArgv: [] },
);

let workerFactory = defaultWorkerFactory;

export function _setBindingStateAwareWorkerFactory(factory?: WorkerFactory): void {
  workerFactory = factory ?? defaultWorkerFactory;
}

export function runBindingStateAwareRequestAsync(
  request: BindingStateAwareRequest,
): Promise<string> {
  return new Promise((resolve, reject) => {
    const worker = workerFactory({ request });
    let settled = false;
    const finish = (action: () => void) => {
      if (settled) return;
      settled = true;
      action();
    };

    worker.on('message', (message) => finish(() => {
      if (message.ok) resolve(message.responseJson);
      else reject(new MxcError(message.error));
    }));
    worker.on('error', (error) => finish(() => reject(error)));
    worker.on('exit', (code) => finish(() => reject(new MxcError({
      code: 'backend_error',
      message: `state-aware worker exited before returning a result (code ${code})`,
    }))));
  });
}
