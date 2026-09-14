// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

import { Worker } from 'node:worker_threads';
import { MxcError, type MxcErrorFields } from './errors.js';
import type { NativeRunResult } from './native-run.js';

export interface NativeRunWorkerData {
  requestJson: string;
}

export type NativeRunWorkerMessage =
  | { ok: true; result: NativeRunResult }
  | { ok: false; error: MxcErrorFields };

/** @internal Minimal worker surface used by deterministic unit tests. */
export interface NativeRunWorkerLike {
  on(event: 'message', listener: (message: NativeRunWorkerMessage) => void): this;
  on(event: 'error', listener: (error: Error) => void): this;
  on(event: 'exit', listener: (code: number) => void): this;
}

type WorkerFactory = (data: NativeRunWorkerData) => NativeRunWorkerLike;

const defaultWorkerFactory: WorkerFactory = (data) => new Worker(
  new URL('./native-run-worker-entry.js', import.meta.url),
  { workerData: data, execArgv: [] },
);

let workerFactory = defaultWorkerFactory;

/** @internal Replaces the worker factory for one process's unit tests. */
export function _setNativeRunWorkerFactory(factory?: WorkerFactory): void {
  workerFactory = factory ?? defaultWorkerFactory;
}

export function runNativeRequestAsync(requestJson: string): Promise<NativeRunResult> {
  return new Promise((resolve, reject) => {
    const worker = workerFactory({ requestJson });
    let settled = false;
    const finish = (action: () => void) => {
      if (settled) return;
      settled = true;
      action();
    };

    worker.on('message', (message) => finish(() => {
      if (message.ok) resolve(message.result);
      else reject(new MxcError(message.error));
    }));
    worker.on('error', (error) => finish(() => reject(error)));
    worker.on('exit', (code) => finish(() => reject(new MxcError({
      code: 'backend_error',
      message: `mxc_ffi worker exited before returning a result (code ${code})`,
    }))));
  });
}
