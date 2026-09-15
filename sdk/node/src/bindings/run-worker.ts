// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

// Main-thread bridge for run-to-completion calls. The native call blocks until
// the sandbox exits, so it runs in a worker thread to keep Node's event loop
// responsive.

import { Worker } from 'node:worker_threads';
import { MxcError, type MxcErrorFields } from '../errors.js';
import type { BindingSandboxRequest } from './request.js';
import type { BindingRunResult } from './run.js';

export interface BindingRunWorkerData {
  request: BindingSandboxRequest;
}

export type BindingRunWorkerMessage =
  | { ok: true; result: BindingRunResult }
  | { ok: false; error: MxcErrorFields };

/** @internal Minimal worker surface used by deterministic unit tests. */
export interface BindingRunWorkerLike {
  on(event: 'message', listener: (message: BindingRunWorkerMessage) => void): this;
  on(event: 'error', listener: (error: Error) => void): this;
  on(event: 'exit', listener: (code: number) => void): this;
}

type WorkerFactory = (data: BindingRunWorkerData) => BindingRunWorkerLike;

const defaultWorkerFactory: WorkerFactory = (data) => new Worker(
  new URL('./run-worker-entry.js', import.meta.url),
  { workerData: data, execArgv: [] },
);

let workerFactory = defaultWorkerFactory;

/** @internal Replaces the worker factory for one process's unit tests. */
export function _setBindingRunWorkerFactory(factory?: WorkerFactory): void {
  workerFactory = factory ?? defaultWorkerFactory;
}

export function runBindingRequestAsync(
  request: BindingSandboxRequest,
): Promise<BindingRunResult> {
  return new Promise((resolve, reject) => {
    const worker = workerFactory({ request });
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
      message: `native execution worker exited before returning a result (code ${code})`,
    }))));
  });
}
