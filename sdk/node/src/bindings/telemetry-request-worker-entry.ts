// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

// Worker-thread entry point for the blocking native consent request.

import { parentPort, workerData } from 'node:worker_threads';
import { MxcError } from '../errors.js';
import {
  requestTelemetryConsentJson,
} from './telemetry.js';
import type {
  TelemetryRequestWorkerData,
  TelemetryRequestWorkerMessage,
} from './telemetry-request-worker.js';

function serializeError(error: unknown) {
  if (error instanceof MxcError) {
    return {
      code: error.code,
      message: error.message,
      operation: error.operation,
      nativeCode: error.nativeCode,
      remediation: error.remediation,
      details: error.details,
    };
  }
  return {
    code: 'backend_error' as const,
    message: error instanceof Error ? error.message : String(error),
  };
}

const data = workerData as TelemetryRequestWorkerData;
let message: TelemetryRequestWorkerMessage;
try {
  const decision = new Int32Array(data.decisionShared);
  message = {
    kind: 'payload',
    payload: requestTelemetryConsentJson(data.locale, (promptJson) => {
      Atomics.store(decision, 0, 0);
      Atomics.store(decision, 1, 0);
      parentPort!.postMessage({ kind: 'present', promptJson } satisfies TelemetryRequestWorkerMessage);
      Atomics.wait(decision, 0, 0);
      return Atomics.load(decision, 1);
    }),
  };
} catch (error) {
  message = { kind: 'error', error: serializeError(error) };
}
parentPort!.postMessage(message);
