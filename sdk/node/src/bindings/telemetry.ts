// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

// Native bindings for telemetry consent and administrative policy.

import koffi, { type KoffiFunc } from 'koffi';
import { loadMxcFfi } from '../native-library.js';
import { decodeString, nativeStatusError } from './native-error.js';
import { bindNativeFunction } from './native-function.js';

export const TELEMETRY_CONSENT_DECISION_NO = 0;
export const TELEMETRY_CONSENT_DECISION_YES = 1;
export const TELEMETRY_CONSENT_DECISION_DISMISSED = 2;
export const TELEMETRY_CONSENT_PRESENTER_ERROR = -1;

const TelemetryConsentPresenter = koffi.proto(
  'MxcNodeTelemetryConsentPresenter',
  'int32_t',
  ['const char *', 'void *'],
);

type StringOutSignature = (out: unknown[]) => number;
type StringFreeSignature = (value: unknown) => void;
type RequestConsentSignature = (
  locale: string | null,
  presenter: ((promptJson: string, context: unknown) => number) | null,
  context: unknown | null,
  out: unknown[],
) => number;
type StringOutFunction = KoffiFunc<StringOutSignature>;
type StringFreeFunction = KoffiFunc<StringFreeSignature>;
type RequestConsentFunction = KoffiFunc<RequestConsentSignature>;

interface TelemetryApi {
  getConsentStatus: StringOutFunction;
  withdrawConsent: StringOutFunction;
  requestConsent: RequestConsentFunction;
  stringFree: StringFreeFunction;
}

export interface TelemetryAsyncImplementation {
  readConsentStatusJson(): Promise<string>;
  withdrawConsentJson(): Promise<string>;
}

function bindTelemetryApi(native: ReturnType<typeof loadMxcFfi>): TelemetryApi {
  const stringOutParameters = [koffi.out(koffi.pointer('char', 2))];
  return {
    getConsentStatus: bindNativeFunction<StringOutSignature>(native.handle, {
      symbol: 'mxc_telemetry_get_consent_status',
      result: 'int32_t',
      parameters: stringOutParameters,
    }),
    withdrawConsent: bindNativeFunction<StringOutSignature>(native.handle, {
      symbol: 'mxc_telemetry_withdraw_consent',
      result: 'int32_t',
      parameters: stringOutParameters,
    }),
    requestConsent: bindNativeFunction<RequestConsentSignature>(native.handle, {
      symbol: 'mxc_telemetry_request_consent',
      result: 'int32_t',
      parameters: [
        'const char *',
        koffi.pointer(TelemetryConsentPresenter),
        'void *',
        koffi.out(koffi.pointer('char', 2)),
      ],
    }),
    stringFree: bindNativeFunction<StringFreeSignature>(native.handle, {
      symbol: 'mxc_string_free',
      result: 'void',
      parameters: ['char *'],
    }),
  };
}

function isNonNullPointer(value: unknown): boolean {
  return value !== null && value !== undefined && value !== 0 && value !== 0n;
}

function decodeRequiredString(
  status: number,
  out: unknown[],
  stringFree: StringFreeFunction,
  message: string,
): string {
  if (status !== 0) {
    throw nativeStatusError(status, {}, message);
  }
  try {
    if (!isNonNullPointer(out[0])) {
      throw new Error(`${message}: native call returned success without a payload`);
    }
    const value = decodeString(out[0]);
    if (value === undefined) {
      throw new Error(`${message}: native call returned an unreadable payload`);
    }
    return value;
  } finally {
    if (isNonNullPointer(out[0])) {
      stringFree(out[0]);
    }
  }
}

function readRequiredString(
  invoke: (out: unknown[]) => number,
  stringFree: StringFreeFunction,
  message: string,
): string {
  const out = [null] as unknown[];
  return decodeRequiredString(invoke(out), out, stringFree, message);
}

function readRequiredStringAsync(
  invoke: StringOutFunction,
  stringFree: StringFreeFunction,
  message: string,
): Promise<string> {
  const out = [null] as unknown[];
  return new Promise((resolve, reject) => {
    invoke.async(out, (error, status) => {
      if (error !== null) {
        reject(error);
        return;
      }
      try {
        resolve(decodeRequiredString(status, out, stringFree, message));
      } catch (decodeError) {
        reject(decodeError);
      }
    });
  });
}

async function readTelemetryStringAsync(
  select: (api: TelemetryApi) => StringOutFunction,
  message: string,
): Promise<string> {
  const native = loadMxcFfi();
  try {
    const api = bindTelemetryApi(native);
    return await readRequiredStringAsync(select(api), api.stringFree, message);
  } finally {
    native.handle.unload();
  }
}

const defaultAsyncImplementation: TelemetryAsyncImplementation = {
  readConsentStatusJson: () => readTelemetryStringAsync(
    (api) => api.getConsentStatus,
    'reading telemetry consent status failed',
  ),
  withdrawConsentJson: () => readTelemetryStringAsync(
    (api) => api.withdrawConsent,
    'withdrawing telemetry consent failed',
  ),
};
let asyncImplementation = defaultAsyncImplementation;

/** @internal Replaces async native calls for one process's unit tests. */
export function _setBindingTelemetryAsyncImplementation(
  implementation?: TelemetryAsyncImplementation,
): void {
  asyncImplementation = implementation ?? defaultAsyncImplementation;
}

export function readTelemetryConsentStatusJsonAsync(): Promise<string> {
  return asyncImplementation.readConsentStatusJson();
}

export function withdrawTelemetryConsentJsonAsync(): Promise<string> {
  return asyncImplementation.withdrawConsentJson();
}

export function requestTelemetryConsentJson(
  locale: string | undefined,
  presenter: (promptJson: string) => number,
): string {
  const native = loadMxcFfi();
  try {
    const api = bindTelemetryApi(native);
    return readRequiredString(
      (out) => api.requestConsent(
        locale ?? null,
        (promptJson) => {
          try {
            return presenter(promptJson);
          } catch {
            return TELEMETRY_CONSENT_PRESENTER_ERROR;
          }
        },
        null,
        out,
      ),
      api.stringFree,
      'requesting telemetry consent failed',
    );
  } finally {
    native.handle.unload();
  }
}
