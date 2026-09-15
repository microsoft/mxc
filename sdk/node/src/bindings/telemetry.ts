// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

// Synchronous native bindings for telemetry consent and administrative policy.

import koffi, { type KoffiFunc } from 'koffi';
import { loadMxcFfi } from '../native-library.js';
import { decodeString, nativeStatusError } from './native-error.js';

export const TELEMETRY_CONSENT_DECISION_NO = 0;
export const TELEMETRY_CONSENT_DECISION_YES = 1;
export const TELEMETRY_CONSENT_DECISION_DISMISSED = 2;
export const TELEMETRY_CONSENT_PRESENTER_ERROR = -1;

export interface TelemetryConsentSnapshot {
  consent: string;
  statusJson: string;
  policy: string;
  needsPrompt: boolean;
}

const TelemetryConsentPresenter = koffi.proto(
  'MxcNodeTelemetryConsentPresenter',
  'int32_t',
  ['const char *', 'void *'],
);

type StringOutFunction = KoffiFunc<(out: unknown[]) => number>;
type BoolOutFunction = KoffiFunc<(out: number[]) => number>;
type StringFreeFunction = KoffiFunc<(value: unknown) => void>;
type RequestConsentFunction = KoffiFunc<(
  locale: string | null,
  presenter: ((promptJson: string, context: unknown) => number) | null,
  context: unknown | null,
  out: unknown[],
) => number>;

interface TelemetryApi {
  getConsent: StringOutFunction;
  getConsentStatus: StringOutFunction;
  getPolicy: StringOutFunction;
  needsConsentPrompt: BoolOutFunction;
  withdrawConsent: StringOutFunction;
  requestConsent: RequestConsentFunction;
  stringFree: StringFreeFunction;
}

function isNonNullPointer(value: unknown): boolean {
  return value !== null && value !== undefined && value !== 0 && value !== 0n;
}

function readRequiredString(
  invoke: (out: unknown[]) => number,
  stringFree: StringFreeFunction,
  message: string,
): string {
  const out = [null] as unknown[];
  const status = invoke(out);
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

function readBoolean(invoke: BoolOutFunction, message: string): boolean {
  const out = [0];
  const status = invoke(out);
  if (status !== 0) {
    throw nativeStatusError(status, {}, message);
  }
  return out[0] !== 0;
}

function withTelemetryApi<T>(action: (api: TelemetryApi) => T): T {
  const native = loadMxcFfi();
  try {
    const handle = native.handle;
    const api: TelemetryApi = {
      getConsent: handle.func(
        'mxc_telemetry_get_consent',
        'int32_t',
        [koffi.out(koffi.pointer('char', 2))],
      ) as StringOutFunction,
      getConsentStatus: handle.func(
        'mxc_telemetry_get_consent_status',
        'int32_t',
        [koffi.out(koffi.pointer('char', 2))],
      ) as StringOutFunction,
      getPolicy: handle.func(
        'mxc_telemetry_get_policy',
        'int32_t',
        [koffi.out(koffi.pointer('char', 2))],
      ) as StringOutFunction,
      needsConsentPrompt: handle.func(
        'mxc_telemetry_needs_consent_prompt',
        'int32_t',
        [koffi.out(koffi.pointer('int32_t'))],
      ) as BoolOutFunction,
      withdrawConsent: handle.func(
        'mxc_telemetry_withdraw_consent',
        'int32_t',
        [koffi.out(koffi.pointer('char', 2))],
      ) as StringOutFunction,
      requestConsent: handle.func(
        'mxc_telemetry_request_consent',
        'int32_t',
        ['const char *', koffi.pointer(TelemetryConsentPresenter), 'void *', koffi.out(koffi.pointer('char', 2))],
      ) as RequestConsentFunction,
      stringFree: handle.func('mxc_string_free', 'void', ['char *']) as StringFreeFunction,
    };
    return action(api);
  } finally {
    native.handle.unload();
  }
}

export function readTelemetryConsentSnapshot(): TelemetryConsentSnapshot {
  return withTelemetryApi((api) => ({
    consent: readRequiredString(
      (out) => api.getConsent(out),
      api.stringFree,
      'reading telemetry consent failed',
    ),
    statusJson: readRequiredString(
      (out) => api.getConsentStatus(out),
      api.stringFree,
      'reading telemetry consent status failed',
    ),
    policy: readRequiredString(
      (out) => api.getPolicy(out),
      api.stringFree,
      'reading telemetry policy failed',
    ),
    needsPrompt: readBoolean(
      api.needsConsentPrompt,
      'checking telemetry consent prompt eligibility failed',
    ),
  }));
}

export function withdrawTelemetryConsentJson(): string {
  return withTelemetryApi((api) => readRequiredString(
    (out) => api.withdrawConsent(out),
    api.stringFree,
    'withdrawing telemetry consent failed',
  ));
}

export function requestTelemetryConsentJson(
  locale: string | undefined,
  presenter: (promptJson: string) => number,
): string {
  return withTelemetryApi((api) => readRequiredString(
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
  ));
}
