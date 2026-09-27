// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

// Async native binding for state-aware lifecycle phases that run to completion.

import koffi from 'koffi';
import { MxcError } from '../errors.js';
import { loadMxcFfi } from '../native-library.js';
import { bindNativeFunction } from './native-function.js';
import {
  AbiErrorDetailType,
  decodeString,
  nativeStatusError,
  type AbiErrorDetail,
} from './native-error.js';
import {
  buildTypedStateAwareRequest,
  MxcTypedStateAwareRequestType,
  MXC_PROVISION_METADATA_ISOLATION_SESSION,
  parseStateAwareEnvelopeJson,
  supportsTypedStateAwareEnvelope,
  type MxcTypedStateAwareRequest,
} from './typed-abi.js';

export interface StateAwareNativeResult {
  status: number;
  responseJsonUtf8: unknown | null;
  error: AbiErrorDetail;
}

export interface TypedStateAwareNativeResult {
  status: number;
  sandboxIdUtf8: unknown | null;
  warningsJsonUtf8: unknown | null;
  metadataKind: number;
  agentUserNameUtf8: unknown | null;
  agentUserSidUtf8: unknown | null;
  ephemeralWorkspacePathUtf8: unknown | null;
  error: AbiErrorDetail;
}

export interface BindingStateAwareRequest {
  requestJson: string;
  dryRun: boolean;
  experimental: boolean;
}

const AbiStateAwareResultType = koffi.struct('MxcNodeStateAwareResult', {
  status: 'int32_t',
  responseJsonUtf8: 'void *',
  error: AbiErrorDetailType,
});

export const AbiTypedStateAwareResultType = koffi.struct('MxcNodeTypedStateAwareResult', {
  status: 'int32_t',
  sandboxIdUtf8: 'void *',
  warningsJsonUtf8: 'void *',
  metadataKind: 'int32_t',
  agentUserNameUtf8: 'void *',
  agentUserSidUtf8: 'void *',
  ephemeralWorkspacePathUtf8: 'void *',
  error: AbiErrorDetailType,
});

type StateAwareFunction = (
  request: string,
  dryRun: number,
  experimental: number,
  result: StateAwareNativeResult,
) => number;
type TypedStateAwareFunction = (
  request: MxcTypedStateAwareRequest,
  dryRun: number,
  result: TypedStateAwareNativeResult,
) => number;
type FreeFunction = (result: StateAwareNativeResult) => void;
type FreeTypedFunction = (result: TypedStateAwareNativeResult) => void;

type StateAwareCompletion = (error: Error | null, status: number) => void;

export interface StateAwareNativeFacade {
  runJson(
    request: string,
    dryRun: number,
    experimental: number,
    result: StateAwareNativeResult,
    completion: StateAwareCompletion,
  ): void;
  runTyped(
    request: MxcTypedStateAwareRequest,
    dryRun: number,
    result: TypedStateAwareNativeResult,
    completion: StateAwareCompletion,
  ): void;
  freeJson(result: StateAwareNativeResult): void;
  freeTyped(result: TypedStateAwareNativeResult): void;
}

function bindStateAwareNativeFacade(
  native: ReturnType<typeof loadMxcFfi>,
): StateAwareNativeFacade {
  const run = bindNativeFunction<StateAwareFunction>(native.handle, {
    symbol: 'mxc_state_aware_json',
    result: 'int32_t',
    parameters: [
      'const char *',
      'int32_t',
      'int32_t',
      koffi.out(koffi.pointer(AbiStateAwareResultType)),
    ],
  });
  const runTyped = bindNativeFunction<TypedStateAwareFunction>(native.handle, {
    symbol: 'mxc_state_aware_typed',
    result: 'int32_t',
    parameters: [
      koffi.pointer(MxcTypedStateAwareRequestType),
      'int32_t',
      koffi.out(koffi.pointer(AbiTypedStateAwareResultType)),
    ],
  });
  const free = bindNativeFunction<FreeFunction>(native.handle, {
    symbol: 'mxc_state_aware_result_free',
    result: 'void',
    parameters: [koffi.pointer(AbiStateAwareResultType)],
  });
  const freeTyped = bindNativeFunction<FreeTypedFunction>(native.handle, {
    symbol: 'mxc_state_aware_typed_result_free',
    result: 'void',
    parameters: [koffi.pointer(AbiTypedStateAwareResultType)],
  });
  return {
    runJson(request, dryRun, experimental, result, completion) {
      run.async(request, dryRun, experimental, result, completion);
    },
    runTyped(request, dryRun, result, completion) {
      runTyped.async(request, dryRun, result, completion);
    },
    freeJson: free,
    freeTyped,
  };
}

function createStateAwareResult(): StateAwareNativeResult {
  return {
    status: 0,
    responseJsonUtf8: null,
    error: {
      message: null,
      operation: null,
      nativeCode: null,
      remediation: null,
    },
  };
}

function createTypedStateAwareResult(): TypedStateAwareNativeResult {
  return {
    status: 0,
    sandboxIdUtf8: null,
    warningsJsonUtf8: null,
    metadataKind: 0,
    agentUserNameUtf8: null,
    agentUserSidUtf8: null,
    ephemeralWorkspacePathUtf8: null,
    error: {
      message: null,
      operation: null,
      nativeCode: null,
      remediation: null,
    },
  };
}

function decodeStateAwareResult(
  nativeStatus: number,
  result: StateAwareNativeResult,
): string {
  if (nativeStatus !== 0 || result.status !== 0) {
    throw nativeStatusError(
      result.status || nativeStatus,
      result.error,
      'state-aware request failed',
    );
  }
  return decodeString(result.responseJsonUtf8) ?? '{}';
}

function decodeTypedStateAwareResult(
  nativeStatus: number,
  result: TypedStateAwareNativeResult,
): string {
  if (nativeStatus !== 0 || result.status !== 0) {
    throw nativeStatusError(
      result.status || nativeStatus,
      result.error,
      'state-aware request failed',
    );
  }

  const body: Record<string, unknown> = {};
  const sandboxId = decodeString(result.sandboxIdUtf8);
  if (sandboxId !== undefined) {
    body.sandboxId = sandboxId;
  }
  const warningsJson = decodeString(result.warningsJsonUtf8);
  if (warningsJson !== undefined) {
    body.warnings = JSON.parse(warningsJson) as unknown;
  }
  if (result.metadataKind === MXC_PROVISION_METADATA_ISOLATION_SESSION) {
    body.metadata = {
      agentUserName: decodeString(result.agentUserNameUtf8) ?? '',
      agentUserSid: decodeString(result.agentUserSidUtf8) ?? '',
      ephemeralWorkspacePath: decodeString(result.ephemeralWorkspacePathUtf8) ?? '',
    };
  }
  return JSON.stringify({ result: body });
}

async function runBindingStateAwareJsonRequestWithNative(
  request: BindingStateAwareRequest,
  native: StateAwareNativeFacade,
): Promise<string> {
  const result = createStateAwareResult();
  let ownsResult = false;
  try {
    const nativeStatus = await new Promise<number>((resolve, reject) => {
      native.runJson(
        request.requestJson,
        request.dryRun ? 1 : 0,
        request.experimental ? 1 : 0,
        result,
        (error, status) => {
          if (error !== null) {
            reject(error);
            return;
          }
          ownsResult = true;
          resolve(status);
        },
      );
    });
    return decodeStateAwareResult(nativeStatus, result);
  } finally {
    if (ownsResult) native.freeJson(result);
  }
}

async function runBindingStateAwareTypedRequestWithNative(
  request: BindingStateAwareRequest,
  native: StateAwareNativeFacade,
  envelope: Record<string, unknown>,
): Promise<string> {
  const typed = buildTypedStateAwareRequest(envelope, request.experimental);
  const result = createTypedStateAwareResult();
  let ownsResult = false;
  try {
    const nativeStatus = await new Promise<number>((resolve, reject) => {
      native.runTyped(
        typed.value,
        request.dryRun ? 1 : 0,
        result,
        (error, status) => {
          if (error !== null) {
            reject(error);
            return;
          }
          ownsResult = true;
          resolve(status);
        },
      );
    });
    return decodeTypedStateAwareResult(nativeStatus, result);
  } finally {
    if (ownsResult) native.freeTyped(result);
  }
}

export async function runBindingStateAwareRequestWithNative(
  request: BindingStateAwareRequest,
  native: StateAwareNativeFacade,
): Promise<string> {
  let envelope: Record<string, unknown>;
  try {
    envelope = parseStateAwareEnvelopeJson(request.requestJson);
  } catch {
    return runBindingStateAwareJsonRequestWithNative(request, native);
  }
  if (!supportsTypedStateAwareEnvelope(envelope)) {
    return runBindingStateAwareJsonRequestWithNative(request, native);
  }
  return runBindingStateAwareTypedRequestWithNative(request, native, envelope);
}

async function runBindingStateAwareRequestAsyncNative(
  request: BindingStateAwareRequest,
): Promise<string> {
  const native = loadMxcFfi();
  try {
    return await runBindingStateAwareRequestWithNative(
      request,
      bindStateAwareNativeFacade(native),
    );
  } finally {
    native.handle.unload();
  }
}

type AsyncStateAwareImplementation = (
  request: BindingStateAwareRequest,
) => Promise<string>;

let asyncStateAwareImplementation = runBindingStateAwareRequestAsyncNative;

/** @internal Replaces the async native call for one process's unit tests. */
export function _setBindingStateAwareAsyncImplementation(
  implementation?: AsyncStateAwareImplementation,
): void {
  asyncStateAwareImplementation =
    implementation ?? runBindingStateAwareRequestAsyncNative;
}

export function runBindingStateAwareRequestAsync(
  request: BindingStateAwareRequest,
): Promise<string> {
  return asyncStateAwareImplementation(request).catch((error: unknown) => {
    if (error instanceof MxcError) throw error;
    throw new MxcError(
      'backend_error',
      error instanceof Error ? error.message : String(error),
    );
  });
}
