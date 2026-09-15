// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

import { mxcErrorFromCode, mxcErrorFromEnvelope, WireError } from './errors.js';
import { Phase, StateAwareContainmentBackend } from './state-aware-types.js';
import { TelemetryConfig } from './types.js';

export const STATE_AWARE_VERSION = '0.6.0-alpha';

// WSLc's state-aware surface shipped at a later schema version than the
// `STATE_AWARE_VERSION` default above (the shared default for IsolationSession
// and Windows Sandbox). WSLc is intentionally NOT gate-locked to it: the
// backends were promoted independently, so WSLc carries its own later default.
// See `DEFAULT_STATE_AWARE_VERSION`.
export const WSLC_STATE_AWARE_VERSION = '0.8.0-alpha';
export const TELEMETRY_STATE_AWARE_VERSION = '0.9.0-alpha';

// Wire-format cross-cutting fields that live at the envelope's top level.
// Anything else on a per-(backend, phase) Config is backend-specific and is
// nested under `experimental.<backend>.<phase>`.
export const CROSS_CUTTING_FIELDS = ['filesystem', 'network', 'ui', 'process', 'telemetry'] as const;

// Per-backend wire-format prefix. Each value mirrors the corresponding
// Rust `<Backend>Runner::ID_PREFIX` const and is the leading segment of a
// `sandboxId` produced by that backend. Each future state-aware backend
// declares its own `<BACKEND>_ID_PREFIX` const here.
export const ISOLATION_SESSION_ID_PREFIX = 'iso';
export const WINDOWS_SANDBOX_ID_PREFIX = 'wsb';
export const WSLC_ID_PREFIX = 'wslc';

// Per-backend default schema version stamped onto an envelope when the caller
// supplies none. Each backend's state-aware surface was promoted at its own
// schema version, so the default is backend-specific rather than a single
// global constant.
const DEFAULT_STATE_AWARE_VERSION: Record<StateAwareContainmentBackend, string> = {
  isolation_session: STATE_AWARE_VERSION,
  windows_sandbox: STATE_AWARE_VERSION,
  wslc: WSLC_STATE_AWARE_VERSION,
};

// Exhaustive backend→prefix map. Typed `Record<StateAwareContainmentBackend,
// string>` so adding a backend to the union without registering a prefix here
// is a compile error — the same exhaustiveness guarantee the config, metadata,
// and default-version registries carry. Without it a new backend would compile
// with no prefix and fail every non-provision call at runtime with
// `malformed_id`.
export const BACKEND_TO_PREFIX: Record<StateAwareContainmentBackend, string> = {
  isolation_session: ISOLATION_SESSION_ID_PREFIX,
  windows_sandbox: WINDOWS_SANDBOX_ID_PREFIX,
  wslc: WSLC_ID_PREFIX,
};

// Reverse lookup (prefix → backend), derived from the exhaustive map above so
// the two can never drift. Used to route a sandboxId's leading prefix segment
// to its wire-format backend key.
export const PREFIX_TO_BACKEND: Record<string, StateAwareContainmentBackend> = Object.fromEntries(
  (Object.entries(BACKEND_TO_PREFIX) as [StateAwareContainmentBackend, string][]).map(
    ([backend, prefix]) => [prefix, backend],
  ),
);

/**
 * Resolves the wire-format backend key for a sandbox id by reading its
 * leading prefix segment. Throws an `MxcError` with `code: 'malformed_id'`
 * when the id has no recognised prefix.
 */
export function backendForSandboxId(sandboxId: string): StateAwareContainmentBackend {
  const colon = sandboxId.indexOf(':');
  if (colon < 0) {
    throw mxcErrorFromCode('malformed_id', `sandboxId must carry a backend prefix: ${sandboxId}`);
  }
  const prefix = sandboxId.slice(0, colon);
  const backend = PREFIX_TO_BACKEND[prefix];
  if (!backend) {
    throw mxcErrorFromCode('malformed_id', `sandboxId prefix '${prefix}' does not match a known state-aware backend`);
  }
  return backend;
}

export interface BuildEnvelopeArgs {
  phase: Phase;
  backendKey: StateAwareContainmentBackend;
  containment?: StateAwareContainmentBackend; // provision only
  sandboxId?: string;                        // non-provision only
  config?: Record<string, unknown>;
}

/**
 * Constructs the wire-format JSON-shaped envelope for a state-aware request
 * from a per-(backend, phase) Config. Lifts cross-cutting fields
 * (filesystem, network, ui, process, telemetry) to envelope top-level; nests any
 * remaining backend-specific fields under `experimental.<backend>.<phase>`.
 */
export function buildStateAwareEnvelope(args: BuildEnvelopeArgs): Record<string, unknown> {
  const {
    phase,
    backendKey,
    containment,
    sandboxId,
    config,
  } = args;
  // Copy of config; fields are removed as they are lifted into the envelope.
  // Anything left becomes experimental.<backend>.<phase>.
  const backendSpecific: Record<string, unknown> = { ...(config ?? {}) };
  const defaultVersion = DEFAULT_STATE_AWARE_VERSION[backendKey] ?? STATE_AWARE_VERSION;
  const suppliedVersion = typeof backendSpecific.version === 'string' && backendSpecific.version;
  const telemetry = backendSpecific.telemetry as TelemetryConfig | undefined;
  const hasTelemetry = telemetry !== undefined;
  const version = suppliedVersion || (hasTelemetry ? TELEMETRY_STATE_AWARE_VERSION : defaultVersion);
  delete backendSpecific.version;

  const envelope: Record<string, unknown> = { version, phase };
  if (containment) {
    envelope.containment = containment;
  }
  if (sandboxId) {
    envelope.sandboxId = sandboxId;
  }
  if (telemetry !== undefined) {
    envelope.telemetry = telemetry;
    delete backendSpecific.telemetry;
  }

  for (const field of CROSS_CUTTING_FIELDS) {
    if (backendSpecific[field] !== undefined) {
      envelope[field] = backendSpecific[field];
      delete backendSpecific[field];
    }
  }

  if (Object.keys(backendSpecific).length > 0) {
    envelope.experimental = { [backendKey]: { [phase]: backendSpecific } };
  }

  return envelope;
}

export interface WireErrorEnvelope {
  error: WireError;
}

export interface WireResultEnvelope<T> {
  result: T;
}

/**
 * Parses the single-envelope JSON stdout produced by non-exec state-aware
 * phases. Throws the corresponding `MxcError` on `{error}`, returns the
 * unwrapped `result` on `{result}`.
 */
export function parseNonExecResponse<T>(stdout: string): T {
  let parsed: unknown;
  try {
    parsed = JSON.parse(stdout.trim());
  } catch (e) {
    throw new Error(`Failed to parse state-aware response envelope: ${(e as Error).message}`);
  }
  if (parsed && typeof parsed === 'object') {
    if ('error' in parsed) {
      const env = (parsed as WireErrorEnvelope).error;
      throw mxcErrorFromEnvelope(env);
    }
    if ('result' in parsed) {
      return (parsed as WireResultEnvelope<T>).result;
    }
  }
  throw new Error(`Unexpected state-aware response envelope shape: ${stdout}`);
}
