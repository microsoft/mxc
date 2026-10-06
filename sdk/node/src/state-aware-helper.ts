// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

import { mxcErrorFromCode, mxcErrorFromEnvelope, WireError } from './v1/errors.js';
import {
  Phase,
  SDK_CONTRACT_VERSION,
  LifecycleContainmentKind,
} from './v1/lifecycle-types.js';
import { TelemetryConfig } from './v1/types.js';

export {
  SDK_CONTRACT_VERSION,
};

// Wire-format cross-cutting fields that live at the envelope's top level.
// Runtime proxy authoring is normalized from WSLC exec `network.runtimeConfig`
// before these fields are lifted. Remaining config is backend-specific and is
// nested under `<backendSection>.<phase>`.
export const CROSS_CUTTING_FIELDS = ['filesystem', 'network', 'runtimeConfig', 'ui', 'process', 'telemetry'] as const;

// Per-backend wire-format prefix. Each value mirrors the corresponding
// Rust `<Backend>Runner::ID_PREFIX` const and is the leading segment of a
// `sandboxId` produced by that backend. Each future state-aware backend
// declares its own `<BACKEND>_ID_PREFIX` const here.
export const ISOLATION_SESSION_ID_PREFIX = 'iso';
export const WSLC_ID_PREFIX = 'wslc';
export const WINDOWS_SANDBOX_ID_PREFIX = 'wsb';

// Exhaustive backend→prefix map. Typed `Record<LifecycleContainmentKind,
// string>` so adding a backend to the union without registering a prefix here
// is a compile error — the same exhaustiveness guarantee the config, metadata,
// and default-version registries carry. Without it a new backend would compile
// with no prefix and fail every non-provision call at runtime with
// `malformed_id`.
export const BACKEND_TO_PREFIX: Record<LifecycleContainmentKind, string> = {
  isolation_session: ISOLATION_SESSION_ID_PREFIX,
  wslc: WSLC_ID_PREFIX,
};

// Reverse lookup (prefix → backend), derived from the exhaustive map above so
// the two can never drift. Used to route a sandboxId's leading prefix segment
// to its wire-format backend key.
export const PREFIX_TO_BACKEND: Record<string, LifecycleContainmentKind> = Object.fromEntries(
  (Object.entries(BACKEND_TO_PREFIX) as [LifecycleContainmentKind, string][]).map(
    ([backend, prefix]) => [prefix, backend],
  ),
);

/**
 * Resolves the wire-format backend key for a sandbox id by reading its
 * leading prefix segment. Throws an `MxcError` with `code: 'malformed_id'`
 * when the id has no recognised prefix, and `code: 'unsupported_containment'`
 * for a Windows Sandbox (`wsb:`) id, which the stable API does not accept.
 */
export function backendForSandboxId(sandboxId: string): LifecycleContainmentKind {
  const colon = sandboxId.indexOf(':');
  if (colon < 0) {
    throw mxcErrorFromCode('malformed_id', `sandboxId must carry a backend prefix: ${sandboxId}`);
  }
  const prefix = sandboxId.slice(0, colon);
  if (prefix === WINDOWS_SANDBOX_ID_PREFIX) {
    throw mxcErrorFromCode(
      'unsupported_containment',
      'Windows Sandbox identities are experimental and are not accepted by ' +
      'the stable high-level lifecycle API; use raw JSON with experimental ' +
      'authorization.',
    );
  }
  const backend = PREFIX_TO_BACKEND[prefix];
  if (!backend) {
    throw mxcErrorFromCode('malformed_id', `sandboxId prefix '${prefix}' does not match a known state-aware backend`);
  }
  return backend;
}

export interface BuildEnvelopeArgs {
  phase: Phase;
  backendKey: LifecycleContainmentKind;
  containment?: LifecycleContainmentKind; // provision only
  sandboxId?: string;                        // non-provision only
  config?: Record<string, unknown>;
}

/**
 * Constructs the wire-format JSON-shaped envelope for a state-aware request
 * from a per-(backend, phase) Config. Lifts cross-cutting fields
 * (filesystem, network, runtimeConfig, ui, process, telemetry) to envelope top-level; nests any
 * remaining backend-specific fields under the backend's permanent top-level
 * section.
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
  // Anything left becomes <backendSection>.<phase>.
  const backendSpecific: Record<string, unknown> = { ...(config ?? {}) };
  const telemetry = backendSpecific.telemetry as TelemetryConfig | undefined;
  if ('version' in backendSpecific) {
    throw mxcErrorFromCode(
      'malformed_request',
      `State-aware high-level requests do not accept a caller-selected version; ` +
      `the v1 SDK targets exact contract ${SDK_CONTRACT_VERSION}.`,
    );
  }
  const version = SDK_CONTRACT_VERSION;

  const fail = (message: string): never => {
    throw mxcErrorFromCode('malformed_request', message);
  };
  if ('runtimeConfig' in backendSpecific) {
    fail('runtimeConfig must be authored as network.runtimeConfig on WSLC exec.');
  }
  const network = backendSpecific.network;
  if (network !== undefined) {
    const isProvisionNetwork = phase === 'provision'
      && (backendKey === 'wslc' || backendKey === 'isolation_session');
    const isWslcExecNetwork = phase === 'exec' && backendKey === 'wslc';
    if (!isProvisionNetwork && !isWslcExecNetwork) {
      fail(`network is not accepted on ${backendKey} ${phase}.`);
    }
    if (network === null || typeof network !== 'object' || Array.isArray(network)) {
      fail('network must be an object.');
    }
    for (const key of Object.keys(network as object)) {
      const validKey = isWslcExecNetwork
        ? key === 'runtimeConfig'
        : key === 'egress' || key === 'ingress';
      if (!validKey) {
        fail(`Schema ${version} does not support network.${key} on ${backendKey} ${phase}.`);
      }
    }
    if (isWslcExecNetwork) {
      backendSpecific.runtimeConfig = (network as { runtimeConfig?: unknown }).runtimeConfig;
      delete backendSpecific.network;
    } else if (backendKey === 'isolation_session') {
      const directional = network as {
        egress?: { default?: unknown; allow?: unknown; deny?: unknown };
        ingress?: { default?: unknown; hostLoopback?: unknown };
      };
      if (
        directional.egress?.default !== 'allow'
        || directional.egress.allow !== undefined
        || directional.egress.deny !== undefined
        || directional.ingress?.default !== 'allow'
        || directional.ingress.hostLoopback !== 'allow'
      ) {
        fail('IsolationSession requires network egress, ingress, and hostLoopback defaults set to allow, with no rules.');
      }
    }
  }
  const runtime = backendSpecific.runtimeConfig;
  if (runtime !== undefined) {
    if (backendKey !== 'wslc' || phase !== 'exec') {
      fail(`network.runtimeConfig is accepted only on WSLC exec, not ${backendKey} ${phase}.`);
    }
    if (runtime === null || typeof runtime !== 'object' || Array.isArray(runtime)) {
      fail('network.runtimeConfig must be an object.');
    }
    for (const [key, value] of Object.entries(runtime as object)) {
      if (key !== 'networkProxy') {
        fail(`Unknown network.runtimeConfig.${key}.`);
      }
      if (value === undefined) continue;
      if (typeof value !== 'string' || value.trim() !== value || !value) {
        fail('network.runtimeConfig.networkProxy must be an HTTP/S URL string.');
      }
      let url!: URL;
      try {
        url = new URL(value as string);
      } catch {
        fail('network.runtimeConfig.networkProxy must be an HTTP/S URL string.');
      }
      if (!['http:', 'https:'].includes(url.protocol)) {
        fail('network.runtimeConfig.networkProxy must use HTTP or HTTPS.');
      }
    }
  }
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
    }
    delete backendSpecific[field];
  }

  if (Object.keys(backendSpecific).length > 0) {
    const backendSection = {
      isolation_session: 'isolationSession',
      wslc: 'wslc',
    }[backendKey];
    envelope[backendSection] = { [phase]: backendSpecific };
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
