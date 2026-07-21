// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

import {
  ContainmentBackend,
  FilesystemConfig,
  ProcessConfig,
} from './types.js';

/**
 * Lifecycle phase in a state-aware sandbox request.
 */
export type Phase = 'provision' | 'start' | 'exec' | 'stop' | 'deprovision';

/**
 * Subset of `ContainmentBackend` whose backends participate in the state-aware
 * lifecycle. Extended as more backends opt in.
 */
export type StateAwareContainmentBackend = Extract<
  ContainmentBackend,
  'isolation_session' | 'windows_sandbox'
>;

/**
 * Branded sandbox identifier returned by `provisionSandbox` and routed back
 * to the same backend by subsequent phases. The runtime value is a plain
 * string; the brand exists at compile time only — TypeScript prevents
 * callers from passing a bare string, or a `SandboxId` from one backend
 * where one for a different backend is expected.
 */
export type SandboxId<C extends StateAwareContainmentBackend> =
  string & { readonly __mxcBrand: 'SandboxId'; readonly __mxcBackend: C };

const ISO_USER_INSPECT = Symbol.for('nodejs.util.inspect.custom');

/**
 * Entra credentials, supplied at provision to opt into an Entra-backed
 * sandbox and at start to authenticate the session. `wamToken` is treated
 * as a secret: `util.inspect` and `console.log` redact it. `JSON.stringify`
 * is unaffected — the wire envelope carries the token verbatim.
 */
export class IsolationSessionUserConfig {
  readonly upn: string;
  readonly wamToken: string;

  constructor(upn: string, wamToken: string) {
    this.upn = upn;
    this.wamToken = wamToken;
  }

  [ISO_USER_INSPECT](): string {
    return `IsolationSessionUserConfig { upn: '${this.upn}', wamToken: '<redacted>' }`;
  }
}

// IsolationSession per-(backend, phase) Configs. Each declares only
// the fields the SDK currently exposes at that phase — scoped to
// what the backend honors per the policy honor matrix and currently
// implements. TypeScript rejects passing fields outside this set.

export interface IsolationSessionProvisionConfig {
  /** Schema version (semver). When omitted, the SDK fills in its own SUPPORTED_VERSION. */
  version?: string;
  filesystem?: FilesystemConfig;
  /**
   * Optional Entra credentials. When supplied, provisioning uses the Entra
   * identity for the sandbox; the same `user` must be supplied to
   * `startSandbox`. Hosts that don't support this surface `backend_unavailable`.
   */
  user?: IsolationSessionUserConfig;
}

export interface IsolationSessionStartConfig {
  /** Schema version (semver). */
  version?: string;
  /**
   * Selected IsoSession size profile. Unknown values are warned and
   * downgraded to `'composable'` on the Rust side.
   */
  configurationId?: 'small' | 'medium' | 'large' | 'composable';
  /**
   * Entra credentials. Required when the sandbox was provisioned with a
   * `user` bundle; rejected otherwise. When required, `upn` must match the
   * UPN supplied at provision (case-insensitive).
   */
  user?: IsolationSessionUserConfig;
}

export interface IsolationSessionExecConfig {
  /** Schema version (semver). */
  version?: string;
  process: ProcessConfig;
}

export interface IsolationSessionStopConfig {
  /** Schema version (semver). */
  version?: string;
}

export interface IsolationSessionDeprovisionConfig {
  /** Schema version (semver). */
  version?: string;
}

/**
 * IsolationSession's provision-phase metadata: the per-instance agent user
 * account name minted for this sandbox.
 */
export interface IsolationSessionProvisionMetadata {
  agentUserName: string;
}

// WindowsSandbox per-(backend, phase) Configs. WindowsSandbox holds a single
// active sandbox behind a persistent host-side daemon. Unlike IsolationSession
// it has no Entra/`user` bundle. Filesystem policy (readwrite/readonly/denied
// HOST paths) is honored at provision and is immutable thereafter.

export interface WindowsSandboxProvisionConfig {
  /** Schema version (semver). When omitted, the SDK fills in its own SUPPORTED_VERSION. */
  version?: string;
  /**
   * Filesystem policy applied at provision and frozen for the life of the
   * sandbox. `readwritePaths` / `readonlyPaths` are mapped into the guest at
   * the same absolute host path; `deniedPaths` name HOST paths the contained
   * code must not reach. The SDK forwards this policy as-is; the backend
   * enforces it at provision and rejects a `deniedPath` equal to or nested
   * within a mapped share (`.wsb` has no Deny primitive).
   */
  filesystem?: FilesystemConfig;
}

export interface WindowsSandboxStartConfig {
  /** Schema version (semver). */
  version?: string;
}

export interface WindowsSandboxExecConfig {
  /** Schema version (semver). */
  version?: string;
  process: ProcessConfig;
}

export interface WindowsSandboxStopConfig {
  /** Schema version (semver). */
  version?: string;
}

export interface WindowsSandboxDeprovisionConfig {
  /** Schema version (semver). */
  version?: string;
}

/**
 * The five per-phase Config slots every state-aware backend must declare.
 * `object` (not `Record<string, unknown>`) is the slot base: interfaces have
 * no implicit index signature, so a `Record<string, unknown>` base would
 * spuriously reject `{ version?: string }`-shaped configs.
 */
type StateAwarePhaseConfigs = Record<Phase, object>;

/**
 * Identity helper that constrains the registry literal to declare an entry for
 * **every** `StateAwareContainmentBackend`. Adding a backend to the union
 * without a registry entry below is a compile error here (the literal no
 * longer satisfies `Record<StateAwareContainmentBackend, …>`), rather than
 * silently widening `ConfigsForBackend` to the slot base / `never`.
 */
type DefineStateAwareConfigRegistry<
  T extends Record<StateAwareContainmentBackend, StateAwarePhaseConfigs>,
> = T;

/**
 * Closed per-backend per-phase Config registry. Keyed by backend; each entry
 * names the concrete Config interface for each phase.
 */
type StateAwareConfigRegistry = DefineStateAwareConfigRegistry<{
  isolation_session: {
    provision: IsolationSessionProvisionConfig;
    start: IsolationSessionStartConfig;
    exec: IsolationSessionExecConfig;
    stop: IsolationSessionStopConfig;
    deprovision: IsolationSessionDeprovisionConfig;
  };
  windows_sandbox: {
    provision: WindowsSandboxProvisionConfig;
    start: WindowsSandboxStartConfig;
    exec: WindowsSandboxExecConfig;
    stop: WindowsSandboxStopConfig;
    deprovision: WindowsSandboxDeprovisionConfig;
  };
}>;

/** Compile-time guard: catches a backend with no registry entry. */
type Assert<T extends true> = T;
type _RegistryCoversAllBackends = Assert<
  [StateAwareContainmentBackend] extends [keyof StateAwareConfigRegistry] ? true : false
>;

/**
 * Per-backend per-phase typed Config bundle. Selects the correct Config
 * bundle for the backend type parameter.
 */
export type ConfigsForBackend<C extends StateAwareContainmentBackend> =
  StateAwareConfigRegistry[C];

export type ProvisionConfigFor<C extends StateAwareContainmentBackend> =
  ConfigsForBackend<C>['provision'];
export type StartConfigFor<C extends StateAwareContainmentBackend> =
  ConfigsForBackend<C>['start'];
export type ExecConfigFor<C extends StateAwareContainmentBackend> =
  ConfigsForBackend<C>['exec'];
export type StopConfigFor<C extends StateAwareContainmentBackend> =
  ConfigsForBackend<C>['stop'];
export type DeprovisionConfigFor<C extends StateAwareContainmentBackend> =
  ConfigsForBackend<C>['deprovision'];

/**
 * Identity helper that constrains the metadata registry literal to declare an
 * entry for **every** `StateAwareContainmentBackend`. A future backend added to
 * the union without a metadata entry below is a compile error here, symmetric
 * to `DefineStateAwareConfigRegistry`.
 */
type DefineStateAwareMetadataRegistry<
  T extends Record<StateAwareContainmentBackend, object>,
> = T;

/**
 * Per-backend per-phase metadata bundle. Backends that don't return metadata
 * for a given phase omit that phase key; backends that return no metadata at
 * all use `Record<never, never>` (so every `*MetadataFor<C>` resolves to
 * `undefined`). Keyed by backend; every backend must declare an entry.
 */
export type StateAwareMetadata = DefineStateAwareMetadataRegistry<{
  isolation_session: {
    provision?: IsolationSessionProvisionMetadata;
    // IsolationSession returns no metadata for start, stop, or deprovision.
  };
  // WindowsSandbox returns no metadata for any phase (provision yields only the
  // sandbox id). The key still participates so `StateAwareMetadata[C]` type-
  // checks for `C = 'windows_sandbox'`. `Record<never, never>` has `keyof =
  // never`, so every `*MetadataFor<'windows_sandbox'>` resolves to `undefined`.
  windows_sandbox: Record<never, never>;
  // Future state-aware-capable backends add typed entries here.
}>;

/** Compile-time guard: catches a backend with no metadata registry entry. */
type _MetadataRegistryCoversAllBackends = Assert<
  [StateAwareContainmentBackend] extends [keyof StateAwareMetadata] ? true : false
>;

type MetadataForPhase<C extends StateAwareContainmentBackend, Phase extends string> =
  Phase extends keyof StateAwareMetadata[C]
    ? StateAwareMetadata[C][Phase]
    : undefined;

export type ProvisionMetadataFor<C extends StateAwareContainmentBackend> = MetadataForPhase<C, 'provision'>;
export type StartMetadataFor<C extends StateAwareContainmentBackend> = MetadataForPhase<C, 'start'>;
export type StopMetadataFor<C extends StateAwareContainmentBackend> = MetadataForPhase<C, 'stop'>;
export type DeprovisionMetadataFor<C extends StateAwareContainmentBackend> = MetadataForPhase<C, 'deprovision'>;

export interface ProvisionResult<C extends StateAwareContainmentBackend> {
  sandboxId: SandboxId<C>;
  metadata?: ProvisionMetadataFor<C>;
  /**
   * Correlation vector (MS-CV) seeded by the executor for this lifecycle when
   * experimental telemetry is enabled. Relay it verbatim as
   * {@link SandboxSpawnOptions.correlationVector} on every later phase so all
   * phases of the lifecycle share a telemetry base prefix. The client relays it
   * unchanged; the executor derives each phase's own vector from it (spinning a
   * mutable base or reseeding a missing/malformed value). Absent when telemetry
   * is not active.
   */
  correlationVector?: string;
}

export interface StartResult<C extends StateAwareContainmentBackend> {
  metadata?: StartMetadataFor<C>;
}

export interface StopResult<C extends StateAwareContainmentBackend> {
  metadata?: StopMetadataFor<C>;
}

export interface DeprovisionResult<C extends StateAwareContainmentBackend> {
  metadata?: DeprovisionMetadataFor<C>;
}

export interface ExecResult {
  stdout: string;
  stderr: string;
  exitCode: number;
}
