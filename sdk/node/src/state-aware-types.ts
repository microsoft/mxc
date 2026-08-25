// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

import {
  ContainmentBackend,
  FilesystemConfig,
  NetworkConfig,
  PortMapping,
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
  'isolation_session' | 'windows_sandbox' | 'wslc'
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

// IsolationSession per-(backend, phase) Configs. Each declares only
// the fields the SDK currently exposes at that phase — scoped to
// what the backend honors per the policy honor matrix and currently
// implements. TypeScript rejects passing fields outside this set.

export interface IsolationSessionProvisionConfig {
  /** Schema version (semver). When omitted, the SDK fills in its own SUPPORTED_VERSION. */
  version?: string;
  /**
   * Optional identifier for the calling application.
   *
   * **A packaged application must supply its Package Family Name in the form
   * `PFN:<packageFamilyName>`** — the literal `PFN:` prefix followed by the
   * PFN, e.g. `PFN:Contoso.App_8wekyb3d8bbwe`. An unpackaged application may 
   * pass any string — MXC does not interpret or verify it. Carried verbatim
   * inside the returned `SandboxId` so later lifecycle phases can recover it
   * without the caller re-supplying it.
   *
   * Validated structurally only: no control characters, at most 256
   * characters. Whitespace and case are preserved exactly. An explicitly
   * supplied empty string is a **distinct** value from omitting the field and
   * round-trips as such. Rejections
   * surface as `MxcError` with `code: 'policy_validation'`.
   *
   * Provision-phase only — it is fixed for the sandbox's lifetime and is not
   * accepted on any later phase.
   */
  appId?: string;
  /**
   * Unrestricted-network acknowledgment (**required**). The isolation session
   * container runs on a network MXC cannot filter or deny — outbound is open,
   * and a process inside can listen on a port reachable from outside via
   * localhost. The caller must explicitly acknowledge this; the ONLY accepted
   * value is `{ defaultPolicy: 'allow', allowLocalNetwork: true }`. Any other
   * network policy (including omission, which the backend treats as the
   * unenforceable default-deny) is rejected at provision. The posture is fixed
   * at provision, so `network` is not accepted on the post-provision phases.
   */
  network: { defaultPolicy: 'allow'; allowLocalNetwork: true };
}

export interface IsolationSessionStartConfig {
  /** Schema version (semver). */
  version?: string;
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
 * IsolationSession's provision-phase metadata surfaced to the caller: the
 * per-instance agent user account name minted for this sandbox, the agent
 * user's SID, and the ephemeral workspace directory shared between the caller
 * and this isolated user (through which the caller can stage files into the
 * session; deleted when the sandbox is deprovisioned).
 */
export interface IsolationSessionProvisionMetadata {
  agentUserName: string;
  agentUserSid: string;
  ephemeralWorkspacePath: string;
}

// WindowsSandbox per-(backend, phase) Configs. WindowsSandbox holds a single
// active sandbox behind a persistent host-side daemon. Filesystem policy
// (readwrite/readonly/denied HOST paths) is honored at provision and is
// immutable thereafter.

export interface WindowsSandboxProvisionConfig {
  /** Schema version (semver). When omitted, the SDK fills in its own SUPPORTED_VERSION. */
  version?: string;
  /**
   * Filesystem policy applied at provision and frozen for the life of the
   * sandbox. `readwritePaths` / `readonlyPaths` are mapped into the guest at
   * the same absolute host path; `deniedPaths` name HOST paths the contained
   * code must not reach. The SDK forwards this policy as-is; the backend
   * enforces it at provision and rejects a `deniedPaths` entry equal to or
   * nested within a mapped share (`.wsb` has no Deny primitive).
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

// WSLc per-(backend, phase) Configs. WSLc runs each sandbox as a warm
// container behind a persistent host-side daemon (one amortized WSL session
// shared across sandboxes). Filesystem mounts and network mode are applied at
// provision and frozen for the sandbox's lifetime; a cooperative env-var proxy
// may be injected per-exec.

export interface WslcProvisionConfig {
  /** Schema version (semver). When omitted, the SDK fills in `0.8.0-alpha`. */
  version?: string;
  /**
   * Filesystem policy applied at provision and frozen for the life of the
   * sandbox. `readwritePaths` / `readonlyPaths` become container volume mounts
   * at the same absolute host path. The backend runs the same object-identity
   * normalization + delegation gate as the one-shot runner and rejects a
   * `deniedPaths` entry equal to or nested within a mounted share (WSLc has no
   * Deny mount primitive) with `code: 'policy_validation'`.
   */
  filesystem?: FilesystemConfig;
  /**
   * Network mode applied at provision and frozen thereafter. Only
   * `defaultPolicy` is honored: `'allow'` provisions a bridged container,
   * `'block'` (the default when omitted) provisions with no network. Per-host
   * filtering (`allowedHosts` / `blockedHosts`) and a `proxy` are rejected at
   * provision (`code: 'policy_validation'`) — WSLc has no in-kernel iptables,
   * and the cooperative proxy is an exec-phase concern (see
   * {@link WslcExecConfig.network}).
   */
  network?: NetworkConfig;
  /**
   * Container image reference (e.g. `alpine:latest`). Defaults to
   * `alpine:latest` when omitted. Nested under
   * `experimental.wslc.provision.image` on the wire.
   */
  image?: string;
  /**
   * Path to a local image tarball to import instead of pulling. Nested under
   * `experimental.wslc.provision.imageTarPath` on the wire.
   */
  imageTarPath?: string;
  /**
   * Host -> container port mappings, applied at provision and fixed for the
   * life of the sandbox. Only TCP is supported: `protocol` defaults to `"tcp"`
   * and `"udp"` is rejected. Nested under
   * `experimental.wslc.provision.portMappings` on the wire.
   */
  portMappings?: PortMapping[];
}

export interface WslcStartConfig {
  /** Schema version (semver). */
  version?: string;
}

export interface WslcExecConfig {
  /** Schema version (semver). */
  version?: string;
  process: ProcessConfig;
  /**
   * Per-exec network overrides. Only `proxy` is honored: it injects a
   * cooperative `HTTP_PROXY` / `HTTPS_PROXY` into the command's environment
   * (well-behaved HTTP clients honor it; raw-socket clients can bypass it).
   * WSLc accepts only the `{ url }` proxy form — its containers run in their
   * own network namespace, so the `localhost` / `builtinTestServer` loopback
   * forms are unreachable and rejected. Every other network field — host
   * filters, a `defaultPolicy` change, and `allowLocalNetwork` — is rejected
   * with `code: 'policy_validation'` (network mode is fixed at provision).
   */
  network?: NetworkConfig;
}

export interface WslcStopConfig {
  /** Schema version (semver). */
  version?: string;
}

export interface WslcDeprovisionConfig {
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
  wslc: {
    provision: WslcProvisionConfig;
    start: WslcStartConfig;
    exec: WslcExecConfig;
    stop: WslcStopConfig;
    deprovision: WslcDeprovisionConfig;
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

/**
 * True when every member of `T` is optional — i.e. `{}` is a valid value.
 *
 * Applied to a single config type. For a possibly-union backend see
 * {@link EveryBackendConfigIsOptional}, which is what `provisionSandbox`
 * actually uses.
 */
export type HasNoRequiredMembers<T> = Record<string, never> extends T ? true : false;

/**
 * True only when **every** backend in `C` has an all-optional provision config.
 *
 * `provisionSandbox` uses this to require its config argument exactly when the
 * selected backend needs one. The rule is derived from the types rather than an
 * enumerated list of backends, so a future backend gaining or losing a required
 * member is handled automatically.
 *
 * The `[C] extends [never]` shape is deliberate and is the whole point of this
 * type. `C` is not always a single literal — a caller holding a variable typed
 * as the full `StateAwareContainmentBackend` union instantiates it with that
 * union. Asking `HasNoRequiredMembers` about the *union* of configs answers
 * "yes" as soon as any one member is all-optional, because `{}` is assignable
 * to that member — which would make the config optional for every backend,
 * including the ones that require it. Instead this distributes over `C`, keeps
 * only the backends that DO require a config, and reports "all optional" only
 * when that set is empty. A union backend therefore behaves like its strictest
 * member, which is the safe direction.
 *
 * Without this, a required field could be bypassed by omitting the whole
 * argument — the config type would advertise a guarantee the call signature did
 * not enforce. IsolationSession depends on it: its unrestricted-network
 * acknowledgment is mandatory, and the backend refuses a provision without it.
 */
export type EveryBackendConfigIsOptional<C extends StateAwareContainmentBackend> =
  [C extends unknown ? (HasNoRequiredMembers<ProvisionConfigFor<C>> extends true ? never : C) : never] extends [never]
    ? true
    : false;
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
  // WSLc returns no metadata for any phase (provision yields only the sandbox
  // id). `Record<never, never>` has `keyof = never`, so every
  // `*MetadataFor<'wslc'>` resolves to `undefined`.
  wslc: Record<never, never>;
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
