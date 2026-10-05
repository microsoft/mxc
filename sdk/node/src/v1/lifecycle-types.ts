// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

import {
  ContainmentBackend,
  FilesystemConfig,
  DirectionalNetworkConfig,
  NetworkRuntimeConfig,
  ProcessConfig,
  ExecutionResult,
  TelemetryConfig,
} from './types.js';

/**
 * Lifecycle phase in a lifecycle request.
 */
export type Phase = 'provision' | 'start' | 'exec' | 'stop' | 'deprovision';

/**
 * Subset of `ContainmentBackend` that supports persistent containers.
 */
export type LifecycleContainmentKind = Extract<
  ContainmentBackend,
  'isolation_session' | 'wslc'
>;

/**
 * Branded container identifier returned by `provisionContainer` and routed back
 * to the same backend by subsequent phases. The runtime value is a plain
 * string; the brand exists at compile time only — TypeScript prevents
 * callers from passing a bare string, or a `ContainerId` from one backend
 * where one for a different backend is expected.
 */
export type ContainerId<C extends LifecycleContainmentKind = LifecycleContainmentKind> =
  string & { readonly __mxcBrand: 'ContainerId'; readonly __mxcBackend: C };

/** SDK-owned exact contract used by all typed lifecycle requests. */
export { SDK_CONTRACT_VERSION } from './contract-version.js';

interface LifecycleConfig {
  /** Optional telemetry request for this phase. */
  telemetry?: TelemetryConfig;
}

// IsolationSession per-(backend, phase) Configs. Each declares only
// the fields the SDK currently exposes at that phase — scoped to
// what the backend honors per the policy honor matrix and currently
// implements. TypeScript rejects passing fields outside this set.

export interface IsolationSessionProvisionConfig extends LifecycleConfig {
  /**
   * Required unrestricted network posture. All three directional axes must be
   * explicitly `allow`; rules, proxies, mixed postures, and legacy fields are
   * rejected. The posture is fixed at provision.
   */
  network: IsolationSessionNetworkConfig;
  /**
   * Optional identifier for the calling application.
   *
   * **A packaged application must supply its Package Family Name in the form
   * `PFN:<packageFamilyName>`** — the literal `PFN:` prefix followed by the
   * PFN, e.g. `PFN:Contoso.App_8wekyb3d8bbwe`. An unpackaged application may 
   * pass any string — MXC does not interpret or verify it. Carried verbatim
   * inside the returned `ContainerId` so later lifecycle phases can recover it
   * without the caller re-supplying it.
   *
   * Validated structurally only: no control characters, at most 256
   * characters. Whitespace and case are preserved exactly. An explicitly
   * supplied empty string is a **distinct** value from omitting the field and
   * round-trips as such. Rejections
   * surface as `MxcError` with `code: 'policy_validation'`.
   *
   * Provision-phase only — it is fixed for the container's lifetime and is not
   * accepted on any later phase.
   */
  appId?: string;
}

/** The only network posture IsolationSession can truthfully provide. */
export interface IsolationSessionNetworkConfig {
  egress: {
    default: 'allow';
    allow?: never;
    deny?: never;
  };
  ingress: {
    default: 'allow';
    hostLoopback: 'allow';
  };
}

export type IsolationSessionStartConfig = LifecycleConfig;

export interface IsolationSessionExecuteConfig extends LifecycleConfig {
  process: ProcessConfig;
}

export type IsolationSessionStopConfig = LifecycleConfig;

export type IsolationSessionDeprovisionConfig = LifecycleConfig;

/**
 * IsolationSession's provision-phase metadata surfaced to the caller: the
 * per-instance agent user account name minted for this container, the agent
 * user's SID, and the ephemeral workspace directory shared between the caller
 * and this isolated user (through which the caller can stage files into the
 * session; deleted when the container is deprovisioned).
 */
export interface IsolationSessionProvisionMetadata {
  agentUserName: string;
  agentUserSid: string;
  ephemeralWorkspacePath: string;
}

// WSLc per-(backend, phase) configs. WSLc runs each container as a warm
// container behind a persistent host-side daemon (one amortized WSL session
// shared across containers). Filesystem mounts and network mode are applied at
// provision and frozen for the container's lifetime; a cooperative env-var proxy
// may be injected for each execution.

export interface WslcProvisionConfig extends LifecycleConfig {
  /**
   * Filesystem policy applied at provision and frozen for the life of the
   * container. `readwritePaths` / `readonlyPaths` become container volume mounts
   * at the same absolute host path. The backend runs the same object-identity
   * normalization + delegation gate as the container request API and rejects a
   * `deniedPaths` entry equal to or nested within a mounted share (WSLc has no
   * Deny mount primitive) with `code: 'policy_validation'`.
   */
  filesystem?: FilesystemConfig;
  /**
   * Network mode applied at provision and frozen thereafter. All three axes
   * (`egress.default`, `ingress.default`, `ingress.hostLoopback`) must be
   * `'allow'` for a bridged container, or `'deny'` (the omitted default)
   * for an isolated container. Mixed postures and filtering rules cannot
   * be enforced and are rejected. Cooperative proxy injection is an execution-phase concern
   * (see {@link WslcExecuteConfig.network}).
   */
  network?: DirectionalNetworkConfig;
  /**
   * Container image reference (e.g. `alpine:latest`). Defaults to
   * `alpine:latest` when omitted. Nested under
   * `wslc.provision.image` on the wire.
   */
  image?: string;
  /**
   * Path to a local image tarball to import instead of pulling. Nested under
   * `wslc.provision.imageTarPath` on the wire.
   */
  imageTarPath?: string;
}

export type WslcStartConfig = LifecycleConfig;

export interface WslcExecuteConfig extends LifecycleConfig {
  process: ProcessConfig;
  /**
   * Per-execution runtime values. `networkProxy` injects a
   * cooperative `HTTP_PROXY` / `HTTPS_PROXY` into the command's environment
   * (well-behaved HTTP clients honor it; raw-socket clients can bypass it).
   * Supply an HTTP/S URL reachable from the guest. Provision policy is fixed;
   * this network object accepts runtime settings only.
   */
  network?: ProcessNetworkConfig;
}

export type WslcStopConfig = LifecycleConfig;

export type WslcDeprovisionConfig = LifecycleConfig;

/**
 * The five per-phase Config slots every lifecycle backend must declare.
 * `object` (not `Record<string, unknown>`) is the slot base: interfaces have
 * no implicit index signature, so a `Record<string, unknown>` base would
 * reject the interface-typed phase configs.
 */
type LifecyclePhaseConfigs = Record<Phase, object>;

/**
 * Identity helper that constrains the registry literal to declare an entry for
 * **every** `LifecycleContainmentKind`. Adding a backend to the union
 * without a registry entry below is a compile error here (the literal no
 * longer satisfies `Record<LifecycleContainmentKind, …>`), rather than
 * silently widening `ConfigsForBackend` to the slot base / `never`.
 */
type DefineLifecycleConfigRegistry<
  T extends Record<LifecycleContainmentKind, LifecyclePhaseConfigs>,
> = T;

/**
 * Closed per-backend per-phase Config registry. Keyed by backend; each entry
 * names the concrete Config interface for each phase.
 */
type LifecycleConfigRegistry = DefineLifecycleConfigRegistry<{
  isolation_session: {
    provision: IsolationSessionProvisionConfig;
    start: IsolationSessionStartConfig;
    exec: IsolationSessionExecuteConfig;
    stop: IsolationSessionStopConfig;
    deprovision: IsolationSessionDeprovisionConfig;
  };
  wslc: {
    provision: WslcProvisionConfig;
    start: WslcStartConfig;
    exec: WslcExecuteConfig;
    stop: WslcStopConfig;
    deprovision: WslcDeprovisionConfig;
  };
}>;

/** Compile-time guard: catches a backend with no registry entry. */
type Assert<T extends true> = T;
type _RegistryCoversAllBackends = Assert<
  [LifecycleContainmentKind] extends [keyof LifecycleConfigRegistry] ? true : false
>;

/**
 * Per-backend per-phase typed Config bundle. Selects the correct Config
 * bundle for the backend type parameter.
 */
export type ConfigsForBackend<C extends LifecycleContainmentKind> =
  LifecycleConfigRegistry[C];

export type ProvisionConfigFor<C extends LifecycleContainmentKind> =
  ConfigsForBackend<C>['provision'];

/**
 * True when every member of `T` is optional — i.e. `{}` is a valid value.
 *
 * Applied to a single config type. For a possibly-union backend see
 * {@link EveryBackendConfigIsOptional}, which is what `provisionContainer`
 * actually uses.
 */
export type HasNoRequiredMembers<T> = Record<string, never> extends T ? true : false;

/**
 * True only when **every** backend in `C` has an all-optional provision config.
 *
 * `provisionContainer` uses this to require its config argument exactly when the
 * selected backend needs one. The rule is derived from the types rather than an
 * enumerated list of backends, so a future backend gaining or losing a required
 * member is handled automatically.
 *
 * The `[C] extends [never]` shape is deliberate and is the whole point of this
 * type. `C` is not always a single literal — a caller holding a variable typed
 * as the full `LifecycleContainmentKind` union instantiates it with that
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
 * not enforce. IsolationSession depends on it because its unrestricted
 * `network` posture is mandatory.
 */
export type EveryBackendConfigIsOptional<C extends LifecycleContainmentKind> =
  [C extends unknown ? (HasNoRequiredMembers<ProvisionConfigFor<C>> extends true ? never : C) : never] extends [never]
    ? true
    : false;
export type StartConfigFor<C extends LifecycleContainmentKind> =
  ConfigsForBackend<C>['start'];
export type ExecuteConfigFor<C extends LifecycleContainmentKind> =
  ConfigsForBackend<C>['exec'];

/** Closed backend-specific request for provisioning a container. */
export type ProvisionRequest<C extends LifecycleContainmentKind = LifecycleContainmentKind> =
  C extends LifecycleContainmentKind
    ? ProvisionConfigFor<C> & { containment: C }
    : never;

/** Process settings for a workload in an existing container. */
export interface ExecutionRequest<C extends LifecycleContainmentKind = LifecycleContainmentKind> {
  command: string;
  workingDirectory?: string;
  environment?: Record<string, string>;
  inheritDefaultEnvironment?: boolean;
  timeoutMs?: number;
  /** Runtime-only network settings; provision policy remains fixed. */
  network?: C extends 'wslc' ? ProcessNetworkConfig : never;
  telemetry?: TelemetryConfig;
}

/** Runtime network values accepted by existing-container execution. */
export interface ProcessNetworkConfig {
  runtimeConfig?: NetworkRuntimeConfig;
}
export type StopConfigFor<C extends LifecycleContainmentKind> =
  ConfigsForBackend<C>['stop'];
export type DeprovisionConfigFor<C extends LifecycleContainmentKind> =
  ConfigsForBackend<C>['deprovision'];

/**
 * Identity helper that constrains the metadata registry literal to declare an
 * entry for **every** `LifecycleContainmentKind`. A future backend added to
 * the union without a metadata entry below is a compile error here, symmetric
 * to `DefineLifecycleConfigRegistry`.
 */
type DefineContainerMetadataRegistry<
  T extends Record<LifecycleContainmentKind, object>,
> = T;

/**
 * Per-backend per-phase metadata bundle. Backends that don't return metadata
 * for a given phase omit that phase key; backends that return no metadata at
 * all use `Record<never, never>` (so `ProvisionMetadata<C>` resolves to
 * `undefined`). Keyed by backend; every backend must declare an entry.
 */
export type ContainerMetadata = DefineContainerMetadataRegistry<{
  isolation_session: {
    provision?: IsolationSessionProvisionMetadata;
    // IsolationSession returns no metadata for start, stop, or deprovision.
  };
  // WSLc returns no metadata for any phase (provision yields only the sandbox
  // id). `Record<never, never>` has `keyof = never`, so
  // `ProvisionMetadata<'wslc'>` resolves to `undefined`.
  wslc: Record<never, never>;
  // Future lifecycle-capable backends add typed entries here.
}>;

/** Compile-time guard: catches a backend with no metadata registry entry. */
type _MetadataRegistryCoversAllBackends = Assert<
  [LifecycleContainmentKind] extends [keyof ContainerMetadata] ? true : false
>;

type MetadataForPhase<C extends LifecycleContainmentKind, Phase extends string> =
  Phase extends keyof ContainerMetadata[C]
    ? ContainerMetadata[C][Phase]
    : undefined;

/** Backend-specific metadata returned by provisioning. */
export type ProvisionMetadata<C extends LifecycleContainmentKind = LifecycleContainmentKind> =
  C extends LifecycleContainmentKind ? MetadataForPhase<C, 'provision'> : never;

/** Warnings returned by validating an operation without executing it. */
export interface ValidationResult {
  warnings: string[];
}

export interface ProvisionResult<C extends LifecycleContainmentKind> {
  containerId: ContainerId<C>;
  metadata?: ProvisionMetadata<C>;
  warnings: string[];
}

/** Warnings returned by starting, stopping, or deprovisioning a container. */
export interface LifecycleResult {
  warnings: string[];
}

export type ExecuteResult = ExecutionResult;
