// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

// Exact one-shot wire conformance oracle. The generated v0.10 module comes
// from the authoritative Rust contract; these assertions keep the handwritten
// SDK surface aligned with that contract while documenting SDK-only
// compatibility conveniences.

import { test } from 'node:test';

import type {
  BaseProcessUiConfig,
  ClipboardPolicy,
  ContainerConfig,
  ContainmentBackend,
  ContainmentType,
  FilesystemConfig,
  LifecycleConfig,
  LxcConfig,
  NetworkAction,
  NetworkConfig,
  NetworkEgressConfig,
  NetworkIngressConfig,
  NetworkPeerConfig,
  NetworkPortConfig,
  NetworkProtocol,
  NetworkRuleConfig,
  PortMapping,
  ProcessConfig,
  ProcessContainerConfig,
  RuntimeConfig,
  SeatbeltConfig,
  TelemetryConfig,
  UiConfig,
  WslcConfig,
} from '../../src/types.js';

import type {
  Filesystem as WireFilesystem,
  Lifecycle as WireLifecycle,
  Lxc as WireLxc,
  Network as WireNetwork,
  NetworkAction as WireNetworkAction,
  NetworkEgress as WireNetworkEgress,
  NetworkIngress as WireNetworkIngress,
  NetworkPeer as WireNetworkPeer,
  NetworkPort as WireNetworkPort,
  NetworkProtocol as WireNetworkProtocol,
  NetworkRule as WireNetworkRule,
  OneShotContainment as WireContainment,
  OneShotRequest as WireRequest,
  OneShotWslc as WireWslc,
  PortMapping as WirePortMapping,
  Process as WireProcess,
  ProcessContainer as WireProcessContainer,
  ProcessContainerUi as WireProcessContainerUi,
  ProcessContainerUiIsolation as WireUiIsolation,
  RuntimeConfig as WireRuntimeConfig,
  Seatbelt as WireSeatbelt,
  Telemetry as WireTelemetry,
  TransportProtocol as WireTransportProtocol,
  Ui as WireUi,
  UiClipboard as WireClipboard,
} from '../../src/generated/v0_10_0_alpha/wire.js';

import type {
  AssertTrue,
  Assignable,
  Equivalent,
  OnlyInPublic,
  OnlyInWire,
} from './conformance-helpers.js';

type _Clipboard = AssertTrue<Equivalent<ClipboardPolicy, WireClipboard>>;
type _Containment = AssertTrue<
  Equivalent<
    ContainmentType | ContainmentBackend,
    Exclude<WireContainment, 'appcontainer' | 'macos_sandbox'>
  >
>;
type _NetworkAction = AssertTrue<Equivalent<NetworkAction, WireNetworkAction>>;
type _NetworkProtocol = AssertTrue<Equivalent<NetworkProtocol, WireNetworkProtocol>>;
type _UiIsolation = AssertTrue<
  Equivalent<NonNullable<BaseProcessUiConfig['isolation']>, WireUiIsolation>
>;
type _PortProtocol = AssertTrue<
  Equivalent<NonNullable<PortMapping['protocol']>, WireTransportProtocol>
>;

type _ProcessValues = AssertTrue<Assignable<ProcessConfig, WireProcess>>;
type _LifecycleValues = AssertTrue<Assignable<LifecycleConfig, WireLifecycle>>;
type _FilesystemValues = AssertTrue<Assignable<FilesystemConfig, WireFilesystem>>;
type _NetworkValues = AssertTrue<Assignable<NetworkConfig, WireNetwork>>;
type _NetworkEgressValues = AssertTrue<Assignable<NetworkEgressConfig, WireNetworkEgress>>;
type _NetworkIngressValues = AssertTrue<Assignable<NetworkIngressConfig, WireNetworkIngress>>;
type _NetworkPeerValues = AssertTrue<Assignable<NetworkPeerConfig, WireNetworkPeer>>;
type _NetworkPortValues = AssertTrue<Assignable<NetworkPortConfig, WireNetworkPort>>;
type _NetworkRuleValues = AssertTrue<Assignable<NetworkRuleConfig, WireNetworkRule>>;
type _RuntimeValues = AssertTrue<Assignable<RuntimeConfig, WireRuntimeConfig>>;
type _UiValues = AssertTrue<Assignable<UiConfig, WireUi>>;
type _ProcessContainerValues = AssertTrue<
  Assignable<ProcessContainerConfig, WireProcessContainer>
>;
type _ProcessContainerUiValues = AssertTrue<
  Assignable<BaseProcessUiConfig, WireProcessContainerUi>
>;
type _WslcValues = AssertTrue<Assignable<WslcConfig, WireWslc>>;
type _PortMappingValues = AssertTrue<Assignable<PortMapping, WirePortMapping>>;
type _SeatbeltValues = AssertTrue<Assignable<SeatbeltConfig, WireSeatbelt>>;
type _TelemetryValues = AssertTrue<Assignable<TelemetryConfig, WireTelemetry>>;
type _ProcessKeys = AssertTrue<Equivalent<OnlyInPublic<ProcessConfig, WireProcess>, never>>;
type _LifecycleKeys = AssertTrue<Equivalent<OnlyInPublic<LifecycleConfig, WireLifecycle>, never>>;
type _FilesystemKeys = AssertTrue<
  Equivalent<OnlyInPublic<FilesystemConfig, WireFilesystem>, 'clearPolicyOnExit'>
>;
type _NetworkKeys = AssertTrue<
  Equivalent<
    OnlyInPublic<NetworkConfig, WireNetwork>,
    | 'enforcementMode'
    | 'defaultPolicy'
    | 'allowLocalNetwork'
    | 'allowedHosts'
    | 'blockedHosts'
    | 'proxy'
    | 'removeRulesOnExit'
  >
>;
type _ProcessContainerKeys = AssertTrue<
  Equivalent<OnlyInPublic<ProcessContainerConfig, WireProcessContainer>, 'name'>
>;
type _LxcKeys = AssertTrue<
  Equivalent<OnlyInPublic<LxcConfig, WireLxc>, 'containerName' | 'destroyOnExit'>
>;
type _RootKeys = AssertTrue<Equivalent<OnlyInPublic<ContainerConfig, WireRequest>, never>>;

type _NetworkWireKeys = AssertTrue<Equivalent<OnlyInWire<NetworkConfig, WireNetwork>, never>>;
type _WslcWireKeys = AssertTrue<Equivalent<OnlyInWire<WslcConfig, WireWslc>, never>>;
type _ProcessContainerWireKeys = AssertTrue<
  Equivalent<OnlyInWire<ProcessContainerConfig, WireProcessContainer>, 'captureDenials'>
>;
type _SeatbeltWireKeys = AssertTrue<
  Equivalent<OnlyInWire<SeatbeltConfig, WireSeatbelt>, 'guiAccess' | 'launchMethod'>
>;
type _RootWireKeys = AssertTrue<
  Equivalent<OnlyInWire<ContainerConfig, WireRequest>, '$schema' | '_comment' | 'fallback' | 'macos_sandbox'>
>;

export type WireConformanceAssertions = [
  _Clipboard,
  _Containment,
  _NetworkAction,
  _NetworkProtocol,
  _UiIsolation,
  _PortProtocol,
  _ProcessValues,
  _LifecycleValues,
  _FilesystemValues,
  _NetworkValues,
  _NetworkEgressValues,
  _NetworkIngressValues,
  _NetworkPeerValues,
  _NetworkPortValues,
  _NetworkRuleValues,
  _RuntimeValues,
  _UiValues,
  _ProcessContainerValues,
  _ProcessContainerUiValues,
  _WslcValues,
  _PortMappingValues,
  _SeatbeltValues,
  _TelemetryValues,
  _ProcessKeys,
  _LifecycleKeys,
  _FilesystemKeys,
  _NetworkKeys,
  _ProcessContainerKeys,
  _LxcKeys,
  _RootKeys,
  _NetworkWireKeys,
  _WslcWireKeys,
  _ProcessContainerWireKeys,
  _SeatbeltWireKeys,
  _RootWireKeys,
];

test('public SDK one-shot types conform to the exact development contract', () => {
  // Compile-time assertions above carry the guarantee.
});
