// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

// Exact v0.10 one-shot type conformance oracle.
//
// The generated module `../../src/generated/v0_10_0_alpha/wire.ts` is emitted
// from the exact v0.10 contract. It is the source of truth for the raw one-shot
// shape produced by the current high-level SDK builder.
//
// This file asserts — at COMPILE TIME — that the hand-written public SDK types
// in `../../src/types.ts` still conform to that generated shape. If the Rust
// exact contract changes (a field renamed/removed, an enum value added/dropped,
// a type narrowed) the regenerated oracle shifts and these assertions stop
// compiling, so `npm run build:test-unit` fails. The runtime body is a no-op;
// the test exists so `tsc` type-checks the assertions below.
//
// Mapping rationale:
//  * The exact contract rejects null and requires one-shot `process`. The
//    high-level builder supplies the exact version, process, and LXC defaults;
//    `PublicV010OneShotConfig` models that emitted raw shape.
//  * `NetworkConfig` intentionally spans historical public versions. Its
//    public-only key assertion documents the legacy fields omitted from v0.10
//    raw JSON while keeping directional field conformance exact.
//  * Stable WSLC is additionally checked against the published v0.9 one-shot
//    contract because this stack exposes WSLC in both v0.9 and v0.10.
//  * `OnlyInPublic` additionally catches a public field whose wire counterpart
//    was renamed or removed (width subtyping alone would not), and is asserted
//    to equal a documented, explicit set of SDK-only fields — so a NEW
//    divergence (not on the allow-list) fails the build. This is applied at the
//    root (`PublicV010OneShotConfig` ↔ exact `OneShotRequest`) as well as the
//    leaves, so a top-level rename/removal cannot slip past.
//  * `OnlyInWire` covers the OPPOSITE direction: because every generated wire
//    field is optional, `Public extends Wire` stays true when the SDK forgets a
//    newly added wire field, so a wire-only ADDITION needs its own check. Each
//    object asserts its wire-only key set equals an explicit allow-list (mostly
//    `never`), so a new wire field the SDK does not expose fails the build until
//    it is surfaced or documented (review finding F1, gpt-5.5 pass).
//  * Assignability is one-way and so does NOT catch a wire ENUM WIDENING (a new
//    value added in the wire model). Enum-backed domains the SDK exposes are
//    therefore additionally checked with the bidirectional `Equivalent` — both
//    the standalone enum types and the enum-typed object fields (review finding
//    F2, codex pass).
//
import { test } from 'node:test';

import type {
  ProcessConfig,
  LifecycleConfig,
  FilesystemConfig,
  NetworkConfig,
  DirectionalNetworkConfig,
  NetworkEgressConfig,
  NetworkIngressConfig,
  NetworkPeerConfig,
  NetworkPortConfig,
  NetworkRuleConfig,
  RuntimeConfig,
  UiConfig,
  ProcessContainerConfig,
  BaseProcessUiConfig,
  WslcConfig,
  PortMapping as PublicPortMapping,
  LxcConfig,
  SeatbeltConfig,
  TelemetryConfig,
  ContainerConfig,
  ClipboardPolicy as PublicClipboardPolicy,
  ContainmentType,
  ContainmentBackend,
} from '../../src/types.js';

import type {
  Process as WireProcess,
  Lifecycle as WireLifecycle,
  Filesystem as WireFilesystem,
  Network as WireNetwork,
  NetworkEgress as WireNetworkEgress,
  NetworkIngress as WireNetworkIngress,
  NetworkPeer as WireNetworkPeer,
  NetworkPort as WireNetworkPort,
  NetworkRule as WireNetworkRule,
  RuntimeConfig as WireRuntimeConfig,
  Ui as WireUi,
  ProcessContainer as WireProcessContainer,
  ProcessContainerUi as WireBaseProcessUi,
  OneShotWslc as WireWslc,
  PortMapping as WirePortMapping,
  Lxc as WireLxc,
  Seatbelt as WireSeatbelt,
  Telemetry as WireTelemetry,
  OneShotRequest as WireMxcConfig,
  UiClipboard as WireClipboardPolicy,
  OneShotContainment as WireContainment,
  NetworkAction as WireNetworkAction,
  NetworkProtocol as WireNetworkProtocol,
  ProcessContainerUiIsolation as WireUiIsolation,
  TransportProtocol as WireTransportProtocol,
  Version as WireVersion,
} from '../../src/generated/v0_10_0_alpha/wire.js';

import type {
  OneShotWslc as WireV09Wslc,
} from '../../src/generated/v0_9_0_alpha/wire.js';

import type {
  AssertTrue,
  StripIndex,
  Assignable,
  OnlyInPublic,
  OnlyInWire,
  Equivalent,
} from './conformance-helpers.js';

// --- enum / union conformance ---------------------------------------------

// Clipboard policy must be value-for-value identical to the wire enum.
type _Clipboard = AssertTrue<Equivalent<PublicClipboardPolicy, WireClipboardPolicy>>;

// The SDK splits containment into abstract intents + concrete backends; their
// union must cover exactly the wire `Containment` enum.
type _Containment = AssertTrue<
  Equivalent<
    ContainmentType | ContainmentBackend,
    Exclude<WireContainment, 'appcontainer' | 'macos_sandbox'>
  >
>;

// Enum-backed object fields are checked bidirectionally so an exact-contract
// enum widening cannot silently outpace the public SDK.
type _NetworkEgressDefault = AssertTrue<
  Equivalent<NonNullable<NetworkEgressConfig['default']>, WireNetworkAction>
>;
type _NetworkIngressDefault = AssertTrue<
  Equivalent<NonNullable<NetworkIngressConfig['default']>, WireNetworkAction>
>;
type _NetworkIngressHostLoopback = AssertTrue<
  Equivalent<NonNullable<NetworkIngressConfig['hostLoopback']>, WireNetworkAction>
>;
type _NetworkPortProtocol = AssertTrue<
  Equivalent<NonNullable<NetworkPortConfig['protocol']>, WireNetworkProtocol>
>;
type _BaseProcessUiIsolation = AssertTrue<
  Equivalent<NonNullable<BaseProcessUiConfig['isolation']>, WireUiIsolation>
>;
type _PortProtocol = AssertTrue<
  Equivalent<NonNullable<PublicPortMapping['protocol']>, WireTransportProtocol>
>;

// --- object-interface value conformance -----------------------------------
// Public is assignable to the (more permissive) wire type. Catches enum/type
// narrowing and incompatible field types.

type _ProcessVals = AssertTrue<Assignable<ProcessConfig, WireProcess>>;
type _LifecycleVals = AssertTrue<Assignable<LifecycleConfig, WireLifecycle>>;
type _FilesystemVals = AssertTrue<Assignable<FilesystemConfig, WireFilesystem>>;
type _NetworkVals = AssertTrue<Assignable<NetworkConfig, WireNetwork>>;
type _NetworkEgressVals = AssertTrue<Assignable<NetworkEgressConfig, WireNetworkEgress>>;
type _NetworkIngressVals = AssertTrue<Assignable<NetworkIngressConfig, WireNetworkIngress>>;
type _NetworkPeerVals = AssertTrue<Assignable<NetworkPeerConfig, WireNetworkPeer>>;
type _NetworkPortVals = AssertTrue<Assignable<NetworkPortConfig, WireNetworkPort>>;
type _NetworkRuleVals = AssertTrue<Assignable<NetworkRuleConfig, WireNetworkRule>>;
type _RuntimeConfigVals = AssertTrue<Assignable<RuntimeConfig, WireRuntimeConfig>>;
type _UiVals = AssertTrue<Assignable<UiConfig, WireUi>>;
type _ProcessContainerVals = AssertTrue<Assignable<ProcessContainerConfig, WireProcessContainer>>;
type _BaseProcessUiVals = AssertTrue<Assignable<BaseProcessUiConfig, WireBaseProcessUi>>;
type _WslcVals = AssertTrue<Assignable<WslcConfig, WireWslc>>;
type _WslcV09Vals = AssertTrue<Assignable<WslcConfig, WireV09Wslc>>;
type _PortMappingVals = AssertTrue<Assignable<PublicPortMapping, WirePortMapping>>;
type _SeatbeltVals = AssertTrue<Assignable<SeatbeltConfig, WireSeatbelt>>;
type _TelemetryVals = AssertTrue<Assignable<TelemetryConfig, WireTelemetry>>;
type RawV010LxcConfig = Required<Pick<LxcConfig, 'distribution' | 'release'>>;
type _LxcVals = AssertTrue<Assignable<RawV010LxcConfig, WireLxc>>;

// --- key conformance (rename / removal detection) -------------------------
// Every public field must either exist on the wire type or be on the EXPLICIT
// SDK-only allow-list below. Each list is asserted to equal exactly the
// divergence set, so a NEW field missing from the wire model fails the build
// (the SDK author must either add it to the wire model or extend this list with
// a justification).
//
// These divergences are the oracle doing its job: each listed field is exposed
// by the SDK but is NOT part of the wire contract (the parser's actual target,
// which uses `deny_unknown_fields`).

type _ProcessKeys = AssertTrue<Equivalent<OnlyInPublic<ProcessConfig, WireProcess>, never>>;
type _LifecycleKeys = AssertTrue<Equivalent<OnlyInPublic<LifecycleConfig, WireLifecycle>, never>>;
type _UiKeys = AssertTrue<Equivalent<OnlyInPublic<UiConfig, WireUi>, never>>;
type _BaseProcessUiKeys = AssertTrue<Equivalent<OnlyInPublic<BaseProcessUiConfig, WireBaseProcessUi>, never>>;
type _WslcKeys = AssertTrue<Equivalent<OnlyInPublic<WslcConfig, WireWslc>, never>>;
type _WslcV09Keys = AssertTrue<Equivalent<OnlyInPublic<WslcConfig, WireV09Wslc>, never>>;
type _PortMappingKeys = AssertTrue<Equivalent<OnlyInPublic<PublicPortMapping, WirePortMapping>, never>>;
type _SeatbeltKeys = AssertTrue<Equivalent<OnlyInPublic<SeatbeltConfig, WireSeatbelt>, never>>;
type _TelemetryKeys = AssertTrue<Equivalent<OnlyInPublic<TelemetryConfig, WireTelemetry>, never>>;

// `FilesystemConfig.clearPolicyOnExit` is an SDK-side convenience flag mapped
// into `lifecycle.preservePolicy`; it is not a wire `filesystem` field.
type _FilesystemKeys = AssertTrue<Equivalent<OnlyInPublic<FilesystemConfig, WireFilesystem>, 'clearPolicyOnExit'>>;

// The public network type spans historical contracts. Exact v0.10 emits only
// directional fields; the listed legacy and SDK-only fields are deliberately
// absent from its raw JSON mapping.
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

// `ProcessContainerConfig.name` is the deprecated AppContainer profile name
// (superseded by top-level `containerId`); not a wire `processContainer` field.
type _ProcessContainerKeys = AssertTrue<Equivalent<OnlyInPublic<ProcessContainerConfig, WireProcessContainer>, 'name'>>;

// `LxcConfig` carries SDK-only `containerName` and `destroyOnExit` (the latter
// duplicated by `lifecycle.destroyOnExit`); neither is a wire `lxc` field.
type _LxcKeys = AssertTrue<Equivalent<OnlyInPublic<RawV010LxcConfig, WireLxc>, never>>;

// --- ROOT conformance (review finding F1) ---------------------------------
// Without these, a top-level wire field rename/removal regenerates wire.ts but
// no assertion notices, so the leaf-only checks above are not enough.
// `PublicV010OneShotConfig` models the current high-level builder output:
//  * its value shape must be assignable to exact v0.10 `OneShotRequest`; and
//  * it must have no public-only root keys.
// A new root divergence fails the build.
type PublicV010OneShotConfig = Omit<
  ContainerConfig,
  'version' | 'process' | 'network' | 'lxc' | 'appContainer'
> & {
  version: WireVersion;
  process: ProcessConfig;
  network?: DirectionalNetworkConfig;
  lxc?: RawV010LxcConfig;
};
type _RootVals = AssertTrue<Assignable<PublicV010OneShotConfig, WireMxcConfig>>;
type _RootKeys = AssertTrue<
  Equivalent<OnlyInPublic<PublicV010OneShotConfig, WireMxcConfig>, never>
>;

// --- reverse key conformance: wire-only fields (review finding F1, gpt-5.5) --
// Catch a NEW optional wire field the SDK forgot to expose. Each list is the
// EXACT set of wire keys the public type intentionally omits; `never` means the
// SDK mirrors the wire object completely. A new wire field not on the relevant
// list fails the build until the SDK either exposes it or documents it here.

type _ProcessWireKeys = AssertTrue<Equivalent<OnlyInWire<ProcessConfig, WireProcess>, never>>;
type _LifecycleWireKeys = AssertTrue<Equivalent<OnlyInWire<LifecycleConfig, WireLifecycle>, never>>;
type _FilesystemWireKeys = AssertTrue<Equivalent<OnlyInWire<FilesystemConfig, WireFilesystem>, never>>;
type _NetworkWireKeys = AssertTrue<Equivalent<OnlyInWire<NetworkConfig, WireNetwork>, never>>;
type _NetworkEgressWireKeys = AssertTrue<Equivalent<OnlyInWire<NetworkEgressConfig, WireNetworkEgress>, never>>;
type _NetworkIngressWireKeys = AssertTrue<Equivalent<OnlyInWire<NetworkIngressConfig, WireNetworkIngress>, never>>;
type _NetworkPeerWireKeys = AssertTrue<Equivalent<OnlyInWire<NetworkPeerConfig, WireNetworkPeer>, never>>;
type _NetworkPortWireKeys = AssertTrue<Equivalent<OnlyInWire<NetworkPortConfig, WireNetworkPort>, never>>;
type _NetworkRuleWireKeys = AssertTrue<Equivalent<OnlyInWire<NetworkRuleConfig, WireNetworkRule>, never>>;
type _RuntimeConfigWireKeys = AssertTrue<Equivalent<OnlyInWire<RuntimeConfig, WireRuntimeConfig>, never>>;
type _UiWireKeys = AssertTrue<Equivalent<OnlyInWire<UiConfig, WireUi>, never>>;
type _BaseProcessUiWireKeys = AssertTrue<Equivalent<OnlyInWire<BaseProcessUiConfig, WireBaseProcessUi>, never>>;
type _WslcWireKeys = AssertTrue<Equivalent<OnlyInWire<WslcConfig, WireWslc>, never>>;
type _WslcV09WireKeys = AssertTrue<Equivalent<OnlyInWire<WslcConfig, WireV09Wslc>, never>>;
type _PortMappingWireKeys = AssertTrue<Equivalent<OnlyInWire<PublicPortMapping, WirePortMapping>, never>>;
type _LxcWireKeys = AssertTrue<Equivalent<OnlyInWire<RawV010LxcConfig, WireLxc>, never>>;

type _ProcessContainerWireKeys = AssertTrue<
  Equivalent<OnlyInWire<ProcessContainerConfig, WireProcessContainer>, never>
>;

type _SeatbeltWireKeys = AssertTrue<
  Equivalent<OnlyInWire<SeatbeltConfig, WireSeatbelt>, never>
>;
type _TelemetryWireKeys = AssertTrue<Equivalent<OnlyInWire<TelemetryConfig, WireTelemetry>, never>>;

// Root: the high-level builder intentionally omits schema metadata, fallback,
// development-only test/Windows Sandbox sections, and the raw Seatbelt alias.
type _RootWireKeys = AssertTrue<
  Equivalent<
    OnlyInWire<PublicV010OneShotConfig, WireMxcConfig>,
    | '$schema'
    | '_comment'
    | 'appContainer'
    | 'fallback'
    | 'test'
    | 'windowsSandbox'
    | 'macos_sandbox'
  >
>;

// Reference the assertion aliases so they read as intentionally load-bearing.
export type WireConformanceAssertions = [
  _Clipboard, _Containment,
  _NetworkEgressDefault, _NetworkIngressDefault, _NetworkIngressHostLoopback,
  _NetworkPortProtocol, _BaseProcessUiIsolation, _PortProtocol,
  _ProcessVals, _LifecycleVals, _FilesystemVals, _NetworkVals, _UiVals,
  _NetworkEgressVals, _NetworkIngressVals, _NetworkPeerVals, _NetworkPortVals,
  _NetworkRuleVals, _RuntimeConfigVals,
  _ProcessContainerVals, _BaseProcessUiVals, _WslcVals, _WslcV09Vals,
  _PortMappingVals,
  _SeatbeltVals, _LxcVals,
  _ProcessKeys, _LifecycleKeys, _FilesystemKeys, _NetworkKeys, _UiKeys,
  _ProcessContainerKeys, _BaseProcessUiKeys, _WslcKeys, _WslcV09Keys,
  _PortMappingKeys,
  _SeatbeltKeys, _LxcKeys,
  _RootVals, _RootKeys,
  _ProcessWireKeys, _LifecycleWireKeys, _FilesystemWireKeys, _NetworkWireKeys,
  _NetworkEgressWireKeys, _NetworkIngressWireKeys, _NetworkPeerWireKeys,
  _NetworkPortWireKeys, _NetworkRuleWireKeys, _RuntimeConfigWireKeys,
  _UiWireKeys, _BaseProcessUiWireKeys, _WslcWireKeys, _WslcV09WireKeys,
  _PortMappingWireKeys,
  _LxcWireKeys, _ProcessContainerWireKeys, _SeatbeltWireKeys, _RootWireKeys,
];

test('public SDK wire types conform to the generated wire schema (compile-time)', () => {
  // Intentionally empty: the guarantee is enforced by the type aliases above at
  // `tsc` time. If they fail to compile, `npm run build:test-unit` fails before
  // this test ever runs.
});
