// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

// Wire-type conformance oracle (Phase 2C, option C).
//
// The generated module `../../src/generated/wire.ts` is emitted from the Rust
// wire model (`wxc_common::wire`) by the `mxc_schema_gen --ts` Rust TypeScript
// emitter. It is the single source of truth for the wire shape.
//
// This file asserts — at COMPILE TIME — that the hand-written public SDK types
// in `../../src/types.ts` still conform to that generated shape. If the Rust
// wire model changes (a field renamed/removed, an enum value added/dropped, a
// type narrowed) the regenerated `wire.ts` shifts and these assertions stop
// compiling, so `npm run build:test-unit` fails. The runtime body is a no-op;
// the test exists so `tsc` type-checks the assertions below.
//
// Direction & null-handling rationale:
//  * Generated fields are uniformly `field?: T | null` (optional AND nullable),
//    so they are strictly more permissive than the SDK's `field?: T`. Therefore
//    `PublicType extends GeneratedType` ("public is assignable to wire") holds
//    cleanly and catches enum/type NARROWING in the wire model.
//  * `OnlyInPublic` additionally catches a public field whose wire counterpart
//    was renamed or removed (width subtyping alone would not), and is asserted
//    to equal a documented, explicit set of SDK-only fields — so a NEW
//    divergence (not on the allow-list) fails the build. This is applied at the
//    ROOT (`ContainerConfig` ↔ `MXCConfiguration`) as well as the leaves, so a
//    top-level rename/removal cannot slip past (review finding F1, codex pass).
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
// One emitter artifact is normalized away: `StripIndex<T>` drops the
// `[k: string]: unknown` index signatures the emitter writes on the OPEN
// (experimental) objects; without this, structural assignment to those
// interfaces misbehaves.

import { test } from 'node:test';

import type {
  ProcessConfig,
  LifecycleConfig,
  FilesystemConfig,
  NetworkConfig,
  UiConfig,
  ProcessContainerConfig,
  BaseProcessUiConfig,
  WslcConfig,
  PortMapping as PublicPortMapping,
  LxcConfig,
  SeatbeltConfig,
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
  Ui as WireUi,
  ProcessContainer as WireProcessContainer,
  BaseProcessUi as WireBaseProcessUi,
  Wslc as WireWslc,
  PortMapping as WirePortMapping,
  Lxc as WireLxc,
  Seatbelt as WireSeatbelt,
  MXCConfiguration as WireMxcConfig,
  ClipboardPolicy as WireClipboardPolicy,
  Containment as WireContainment,
  NetworkPolicy as WireNetworkPolicy,
  NetworkEnforcement as WireNetworkEnforcement,
  UiIsolation as WireUiIsolation,
  TransportProtocol as WireTransportProtocol,
} from '../../src/generated/wire.js';

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
  Equivalent<ContainmentType | ContainmentBackend, WireContainment>
>;

// Enum-backed OBJECT FIELDS (review finding F2). Assignability alone is one-way
// and would let a wire ENUM WIDENING (a new value) slip past, so each enum-typed
// field the SDK exposes inline is checked for exact equivalence with its wire
// enum. `NonNullable` strips the generated `| null` so only the value set is
// compared. A new wire enum value now fails the build until the SDK adds it.
type _NetDefaultPolicy = AssertTrue<
  Equivalent<NonNullable<NetworkConfig['defaultPolicy']>, WireNetworkPolicy>
>;
type _NetEnforcement = AssertTrue<
  Equivalent<NonNullable<NetworkConfig['enforcementMode']>, WireNetworkEnforcement>
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
type _UiVals = AssertTrue<Assignable<UiConfig, WireUi>>;
type _ProcessContainerVals = AssertTrue<Assignable<ProcessContainerConfig, WireProcessContainer>>;
type _BaseProcessUiVals = AssertTrue<Assignable<BaseProcessUiConfig, WireBaseProcessUi>>;
type _WslcVals = AssertTrue<Assignable<WslcConfig, WireWslc>>;
type _PortMappingVals = AssertTrue<Assignable<PublicPortMapping, WirePortMapping>>;
type _SeatbeltVals = AssertTrue<Assignable<SeatbeltConfig, WireSeatbelt>>;
type _LxcVals = AssertTrue<Assignable<StripIndex<LxcConfig>, WireLxc>>;

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
type _PortMappingKeys = AssertTrue<Equivalent<OnlyInPublic<PublicPortMapping, WirePortMapping>, never>>;
type _SeatbeltKeys = AssertTrue<Equivalent<OnlyInPublic<SeatbeltConfig, WireSeatbelt>, never>>;

// `FilesystemConfig.clearPolicyOnExit` is an SDK-side convenience flag mapped
// into `lifecycle.preservePolicy`; it is not a wire `filesystem` field.
type _FilesystemKeys = AssertTrue<Equivalent<OnlyInPublic<FilesystemConfig, WireFilesystem>, 'clearPolicyOnExit'>>;

// `NetworkConfig.removeRulesOnExit` is deprecated (use `lifecycle.preservePolicy`)
// and not a wire `network` field.
type _NetworkKeys = AssertTrue<Equivalent<OnlyInPublic<NetworkConfig, WireNetwork>, 'removeRulesOnExit'>>;

// `ProcessContainerConfig.name` is the deprecated AppContainer profile name
// (superseded by top-level `containerId`); not a wire `processContainer` field.
type _ProcessContainerKeys = AssertTrue<Equivalent<OnlyInPublic<ProcessContainerConfig, WireProcessContainer>, 'name'>>;

// `LxcConfig` carries SDK-only `containerName` and `destroyOnExit` (the latter
// duplicated by `lifecycle.destroyOnExit`); neither is a wire `lxc` field.
type _LxcKeys = AssertTrue<Equivalent<OnlyInPublic<LxcConfig, WireLxc>, 'containerName' | 'destroyOnExit'>>;

// --- ROOT conformance (review finding F1) ---------------------------------
// Without these, a top-level wire field rename/removal regenerates wire.ts but
// no assertion notices, so the leaf-only checks above are not enough. The public
// root `ContainerConfig` is checked the same way as the leaves:
//  * value-shape: assignable to the generated `MXCConfiguration`, and
//  * key-drift: the only public-but-not-wire root key is `appContainer`, the
//    deprecated serde alias the schema folds away (so it is absent from the
//    generated root). A NEW root divergence fails the build.
type _RootVals = AssertTrue<Assignable<ContainerConfig, WireMxcConfig>>;
type _RootKeys = AssertTrue<Equivalent<OnlyInPublic<ContainerConfig, WireMxcConfig>, 'appContainer'>>;

// --- reverse key conformance: wire-only fields (review finding F1, gpt-5.5) --
// Catch a NEW optional wire field the SDK forgot to expose. Each list is the
// EXACT set of wire keys the public type intentionally omits; `never` means the
// SDK mirrors the wire object completely. A new wire field not on the relevant
// list fails the build until the SDK either exposes it or documents it here.

type _ProcessWireKeys = AssertTrue<Equivalent<OnlyInWire<ProcessConfig, WireProcess>, never>>;
type _LifecycleWireKeys = AssertTrue<Equivalent<OnlyInWire<LifecycleConfig, WireLifecycle>, never>>;
type _FilesystemWireKeys = AssertTrue<Equivalent<OnlyInWire<FilesystemConfig, WireFilesystem>, never>>;
type _NetworkWireKeys = AssertTrue<Equivalent<OnlyInWire<NetworkConfig, WireNetwork>, never>>;
type _UiWireKeys = AssertTrue<Equivalent<OnlyInWire<UiConfig, WireUi>, never>>;
type _BaseProcessUiWireKeys = AssertTrue<Equivalent<OnlyInWire<BaseProcessUiConfig, WireBaseProcessUi>, never>>;
type _WslcWireKeys = AssertTrue<Equivalent<OnlyInWire<WslcConfig, WireWslc>, never>>;
type _PortMappingWireKeys = AssertTrue<Equivalent<OnlyInWire<PublicPortMapping, WirePortMapping>, never>>;
type _LxcWireKeys = AssertTrue<Equivalent<OnlyInWire<LxcConfig, WireLxc>, never>>;

// `processContainer.learningMode` is a wire field the SDK does not expose (the
// AppContainer permissive learning mode is not surfaced through the policy API).
type _ProcessContainerWireKeys = AssertTrue<
  Equivalent<OnlyInWire<ProcessContainerConfig, WireProcessContainer>, 'learningMode'>
>;

// `seatbelt.guiAccess` and `seatbelt.launchMethod` are wire fields the one-shot
// `SeatbeltConfig` does not expose today.
type _SeatbeltWireKeys = AssertTrue<
  Equivalent<OnlyInWire<SeatbeltConfig, WireSeatbelt>, 'guiAccess' | 'launchMethod'>
>;

// Root: the SDK's `ContainerConfig` intentionally omits the schema-metadata keys
// (`$schema`, `_comment`), the state-aware-only keys (`phase`, `sandboxId` — see
// `state-aware-types.ts`), and `fallback` (AppContainer DACL-mutation policy not
// surfaced through the one-shot policy API). Any OTHER new root wire field fails.
type _RootWireKeys = AssertTrue<
  Equivalent<
    OnlyInWire<ContainerConfig, WireMxcConfig>,
    '$schema' | '_comment' | 'phase' | 'sandboxId' | 'fallback'
  >
>;

// Reference the assertion aliases so they read as intentionally load-bearing.
export type WireConformanceAssertions = [
  _Clipboard, _Containment,
  _NetDefaultPolicy, _NetEnforcement, _BaseProcessUiIsolation, _PortProtocol,
  _ProcessVals, _LifecycleVals, _FilesystemVals, _NetworkVals, _UiVals,
  _ProcessContainerVals, _BaseProcessUiVals, _WslcVals, _PortMappingVals,
  _SeatbeltVals, _LxcVals,
  _ProcessKeys, _LifecycleKeys, _FilesystemKeys, _NetworkKeys, _UiKeys,
  _ProcessContainerKeys, _BaseProcessUiKeys, _WslcKeys, _PortMappingKeys,
  _SeatbeltKeys, _LxcKeys,
  _RootVals, _RootKeys,
  _ProcessWireKeys, _LifecycleWireKeys, _FilesystemWireKeys, _NetworkWireKeys,
  _UiWireKeys, _BaseProcessUiWireKeys, _WslcWireKeys, _PortMappingWireKeys,
  _LxcWireKeys, _ProcessContainerWireKeys, _SeatbeltWireKeys, _RootWireKeys,
];

test('public SDK wire types conform to the generated wire schema (compile-time)', () => {
  // Intentionally empty: the guarantee is enforced by the type aliases above at
  // `tsc` time. If they fail to compile, `npm run build:test-unit` fails before
  // this test ever runs.
});
