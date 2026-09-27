// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

import koffi from 'koffi';
import { MxcError } from '../errors.js';
import type {
  ClipboardPolicy,
  DirectionalNetworkConfig,
  FilesystemConfig,
  NetworkAction,
  NetworkPeerConfig,
  NetworkPortConfig,
  NetworkProtocol,
  NetworkRuleConfig,
  ProcessConfig,
  RuntimeConfig,
  TelemetryConfig,
} from '../types.js';
import type { RequestSpec } from './request.js';

export const MXC_TYPED_ABI_VERSION_1 = 1;

export const MXC_CONTAINMENT_PROCESS = 0;
export const MXC_CONTAINMENT_PROCESS_CONTAINER = 1;
export const MXC_CONTAINMENT_BUBBLEWRAP = 2;
export const MXC_CONTAINMENT_LXC = 3;
export const MXC_CONTAINMENT_SEATBELT = 4;
export const MXC_CONTAINMENT_WSLC = 5;
export const MXC_CONTAINMENT_ISOLATION_SESSION = 6;

export const MXC_NETWORK_ACTION_DENY = 0;
export const MXC_NETWORK_ACTION_ALLOW = 1;

export const MXC_NETWORK_PROTOCOL_TCP = 0;
export const MXC_NETWORK_PROTOCOL_UDP = 1;
export const MXC_NETWORK_PROTOCOL_ICMP = 2;
export const MXC_NETWORK_PROTOCOL_ANY = 3;

export const MXC_CLIPBOARD_NONE = 0;
export const MXC_CLIPBOARD_READ = 1;
export const MXC_CLIPBOARD_WRITE = 2;
export const MXC_CLIPBOARD_ALL = 3;

export const MXC_CAPTURE_DENIALS_BLOCK = 0;
export const MXC_CAPTURE_DENIALS_ALLOW = 1;

export const MXC_PROCESS_UI_DESKTOP = 0;
export const MXC_PROCESS_UI_HANDLES = 1;
export const MXC_PROCESS_UI_ATOMS = 2;
export const MXC_PROCESS_UI_CONTAINER = 3;

export const MXC_PROCESS_SYSTEM_SETTINGS_ALL = 0;
export const MXC_PROCESS_SYSTEM_SETTINGS_PARAMETERS = 1;
export const MXC_PROCESS_SYSTEM_SETTINGS_DISPLAY = 2;
export const MXC_PROCESS_SYSTEM_SETTINGS_NONE = 3;

export const MXC_STATE_AWARE_PROVISION = 0;
export const MXC_STATE_AWARE_START = 1;
export const MXC_STATE_AWARE_EXEC = 2;
export const MXC_STATE_AWARE_STOP = 3;
export const MXC_STATE_AWARE_DEPROVISION = 4;

export const MXC_STATE_AWARE_ISOLATION_SESSION = 0;
export const MXC_STATE_AWARE_WSLC = 1;

export const MXC_PROVISION_METADATA_NONE = 0;
export const MXC_PROVISION_METADATA_ISOLATION_SESSION = 1;

export interface MxcUtf8Slice {
  data: Buffer | null;
  len: number;
}

export interface MxcUtf8SliceList {
  items: MxcUtf8Slice[] | null;
  len: number;
}

export interface MxcOptionalBool {
  is_set: number;
  value: number;
}

export interface MxcOptionalU16 {
  is_set: number;
  value: number;
}

export interface MxcOptionalU32 {
  is_set: number;
  value: number;
}

export interface MxcOptionalU64 {
  is_set: number;
  value: bigint;
}

export interface MxcOptionalI32 {
  is_set: number;
  value: number;
}

export interface MxcEnvironmentEntry {
  key: MxcUtf8Slice;
  value: MxcUtf8Slice;
}

export interface MxcEnvironment {
  is_set: number;
  entries: MxcEnvironmentEntry[] | null;
  len: number;
}

export interface MxcTypedFilesystemPolicy {
  readwrite_paths: MxcUtf8SliceList;
  readonly_paths: MxcUtf8SliceList;
  denied_paths: MxcUtf8SliceList;
  clear_policy_on_exit: MxcOptionalBool;
}

export interface MxcTypedNetworkPeer {
  cidr: MxcUtf8Slice;
  except_is_set: number;
  except: MxcUtf8SliceList;
}

export interface MxcTypedNetworkPort {
  protocol: MxcOptionalI32;
  port: MxcOptionalU16;
  end_port: MxcOptionalU16;
}

export interface MxcTypedNetworkRule {
  to_is_set: number;
  to: MxcTypedNetworkPeer[] | null;
  to_len: number;
  ports_is_set: number;
  ports: MxcTypedNetworkPort[] | null;
  ports_len: number;
}

export interface MxcTypedNetworkEgress {
  default_action: MxcOptionalI32;
  allow_is_set: number;
  allow: MxcTypedNetworkRule[] | null;
  allow_len: number;
  deny_is_set: number;
  deny: MxcTypedNetworkRule[] | null;
  deny_len: number;
}

export interface MxcTypedNetworkIngress {
  default_action: MxcOptionalI32;
  host_loopback: MxcOptionalI32;
}

export interface MxcTypedNetworkPolicy {
  egress: MxcTypedNetworkEgress | null;
  ingress: MxcTypedNetworkIngress | null;
  network_proxy: MxcUtf8Slice | null;
}

export interface MxcTypedUiPolicy {
  allow_windows: number;
  clipboard: number;
  allow_input_injection: number;
}

export interface MxcTypedSandboxPolicy {
  filesystem: MxcTypedFilesystemPolicy | null;
  network: MxcTypedNetworkPolicy | null;
  ui: MxcTypedUiPolicy | null;
  timeout_ms: MxcOptionalU32;
  telemetry_enabled: MxcOptionalBool;
}

export interface MxcTypedCaptureDenials {
  mode: number;
  output_path: MxcUtf8Slice | null;
  retain_etl: number;
}

export interface MxcTypedProcessContainerUi {
  isolation: number;
  desktop_system_control: number;
  system_settings: number;
  ime: number;
}

export interface MxcTypedProcessContainer {
  least_privilege: number;
  learning_mode: number;
  capabilities: MxcUtf8SliceList;
  capture_denials: MxcTypedCaptureDenials | null;
  ui: MxcTypedProcessContainerUi | null;
  enumerate_paths: MxcUtf8SliceList;
  allowed_proxy_peer: MxcUtf8Slice | null;
}

export interface MxcTypedSeatbelt {
  profile_override: MxcUtf8Slice | null;
  gui_access: number;
  nested_pty: number;
  keychain_access: number;
  extra_mach_lookups: MxcUtf8SliceList;
}

export interface MxcTypedLxc {
  distribution: MxcUtf8Slice | null;
  release: MxcUtf8Slice | null;
}

export interface MxcTypedWslcPortMapping {
  windows_port: number;
  container_port: number;
}

export interface MxcTypedWslc {
  image: MxcUtf8Slice | null;
  image_tar_path: MxcUtf8Slice | null;
  cpu_count: MxcOptionalU32;
  memory_mb: MxcOptionalU64;
  gpu: number;
  storage_path: MxcUtf8Slice | null;
  port_mappings: MxcTypedWslcPortMapping[] | null;
  port_mappings_len: number;
}

export interface MxcTypedOneShotRequest {
  abi_version: number;
  struct_size: number;
  policy: MxcTypedSandboxPolicy | null;
  command: MxcUtf8Slice;
  containment: number;
  process_container: MxcTypedProcessContainer | null;
  seatbelt: MxcTypedSeatbelt | null;
  lxc: MxcTypedLxc | null;
  wslc: MxcTypedWslc | null;
  container_name: MxcUtf8Slice | null;
  working_directory: MxcUtf8Slice | null;
  environment: MxcEnvironment;
  inherit_default_env: number;
  experimental: number;
}

export interface MxcTypedProvisionRequest {
  backend: number;
  app_id: MxcUtf8Slice | null;
  image: MxcUtf8Slice | null;
  image_tar_path: MxcUtf8Slice | null;
  filesystem: MxcTypedFilesystemPolicy | null;
  network: MxcTypedNetworkPolicy | null;
}

export interface MxcTypedExecRequest {
  command: MxcUtf8Slice;
  working_directory: MxcUtf8Slice | null;
  environment: MxcEnvironment;
  inherit_default_env: MxcOptionalBool;
  timeout_ms: MxcOptionalU32;
  network_proxy: MxcUtf8Slice | null;
}

export interface MxcTypedStateAwareRequest {
  abi_version: number;
  struct_size: number;
  operation: number;
  sandbox_id: MxcUtf8Slice | null;
  provision: MxcTypedProvisionRequest | null;
  exec: MxcTypedExecRequest | null;
  telemetry_enabled: MxcOptionalBool;
  experimental: number;
}

export interface TypedAbiRequest<T> {
  value: T;
  keepAlive: unknown[];
}

class Arena {
  readonly keepAlive: unknown[] = [];

  keep<T>(value: T): T {
    this.keepAlive.push(value);
    return value;
  }

  utf8(value: string): MxcUtf8Slice {
    const data = this.keep(Buffer.from(value, 'utf8'));
    return this.keep({ data, len: data.length });
  }

  optionalUtf8(value: string | undefined): MxcUtf8Slice | null {
    return value === undefined ? null : this.utf8(value);
  }

  utf8List(values: readonly string[] | undefined): MxcUtf8SliceList {
    if (values === undefined || values.length === 0) {
      return { items: null, len: 0 };
    }
    const items = this.keep(values.map((value) => this.utf8(value)));
    return { items, len: items.length };
  }

  environment(
    entries: Record<string, string> | undefined,
  ): MxcEnvironment {
    if (entries === undefined) {
      return { is_set: 0, entries: null, len: 0 };
    }
    const mapped = Object.entries(entries).map(([key, value]) => ({
      key: this.utf8(key),
      value: this.utf8(value),
    }));
    return {
      is_set: 1,
      entries: mapped.length === 0 ? null : this.keep(mapped),
      len: mapped.length,
    };
  }

  environmentFromProcess(process: ProcessConfig | undefined): MxcEnvironment {
    if (process?.env === undefined) {
      return { is_set: 0, entries: null, len: 0 };
    }
    const mapped = process.env.map((entry) => {
      const separator = entry.indexOf('=');
      const key = separator < 0 ? entry : entry.slice(0, separator);
      const value = separator < 0 ? '' : entry.slice(separator + 1);
      return { key: this.utf8(key), value: this.utf8(value) };
    });
    return {
      is_set: 1,
      entries: mapped.length === 0 ? null : this.keep(mapped),
      len: mapped.length,
    };
  }
}

export const MxcUtf8SliceType = koffi.struct('MxcNodeTypedUtf8Slice', {
  data: koffi.pointer('uint8_t'),
  len: 'size_t',
});
export const MxcUtf8SliceListType = koffi.struct('MxcNodeTypedUtf8SliceList', {
  items: koffi.pointer(MxcUtf8SliceType),
  len: 'size_t',
});
export const MxcOptionalBoolType = koffi.struct('MxcNodeTypedOptionalBool', {
  is_set: 'int32_t',
  value: 'int32_t',
});
export const MxcOptionalU16Type = koffi.struct('MxcNodeTypedOptionalU16', {
  is_set: 'int32_t',
  value: 'uint16_t',
});
export const MxcOptionalU32Type = koffi.struct('MxcNodeTypedOptionalU32', {
  is_set: 'int32_t',
  value: 'uint32_t',
});
export const MxcOptionalU64Type = koffi.struct('MxcNodeTypedOptionalU64', {
  is_set: 'int32_t',
  value: 'uint64_t',
});
export const MxcOptionalI32Type = koffi.struct('MxcNodeTypedOptionalI32', {
  is_set: 'int32_t',
  value: 'int32_t',
});
export const MxcEnvironmentEntryType = koffi.struct('MxcNodeTypedEnvironmentEntry', {
  key: MxcUtf8SliceType,
  value: MxcUtf8SliceType,
});
export const MxcEnvironmentType = koffi.struct('MxcNodeTypedEnvironment', {
  is_set: 'int32_t',
  entries: koffi.pointer(MxcEnvironmentEntryType),
  len: 'size_t',
});
export const MxcTypedFilesystemPolicyType = koffi.struct('MxcNodeTypedFilesystemPolicy', {
  readwrite_paths: MxcUtf8SliceListType,
  readonly_paths: MxcUtf8SliceListType,
  denied_paths: MxcUtf8SliceListType,
  clear_policy_on_exit: MxcOptionalBoolType,
});
export const MxcTypedNetworkPeerType = koffi.struct('MxcNodeTypedNetworkPeer', {
  cidr: MxcUtf8SliceType,
  except_is_set: 'int32_t',
  except: MxcUtf8SliceListType,
});
export const MxcTypedNetworkPortType = koffi.struct('MxcNodeTypedNetworkPort', {
  protocol: MxcOptionalI32Type,
  port: MxcOptionalU16Type,
  end_port: MxcOptionalU16Type,
});
export const MxcTypedNetworkRuleType = koffi.struct('MxcNodeTypedNetworkRule', {
  to_is_set: 'int32_t',
  to: koffi.pointer(MxcTypedNetworkPeerType),
  to_len: 'size_t',
  ports_is_set: 'int32_t',
  ports: koffi.pointer(MxcTypedNetworkPortType),
  ports_len: 'size_t',
});
export const MxcTypedNetworkEgressType = koffi.struct('MxcNodeTypedNetworkEgress', {
  default_action: MxcOptionalI32Type,
  allow_is_set: 'int32_t',
  allow: koffi.pointer(MxcTypedNetworkRuleType),
  allow_len: 'size_t',
  deny_is_set: 'int32_t',
  deny: koffi.pointer(MxcTypedNetworkRuleType),
  deny_len: 'size_t',
});
export const MxcTypedNetworkIngressType = koffi.struct('MxcNodeTypedNetworkIngress', {
  default_action: MxcOptionalI32Type,
  host_loopback: MxcOptionalI32Type,
});
export const MxcTypedNetworkPolicyType = koffi.struct('MxcNodeTypedNetworkPolicy', {
  egress: koffi.pointer(MxcTypedNetworkEgressType),
  ingress: koffi.pointer(MxcTypedNetworkIngressType),
  network_proxy: koffi.pointer(MxcUtf8SliceType),
});
export const MxcTypedUiPolicyType = koffi.struct('MxcNodeTypedUiPolicy', {
  allow_windows: 'int32_t',
  clipboard: 'int32_t',
  allow_input_injection: 'int32_t',
});
export const MxcTypedSandboxPolicyType = koffi.struct('MxcNodeTypedSandboxPolicy', {
  filesystem: koffi.pointer(MxcTypedFilesystemPolicyType),
  network: koffi.pointer(MxcTypedNetworkPolicyType),
  ui: koffi.pointer(MxcTypedUiPolicyType),
  timeout_ms: MxcOptionalU32Type,
  telemetry_enabled: MxcOptionalBoolType,
});
export const MxcTypedCaptureDenialsType = koffi.struct('MxcNodeTypedCaptureDenials', {
  mode: 'int32_t',
  output_path: koffi.pointer(MxcUtf8SliceType),
  retain_etl: 'int32_t',
});
export const MxcTypedProcessContainerUiType = koffi.struct('MxcNodeTypedProcessContainerUi', {
  isolation: 'int32_t',
  desktop_system_control: 'int32_t',
  system_settings: 'int32_t',
  ime: 'int32_t',
});
export const MxcTypedProcessContainerType = koffi.struct('MxcNodeTypedProcessContainer', {
  least_privilege: 'int32_t',
  learning_mode: 'int32_t',
  capabilities: MxcUtf8SliceListType,
  capture_denials: koffi.pointer(MxcTypedCaptureDenialsType),
  ui: koffi.pointer(MxcTypedProcessContainerUiType),
  enumerate_paths: MxcUtf8SliceListType,
  allowed_proxy_peer: koffi.pointer(MxcUtf8SliceType),
});
export const MxcTypedSeatbeltType = koffi.struct('MxcNodeTypedSeatbelt', {
  profile_override: koffi.pointer(MxcUtf8SliceType),
  gui_access: 'int32_t',
  nested_pty: 'int32_t',
  keychain_access: 'int32_t',
  extra_mach_lookups: MxcUtf8SliceListType,
});
export const MxcTypedLxcType = koffi.struct('MxcNodeTypedLxc', {
  distribution: koffi.pointer(MxcUtf8SliceType),
  release: koffi.pointer(MxcUtf8SliceType),
});
export const MxcTypedWslcPortMappingType = koffi.struct('MxcNodeTypedWslcPortMapping', {
  windows_port: 'uint16_t',
  container_port: 'uint16_t',
});
export const MxcTypedWslcType = koffi.struct('MxcNodeTypedWslc', {
  image: koffi.pointer(MxcUtf8SliceType),
  image_tar_path: koffi.pointer(MxcUtf8SliceType),
  cpu_count: MxcOptionalU32Type,
  memory_mb: MxcOptionalU64Type,
  gpu: 'int32_t',
  storage_path: koffi.pointer(MxcUtf8SliceType),
  port_mappings: koffi.pointer(MxcTypedWslcPortMappingType),
  port_mappings_len: 'size_t',
});
export const MxcTypedOneShotRequestType = koffi.struct('MxcNodeTypedOneShotRequest', {
  abi_version: 'uint32_t',
  struct_size: 'size_t',
  policy: koffi.pointer(MxcTypedSandboxPolicyType),
  command: MxcUtf8SliceType,
  containment: 'int32_t',
  process_container: koffi.pointer(MxcTypedProcessContainerType),
  seatbelt: koffi.pointer(MxcTypedSeatbeltType),
  lxc: koffi.pointer(MxcTypedLxcType),
  wslc: koffi.pointer(MxcTypedWslcType),
  container_name: koffi.pointer(MxcUtf8SliceType),
  working_directory: koffi.pointer(MxcUtf8SliceType),
  environment: MxcEnvironmentType,
  inherit_default_env: 'int32_t',
  experimental: 'int32_t',
});
export const MxcTypedProvisionRequestType = koffi.struct('MxcNodeTypedProvisionRequest', {
  backend: 'int32_t',
  app_id: koffi.pointer(MxcUtf8SliceType),
  image: koffi.pointer(MxcUtf8SliceType),
  image_tar_path: koffi.pointer(MxcUtf8SliceType),
  filesystem: koffi.pointer(MxcTypedFilesystemPolicyType),
  network: koffi.pointer(MxcTypedNetworkPolicyType),
});
export const MxcTypedExecRequestType = koffi.struct('MxcNodeTypedExecRequest', {
  command: MxcUtf8SliceType,
  working_directory: koffi.pointer(MxcUtf8SliceType),
  environment: MxcEnvironmentType,
  inherit_default_env: MxcOptionalBoolType,
  timeout_ms: MxcOptionalU32Type,
  network_proxy: koffi.pointer(MxcUtf8SliceType),
});
export const MxcTypedStateAwareRequestType = koffi.struct('MxcNodeTypedStateAwareRequest', {
  abi_version: 'uint32_t',
  struct_size: 'size_t',
  operation: 'int32_t',
  sandbox_id: koffi.pointer(MxcUtf8SliceType),
  provision: koffi.pointer(MxcTypedProvisionRequestType),
  exec: koffi.pointer(MxcTypedExecRequestType),
  telemetry_enabled: MxcOptionalBoolType,
  experimental: 'int32_t',
});

function flag(value: boolean | undefined, defaultValue = false): number {
  return (value ?? defaultValue) ? 1 : 0;
}

function optionalBool(value: boolean | undefined): MxcOptionalBool {
  return value === undefined ? { is_set: 0, value: 0 } : { is_set: 1, value: flag(value) };
}

function optionalU16(value: number | undefined): MxcOptionalU16 {
  return value === undefined ? { is_set: 0, value: 0 } : { is_set: 1, value };
}

function optionalU32(value: number | undefined): MxcOptionalU32 {
  return value === undefined ? { is_set: 0, value: 0 } : { is_set: 1, value };
}

function optionalU64(value: number | undefined): MxcOptionalU64 {
  return value === undefined
    ? { is_set: 0, value: 0n }
    : { is_set: 1, value: BigInt(value) };
}

function optionalI32(value: number | undefined): MxcOptionalI32 {
  return value === undefined ? { is_set: 0, value: 0 } : { is_set: 1, value };
}

function networkAction(value: NetworkAction | undefined): number | undefined {
  if (value === undefined) return undefined;
  return value === 'allow' ? MXC_NETWORK_ACTION_ALLOW : MXC_NETWORK_ACTION_DENY;
}

function networkProtocol(value: NetworkProtocol | undefined): number | undefined {
  switch (value) {
    case undefined:
      return undefined;
    case 'tcp':
      return MXC_NETWORK_PROTOCOL_TCP;
    case 'udp':
      return MXC_NETWORK_PROTOCOL_UDP;
    case 'icmp':
      return MXC_NETWORK_PROTOCOL_ICMP;
    case 'any':
      return MXC_NETWORK_PROTOCOL_ANY;
  }
}

function clipboard(value: ClipboardPolicy): number {
  switch (value) {
    case 'none':
      return MXC_CLIPBOARD_NONE;
    case 'read':
      return MXC_CLIPBOARD_READ;
    case 'write':
      return MXC_CLIPBOARD_WRITE;
    case 'all':
      return MXC_CLIPBOARD_ALL;
  }
}

function processUiIsolation(value: string | undefined): number {
  switch (value) {
    case 'desktop':
      return MXC_PROCESS_UI_DESKTOP;
    case 'handles':
      return MXC_PROCESS_UI_HANDLES;
    case 'atoms':
      return MXC_PROCESS_UI_ATOMS;
    case undefined:
    case 'container':
      return MXC_PROCESS_UI_CONTAINER;
    default:
      throw new MxcError('malformed_request', `unknown ProcessContainer UI isolation '${value}'`);
  }
}

function processSystemSettings(value: string | undefined): number {
  switch (value) {
    case 'all':
      return MXC_PROCESS_SYSTEM_SETTINGS_ALL;
    case 'parameters':
      return MXC_PROCESS_SYSTEM_SETTINGS_PARAMETERS;
    case 'display':
      return MXC_PROCESS_SYSTEM_SETTINGS_DISPLAY;
    case undefined:
    case 'none':
      return MXC_PROCESS_SYSTEM_SETTINGS_NONE;
    default:
      throw new MxcError('malformed_request', `unknown ProcessContainer system settings '${value}'`);
  }
}

function filesystem(
  arena: Arena,
  value: FilesystemConfig | undefined,
): MxcTypedFilesystemPolicy | null {
  if (value === undefined) return null;
  return arena.keep({
    readwrite_paths: arena.utf8List(value.readwritePaths),
    readonly_paths: arena.utf8List(value.readonlyPaths),
    denied_paths: arena.utf8List(value.deniedPaths),
    clear_policy_on_exit: optionalBool(value.clearPolicyOnExit),
  });
}

function peer(arena: Arena, value: NetworkPeerConfig): MxcTypedNetworkPeer {
  return {
    cidr: arena.utf8(value.cidr),
    except_is_set: value.except === undefined ? 0 : 1,
    except: arena.utf8List(value.except),
  };
}

function port(value: NetworkPortConfig): MxcTypedNetworkPort {
  return {
    protocol: optionalI32(networkProtocol(value.protocol)),
    port: optionalU16(value.port),
    end_port: optionalU16(value.endPort),
  };
}

function rules(
  arena: Arena,
  values: NetworkRuleConfig[] | undefined,
): { is_set: number; items: MxcTypedNetworkRule[] | null; len: number } {
  if (values === undefined) return { is_set: 0, items: null, len: 0 };
  const items = values.map((value) => {
    const to = value.to?.map((entry) => peer(arena, entry));
    const ports = value.ports?.map(port);
    return {
      to_is_set: value.to === undefined ? 0 : 1,
      to: to === undefined || to.length === 0 ? null : arena.keep(to),
      to_len: to?.length ?? 0,
      ports_is_set: value.ports === undefined ? 0 : 1,
      ports: ports === undefined || ports.length === 0 ? null : arena.keep(ports),
      ports_len: ports?.length ?? 0,
    };
  });
  return {
    is_set: 1,
    items: items.length === 0 ? null : arena.keep(items),
    len: items.length,
  };
}

function network(
  arena: Arena,
  value: (DirectionalNetworkConfig & { runtimeConfig?: RuntimeConfig }) | undefined,
): MxcTypedNetworkPolicy | null {
  if (value === undefined) return null;
  const allow = rules(arena, value.egress?.allow);
  const deny = rules(arena, value.egress?.deny);
  const egress = value.egress === undefined ? null : arena.keep({
    default_action: optionalI32(networkAction(value.egress.default)),
    allow_is_set: allow.is_set,
    allow: allow.items,
    allow_len: allow.len,
    deny_is_set: deny.is_set,
    deny: deny.items,
    deny_len: deny.len,
  });
  const ingress = value.ingress === undefined ? null : arena.keep({
    default_action: optionalI32(networkAction(value.ingress.default)),
    host_loopback: optionalI32(networkAction(value.ingress.hostLoopback)),
  });
  return arena.keep({
    egress,
    ingress,
    network_proxy: arena.optionalUtf8(value.runtimeConfig?.networkProxy),
  });
}

function telemetryEnabled(value: TelemetryConfig | undefined): MxcOptionalBool {
  return optionalBool(value?.enabled);
}

function sandboxPolicy(
  arena: Arena,
  value: RequestSpec['policy'],
): MxcTypedSandboxPolicy | null {
  const policy = arena.keep({
    filesystem: filesystem(arena, value.filesystem),
    network: network(arena, value.network),
    ui: value.ui === undefined ? null : arena.keep({
      allow_windows: flag(value.ui.allowWindows),
      clipboard: clipboard(value.ui.clipboard),
      allow_input_injection: flag(value.ui.allowInputInjection),
    }),
    timeout_ms: optionalU32(value.timeoutMs),
    telemetry_enabled: telemetryEnabled(value.telemetry),
  });
  return policy.filesystem === null
    && policy.network === null
    && policy.ui === null
    && policy.timeout_ms.is_set === 0
    && policy.telemetry_enabled.is_set === 0
    ? null
    : policy;
}

function processContainer(
  arena: Arena,
  value: Extract<RequestSpec['containment'], { type: 'processContainer' }>,
): MxcTypedProcessContainer {
  return arena.keep({
    least_privilege: flag(value.leastPrivilege),
    learning_mode: flag(value.learningMode),
    capabilities: arena.utf8List(value.capabilities),
    capture_denials: value.captureDenials === undefined ? null : arena.keep({
      mode: value.captureDenials.mode === 'allow'
        ? MXC_CAPTURE_DENIALS_ALLOW
        : MXC_CAPTURE_DENIALS_BLOCK,
      output_path: arena.optionalUtf8(value.captureDenials.outputPath),
      retain_etl: flag(value.captureDenials.retainEtl),
    }),
    ui: arena.keep({
      isolation: processUiIsolation(value.ui?.isolation),
      desktop_system_control: flag(value.ui?.desktopSystemControl),
      system_settings: processSystemSettings(value.ui?.systemSettings),
      ime: flag(value.ui?.ime),
    }),
    enumerate_paths: arena.utf8List(value.filesystem?.enumeratePaths),
    allowed_proxy_peer: arena.optionalUtf8(value.network?.allowedProxyPeer),
  });
}

function seatbelt(
  arena: Arena,
  value: Extract<RequestSpec['containment'], { type: 'seatbelt' }>,
): MxcTypedSeatbelt {
  return arena.keep({
    profile_override: arena.optionalUtf8(value.profileOverride),
    gui_access: flag(value.guiAccess),
    nested_pty: flag(value.nestedPty, true),
    keychain_access: flag(value.keychainAccess),
    extra_mach_lookups: arena.utf8List(value.extraMachLookups),
  });
}

function lxc(
  arena: Arena,
  value: Extract<RequestSpec['containment'], { type: 'lxc' }>,
): MxcTypedLxc {
  return arena.keep({
    distribution: arena.utf8(value.distribution ?? 'alpine'),
    release: arena.utf8(value.release ?? '3.23'),
  });
}

function wslc(
  arena: Arena,
  value: Extract<RequestSpec['containment'], { type: 'wslc' }>,
): MxcTypedWslc {
  const portMappings = value.portMappings?.map((mapping) => ({
    windows_port: mapping.windowsPort,
    container_port: mapping.containerPort,
  })) ?? [];
  return arena.keep({
    image: arena.utf8(value.image ?? 'alpine:latest'),
    image_tar_path: arena.optionalUtf8(value.imageTarPath),
    cpu_count: optionalU32(value.cpuCount),
    memory_mb: optionalU64(value.memoryMb),
    gpu: flag(value.gpu),
    storage_path: arena.optionalUtf8(value.storagePath),
    port_mappings: portMappings.length === 0 ? null : arena.keep(portMappings),
    port_mappings_len: portMappings.length,
  });
}

export function buildTypedOneShotRequest(
  request: RequestSpec,
): TypedAbiRequest<MxcTypedOneShotRequest> {
  const arena = new Arena();
  let containment = MXC_CONTAINMENT_PROCESS;
  let process_container: MxcTypedProcessContainer | null = null;
  let seatbeltValue: MxcTypedSeatbelt | null = null;
  let lxcValue: MxcTypedLxc | null = null;
  let wslcValue: MxcTypedWslc | null = null;

  switch (request.containment.type) {
    case 'process':
      break;
    case 'processContainer':
      containment = MXC_CONTAINMENT_PROCESS_CONTAINER;
      process_container = processContainer(arena, request.containment);
      break;
    case 'bubblewrap':
      containment = MXC_CONTAINMENT_BUBBLEWRAP;
      break;
    case 'lxc':
      containment = MXC_CONTAINMENT_LXC;
      lxcValue = lxc(arena, request.containment);
      break;
    case 'seatbelt':
      containment = MXC_CONTAINMENT_SEATBELT;
      seatbeltValue = seatbelt(arena, request.containment);
      break;
    case 'wslc':
      containment = MXC_CONTAINMENT_WSLC;
      wslcValue = wslc(arena, request.containment);
      break;
    case 'isolationSession':
      containment = MXC_CONTAINMENT_ISOLATION_SESSION;
      break;
  }

  return {
    value: arena.keep({
      abi_version: MXC_TYPED_ABI_VERSION_1,
      struct_size: koffi.sizeof(MxcTypedOneShotRequestType),
      policy: sandboxPolicy(arena, request.policy),
      command: arena.utf8(request.command),
      containment,
      process_container,
      seatbelt: seatbeltValue,
      lxc: lxcValue,
      wslc: wslcValue,
      container_name: arena.optionalUtf8(request.containerName),
      working_directory: arena.optionalUtf8(request.workingDirectory),
      environment: arena.environment(request.environment),
      inherit_default_env: flag(request.inheritDefaultEnv),
      experimental: containment === MXC_CONTAINMENT_WSLC ? 0 : flag(request.experimental),
    }),
    keepAlive: arena.keepAlive,
  };
}

function record(value: unknown): Record<string, unknown> | undefined {
  return value !== null && typeof value === 'object' && !Array.isArray(value)
    ? value as Record<string, unknown>
    : undefined;
}

function asString(value: unknown): string | undefined {
  return typeof value === 'string' ? value : undefined;
}

function asBoolean(value: unknown): boolean | undefined {
  return typeof value === 'boolean' ? value : undefined;
}

function asProcess(value: unknown): ProcessConfig | undefined {
  return record(value) as ProcessConfig | undefined;
}

function stateAwareBackend(envelope: Record<string, unknown>): 'isolation_session' | 'wslc' | undefined {
  const phase = envelope.phase;
  if (phase === 'provision') {
    const containment = envelope.containment;
    return containment === 'isolation_session' || containment === 'wslc'
      ? containment
      : undefined;
  }
  const sandboxId = asString(envelope.sandboxId);
  if (sandboxId?.startsWith('iso:')) return 'isolation_session';
  if (sandboxId?.startsWith('wslc:')) return 'wslc';
  return undefined;
}

export function supportsTypedStateAwareEnvelope(envelope: Record<string, unknown>): boolean {
  return (envelope.version === undefined || envelope.version === '1.0.0')
    && stateAwareBackend(envelope) !== undefined;
}

function stateAwareOperation(phase: unknown): number {
  switch (phase) {
    case 'provision':
      return MXC_STATE_AWARE_PROVISION;
    case 'start':
      return MXC_STATE_AWARE_START;
    case 'exec':
      return MXC_STATE_AWARE_EXEC;
    case 'stop':
      return MXC_STATE_AWARE_STOP;
    case 'deprovision':
      return MXC_STATE_AWARE_DEPROVISION;
    default:
      throw new MxcError('malformed_request', `unknown state-aware phase '${String(phase)}'`);
  }
}

function stateAwareFilesystem(
  arena: Arena,
  envelope: Record<string, unknown>,
): MxcTypedFilesystemPolicy | null {
  return filesystem(arena, record(envelope.filesystem) as FilesystemConfig | undefined);
}

function stateAwareNetwork(
  arena: Arena,
  envelope: Record<string, unknown>,
): MxcTypedNetworkPolicy | null {
  return network(arena, record(envelope.network) as DirectionalNetworkConfig | undefined);
}

function provision(
  arena: Arena,
  envelope: Record<string, unknown>,
): MxcTypedProvisionRequest {
  const backend = stateAwareBackend(envelope);
  if (backend === undefined) {
    throw new MxcError('malformed_request', 'typed state-aware provision requires a typed backend');
  }
  const backendSection = backend === 'isolation_session'
    ? record(envelope.isolationSession)
    : record(envelope.wslc);
  const provisionSection = record(backendSection?.provision);
  return arena.keep({
    backend: backend === 'isolation_session'
      ? MXC_STATE_AWARE_ISOLATION_SESSION
      : MXC_STATE_AWARE_WSLC,
    app_id: backend === 'isolation_session'
      ? arena.optionalUtf8(asString(provisionSection?.appId))
      : null,
    image: backend === 'wslc'
      ? arena.optionalUtf8(asString(provisionSection?.image))
      : null,
    image_tar_path: backend === 'wslc'
      ? arena.optionalUtf8(asString(provisionSection?.imageTarPath))
      : null,
    filesystem: stateAwareFilesystem(arena, envelope),
    network: stateAwareNetwork(arena, envelope),
  });
}

function exec(
  arena: Arena,
  envelope: Record<string, unknown>,
): MxcTypedExecRequest {
  const process = asProcess(envelope.process);
  const command = process?.commandLine;
  if (typeof command !== 'string') {
    throw new MxcError('malformed_request', 'state-aware exec requires process.commandLine');
  }
  const runtimeConfig = record(envelope.runtimeConfig) as RuntimeConfig | undefined;
  return arena.keep({
    command: arena.utf8(command),
    working_directory: arena.optionalUtf8(process?.cwd),
    environment: arena.environmentFromProcess(process),
    inherit_default_env: optionalBool(process?.inheritDefaultEnv),
    timeout_ms: optionalU32(process?.timeout),
    network_proxy: arena.optionalUtf8(runtimeConfig?.networkProxy),
  });
}

export function buildTypedStateAwareRequest(
  envelope: Record<string, unknown>,
  experimental: boolean,
): TypedAbiRequest<MxcTypedStateAwareRequest> {
  if (!supportsTypedStateAwareEnvelope(envelope)) {
    throw new MxcError('malformed_request', 'state-aware request is not supported by the typed ABI');
  }

  const arena = new Arena();
  const operation = stateAwareOperation(envelope.phase);
  const telemetry = record(envelope.telemetry) as TelemetryConfig | undefined;
  return {
    value: arena.keep({
      abi_version: MXC_TYPED_ABI_VERSION_1,
      struct_size: koffi.sizeof(MxcTypedStateAwareRequestType),
      operation,
      sandbox_id: operation === MXC_STATE_AWARE_PROVISION
        ? null
        : arena.optionalUtf8(asString(envelope.sandboxId)),
      provision: operation === MXC_STATE_AWARE_PROVISION
        ? provision(arena, envelope)
        : null,
      exec: operation === MXC_STATE_AWARE_EXEC
        ? exec(arena, envelope)
        : null,
      telemetry_enabled: telemetryEnabled(telemetry),
      experimental: flag(experimental),
    }),
    keepAlive: arena.keepAlive,
  };
}

export function parseStateAwareEnvelopeJson(requestJson: string): Record<string, unknown> {
  const parsed: unknown = JSON.parse(requestJson);
  const envelope = record(parsed);
  if (envelope === undefined) {
    throw new MxcError('malformed_request', 'state-aware request must be a JSON object');
  }
  return envelope;
}
