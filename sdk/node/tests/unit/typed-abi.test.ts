// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

import assert from 'node:assert';
import { describe, it } from 'node:test';
import {
  buildTypedOneShotRequest,
  buildTypedStateAwareRequest,
  MXC_CAPTURE_DENIALS_ALLOW,
  MXC_CLIPBOARD_READ,
  MXC_CONTAINMENT_PROCESS,
  MXC_CONTAINMENT_PROCESS_CONTAINER,
  MXC_CONTAINMENT_SEATBELT,
  MXC_CONTAINMENT_WSLC,
  MXC_NETWORK_ACTION_ALLOW,
  MXC_NETWORK_ACTION_DENY,
  MXC_NETWORK_PROTOCOL_TCP,
  MXC_PROCESS_SYSTEM_SETTINGS_PARAMETERS,
  MXC_PROCESS_UI_ATOMS,
  MXC_STATE_AWARE_EXEC,
  MXC_STATE_AWARE_PROVISION,
  MXC_STATE_AWARE_WSLC,
  MXC_TYPED_ABI_VERSION_1,
  type MxcUtf8Slice,
} from '../../src/bindings/typed-abi.js';
import type { RequestSpec } from '../../src/bindings/request.js';

function text(value: MxcUtf8Slice | null): string | undefined {
  if (value === null || value.data === null) return undefined;
  return value.data.toString('utf8', 0, value.len);
}

describe('typed one-shot ABI marshalling', () => {
  it('sets top-level version, size, strings, and absent environment', () => {
    const typed = buildTypedOneShotRequest({
      policy: {},
      command: 'echo hello',
      containment: { type: 'process' },
      inheritDefaultEnv: false,
      experimental: false,
    });

    assert.strictEqual(typed.value.abi_version, MXC_TYPED_ABI_VERSION_1);
    assert.ok(typed.value.struct_size > 0);
    assert.strictEqual(text(typed.value.command), 'echo hello');
    assert.strictEqual(typed.value.containment, MXC_CONTAINMENT_PROCESS);
    assert.strictEqual(typed.value.environment.is_set, 0);
    assert.strictEqual(typed.value.environment.entries, null);
  });

  it('preserves present-empty environment separately from omission', () => {
    const typed = buildTypedOneShotRequest({
      policy: {},
      command: 'echo hello',
      containment: { type: 'process' },
      environment: {},
      inheritDefaultEnv: true,
      experimental: false,
    });

    assert.strictEqual(typed.value.environment.is_set, 1);
    assert.strictEqual(typed.value.environment.entries, null);
    assert.strictEqual(typed.value.environment.len, 0);
    assert.strictEqual(typed.value.inherit_default_env, 1);
  });

  it('maps policy fields, network rule presence, ports, and telemetry', () => {
    const typed = buildTypedOneShotRequest({
      policy: {
        filesystem: {
          readonlyPaths: ['C:\\input'],
          readwritePaths: [],
          clearPolicyOnExit: false,
        },
        network: {
          egress: {
            default: 'deny',
            allow: [{
              to: [{ cidr: '10.0.0.0/8', except: ['10.1.0.0/16'] }],
              ports: [{ protocol: 'tcp', port: 443, endPort: 444 }],
            }],
            deny: [],
          },
          ingress: { default: 'allow', hostLoopback: 'deny' },
          runtimeConfig: { networkProxy: 'http://127.0.0.1:8080' },
        },
        ui: {
          allowWindows: true,
          clipboard: 'read',
          allowInputInjection: false,
        },
        timeoutMs: 30_000,
        telemetry: { enabled: false },
      },
      command: 'echo hello',
      containment: { type: 'process' },
      inheritDefaultEnv: false,
      experimental: false,
    });

    const policy = typed.value.policy!;
    assert.strictEqual(policy.filesystem!.readonly_paths.len, 1);
    assert.strictEqual(text(policy.filesystem!.readonly_paths.items![0]!), 'C:\\input');
    assert.strictEqual(policy.filesystem!.readwrite_paths.len, 0);
    assert.deepStrictEqual(policy.filesystem!.clear_policy_on_exit, { is_set: 1, value: 0 });
    assert.deepStrictEqual(policy.timeout_ms, { is_set: 1, value: 30_000 });
    assert.deepStrictEqual(policy.telemetry_enabled, { is_set: 1, value: 0 });
    assert.strictEqual(policy.ui!.allow_windows, 1);
    assert.strictEqual(policy.ui!.clipboard, MXC_CLIPBOARD_READ);

    const egress = policy.network!.egress!;
    assert.deepStrictEqual(egress.default_action, { is_set: 1, value: MXC_NETWORK_ACTION_DENY });
    assert.strictEqual(egress.allow_is_set, 1);
    assert.strictEqual(egress.allow_len, 1);
    assert.strictEqual(egress.deny_is_set, 1);
    assert.strictEqual(egress.deny_len, 0);
    const rule = egress.allow![0]!;
    assert.strictEqual(rule.to_is_set, 1);
    assert.strictEqual(rule.ports_is_set, 1);
    assert.strictEqual(text(rule.to![0]!.cidr), '10.0.0.0/8');
    assert.strictEqual(text(rule.to![0]!.except.items![0]!), '10.1.0.0/16');
    assert.deepStrictEqual(rule.ports![0]!.protocol, { is_set: 1, value: MXC_NETWORK_PROTOCOL_TCP });
    assert.deepStrictEqual(rule.ports![0]!.port, { is_set: 1, value: 443 });
    assert.deepStrictEqual(rule.ports![0]!.end_port, { is_set: 1, value: 444 });
    assert.deepStrictEqual(
      policy.network!.ingress!.default_action,
      { is_set: 1, value: MXC_NETWORK_ACTION_ALLOW },
    );
    assert.strictEqual(text(policy.network!.network_proxy), 'http://127.0.0.1:8080');
  });

  it('maps backend-specific ProcessContainer, Seatbelt, and WSLC options', () => {
    const processContainer = buildTypedOneShotRequest({
      policy: {},
      command: 'echo pc',
      containment: {
        type: 'processContainer',
        leastPrivilege: true,
        learningMode: true,
        capabilities: ['internetClient'],
        captureDenials: { mode: 'allow', outputPath: 'C:\\denials.json', retainEtl: true },
        ui: {
          isolation: 'atoms',
          desktopSystemControl: true,
          systemSettings: 'parameters',
          ime: true,
        },
        filesystem: { enumeratePaths: ['C:\\tools'] },
        network: { allowedProxyPeer: 'Contoso.Proxy_123' },
      },
      inheritDefaultEnv: false,
      experimental: true,
    });
    assert.strictEqual(processContainer.value.containment, MXC_CONTAINMENT_PROCESS_CONTAINER);
    assert.strictEqual(processContainer.value.process_container!.least_privilege, 1);
    assert.strictEqual(processContainer.value.process_container!.capture_denials!.mode, MXC_CAPTURE_DENIALS_ALLOW);
    assert.strictEqual(
      text(processContainer.value.process_container!.capture_denials!.output_path),
      'C:\\denials.json',
    );
    assert.strictEqual(processContainer.value.process_container!.ui!.isolation, MXC_PROCESS_UI_ATOMS);
    assert.strictEqual(
      processContainer.value.process_container!.ui!.system_settings,
      MXC_PROCESS_SYSTEM_SETTINGS_PARAMETERS,
    );
    assert.strictEqual(text(processContainer.value.process_container!.allowed_proxy_peer), 'Contoso.Proxy_123');
    assert.strictEqual(text(processContainer.value.process_container!.enumerate_paths.items![0]!), 'C:\\tools');

    const seatbelt = buildTypedOneShotRequest({
      policy: {},
      command: 'echo seatbelt',
      containment: {
        type: 'seatbelt',
        profileOverride: '(version 1)',
        guiAccess: true,
        nestedPty: false,
        keychainAccess: true,
        extraMachLookups: ['com.example.service'],
      },
      inheritDefaultEnv: false,
      experimental: false,
    });
    assert.strictEqual(seatbelt.value.containment, MXC_CONTAINMENT_SEATBELT);
    assert.strictEqual(text(seatbelt.value.seatbelt!.profile_override), '(version 1)');
    assert.strictEqual(seatbelt.value.seatbelt!.nested_pty, 0);
    assert.strictEqual(text(seatbelt.value.seatbelt!.extra_mach_lookups.items![0]!), 'com.example.service');

    const wslc = buildTypedOneShotRequest({
      policy: {},
      command: 'echo wslc',
      containment: {
        type: 'wslc',
        image: 'alpine:3.20',
        cpuCount: 2,
        memoryMb: 1024,
        gpu: true,
        storagePath: 'C:\\wslc',
        portMappings: [{ windowsPort: 8080, containerPort: 80 }],
      },
      inheritDefaultEnv: false,
      experimental: false,
    });
    assert.strictEqual(wslc.value.containment, MXC_CONTAINMENT_WSLC);
    assert.strictEqual(text(wslc.value.wslc!.image), 'alpine:3.20');
    assert.deepStrictEqual(wslc.value.wslc!.cpu_count, { is_set: 1, value: 2 });
    assert.deepStrictEqual(wslc.value.wslc!.memory_mb, { is_set: 1, value: 1024n });
    assert.strictEqual(wslc.value.wslc!.gpu, 1);
    assert.deepStrictEqual(wslc.value.wslc!.port_mappings![0], {
      windows_port: 8080,
      container_port: 80,
    });
  });

  it('provides JSON-defaulted backend values for omitted private-request fields', () => {
    const request: RequestSpec = {
      policy: {},
      command: 'echo defaults',
      containment: { type: 'seatbelt' },
      inheritDefaultEnv: false,
      experimental: false,
    };
    const typed = buildTypedOneShotRequest(request);
    assert.strictEqual(typed.value.seatbelt!.nested_pty, 1);
  });
});

describe('typed state-aware ABI marshalling', () => {
  it('maps WSLC provision policy and backend image fields', () => {
    const typed = buildTypedStateAwareRequest({
      version: '1.0.0',
      phase: 'provision',
      containment: 'wslc',
      filesystem: { readwritePaths: ['C:\\workspace'] },
      network: {
        egress: { default: 'allow' },
        ingress: { default: 'allow', hostLoopback: 'allow' },
      },
      wslc: { provision: { image: 'alpine:3.20', imageTarPath: 'C:\\images\\alpine.tar' } },
      telemetry: { enabled: true },
    }, false);

    assert.strictEqual(typed.value.operation, MXC_STATE_AWARE_PROVISION);
    assert.strictEqual(typed.value.provision!.backend, MXC_STATE_AWARE_WSLC);
    assert.strictEqual(text(typed.value.provision!.image), 'alpine:3.20');
    assert.strictEqual(text(typed.value.provision!.image_tar_path), 'C:\\images\\alpine.tar');
    assert.strictEqual(text(typed.value.provision!.filesystem!.readwrite_paths.items![0]!), 'C:\\workspace');
    assert.deepStrictEqual(typed.value.telemetry_enabled, { is_set: 1, value: 1 });
  });

  it('maps typed exec process fields and cooperative proxy runtime config', () => {
    const typed = buildTypedStateAwareRequest({
      version: '1.0.0',
      phase: 'exec',
      sandboxId: 'wslc:abc',
      process: {
        commandLine: 'echo hi',
        cwd: '/work',
        env: ['A=B', 'EMPTY'],
        inheritDefaultEnv: true,
        timeout: 250,
      },
      runtimeConfig: { networkProxy: 'http://127.0.0.1:8888' },
    }, true);

    assert.strictEqual(typed.value.operation, MXC_STATE_AWARE_EXEC);
    assert.strictEqual(typed.value.experimental, 1);
    assert.strictEqual(text(typed.value.sandbox_id), 'wslc:abc');
    assert.strictEqual(text(typed.value.exec!.command), 'echo hi');
    assert.strictEqual(text(typed.value.exec!.working_directory), '/work');
    assert.deepStrictEqual(typed.value.exec!.inherit_default_env, { is_set: 1, value: 1 });
    assert.deepStrictEqual(typed.value.exec!.timeout_ms, { is_set: 1, value: 250 });
    assert.strictEqual(typed.value.exec!.environment.is_set, 1);
    assert.strictEqual(text(typed.value.exec!.environment.entries![0]!.key), 'A');
    assert.strictEqual(text(typed.value.exec!.environment.entries![0]!.value), 'B');
    assert.strictEqual(text(typed.value.exec!.environment.entries![1]!.key), 'EMPTY');
    assert.strictEqual(text(typed.value.exec!.environment.entries![1]!.value), '');
    assert.strictEqual(text(typed.value.exec!.network_proxy), 'http://127.0.0.1:8888');
  });
});
