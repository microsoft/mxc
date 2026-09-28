// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

import assert from 'node:assert/strict';
import * as fs from 'node:fs';
import { afterEach, describe, it } from 'node:test';
import {
  _setRequestProbeDependencies,
  probeSandboxSupport,
} from '../../src/probe.js';

const completeProbe = {
  tier: 'appcontainer-dacl',
  needsDaclAugmentation: true,
  warnings: [],
  probes: {
    baseContainerApiPresent: true,
    nativeCaptureAvailable: false,
    guardedCaptureAvailable: true,
    bfscfgPresent: false,
    bfsCompiledIn: false,
    baseContainerSupportsDenyPaths: false,
    baseContainerSupportsEnumeratePaths: false,
    baseContainerSupportsIngressHostLoopbackAllow: false,
    isolationSessionAvailable: false,
    hyperlightAvailable: false,
    uiCapabilities: {
      canBlockClipboardRead: true,
      canBlockClipboardWrite: true,
      canBlockInputInjection: true,
      canBlockInputMethodChanges: true,
      canBlockExternalUiObjects: true,
      canBlockGlobalUiNamespace: true,
      canBlockDesktopSwitching: true,
      canBlockLogoffOrShutdown: true,
      canBlockSystemParameterChanges: true,
      canBlockDisplaySettingsChanges: true,
    },
  },
};

function cloneCompleteProbe(): Record<string, unknown> {
  return JSON.parse(JSON.stringify(completeProbe)) as Record<string, unknown>;
}

function runProbeOutput(payload: unknown) {
  _setRequestProbeDependencies(
    () => JSON.stringify(payload),
    () => 'wxc-exec.exe',
    'win32',
  );
  return probeSandboxSupport();
}

function assertProbeOutputRejected(payload: unknown): void {
  assert.throws(
    () => runProbeOutput(payload),
    /invalid request probe output/,
  );
}

afterEach(() => _setRequestProbeDependencies());

describe('probeSandboxSupport', () => {
  it('serializes the config, invokes --probe, and removes the temp file', () => {
    let configPath = '';
    _setRequestProbeDependencies((_executable, args) => {
      assert.equal(args[0], '--probe');
      configPath = args[1];
      const config = JSON.parse(fs.readFileSync(configPath, 'utf-8')) as {
        containment: string;
      };
      assert.equal(config.containment, 'processcontainer');
      return JSON.stringify(completeProbe);
    }, () => 'wxc-exec.exe', 'win32');

    const output = probeSandboxSupport({
      version: '0.9.0-alpha',
      containment: 'processcontainer',
      process: { commandLine: 'cmd /c exit 0' },
    });

    assert.equal(output.tier, 'appcontainer-dacl');
    assert.equal(fs.existsSync(configPath), false);
  });

  it('rejects non-ProcessContainer executor failures and cleans up', () => {
    let configPath = '';
    _setRequestProbeDependencies((_executable, args) => {
      configPath = args[1];
      const error = new Error('Command failed') as Error & { stderr: string };
      error.stderr =
        'Error: request-aware probe supports only ProcessContainer containment; got wslc';
      throw error;
    }, () => 'wxc-exec.exe', 'win32');

    assert.throws(
      () => probeSandboxSupport({
        version: '0.9.0-alpha',
        containment: 'wslc',
        process: { commandLine: 'echo hi' },
      }),
      /supports only ProcessContainer containment; got wslc/,
    );
    assert.equal(fs.existsSync(configPath), false);
  });

  it('surfaces malformed executor output', () => {
    _setRequestProbeDependencies(
      () => 'not json',
      () => 'wxc-exec.exe',
      'win32',
    );
    assert.throws(() => probeSandboxSupport(), /invalid request probe JSON/);
  });

  it('rejects complete facts with neither a tier nor an error', () => {
    const payload = cloneCompleteProbe();
    delete payload.tier;
    delete payload.needsDaclAugmentation;

    assertProbeOutputRejected(payload);
  });

  it('rejects missing warnings', () => {
    const payload = cloneCompleteProbe();
    delete payload.warnings;

    assertProbeOutputRejected(payload);
  });

  it('accepts a complete output envelope', () => {
    const output = runProbeOutput(cloneCompleteProbe());

    assert.equal(output.tier, 'appcontainer-dacl');
    assert.equal(output.needsDaclAugmentation, true);
  });

  it('rejects an unknown envelope field', () => {
    const payload = cloneCompleteProbe();
    payload.unknownEnvelopeField = true;

    assertProbeOutputRejected(payload);
  });

  it('rejects an unknown probe facts field', () => {
    const payload = cloneCompleteProbe();
    const probes = payload.probes as Record<string, unknown>;
    probes.unknownProbeField = true;

    assertProbeOutputRejected(payload);
  });

  it('rejects an unknown UI capability field', () => {
    const payload = cloneCompleteProbe();
    const probes = payload.probes as Record<string, unknown>;
    const uiCapabilities = probes.uiCapabilities as Record<string, unknown>;
    uiCapabilities.unknownUiField = true;

    assertProbeOutputRejected(payload);
  });

  it('rejects a missing required probe boolean', () => {
    const payload = cloneCompleteProbe();
    const probes = payload.probes as Record<string, unknown>;
    delete probes.bfscfgPresent;

    assertProbeOutputRejected(payload);
  });

  it('rejects a missing required UI boolean', () => {
    const payload = cloneCompleteProbe();
    const probes = payload.probes as Record<string, unknown>;
    const uiCapabilities = probes.uiCapabilities as Record<string, unknown>;
    delete uiCapabilities.canBlockClipboardRead;

    assertProbeOutputRejected(payload);
  });

  it('rejects unknown and non-string tiers', () => {
    for (const tier of ['unknown-tier', 1]) {
      const payload = cloneCompleteProbe();
      payload.tier = tier;

      assertProbeOutputRejected(payload);
    }
  });

  it('rejects success output without DACL augmentation state', () => {
    const payload = cloneCompleteProbe();
    delete payload.needsDaclAugmentation;

    assertProbeOutputRejected(payload);
  });

  it('accepts an error envelope without tier selection fields', () => {
    const payload = cloneCompleteProbe();
    delete payload.tier;
    delete payload.needsDaclAugmentation;
    payload.error = 'tier detection failed';

    const output = runProbeOutput(payload);

    assert.equal(output.tier, undefined);
    assert.equal(output.needsDaclAugmentation, undefined);
    assert.equal(output.error, 'tier detection failed');
  });

  it('rejects DACL augmentation state on an error envelope', () => {
    const payload = cloneCompleteProbe();
    delete payload.tier;
    payload.error = 'tier detection failed';

    assertProbeOutputRejected(payload);
  });

  it('rejects off-Windows calls before executor discovery', () => {
    _setRequestProbeDependencies(
      () => JSON.stringify(completeProbe),
      () => {
        throw new Error('must not resolve');
      },
      'linux',
    );
    assert.throws(
      () => probeSandboxSupport(),
      /available only for Windows ProcessContainer/,
    );
  });

  it('surfaces a missing executor', () => {
    _setRequestProbeDependencies(undefined, () => null, 'win32');
    assert.throws(() => probeSandboxSupport(), /wxc-exec\.exe not found/);
  });
});
