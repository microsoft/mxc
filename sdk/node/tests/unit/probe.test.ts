// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

import { afterEach, describe, it } from 'node:test';
import assert from 'node:assert';
import {
  _setRequestProbeRunner,
  probeSandboxSupport,
} from '../../src/probe.js';
import type { ContainerConfig } from '../../src/types.js';

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

afterEach(() => _setRequestProbeRunner());

describe('probeSandboxSupport', () => {
  it('runs the empty request probe', () => {
    let received: readonly string[] = [];
    _setRequestProbeRunner((args) => {
      received = args;
      return JSON.stringify(completeProbe);
    });

    assert.strictEqual(probeSandboxSupport().tier, 'appcontainer-dacl');
    assert.deepStrictEqual(received, ['--probe']);
  });

  it('passes a config through config-base64', () => {
    let received: readonly string[] = [];
    const config = {
      version: '0.9.0-alpha' as const,
      containment: 'processcontainer' as const,
      process: { commandLine: 'cmd /c exit 0' },
    } satisfies ContainerConfig;
    _setRequestProbeRunner((args) => {
      received = args;
      return JSON.stringify(completeProbe);
    });

    probeSandboxSupport(config);

    assert.deepStrictEqual(received.slice(0, 2), ['--probe', '--config-base64']);
    assert.deepStrictEqual(
      JSON.parse(Buffer.from(received[2], 'base64').toString('utf-8')),
      config,
    );
  });

  it('rejects malformed probe output', () => {
    _setRequestProbeRunner(() => JSON.stringify({ warnings: [], probes: {} }));
    assert.throws(
      () => probeSandboxSupport(),
      /invalid request probe output/,
    );
  });
});
