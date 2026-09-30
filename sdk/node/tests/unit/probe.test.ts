// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

import assert from 'node:assert/strict';
import { afterEach, describe, it } from 'node:test';
import { readProbeJsonWithNative } from '../../src/bindings/probe.js';
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
  it('serializes the config and forwards it to the native binding', () => {
    let forwarded: string | undefined;
    _setRequestProbeDependencies((requestJson) => {
      forwarded = requestJson;
      const config = JSON.parse(requestJson ?? '') as {
        containment: string;
      };
      assert.equal(config.containment, 'processcontainer');
      return JSON.stringify(completeProbe);
    }, 'win32');

    const output = probeSandboxSupport({
      version: '0.9.0-alpha',
      containment: 'processcontainer',
      process: { commandLine: 'cmd /c exit 0' },
    });

    assert.equal(output.tier, 'appcontainer-dacl');
    assert.equal(typeof forwarded, 'string');
  });

  it('uses the default native request when config is omitted', () => {
    let forwarded = 'not-called';
    _setRequestProbeDependencies((requestJson) => {
      forwarded = requestJson ?? 'default';
      return JSON.stringify(completeProbe);
    }, 'win32');

    const output = probeSandboxSupport();

    assert.equal(output.tier, 'appcontainer-dacl');
    assert.equal(forwarded, 'default');
  });

  it('uses the default native request when config is explicitly undefined', () => {
    let forwarded = 'not-called';
    _setRequestProbeDependencies((requestJson) => {
      forwarded = requestJson ?? 'default';
      return JSON.stringify(completeProbe);
    }, 'win32');

    probeSandboxSupport(undefined);

    assert.equal(forwarded, 'default');
  });

  it('rejects a supplied config that does not serialize to a string', () => {
    let nativeCalls = 0;
    _setRequestProbeDependencies(() => {
      nativeCalls += 1;
      return JSON.stringify(completeProbe);
    }, 'win32');
    const config = {
      toJSON: () => undefined,
    };

    assert.throws(
      () => probeSandboxSupport(config as never),
      /config must serialize to a JSON string/,
    );
    assert.equal(nativeCalls, 0);
  });

  it('rejects other supplied values that stringify to undefined', () => {
    let nativeCalls = 0;
    _setRequestProbeDependencies(() => {
      nativeCalls += 1;
      return JSON.stringify(completeProbe);
    }, 'win32');

    for (const config of [() => undefined, Symbol('config')]) {
      assert.throws(
        () => probeSandboxSupport(config as never),
        /config must serialize to a JSON string/,
      );
    }
    assert.equal(nativeCalls, 0);
  });

  it('preserves native probe failures', () => {
    const nativeError = new Error('unsupported containment');
    _setRequestProbeDependencies(() => {
      throw nativeError;
    }, 'win32');

    assert.throws(() => {
      probeSandboxSupport({
        version: '0.9.0-alpha',
        containment: 'wslc',
        process: { commandLine: 'echo hi' },
      });
    }, (error) => error === nativeError);
  });

  it('surfaces malformed native output', () => {
    _setRequestProbeDependencies(
      () => 'not json',
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
    let nativeCalls = 0;
    _setRequestProbeDependencies(
      () => {
        nativeCalls += 1;
        return JSON.stringify(completeProbe);
      },
      'linux',
    );
    assert.throws(
      () => probeSandboxSupport(),
      /available only for Windows ProcessContainer/,
    );
    assert.equal(nativeCalls, 0);
  });

  it('reports serialization failures before off-Windows platform errors', () => {
    let nativeCalls = 0;
    _setRequestProbeDependencies(
      () => {
        nativeCalls += 1;
        return JSON.stringify(completeProbe);
      },
      'linux',
    );

    assert.throws(
      () => probeSandboxSupport({ toJSON: () => undefined } as never),
      /config must serialize to a JSON string/,
    );
    assert.equal(nativeCalls, 0);
  });
});

describe('request probe native ownership', () => {
  for (const pointer of [null, undefined, 0, 0n]) {
    it(`rejects ${String(pointer)} without freeing`, () => {
      let frees = 0;
      assert.throws(
        () => readProbeJsonWithNative({
          probeRequest: (_request, output) => {
            output[0] = pointer;
            return 0;
          },
          freeString: () => { frees += 1; },
          freeError: () => {},
        }),
        /null success result/,
      );
      assert.equal(frees, 0);
    });
  }

  it('preserves native status and error detail', () => {
    let errorFrees = 0;
    assert.throws(
      () => readProbeJsonWithNative({
        probeRequest: () => 2,
        freeString: () => {},
        freeError: () => { errorFrees += 1; },
      }),
      (error) => error instanceof Error
        && 'code' in error
        && error.code === 'unsupported_containment'
        && error.message.includes('status 2'),
    );
    assert.equal(errorFrees, 1);
  });

  it('forwards the request, decodes, and frees exactly once', () => {
    const pointer = { address: 1 };
    const freed: unknown[] = [];
    let forwarded: string | null | undefined;
    const json = readProbeJsonWithNative(
      {
        probeRequest: (requestJson, output) => {
          forwarded = requestJson;
          output[0] = pointer;
          return 0;
        },
        freeString: (candidate) => freed.push(candidate),
        freeError: () => {},
      },
      '{"version":"0.9.0-alpha"}',
      (candidate) => candidate === pointer ? '{}' : undefined,
    );

    assert.equal(forwarded, '{"version":"0.9.0-alpha"}');
    assert.equal(json, '{}');
    assert.deepEqual(freed, [pointer]);
  });

  it('passes null for the default request', () => {
    const pointer = { address: 1 };
    let forwarded: string | null | undefined;
    readProbeJsonWithNative(
      {
        probeRequest: (requestJson, output) => {
          forwarded = requestJson;
          output[0] = pointer;
          return 0;
        },
        freeString: () => {},
        freeError: () => {},
      },
      undefined,
      () => '{}',
    );
    assert.equal(forwarded, null);
  });

  it('frees after decode failure', () => {
    const pointer = { address: 1 };
    let frees = 0;
    assert.throws(
      () => readProbeJsonWithNative(
        {
          probeRequest: (_request, output) => {
            output[0] = pointer;
            return 0;
          },
          freeString: () => { frees += 1; },
          freeError: () => {},
        },
        undefined,
        () => { throw new Error('decode failed'); },
      ),
      /decode failed/,
    );
    assert.equal(frees, 1);
  });

  it('frees an undecodable non-null pointer', () => {
    const pointer = { address: 1 };
    let frees = 0;
    assert.throws(
      () => readProbeJsonWithNative(
        {
          probeRequest: (_request, output) => {
            output[0] = pointer;
            return 0;
          },
          freeString: () => { frees += 1; },
          freeError: () => {},
        },
        undefined,
        () => undefined,
      ),
      /undecodable string/,
    );
    assert.equal(frees, 1);
  });
});
