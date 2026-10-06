// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { pathToFileURL } from 'node:url';
import * as path from 'node:path';
import { afterEach, describe, it } from 'node:test';
import {
  _setProbeNativeDependencies,
  readProbeJson,
  readProbeJsonWithNative,
} from '../../src/bindings/probe.js';
import { findMxcFfiLibrary } from '../../src/native-library.js';
import {
  _setRequestProbeDependencies,
  probe,
} from '../../src/v1/probe.js';

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
    baseContainerSupportsIdentitylessLoopbackProxy: false,
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
  return probe();
}

function assertProbeOutputRejected(payload: unknown): void {
  assert.throws(
    () => runProbeOutput(payload),
    /invalid request probe output/,
  );
}

afterEach(() => {
  _setRequestProbeDependencies();
  _setProbeNativeDependencies();
});

describe('probe', () => {
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

    const output = probe({
      containment: { type: 'processcontainer' },
      command: 'cmd /c exit 0',
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

    const output = probe();

    assert.equal(output.tier, 'appcontainer-dacl');
    assert.equal(forwarded, 'default');
  });

  it('uses the default native request when config is explicitly undefined', () => {
    let forwarded = 'not-called';
    _setRequestProbeDependencies((requestJson) => {
      forwarded = requestJson ?? 'default';
      return JSON.stringify(completeProbe);
    }, 'win32');

    probe(undefined);

    assert.equal(forwarded, 'default');
  });

  it('rejects a request without a command before dispatch', () => {
    let nativeCalls = 0;
    _setRequestProbeDependencies(() => {
      nativeCalls += 1;
      return JSON.stringify(completeProbe);
    }, 'win32');
    const config = { command: undefined };

    assert.throws(
      () => probe(config as never),
      /command must be a non-empty string/,
    );
    assert.equal(nativeCalls, 0);
  });

  it('rejects non-request values before dispatch', () => {
    let nativeCalls = 0;
    _setRequestProbeDependencies(() => {
      nativeCalls += 1;
      return JSON.stringify(completeProbe);
    }, 'win32');

    for (const config of [() => undefined, Symbol('config')]) {
      assert.throws(
        () => probe(config as never),
        (error) => error instanceof Error,
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
      probe({
        containment: { type: 'wslc' },
        command: 'echo hi',
      });
    }, (error) => error === nativeError);
  });

  it('surfaces malformed native output', () => {
    _setRequestProbeDependencies(
      () => 'not json',
      'win32',
    );
    assert.throws(() => probe(), /invalid request probe JSON/);
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

  it('preserves identity-less proxy support with or without general ingress', () => {
    for (const [supported, ingressSupported] of [[false, false], [true, false], [true, true]]) {
      const output = runProbeOutput({
        ...completeProbe,
        tier: 'base-container',
        needsDaclAugmentation: false,
        probes: {
          ...completeProbe.probes,
          baseContainerSupportsIdentitylessLoopbackProxy: supported,
          baseContainerSupportsIngressHostLoopbackAllow: ingressSupported,
        },
      });
      assert.equal(output.probes.baseContainerSupportsIdentitylessLoopbackProxy, supported);
      assert.equal(output.probes.baseContainerSupportsIngressHostLoopbackAllow, ingressSupported);
    }
  });

  it('rejects missing or invalid identity-less loopback proxy facts', () => {
    for (const value of [undefined, null, 'true', 1]) {
      assertProbeOutputRejected({
        ...completeProbe,
        probes: {
          ...completeProbe.probes,
          baseContainerSupportsIdentitylessLoopbackProxy: value,
        },
      });
    }
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
      () => probe(),
      /available only for Windows ProcessContainer/,
    );
    assert.equal(nativeCalls, 0);
  });

  it('rejects malformed requests before off-Windows platform errors', () => {
    let nativeCalls = 0;
    _setRequestProbeDependencies(
      () => {
        nativeCalls += 1;
        return JSON.stringify(completeProbe);
      },
      'linux',
    );

    assert.throws(
      () => probe({ command: undefined } as never),
      /command must be a non-empty string/,
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

  describe('request probe production wiring', () => {
    function installNative(
      probeStatus: number,
      events: string[],
      decode: () => string | undefined = () => '{}',
    ): void {
      const pointer = { address: 1 };
      _setProbeNativeDependencies(
        (() => ({
          path: 'fake',
          version: () => 'test',
          handle: {
            unload: () => events.push('unload'),
          },
        })) as never,
        ((_: unknown, spec: { symbol: string }) => {
          if (spec.symbol === 'mxc_probe_request_json_with_error') {
            return (_request: string | null, output: unknown[]) => {
              events.push('probe');
              output[0] = pointer;
              return probeStatus;
            };
          }
          if (spec.symbol === 'mxc_string_free') {
            return () => events.push('free-string');
          }
          return () => events.push('free-error');
        }) as never,
        (() => {
          events.push('decode');
          return decode();
        }) as never,
      );
    }

    it('unloads after decoding and freeing a successful result', () => {
      const events: string[] = [];
      installNative(0, events);

      assert.equal(readProbeJson(), '{}');
      assert.deepEqual(events, ['probe', 'decode', 'free-string', 'unload']);
    });

    it('unloads after freeing a native error', () => {
      const events: string[] = [];
      installNative(2, events);

      assert.throws(() => readProbeJson(), /status 2/);
      assert.deepEqual(events, ['probe', 'free-error', 'unload']);
    });

    it('unloads after decode failure and result free', () => {
      const events: string[] = [];
      installNative(0, events, () => {
        throw new Error('decode failed');
      });

      assert.throws(() => readProbeJson(), /decode failed/);
      assert.deepEqual(events, ['probe', 'decode', 'free-string', 'unload']);
    });

    it('unloads when symbol binding fails', () => {
      const events: string[] = [];
      _setProbeNativeDependencies(
        (() => ({
          path: 'fake',
          version: () => 'test',
          handle: { unload: () => events.push('unload') },
        })) as never,
        (() => {
          throw new Error('binding failed');
        }) as never,
      );

      assert.throws(() => readProbeJson(), /binding failed/);
      assert.deepEqual(events, ['unload']);
    });

    it('unloads a null success result without freeing it', () => {
      const events: string[] = [];
      _setProbeNativeDependencies(
        (() => ({
          path: 'fake',
          version: () => 'test',
          handle: { unload: () => events.push('unload') },
        })) as never,
        ((_: unknown, spec: { symbol: string }) => {
          if (spec.symbol === 'mxc_probe_request_json_with_error') {
            return (_request: string | null, output: unknown[]) => {
              events.push('probe');
              output[0] = null;
              return 0;
            };
          }
          if (spec.symbol === 'mxc_string_free') {
            return () => events.push('free-string');
          }
          return () => events.push('free-error');
        }) as never,
      );

      assert.throws(() => readProbeJson(), /null success result/);
      assert.deepEqual(events, ['probe', 'unload']);
    });

    it('survives repeated real loads and a malformed native request', {
      skip: process.platform !== 'win32' || findMxcFfiLibrary() === null
        ? 'requires a built Windows mxc_ffi library'
        : false,
    }, () => {
      const entrypoint = pathToFileURL(path.join(process.cwd(), 'dist', 'v1', 'index.js')).href;
      const script = `
        import { probe } from ${JSON.stringify(entrypoint)};
        const first = probe();
        const second = probe();
        const hasValidResult = (result) =>
          result.probes && (result.tier !== undefined || result.error !== undefined);
        if (!hasValidResult(first) || !hasValidResult(second)) {
          throw new Error('invalid probe result');
        }
        try {
          probe({
            containment: { type: 'processcontainer' },
            command: 'cmd /c exit 0',
            ui: { disable: 'malformed' },
          });
          throw new Error('malformed request unexpectedly succeeded');
        } catch (error) {
          if (error?.code !== 'malformed_request') throw error;
        }
        console.log('native-probe-ok');
      `;
      const result = spawnSync(
        process.execPath,
        ['--input-type=module', '-e', script],
        { encoding: 'utf8' },
      );

      assert.equal(result.status, 0, result.stderr || result.stdout);
      assert.match(result.stdout, /native-probe-ok/);
    });
  });

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
