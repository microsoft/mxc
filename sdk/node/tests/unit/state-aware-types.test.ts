// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

import { describe, it } from 'node:test';
import assert from 'node:assert';
import {
  ConfigsForBackend,
  DeprovisionConfigFor,
  ExecConfigFor,
  IsolationSessionProvisionConfig,
  IsolationSessionStartConfig,
  ProvisionMetadataFor,
  ProvisionResult,
  SandboxId,
  StartMetadataFor,
  STATE_AWARE_VERSION,
  StateAwareContainmentBackend,
  StopConfigFor,
  WslcProvisionConfig,
  WslcStartConfig,
  WslcExecConfig,
  WslcStopConfig,
  WslcDeprovisionConfig,
} from '../../src/state-aware-types.js';
import { backendForSandboxId } from '../../src/state-aware-helper.js';

// These tests are primarily compile-time checks. Lines marked with
// `// @ts-expect-error` MUST trigger a TypeScript error on the line below;
// otherwise the marker itself becomes a violation and the test build fails.
// The runtime assertions are minimal placeholders so node:test sees a
// passing test for each scenario.

describe('SandboxId<C> brand', () => {
  it('rejects bare strings where SandboxId is expected', () => {
    function takesIsolationSessionId(_id: SandboxId<'isolation_session'>): void {
      // body unused
    }
    // @ts-expect-error — bare string is not a branded SandboxId.
    takesIsolationSessionId('iso:abcd');
    assert.ok(true);
  });

  it('runtime value is a string', () => {
    const id = 'iso:abcd' as SandboxId<'isolation_session'>;
    assert.strictEqual(typeof id, 'string');
  });
});

describe('STATE_AWARE_VERSION', () => {
  it('targets the SDK-owned stable v1 contract', () => {
    assert.strictEqual(STATE_AWARE_VERSION, '1.0.0');
  });
});

describe('StateAwareContainmentBackend', () => {
  it('excludes Windows Sandbox from the typed high-level lifecycle', async () => {
    // @ts-expect-error — Windows Sandbox lifecycle is raw exact 1.1 only.
    const unsupported: StateAwareContainmentBackend = 'windows_sandbox';
    const { provisionSandbox } = await import('../../src/state-aware.js');
    // @ts-expect-error — Windows Sandbox is not a high-level lifecycle backend.
    const provision = () => provisionSandbox('windows_sandbox');

    assert.ok(unsupported);
    assert.ok(provision);
    assert.throws(() => backendForSandboxId('wsb:prov-1'), /does not match a known/);
  });
});

describe('IsolationSessionProvisionConfig', () => {
  const directionalNetwork = {
    egress: { default: 'allow' },
    ingress: { default: 'allow', hostLoopback: 'allow' },
  } as const;

  it('requires a canonical unrestricted network posture', () => {
    const directional: IsolationSessionProvisionConfig = {
      network: directionalNetwork,
    };
    assert.strictEqual(directional.network.egress.default, 'allow');

    const oldVersion: IsolationSessionProvisionConfig = {
      // @ts-expect-error — high-level lifecycle configs are version-free.
      version: '0.8.0-alpha',
      network: directionalNetwork,
    };
    assert.ok(oldVersion);

    // @ts-expect-error — network is required; provision must acknowledge the unrestricted network.
    const missing: IsolationSessionProvisionConfig = {};
    assert.ok(missing);
  });

  describe('version-free lifecycle configs', () => {
    it('rejects caller-selected versions for each typed backend', () => {
      const isolation: IsolationSessionStartConfig = {
        // @ts-expect-error — the v1 SDK owns the exact contract target.
        version: '1.0.0',
      };
      const wslc: WslcStartConfig = {
        // @ts-expect-error — the v1 SDK owns the exact contract target.
        version: '1.0.0',
      };

      assert.ok(isolation);
      assert.ok(wslc);
    });
  });

  it('cannot be skipped by omitting the config argument entirely', async () => {
    // Declaring `network` required on the config type is only a real guarantee
    // if the call signature also refuses an omitted config — otherwise the
    // requirement is bypassable by passing nothing at all. `provisionSandbox`
    // takes a conditional parameter tuple so the config is mandatory exactly
    // for backends whose provision config has a required member.
    const { provisionSandbox } = await import('../../src/state-aware.js');

    // @ts-expect-error — isolation_session provision requires a config.
    const skipped = () => provisionSandbox('isolation_session');
    assert.ok(skipped);

    // Backends whose provision config is entirely optional stay skippable.
    const optional = () => provisionSandbox('wslc');
    assert.ok(optional);
  });

  it('cannot be skipped by widening the backend to the union', async () => {
    // A caller holding a variable typed as the whole backend union — rather
    // than a literal — instantiates the conditional tuple with that union. If
    // optionality were decided over the *union of configs*, the all-optional
    // WSLC member would satisfy it and make the config optional for
    // every backend, silently re-opening the hole the test above closes.
    // A union backend must behave like its strictest member.
    const { provisionSandbox } = await import('../../src/state-aware.js');
    const wide = 'isolation_session' as StateAwareContainmentBackend;

    // @ts-expect-error — the union includes a backend that requires a config.
    const widened = () => provisionSandbox(wide);
    assert.ok(widened);
  });

  it('rejects restrictive, partial, and mixed network values', () => {
    const block: IsolationSessionProvisionConfig = {
      // @ts-expect-error — defaultPolicy must be 'allow'; the backend cannot enforce a deny.
      network: { defaultPolicy: 'block', allowLocalNetwork: true },
    };
    const noLocal: IsolationSessionProvisionConfig = {
      // @ts-expect-error — allowLocalNetwork must be true; inbound is open and cannot be denied.
      network: { defaultPolicy: 'allow', allowLocalNetwork: false },
    };
    const partialDirectional: IsolationSessionProvisionConfig = {
      // @ts-expect-error — all three directional axes must explicitly allow.
      network: { egress: { default: 'allow' } },
    };
    const mixed: IsolationSessionProvisionConfig = {
      network: {
        // @ts-expect-error — legacy network fields are removed from schema 0.9.
        defaultPolicy: 'allow',
        allowLocalNetwork: true,
        ...directionalNetwork,
      },
    };
    assert.ok(block);
    assert.ok(noLocal);
    assert.ok(partialDirectional);
    assert.ok(mixed);
  });

  it('rejects filesystem', () => {
    const cfg: IsolationSessionProvisionConfig = {
      network: directionalNetwork,
      // @ts-expect-error — filesystem is rejected at provision; the backend has no host-folder-sharing primitive.
      filesystem: { readwritePaths: ['C:\\workspace'] },
    };
    assert.ok(cfg);
  });

  it('rejects ui until that feature lands Rust-side', () => {
    const cfg: IsolationSessionProvisionConfig = {
      network: directionalNetwork,
      // @ts-expect-error — ui is not exposed at provision until the Rust runtime honors it.
      ui: { disable: true, clipboard: 'none', injection: false },
    };
    assert.ok(cfg);
  });

  it('accepts an optional appId', () => {
    const cfg: IsolationSessionProvisionConfig = {
      network: directionalNetwork,
      appId: 'PFN:Contoso.App_8wekyb3d8bbwe',
    };
    assert.strictEqual(cfg.appId, 'PFN:Contoso.App_8wekyb3d8bbwe');
  });

  it('accepts an empty appId as a value distinct from omitting it', () => {
    // A future OS API may assign meaning to the empty string, so the SDK must
    // not treat it as equivalent to absent.
    const empty: IsolationSessionProvisionConfig = { network: directionalNetwork, appId: '' };
    const absent: IsolationSessionProvisionConfig = { network: directionalNetwork };
    assert.strictEqual(empty.appId, '');
    assert.strictEqual(absent.appId, undefined);
    assert.ok('appId' in empty);
    assert.ok(!('appId' in absent));
  });

  it('rejects a non-string appId', () => {
    const cfg: IsolationSessionProvisionConfig = {
      network: directionalNetwork,
      // @ts-expect-error — appId is a string.
      appId: 42,
    };
    assert.ok(cfg);
  });
});

describe('IsolationSessionStartConfig', () => {
  it('rejects appId (provision-only; fixed for the sandbox lifetime)', () => {
    const cfg: IsolationSessionStartConfig = {
      // @ts-expect-error — appId is accepted only at provision.
      appId: 'PFN:Contoso.App_8wekyb3d8bbwe',
    };
    assert.ok(cfg);
  });

  it('rejects cross-cutting fields the matrix marks as rejected', () => {
    const cfg: IsolationSessionStartConfig = {
      // @ts-expect-error — start phase does not honor filesystem.
      filesystem: { readwritePaths: ['C:\\workspace'] },
    };
    assert.ok(cfg);
  });

  it('rejects network (fixed at provision; provision-only)', () => {
    const cfg: IsolationSessionStartConfig = {
      // @ts-expect-error — network is fixed at provision; post-provision phases do not accept it.
      network: { defaultPolicy: 'allow', allowLocalNetwork: true },
    };
    assert.ok(cfg);
  });

  it('rejects configurationId', () => {
    const cfg: IsolationSessionStartConfig = {
      // @ts-expect-error — configurationId is not part of the start config.
      configurationId: 'composable',
    };
    assert.ok(cfg);
  });

  it('rejects a backend-specific field (start takes only telemetry)', () => {
    const cfg: IsolationSessionStartConfig = {
      // @ts-expect-error — start accepts no backend-specific config.
      unsupportedSetting: { nested: true },
    };
    assert.ok(cfg);
  });
});

describe('IsolationSessionExecConfig', () => {
  it('requires process', () => {
    const cfg: ExecConfigFor<'isolation_session'> = {
      process: { commandLine: 'echo hi' },
    };
    assert.strictEqual(cfg.process.commandLine, 'echo hi');

    // @ts-expect-error — exec config requires process.
    const missing: ExecConfigFor<'isolation_session'> = {};
    assert.ok(missing);
  });
});

describe('IsolationSessionStopConfig and IsolationSessionDeprovisionConfig', () => {
  it('only carry telemetry', () => {
    const stopCfg: StopConfigFor<'isolation_session'> = {};
    const deprovCfg: DeprovisionConfigFor<'isolation_session'> = {};

    const wrongStop: StopConfigFor<'isolation_session'> = {
      // @ts-expect-error — stop phase does not honor network.
      network: { defaultPolicy: 'block' },
    };
    assert.ok(stopCfg);
    assert.ok(deprovCfg);
    assert.ok(wrongStop);
  });
});

describe('ConfigsForBackend', () => {
  it('selects the IsolationSession bundle for the isolation_session backend', () => {
    const bundle: ConfigsForBackend<'isolation_session'> = {
      provision: {
        network: {
          egress: { default: 'allow' },
          ingress: { default: 'allow', hostLoopback: 'allow' },
        },
      },
      start: {},
      exec: { process: { commandLine: 'echo' } },
      stop: {},
      deprovision: {},
    };
    assert.strictEqual(bundle.exec.process.commandLine, 'echo');
  });

});

describe('SandboxId<C> brand is compile-time only; prefix is the runtime routing authority', () => {
  it('routes a force-cast wslc id to wslc despite the iso brand', () => {
    // A caller can defeat the compile-time brand with a forced cast. Routing
    // must still follow the *runtime* prefix (`wslc:`), not the (wrong) brand —
    // pinning that the brand is advisory and the prefix is authoritative.
    const misbranded = 'wslc:prov-1' as unknown as SandboxId<'isolation_session'>;
    assert.strictEqual(backendForSandboxId(misbranded), 'wslc');

    const isoId = 'iso:abcd' as SandboxId<'isolation_session'>;
    assert.strictEqual(backendForSandboxId(isoId), 'isolation_session');
  });
});

describe('ProvisionResult<C>', () => {
  it('carries backend-typed metadata for isolation_session', () => {
    const result: ProvisionResult<'isolation_session'> = {
      sandboxId: 'iso:abcd' as SandboxId<'isolation_session'>,
      metadata: {
        agentUserName: 'iso\\agent',
        agentUserSid: 'S-1-5-21-1001',
        ephemeralWorkspacePath: 'C:\\ProgramData\\ws',
      },
    };
    assert.strictEqual(result.metadata?.agentUserName, 'iso\\agent');
    assert.strictEqual(result.metadata?.agentUserSid, 'S-1-5-21-1001');
    assert.strictEqual(result.metadata?.ephemeralWorkspacePath, 'C:\\ProgramData\\ws');
  });
});

describe('WslcProvisionConfig', () => {
  it('accepts filesystem, network, and the backend-specific image knobs', () => {
    const cfg: WslcProvisionConfig = {
      filesystem: { readwritePaths: ['C:\\ws\\rw'], readonlyPaths: ['C:\\ws\\ro'] },
      network: {
        egress: { default: 'allow' },
        ingress: { default: 'allow', hostLoopback: 'allow' },
      },
      image: 'alpine:latest',
      imageTarPath: 'C:\\images\\alpine.tar',
    };
    assert.strictEqual(cfg.image, 'alpine:latest');
    assert.strictEqual(cfg.imageTarPath, 'C:\\images\\alpine.tar');
    assert.strictEqual(cfg.filesystem?.readwritePaths?.[0], 'C:\\ws\\rw');
  });

  it('is entirely optional (every member optional)', () => {
    const empty: WslcProvisionConfig = {};
    assert.ok(empty);
  });

  it('rejects an undeclared backend-specific field', () => {
    const cfg: WslcProvisionConfig = {
      // @ts-expect-error — wslc provision declares no such field.
      unsupportedSetting: { nested: true },
    };
    assert.ok(cfg);
  });

  it('rejects ui at provision', () => {
    const cfg: WslcProvisionConfig = {
      // @ts-expect-error — ui is not exposed on the wslc provision config.
      ui: { disable: true, clipboard: 'none', injection: false },
    };
    assert.ok(cfg);
  });
});

describe('WslcStartConfig / WslcStopConfig / WslcDeprovisionConfig', () => {
  it('carry only telemetry', () => {
    const start: WslcStartConfig = {};
    const stop: WslcStopConfig = {};
    const deprov: WslcDeprovisionConfig = {};
    assert.ok(start);
    assert.ok(stop);
    assert.ok(deprov);

    const wrongStart: WslcStartConfig = {
      // @ts-expect-error — start accepts no backend-specific config.
      image: 'alpine:latest',
    };
    assert.ok(wrongStart);
  });
});

describe('WslcExecConfig', () => {
  it('requires process and accepts an optional cooperative proxy', () => {
    const cfg: WslcExecConfig = {
      process: { commandLine: 'echo hi' },
      runtimeConfig: { networkProxy: 'http://127.0.0.1:8888' },
    };
    assert.strictEqual(cfg.process.commandLine, 'echo hi');

    // @ts-expect-error — exec config requires process.
    const missing: WslcExecConfig = {
      runtimeConfig: { networkProxy: 'http://127.0.0.1:8888' },
    };
    assert.ok(missing);
  });
});

describe('Wslc metadata resolves to undefined for every phase', () => {
  it('ProvisionResult carries no metadata and the id brands distinctly', () => {
    const provMeta: ProvisionMetadataFor<'wslc'> = undefined;
    const startMeta: StartMetadataFor<'wslc'> = undefined;
    assert.strictEqual(provMeta, undefined);
    assert.strictEqual(startMeta, undefined);

    const result: ProvisionResult<'wslc'> = {
      sandboxId: 'wslc:abcd' as SandboxId<'wslc'>,
    };
    assert.strictEqual(result.metadata, undefined);

    function takesWslcId(_id: SandboxId<'wslc'>): void {
      // body unused
    }
    // @ts-expect-error — an isolation_session id is not a wslc id.
    takesWslcId('iso:abcd' as SandboxId<'isolation_session'>);
    assert.ok(true);
  });

  it('routes a wslc: id to the wslc backend by prefix', () => {
    const id = 'wslc:0123abcd' as SandboxId<'wslc'>;
    assert.strictEqual(backendForSandboxId(id), 'wslc');
  });
});

describe('ConfigsForBackend selects the wslc bundle', () => {
  it('selects the Wslc bundle for the wslc backend', () => {
    const bundle: ConfigsForBackend<'wslc'> = {
      provision: { image: 'alpine:latest' },
      start: {},
      exec: { process: { commandLine: 'echo' } },
      stop: {},
      deprovision: {},
    };
    assert.strictEqual(bundle.provision.image, 'alpine:latest');
    assert.strictEqual(bundle.exec.process.commandLine, 'echo');
  });
});
