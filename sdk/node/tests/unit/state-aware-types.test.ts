// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

import { describe, it } from 'node:test';
import assert from 'node:assert';
import { inspect } from 'node:util';
import {
  ConfigsForBackend,
  DeprovisionConfigFor,
  ExecConfigFor,
  IsolationSessionProvisionConfig,
  IsolationSessionStartConfig,
  IsolationSessionUserConfig,
  ProvisionMetadataFor,
  ProvisionResult,
  SandboxId,
  StartMetadataFor,
  StopConfigFor,
  WindowsSandboxProvisionConfig,
  WindowsSandboxStartConfig,
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

describe('IsolationSessionProvisionConfig', () => {
  // The one accepted network value: the unrestricted-network acknowledgment.
  const network: { defaultPolicy: 'allow'; allowLocalNetwork: true } = {
    defaultPolicy: 'allow',
    allowLocalNetwork: true,
  };

  it('requires the canonical network acknowledgment', () => {
    const ok: IsolationSessionProvisionConfig = { version: '0.6.0-alpha', network };
    assert.strictEqual(ok.network.defaultPolicy, 'allow');
    assert.strictEqual(ok.network.allowLocalNetwork, true);

    // @ts-expect-error — network is required; provision must acknowledge the unrestricted network.
    const missing: IsolationSessionProvisionConfig = { version: '0.6.0-alpha' };
    assert.ok(missing);
  });

  it('rejects any network value other than the canonical acknowledgment', () => {
    const block: IsolationSessionProvisionConfig = {
      // @ts-expect-error — defaultPolicy must be 'allow'; the backend cannot enforce a deny.
      network: { defaultPolicy: 'block', allowLocalNetwork: true },
    };
    const noLocal: IsolationSessionProvisionConfig = {
      // @ts-expect-error — allowLocalNetwork must be true; inbound is open and cannot be denied.
      network: { defaultPolicy: 'allow', allowLocalNetwork: false },
    };
    assert.ok(block);
    assert.ok(noLocal);
  });

  it('rejects filesystem', () => {
    const cfg: IsolationSessionProvisionConfig = {
      network,
      // @ts-expect-error — filesystem is rejected at provision; the backend has no host-folder-sharing primitive.
      filesystem: { readwritePaths: ['C:\\workspace'] },
    };
    assert.ok(cfg);
  });

  it('rejects ui until that feature lands Rust-side', () => {
    const cfg: IsolationSessionProvisionConfig = {
      network,
      // @ts-expect-error — ui is not exposed at provision until the Rust runtime honors it.
      ui: { disable: true, clipboard: 'none', injection: false },
    };
    assert.ok(cfg);
  });

  it('accepts user only as an IsolationSessionUserConfig instance', () => {
    const ok: IsolationSessionProvisionConfig = {
      network,
      user: new IsolationSessionUserConfig('alice@contoso.com', 'tok'),
    };
    const bare: IsolationSessionProvisionConfig = {
      network,
      // @ts-expect-error — user must be constructed via IsolationSessionUserConfig for wamToken redaction.
      user: { upn: 'alice@contoso.com', wamToken: 'tok' },
    };
    assert.strictEqual(ok.user?.upn, 'alice@contoso.com');
    assert.ok(bare);
  });

  it('accepts an optional appId', () => {
    const cfg: IsolationSessionProvisionConfig = {
      network,
      appId: 'Contoso.App_8wekyb3d8bbwe',
    };
    assert.strictEqual(cfg.appId, 'Contoso.App_8wekyb3d8bbwe');
  });

  it('accepts an empty appId as a value distinct from omitting it', () => {
    // A future OS API may assign meaning to the empty string, so the SDK must
    // not treat it as equivalent to absent.
    const empty: IsolationSessionProvisionConfig = { network, appId: '' };
    const absent: IsolationSessionProvisionConfig = { network };
    assert.strictEqual(empty.appId, '');
    assert.strictEqual(absent.appId, undefined);
    assert.ok('appId' in empty);
    assert.ok(!('appId' in absent));
  });

  it('rejects a non-string appId', () => {
    const cfg: IsolationSessionProvisionConfig = {
      network,
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
      appId: 'Contoso.App_8wekyb3d8bbwe',
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

  it('rejects configurationId (sizing profiles were removed)', () => {
    const cfg: IsolationSessionStartConfig = {
      // @ts-expect-error — configurationId is no longer part of the start config.
      configurationId: 'composable',
    };
    assert.ok(cfg);
  });

  it('accepts user only as an IsolationSessionUserConfig instance', () => {
    const ok: IsolationSessionStartConfig = {
      user: new IsolationSessionUserConfig('alice@contoso.com', 'tok'),
    };
    const bare: IsolationSessionStartConfig = {
      // @ts-expect-error — user must be constructed via IsolationSessionUserConfig for wamToken redaction.
      user: { upn: 'alice@contoso.com', wamToken: 'tok' },
    };
    assert.strictEqual(ok.user?.wamToken, 'tok');
    assert.ok(bare);
  });
});

describe('IsolationSessionUserConfig', () => {
  it('redacts wamToken under util.inspect', () => {
    const user = new IsolationSessionUserConfig('alice@contoso.com', 'super-secret');
    const inspected = inspect(user);
    assert.ok(inspected.includes('alice@contoso.com'), `got: ${inspected}`);
    assert.ok(inspected.includes('<redacted>'), `got: ${inspected}`);
    assert.ok(!inspected.includes('super-secret'), `got: ${inspected}`);
  });

  it('JSON.stringify preserves both fields for wire serialisation', () => {
    const user = new IsolationSessionUserConfig('alice@contoso.com', 'super-secret');
    const json = JSON.parse(JSON.stringify(user));
    assert.strictEqual(json.upn, 'alice@contoso.com');
    assert.strictEqual(json.wamToken, 'super-secret');
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
  it('only carry version', () => {
    const stopCfg: StopConfigFor<'isolation_session'> = { version: '0.6.0-alpha' };
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
      provision: { version: '0.6.0-alpha', network: { defaultPolicy: 'allow', allowLocalNetwork: true } },
      start: {},
      exec: { process: { commandLine: 'echo' } },
      stop: {},
      deprovision: {},
    };
    assert.strictEqual(bundle.exec.process.commandLine, 'echo');
  });

  it('selects the WindowsSandbox bundle for the windows_sandbox backend', () => {
    const bundle: ConfigsForBackend<'windows_sandbox'> = {
      provision: { version: '0.6.0-alpha', filesystem: { readwritePaths: ['C:\\workspace'] } },
      start: {},
      exec: { process: { commandLine: 'echo' } },
      stop: {},
      deprovision: {},
    };
    assert.strictEqual(bundle.provision.filesystem?.readwritePaths?.[0], 'C:\\workspace');
  });
});

describe('WindowsSandboxProvisionConfig', () => {
  it('accepts version and filesystem (incl. deniedPaths)', () => {
    const cfg: WindowsSandboxProvisionConfig = {
      version: '0.6.0-alpha',
      filesystem: {
        readwritePaths: ['C:\\workspace'],
        readonlyPaths: ['C:\\inputs'],
        deniedPaths: ['C:\\secrets'],
      },
    };
    assert.deepStrictEqual(cfg.filesystem?.deniedPaths, ['C:\\secrets']);
  });

  it('rejects the Entra user bundle (WindowsSandbox has no Entra surface)', () => {
    const cfg: WindowsSandboxProvisionConfig = {
      // @ts-expect-error — windows_sandbox provision has no `user` bundle.
      user: new IsolationSessionUserConfig('alice@contoso.com', 'tok'),
    };
    assert.ok(cfg);
  });

  it('rejects network and ui at provision', () => {
    const withNetwork: WindowsSandboxProvisionConfig = {
      // @ts-expect-error — network is not exposed on the windows_sandbox provision config.
      network: { defaultPolicy: 'block' },
    };
    const withUi: WindowsSandboxProvisionConfig = {
      // @ts-expect-error — ui is not exposed on the windows_sandbox provision config.
      ui: { disable: true, clipboard: 'none', injection: false },
    };
    assert.ok(withNetwork);
    assert.ok(withUi);
  });
});

describe('WindowsSandboxStartConfig', () => {
  it('carries only version (no configurationId, no user)', () => {
    const ok: WindowsSandboxStartConfig = { version: '0.6.0-alpha' };
    assert.strictEqual(ok.version, '0.6.0-alpha');

    const withConfigurationId: WindowsSandboxStartConfig = {
      // @ts-expect-error — windows_sandbox start has no configurationId.
      configurationId: 'small',
    };
    assert.ok(withConfigurationId);

    const withUser: WindowsSandboxStartConfig = {
      // @ts-expect-error — windows_sandbox start has no Entra `user` bundle.
      user: new IsolationSessionUserConfig('alice@contoso.com', 'tok'),
    };
    assert.ok(withUser);
  });
});

describe('WindowsSandbox SandboxId<C> brand', () => {
  it('runtime value is a string and brands distinctly from isolation_session', () => {
    const id = 'wsb:prov-1' as SandboxId<'windows_sandbox'>;
    assert.strictEqual(typeof id, 'string');

    function takesWsbId(_id: SandboxId<'windows_sandbox'>): void {
      // body unused
    }
    // @ts-expect-error — an isolation_session id is not a windows_sandbox id.
    takesWsbId('iso:abcd' as SandboxId<'isolation_session'>);
    assert.ok(true);
  });
});

describe('WindowsSandbox metadata resolves to undefined for every phase', () => {
  it('typed metadata accessors are undefined and ProvisionResult carries no metadata', () => {
    // These assignments only compile if the *MetadataFor<'windows_sandbox'>
    // aliases resolve to `undefined` (not `never` / not an object).
    const provMeta: ProvisionMetadataFor<'windows_sandbox'> = undefined;
    const startMeta: StartMetadataFor<'windows_sandbox'> = undefined;
    assert.strictEqual(provMeta, undefined);
    assert.strictEqual(startMeta, undefined);

    const result: ProvisionResult<'windows_sandbox'> = {
      sandboxId: 'wsb:prov-1' as SandboxId<'windows_sandbox'>,
    };
    assert.strictEqual(result.metadata, undefined);

    const withBogusMetadata: ProvisionResult<'windows_sandbox'> = {
      sandboxId: 'wsb:prov-1' as SandboxId<'windows_sandbox'>,
      // @ts-expect-error — WindowsSandbox provision returns no metadata object.
      metadata: { agentUserName: 'nope' },
    };
    assert.ok(withBogusMetadata);
  });
});

describe('SandboxId<C> brand is compile-time only; prefix is the runtime routing authority', () => {
  it('routes a force-cast wsb id to windows_sandbox despite the iso brand', () => {
    // A caller can defeat the compile-time brand with a forced cast. Routing
    // must still follow the *runtime* prefix (`wsb:`), not the (wrong) brand —
    // pinning that the brand is advisory and the prefix is authoritative.
    const misbranded = 'wsb:prov-1' as unknown as SandboxId<'isolation_session'>;
    assert.strictEqual(backendForSandboxId(misbranded), 'windows_sandbox');

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
