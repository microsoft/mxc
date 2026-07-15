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
  ProvisionResult,
  SandboxId,
  StartConfigFor,
  StopConfigFor,
} from '../../src/state-aware-types.js';

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
  it('accepts version and filesystem', () => {
    const cfg: IsolationSessionProvisionConfig = {
      version: '0.6.0-alpha',
      filesystem: { readwritePaths: ['C:\\workspace'] },
    };
    assert.deepStrictEqual(cfg.filesystem?.readwritePaths, ['C:\\workspace']);
  });

  it('rejects network and ui until those features land Rust-side', () => {
    const withNetwork: IsolationSessionProvisionConfig = {
      // @ts-expect-error — network is not exposed at provision until the Rust runtime honors it.
      network: { defaultPolicy: 'block' },
    };
    const withUi: IsolationSessionProvisionConfig = {
      // @ts-expect-error — ui is not exposed at provision until the Rust runtime honors it.
      ui: { disable: true, clipboard: 'none', injection: false },
    };
    assert.ok(withNetwork);
    assert.ok(withUi);
  });

  it('accepts user only as an IsolationSessionUserConfig instance', () => {
    const ok: IsolationSessionProvisionConfig = {
      user: new IsolationSessionUserConfig('alice@contoso.com', 'tok'),
    };
    const bare: IsolationSessionProvisionConfig = {
      // @ts-expect-error — user must be constructed via IsolationSessionUserConfig for wamToken redaction.
      user: { upn: 'alice@contoso.com', wamToken: 'tok' },
    };
    assert.strictEqual(ok.user?.upn, 'alice@contoso.com');
    assert.ok(bare);
  });
});

describe('IsolationSessionStartConfig', () => {
  it('rejects cross-cutting fields the matrix marks as rejected', () => {
    const cfg: IsolationSessionStartConfig = {
      // @ts-expect-error — start phase does not honor filesystem.
      filesystem: { readwritePaths: ['C:\\workspace'] },
    };
    assert.ok(cfg);
  });

  it('accepts configurationId only from the closed enum', () => {
    const ok: IsolationSessionStartConfig = { configurationId: 'composable' };
    assert.strictEqual(ok.configurationId, 'composable');

    const bogus: IsolationSessionStartConfig = {
      // @ts-expect-error — configurationId must be in the closed enum.
      configurationId: 'xlarge',
    };
    assert.ok(bogus);
  });

  it('accepts user only as an IsolationSessionUserConfig instance', () => {
    const ok: IsolationSessionStartConfig = {
      configurationId: 'composable',
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

describe('LxcStartConfig', () => {
  it('accepts network fields other than proxy', () => {
    const cfg: StartConfigFor<'lxc'> = {
      version: '0.6.0-alpha',
      filesystem: { readwritePaths: ['/workspace'] },
      network: {
        defaultPolicy: 'block',
        allowedHosts: ['example.com'],
        removeRulesOnExit: true,
      },
    };
    assert.strictEqual(cfg.network?.defaultPolicy, 'block');
  });

  it('rejects network.proxy because the LXC runner rejects it at start', () => {
    const cfg: StartConfigFor<'lxc'> = {
      network: {
        // @ts-expect-error — LXC state-aware start does not support network.proxy.
        proxy: { builtinTestServer: true },
      },
    };
    assert.ok(cfg);
  });
});

describe('ConfigsForBackend', () => {
  it('selects the IsolationSession bundle for the isolation_session backend', () => {
    const bundle: ConfigsForBackend<'isolation_session'> = {
      provision: { version: '0.6.0-alpha' },
      start: {},
      exec: { process: { commandLine: 'echo' } },
      stop: {},
      deprovision: {},
    };
    assert.strictEqual(bundle.exec.process.commandLine, 'echo');
  });
});

describe('ProvisionResult<C>', () => {
  it('carries backend-typed metadata for isolation_session', () => {
    const result: ProvisionResult<'isolation_session'> = {
      sandboxId: 'iso:abcd' as SandboxId<'isolation_session'>,
      metadata: { agentUserName: 'iso\\agent' },
    };
    assert.strictEqual(result.metadata?.agentUserName, 'iso\\agent');
  });
});
