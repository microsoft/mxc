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
  ProvisionResult,
  SandboxId,
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

describe('Per-(backend, phase) Configs', () => {
  it('IsolationSessionProvisionConfig accepts cross-cutting fields per the policy honor matrix', () => {
    const cfg: IsolationSessionProvisionConfig = {
      version: '0.6.0-alpha',
      filesystem: { readwritePaths: ['C:\\workspace'] },
      network: { defaultPolicy: 'block' },
      ui: { disable: true, clipboard: 'none', injection: false },
    };
    assert.strictEqual(cfg.network?.defaultPolicy, 'block');
  });

  it('IsolationSessionStartConfig rejects cross-cutting fields the matrix marks as rejected', () => {
    const cfg: IsolationSessionStartConfig = {
      // @ts-expect-error — start phase does not honor filesystem.
      filesystem: { readwritePaths: ['C:\\workspace'] },
    };
    assert.ok(cfg);
  });

  it('IsolationSessionStartConfig accepts configurationId only from the closed enum', () => {
    const ok: IsolationSessionStartConfig = { configurationId: 'composable' };
    assert.strictEqual(ok.configurationId, 'composable');

    const bogus: IsolationSessionStartConfig = {
      // @ts-expect-error — configurationId must be in the closed enum.
      configurationId: 'xlarge',
    };
    assert.ok(bogus);
  });

  it('IsolationSessionExecConfig requires process', () => {
    const cfg: ExecConfigFor<'isolation_session'> = {
      process: { commandLine: 'echo hi' },
    };
    assert.strictEqual(cfg.process.commandLine, 'echo hi');

    // @ts-expect-error — exec config requires process.
    const missing: ExecConfigFor<'isolation_session'> = {};
    assert.ok(missing);
  });

  it('IsolationSessionStopConfig and DeprovisionConfig only carry version', () => {
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

describe('ConfigsForBackend conditional', () => {
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

describe('ProvisionResult<C> carries backend-typed metadata', () => {
  it('ProvisionResult<isolation_session>.metadata is IsolationSessionProvisionMetadata', () => {
    const result: ProvisionResult<'isolation_session'> = {
      sandboxId: 'iso:abcd' as SandboxId<'isolation_session'>,
      metadata: { agentUserName: 'iso\\agent' },
    };
    assert.strictEqual(result.metadata?.agentUserName, 'iso\\agent');
  });
});
