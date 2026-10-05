// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

import assert from 'node:assert';
import { readdirSync, readFileSync } from 'node:fs';
import path from 'node:path';
import { describe, it } from 'node:test';
import { prepareOneShotRequest } from '../../src/bindings/one-shot.js';
import { MxcError } from '../../src/v1/errors.js';
import { prepareContainerRequest } from '../../src/v1/container.js';
import type {
  Containment,
  ContainerRequest,
} from '../../src/v1/types.js';

type FixtureRequestSections = Omit<ContainerRequest, 'command' | 'containment'>;

interface SdkV1Fixture {
  policy?: FixtureRequestSections;
  containment: {
    kind: string;
    distribution?: string;
    release?: string;
    learningMode?: boolean;
    capabilities?: string[];
    allowedProxyPeer?: string;
    guiAccess?: boolean;
    nestedPty?: boolean;
    keychainAccess?: boolean;
    extraMachLookups?: string[];
    image?: string;
    cpuCount?: number;
    memoryMb?: number;
    gpu?: boolean;
    portMappings?: Array<[number, number]>;
  };
  command: string;
  containerName?: string;
  workingDirectory?: string;
  environment?: Record<string, string>;
  inheritDefaultEnv?: boolean;
  telemetry?: boolean;
}

const repoRoot = path.resolve(process.cwd(), '..', '..');
const fixturesRoot = path.join(repoRoot, 'tests', 'policy', 'sdk-v1');

function readJson<T>(file: string): T {
  return JSON.parse(readFileSync(file, 'utf8')) as T;
}

function cloneRequestSections(
  sections: FixtureRequestSections | undefined,
): FixtureRequestSections {
  return JSON.parse(JSON.stringify(sections ?? {})) as FixtureRequestSections;
}

function containment(fixture: SdkV1Fixture['containment']): Containment {
  switch (fixture.kind) {
    case 'processContainer':
      return {
        type: 'processcontainer',
        config: {
          learningMode: fixture.learningMode,
          capabilities: fixture.capabilities,
          network: fixture.allowedProxyPeer === undefined
            ? undefined
            : { allowedProxyPeer: fixture.allowedProxyPeer },
        },
      };
    case 'lxc':
      return {
        type: 'lxc',
        config: {
          distribution: fixture.distribution,
          release: fixture.release,
        },
      };
    case 'seatbelt':
      return {
        type: 'seatbelt',
        config: {
          guiAccess: fixture.guiAccess,
          nestedPty: fixture.nestedPty,
          keychainAccess: fixture.keychainAccess,
          extraMachLookups: fixture.extraMachLookups,
        },
      };
    case 'wslc':
      return {
        type: 'wslc',
        config: {
          image: fixture.image,
          cpuCount: fixture.cpuCount,
          memoryMb: fixture.memoryMb,
          gpu: fixture.gpu,
          portMappings: fixture.portMappings?.map(([windowsPort, containerPort]) => ({
            windowsPort,
            containerPort,
            protocol: 'tcp',
          })),
        },
      };
    case 'isolationSession':
      return { type: 'isolation_session' };
    case 'bubblewrap':
      return { type: 'bubblewrap' };
    case 'process':
    default:
      return { type: 'process' };
  }
}

function configFromFixture(fixture: SdkV1Fixture) {
  const sections = cloneRequestSections(fixture.policy);
  const request: ContainerRequest = {
    ...sections,
    command: fixture.command,
    containment: containment(fixture.containment),
    containerName: fixture.containerName,
    workingDirectory: fixture.workingDirectory,
    environment: fixture.environment,
    inheritDefaultEnvironment: fixture.inheritDefaultEnv,
  };
  return prepareContainerRequest(
    request,
    fixture.telemetry === undefined ? undefined : { enabled: fixture.telemetry },
  );
}

function assertMalformed(action: () => unknown): void {
  assert.throws(
    action,
    (error: unknown) =>
      error instanceof MxcError &&
      error.code === 'malformed_request',
  );
}

describe('SDK v1 shared conformance fixtures', () => {
  const names = readdirSync(path.join(fixturesRoot, 'input'))
    .filter((name) => name.endsWith('.json'))
    .sort();

  for (const name of names) {
    it(`matches ${name}`, () => {
      const input = readJson<SdkV1Fixture>(
        path.join(fixturesRoot, 'input', name),
      );
      const expected = readJson<unknown>(
        path.join(fixturesRoot, 'expected', name),
      );

      assert.deepStrictEqual(
        configFromFixture(input),
        expected,
      );
    });
  }

  it('mints a fresh non-empty containerId when no name is supplied', () => {
    const first = prepareOneShotRequest({
      version: '1.0.0',
      containment: 'process',
      process: { commandLine: 'echo one' },
    });
    const second = prepareOneShotRequest({
      version: '1.0.0',
      containment: 'process',
      process: { commandLine: 'echo two' },
    });

    assert.match(first.containerId!, /^[0-9a-f]{32}$/);
    assert.match(second.containerId!, /^[0-9a-f]{32}$/);
    assert.notStrictEqual(first.containerId, second.containerId);
  });

  it('rejects inverted or incomplete port ranges before native execution', () => {
    const config = {
      version: '1.0.0' as const,
      containment: 'process' as const,
      process: { commandLine: 'echo' },
    };
    for (const [port, message] of [
      [{ port: 445, endPort: 443 }, 'greater than or equal to port'],
      [{ endPort: 443 }, 'requires port'],
    ] as const) {
      assert.throws(
        () => prepareOneShotRequest({
          ...config,
          network: { egress: { allow: [{ ports: [port] }] } },
        }),
        (error: unknown) =>
          error instanceof MxcError &&
          error.code === 'malformed_request' &&
          error.message.includes(message),
      );
    }
    assert.deepStrictEqual(
      prepareOneShotRequest({
        ...config,
        network: { egress: { allow: [{ ports: [{ port: 443, endPort: 443 }] }] } },
      }).network?.egress?.allow?.[0].ports,
      [{ port: 443, endPort: 443 }],
    );
  });

  it('rejects legacy network fields rather than silently omitting policy', () => {
    const config = {
      version: '1.0.0' as const,
      containment: 'process' as const,
      process: { commandLine: 'echo' },
    };
    for (const field of ['removeRulesOnExit', 'allowOutbound'] as const) {
      assert.throws(
        () => prepareOneShotRequest({
          ...config,
          network: { [field]: false },
        }),
        (error: unknown) =>
          error instanceof MxcError &&
          error.code === 'malformed_request' &&
          error.message.includes(`network.${field}`) &&
          error.message.includes('not supported by any registered exact contract') &&
          error.message.includes('network.egress/network.ingress'),
      );
    }
  });

  it('rejects retired aliases instead of translating them into V1', () => {
    const config = {
      version: '1.0.0' as const,
      process: { commandLine: 'echo' },
    };
    for (const alias of ['appcontainer', 'macos_sandbox']) {
      assert.throws(
        () => prepareOneShotRequest({ ...config, containment: alias as never }),
        (error: unknown) =>
          error instanceof MxcError &&
          error.code === 'malformed_request' &&
          error.message.includes(alias),
      );
    }
    assert.throws(
      () => prepareOneShotRequest({
        ...config,
        containment: 'processcontainer',
        appContainer: { capabilities: ['registryRead'] },
      }),
      (error: unknown) =>
        error instanceof MxcError &&
        error.code === 'malformed_request' &&
        error.message.includes('appContainer'),
    );
    const configWithUnsupportedSection = { ...config, macos_sandbox: {} };
    assert.throws(
      () => prepareOneShotRequest(configWithUnsupportedSection),
      (error: unknown) =>
        error instanceof MxcError &&
        error.code === 'malformed_request' &&
        error.message.includes('macos_sandbox'),
    );
    for (const configWithName of [
      { ...config, containment: 'processcontainer' as const, processContainer: { name: '' } },
      { ...config, containment: 'lxc' as const, lxc: { containerName: 'old-name' } },
    ]) {
      assert.throws(
        () => prepareOneShotRequest(configWithName),
        (error: unknown) =>
          error instanceof MxcError &&
          error.code === 'malformed_request' &&
          error.message.includes('use containerId'),
      );
    }
  });

  it('preserves explicit empty environment values without legacy normalization', () => {
    const request = prepareOneShotRequest({
      version: '1.0.0',
      containment: 'process',
      process: {
        commandLine: 'echo',
        env: ['EMPTY=', 'WITH_EQUALS=one=two'],
      },
    }, { env: { ADDED: '', MORE: 'three=four' } });
    assert.deepStrictEqual(request.process.env, [
      'EMPTY=', 'WITH_EQUALS=one=two', 'ADDED=', 'MORE=three=four',
    ]);
  });

  it('rejects invalid environment names before native execution', () => {
    const config = {
      version: '1.0.0' as const,
      containment: 'process' as const,
      process: { commandLine: 'echo' },
    };
    for (const entry of ['BARE', '', '=value']) {
      assertMalformed(() => prepareOneShotRequest({
        ...config,
        process: { commandLine: 'echo', env: [entry] },
      }));
    }
    assert.throws(
      () => prepareOneShotRequest({
        ...config,
        process: { commandLine: 'echo', env: ['BARE'] },
      }),
      /must be NAME=value/,
    );
    for (const name of ['', 'A=B']) {
      assertMalformed(() => prepareOneShotRequest(config, { env: { [name]: 'value' } }));
    }
  });

  it('distinguishes absent and explicitly empty environments', () => {
    const config = {
      version: '1.0.0' as const,
      containment: 'process' as const,
      process: { commandLine: 'echo' },
    };

    assert.strictEqual(prepareOneShotRequest(config).process.env, undefined);
    assert.deepStrictEqual(
      prepareOneShotRequest({
        ...config,
        process: { commandLine: 'echo', env: [] },
      }).process.env,
      [],
    );
    assert.deepStrictEqual(prepareOneShotRequest(config, { env: {} }).process.env, []);
    assert.deepStrictEqual(
      prepareOneShotRequest(config, { env: { OMIT: undefined } }).process.env,
      [],
    );
    assert.deepStrictEqual(
      prepareOneShotRequest({
        ...config,
        process: { commandLine: 'echo', env: ['FIRST=1'] },
      }, {
        env: { SECOND: '2' },
        inheritDefaultEnv: true,
      }).process,
      {
        commandLine: 'echo',
        timeout: 0,
        env: ['FIRST=1', 'SECOND=2'],
        inheritDefaultEnv: true,
      },
    );
  });

  it('preserves explicit capabilities without directional network policy', () => {
    const config = {
      version: '1.0.0' as const,
      containment: 'processcontainer' as const,
      process: { commandLine: 'echo' },
      processContainer: {
        capabilities: ['internetClient', 'privateNetworkClientServer', 'registryRead'],
      },
    };
    const expected = config.processContainer.capabilities;

    assert.deepStrictEqual(
      prepareOneShotRequest(config).processContainer?.capabilities,
      expected,
    );
    assert.deepStrictEqual(
      prepareOneShotRequest({
        ...config,
        runtimeConfig: { networkProxy: 'http://127.0.0.1:8888' },
      }).processContainer?.capabilities,
      expected,
    );
    assert.deepStrictEqual(
      prepareOneShotRequest({
        ...config,
        network: { egress: { default: 'deny' as const } },
      }).processContainer?.capabilities,
      ['registryRead'],
    );
    assert.deepStrictEqual(
      prepareOneShotRequest({
        ...config,
        network: { ingress: { default: 'deny' as const } },
      }).processContainer?.capabilities,
      ['registryRead'],
    );
  });

  it('rejects out-of-range and fractional numeric inputs as malformed', () => {
    assertMalformed(() => prepareOneShotRequest({
      version: '1.0.0',
      containment: 'process',
      process: { commandLine: 'echo', timeout: 1.5 },
    }));
    assertMalformed(() => prepareOneShotRequest({
      version: '1.0.0',
      containment: 'process',
      process: { commandLine: 'echo', timeout: 4_294_967_296 },
    }));
    assertMalformed(() => prepareOneShotRequest({
      version: '1.0.0',
      containment: 'process',
      process: { commandLine: 'echo' },
      network: {
        egress: {
          allow: [{ ports: [{ port: 65_536 }] }],
        },
      },
    }));
    assertMalformed(() => prepareOneShotRequest({
      version: '1.0.0',
      containment: 'wslc',
      process: { commandLine: 'echo' },
      wslc: { cpuCount: 2.5 },
    }));
    assertMalformed(() => prepareOneShotRequest({
      version: '1.0.0',
      containment: 'wslc',
      process: { commandLine: 'echo' },
      wslc: {
        portMappings: [{ windowsPort: 8080, containerPort: 0 }],
      },
    }));
  });
});
