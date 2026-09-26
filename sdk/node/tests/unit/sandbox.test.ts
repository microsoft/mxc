// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

import { describe, it } from 'node:test';
import assert from 'node:assert';
import { buildSandboxPayload, createConfigFromPolicy, spawnSandbox, spawnSandboxFromConfig } from '../../src/sandbox.js';
import { resolveExecutableAndArgs } from '../../src/helper.js';
import {
  _resetPlatformSupportCache,
  _setBwrapVersionRunner,
  _setLxcAvailabilityProbe,
} from '../../src/platform.js';
import { ContainerConfig, SandboxPolicy, SandboxingMethod } from '../../src/types.js';
import { MxcError } from '../../src/errors.js';
import { platformSkip } from './test-helpers.js';

describe('buildSandboxPayload', () => {
  const defaultPolicy: SandboxPolicy = {};

  describe('Windows', () => {
    let originalPlatform: PropertyDescriptor | undefined;

    const mockPlatform = (platform: NodeJS.Platform) => {
      originalPlatform = Object.getOwnPropertyDescriptor(process, 'platform');
      Object.defineProperty(process, 'platform', { value: platform });
    };

    const mockWindows = () => mockPlatform('win32');

    const restore = () => {
      if (originalPlatform) {
        Object.defineProperty(process, 'platform', originalPlatform);
      }
    };

    it('should set process.commandLine from script parameter', () => {
      mockWindows();
      try {
        const payload = buildSandboxPayload('echo hello', defaultPolicy);
        assert.strictEqual(payload.process!.commandLine, 'echo hello');
      } finally {
        restore();
      }
    });

      });

  describe('Linux', () => {
    let originalPlatform: PropertyDescriptor | undefined;

    const mockLinux = () => {
      originalPlatform = Object.getOwnPropertyDescriptor(process, 'platform');
      Object.defineProperty(process, 'platform', { value: 'linux' });
    };

    const restore = () => {
      if (originalPlatform) {
        Object.defineProperty(process, 'platform', originalPlatform);
      }
    };

    it('should default to process containment on Linux (resolved by binary to bubblewrap)', () => {
      mockLinux();
      try {
        const payload = buildSandboxPayload('echo hi', defaultPolicy);
        assert.strictEqual(payload.containment, 'process');
        // Abstract 'process' on Linux resolves to Bubblewrap at runtime;
        // the wire-format payload must NOT carry an LXC-specific block.
        assert.strictEqual(payload.lxc, undefined);
      } finally {
        restore();
      }
    });

      });

});

describe('createConfigFromPolicy', () => {
  const defaultPolicy: SandboxPolicy = {};

  it('should produce a locked-down v1 config for an empty policy', () => {
    const config = createConfigFromPolicy(defaultPolicy);
    assert.strictEqual(config.version, '1.0.0');
    assert.deepStrictEqual(config.filesystem!.readwritePaths, []);
    assert.deepStrictEqual(config.filesystem!.readonlyPaths, []);
    assert.deepStrictEqual(config.filesystem!.deniedPaths, []);
    assert.strictEqual(config.ui!.disable, true);
    assert.strictEqual(config.ui!.clipboard, 'none');
    assert.strictEqual(config.ui!.injection, false);
    assert.strictEqual(config.process!.timeout, 0);
    assert.strictEqual(config.process!.commandLine, '');
    assert.strictEqual(config.lifecycle!.destroyOnExit, true);
    assert.strictEqual(config.lifecycle!.preservePolicy, false);
  });

  describe('Windows', () => {
    let originalPlatform: PropertyDescriptor | undefined;

    const mockWindows = () => {
      originalPlatform = Object.getOwnPropertyDescriptor(process, 'platform');
      Object.defineProperty(process, 'platform', { value: 'win32' });
    };

    const restore = () => {
      if (originalPlatform) {
        Object.defineProperty(process, 'platform', originalPlatform);
      }
    };

    it('should set processContainer with UI defaults for process containment', () => {
      mockWindows();
      try {
        const config = createConfigFromPolicy(defaultPolicy, 'process');
        assert.ok(config.processContainer);
        assert.deepStrictEqual(config.processContainer!.capabilities, []);
        assert.strictEqual(config.processContainer!.ui!.isolation, 'container');
        assert.strictEqual(config.processContainer!.ui!.desktopSystemControl, false);
      } finally {
        restore();
      }
    });

      });

  describe('Linux', () => {
    let originalPlatform: PropertyDescriptor | undefined;

    const mockLinux = () => {
      originalPlatform = Object.getOwnPropertyDescriptor(process, 'platform');
      Object.defineProperty(process, 'platform', { value: 'linux' });
    };

    const restore = () => {
      if (originalPlatform) {
        Object.defineProperty(process, 'platform', originalPlatform);
      }
    };

    it('should default to process containment (resolved by binary to bubblewrap on Linux)', () => {
      mockLinux();
      try {
        const config = createConfigFromPolicy(defaultPolicy);
        assert.strictEqual(config.containment, 'process');
        // Abstract 'process' on Linux resolves to Bubblewrap at runtime;
        // the wire-format config must NOT carry an LXC-specific block.
        assert.strictEqual(config.lxc, undefined);
      } finally {
        restore();
      }
    });

      });

  describe('macOS', () => {
    let originalPlatform: PropertyDescriptor | undefined;

    const mockDarwin = () => {
      originalPlatform = Object.getOwnPropertyDescriptor(process, 'platform');
      Object.defineProperty(process, 'platform', { value: 'darwin' });
    };

    const restore = () => {
      if (originalPlatform) {
        Object.defineProperty(process, 'platform', originalPlatform);
      }
    };

      });

});

describe('Development containment vocabulary', () => {
  it('should accept isolation_session as a SandboxingMethod', () => {
    const m: SandboxingMethod = 'isolation_session';
    assert.strictEqual(m, 'isolation_session');
  });

  it('should accept isolation_session as a ContainerConfig.containment value', () => {
    const c: ContainerConfig = {
      version: '0.9.0-alpha',
      containment: 'isolation_session',
    };
    assert.strictEqual(c.containment, 'isolation_session');
  });

});

describe('IsolationSession one-shot request serialization', () => {
  const decodeConfig = (config: ContainerConfig): Record<string, unknown> => {
    const { args } = resolveExecutableAndArgs(config, {
      executablePath: process.execPath,
      skipPlatformCheck: true,
      experimental: true,
    });
    const index = args.indexOf('--config-base64');
    assert.ok(index >= 0, '--config-base64 should be present in args');
    return JSON.parse(Buffer.from(args[index + 1], 'base64').toString('utf-8'));
  };

  it('preserves every removed raw network field for native exact-contract rejection', () => {
    for (const [field, value] of Object.entries({
      defaultPolicy: 'block', enforcementMode: 'both', allowedHosts: [],
      blockedHosts: [], allowLocalNetwork: false, proxy: { url: 'http://proxy.example:8080' },
    })) {
      for (const authoredValue of [value, null]) {
        const request = decodeConfig({
          version: '0.9.0-alpha', containment: 'process',
          process: { commandLine: 'echo test' },
          network: { [field]: authoredValue },
        });
        assert.deepStrictEqual(request.network, { [field]: authoredValue });
      }
    }
  });

  it('preserves the directional IsolationSession network posture', () => {
    const request = decodeConfig({
      version: '0.9.0-alpha',
      containment: 'isolation_session',
      process: { commandLine: 'echo hello' },
      network: {
        egress: { default: 'allow' },
        ingress: { default: 'allow', hostLoopback: 'allow' },
      },
    });
    assert.deepStrictEqual(request.network, {
      egress: { default: 'allow' },
      ingress: { default: 'allow', hostLoopback: 'allow' },
    });
    assert.ok(!('experimental' in request));
  });
});

describe('resolveExecutableAndArgs (containment validation)', { skip: platformSkip }, () => {
  // Use the running node binary as a stand-in executable so the helper does
  // not try to discover wxc-exec on disk. The helper does not actually exec
  // anything; it just builds the path + args.
  const fakeExe = process.execPath;

  function makeConfig(containment: string): ContainerConfig {
    const version =
      containment === 'isolation_session' || containment === 'wslc'
        ? '0.9.0-alpha'
        : ['microvm', 'vm', 'hyperlight', 'windows_sandbox'].includes(containment)
        ? '1.1.0-alpha'
        : ['seatbelt', 'macos_sandbox'].includes(containment)
          ? '0.7.0-alpha'
          : '0.6.0-alpha';
    return {
      version,
      containment: containment as ContainerConfig['containment'],
      process: { commandLine: 'echo hi' },
    };
  }

  it('should accept the abstract intent "process" without throwing', () => {
    // Regression guard: createConfigFromPolicy() defaults to "process" and
    // the SDK no longer pre-resolves it to a concrete backend. The validator
    // must accept abstract intents and let the native binary resolve them.
    assert.doesNotThrow(() =>
      resolveExecutableAndArgs(makeConfig('process'), { executablePath: fakeExe }),
    );
  });

  it('should accept the abstract intent "microvm" with experimental flag (Windows only)', function (this: { skip: (reason?: string) => void }) {
    if (process.platform !== 'win32') {
      this.skip('microvm is Windows-only');
      return;
    }
    assert.doesNotThrow(() =>
      resolveExecutableAndArgs(makeConfig('microvm'), {
        executablePath: fakeExe,
        experimental: true,
      }),
    );
  });

  it('should not require experimental mode for the non-experimental "process" intent', () => {
    // process is an abstract intent; only its concrete resolution may be
    // experimental (e.g. seatbelt today). The intent itself does not
    // require --experimental at the SDK boundary.
    assert.doesNotThrow(() =>
      resolveExecutableAndArgs(makeConfig('process'), { executablePath: fakeExe }),
    );
  });

  it('should accept the abstract intent "vm" without throwing', () => {
    // "vm" is a forward-looking ContainmentType intent. Even though no
    // concrete VM backend resolves it yet, the SDK validator must let it
    // pass — the binary owns the resolve/error step.
    assert.doesNotThrow(() =>
      resolveExecutableAndArgs(makeConfig('vm'), { executablePath: fakeExe }),
    );
  });

  it('should still reject genuinely unknown containment values', () => {
    assert.throws(
      () => resolveExecutableAndArgs(makeConfig('bogus_backend'), { executablePath: fakeExe }),
      { message: /not available on this platform/ },
    );
  });

  it('includes the selected Linux backend failure reason', function (this: { skip: (reason?: string) => void }) {
    if (process.platform !== 'linux') {
      this.skip('per-backend availability reasons are Linux-only');
      return;
    }
    try {
      _setLxcAvailabilityProbe(() => true);
      _setBwrapVersionRunner(() => ({
        kind: 'failed',
        status: null,
        detail: 'timed out after 5000ms',
      }));
      _resetPlatformSupportCache();

      assert.throws(
        () => resolveExecutableAndArgs(makeConfig('bubblewrap'), { executablePath: fakeExe }),
        { message: /timed out after 5000ms/ },
      );
    } finally {
      _setLxcAvailabilityProbe(null);
      _setBwrapVersionRunner(null);
      _resetPlatformSupportCache();
    }
  });

  it('should not require experimental mode for wslc', () => {
    const resolved = resolveExecutableAndArgs(
      makeConfig('wslc'),
      { executablePath: fakeExe, skipPlatformCheck: true },
    );
    assert.ok(!resolved.args.includes('--experimental'));
  });

  it('should not require experimental mode for isolation_session', () => {
    assert.doesNotThrow(() =>
      resolveExecutableAndArgs(makeConfig('isolation_session'), {
        executablePath: fakeExe,
        skipPlatformCheck: true,
      }),
    );
  });

  it('should NOT require experimental mode for explicit lxc containment', function (this: { skip: (reason?: string) => void }) {
    if (process.platform !== 'linux') {
      this.skip('lxc is Linux-only');
      return;
    }
    assert.doesNotThrow(() =>
      resolveExecutableAndArgs(makeConfig('lxc'), { executablePath: fakeExe }),
    );
  });

  // Legacy wire-value aliases (PR #268 deprecation window). Historical v0
  // contracts accept these via serde aliases; the SDK validator must mirror
  // each exact contract so legacy configs reach wxc-exec while v1 rejects the
  // retired spellings. See also Rust parser tests
  // `legacy_appcontainer_wire_value_aliases_processcontainer` and
  // `legacy_macos_sandbox_wire_value_aliases_seatbelt`.
  describe('legacy containment aliases', () => {
    it('should accept "appcontainer" as an alias of processcontainer (Windows)', function (this: { skip: (reason?: string) => void }) {
      if (process.platform !== 'win32') {
        this.skip('processcontainer is Windows-only');
        return;
      }
      assert.doesNotThrow(() =>
        resolveExecutableAndArgs(makeConfig('appcontainer'), { executablePath: fakeExe }),
      );
    });

    it('should reject "appcontainer" on non-Windows hosts with the canonical error', function (this: { skip: (reason?: string) => void }) {
      if (process.platform === 'win32') {
        this.skip('appcontainer is the native value on Windows');
        return;
      }
      assert.throws(
        () => resolveExecutableAndArgs(makeConfig('appcontainer'), { executablePath: fakeExe }),
        { message: /'appcontainer' is not available on this platform/ },
      );
    });

    it('should accept "macos_sandbox" on macOS', function (this: { skip: (reason?: string) => void }) {
      if (process.platform !== 'darwin') {
        this.skip('seatbelt is macOS-only');
        return;
      }
      assert.doesNotThrow(() =>
        resolveExecutableAndArgs(makeConfig('macos_sandbox'), { executablePath: fakeExe }),
      );
    });

    it('should forward the legacy wire value to the binary unchanged', () => {
      // The SDK resolves the alias only for its own validation; the on-wire
      // string sent to wxc-exec must still be the legacy form, because the
      // Rust serde alias is the canonical resolution point. Re-decoding the
      // base64 envelope confirms the wire form is preserved.
      const { args } = resolveExecutableAndArgs(
        // Force the validator to accept regardless of host: macOS would
        // otherwise fail on the experimental gate; Windows/Linux on platform
        // availability for non-native legacy values.
        makeConfig('appcontainer'),
        { executablePath: fakeExe, skipPlatformCheck: true },
      );
      const idx = args.indexOf('--config-base64');
      assert.ok(idx >= 0, '--config-base64 should be present in args');
      const decoded = Buffer.from(args[idx + 1], 'base64').toString('utf-8');
      const envelope = JSON.parse(decoded);
      assert.strictEqual(envelope.containment, 'appcontainer');
    });

    for (const version of ['1.0.0', '1.1.0-alpha']) {
      it(`should reject legacy containment values for ${version}`, () => {
        for (const [alias, canonical] of [
          ['appcontainer', 'processcontainer'],
          ['macos_sandbox', 'seatbelt'],
        ] as const) {
          assert.throws(
            () => resolveExecutableAndArgs({
              version,
              containment: alias as ContainerConfig['containment'],
              process: { commandLine: 'echo hi' },
            }, {
              executablePath: fakeExe,
              skipPlatformCheck: true,
            }),
            {
              message: new RegExp(
                `Schema ${version.replaceAll('.', '\\.')} does not support legacy containment alias '${alias}'; use '${canonical}' instead`,
              ),
            },
          );
        }
      });

      it(`should reject legacy backend sections for ${version}`, () => {
        assert.throws(
          () => resolveExecutableAndArgs({
            version,
            containment: 'processcontainer',
            process: { commandLine: 'echo hi' },
            appContainer: {},
          }, {
            executablePath: fakeExe,
            skipPlatformCheck: true,
          }),
          {
            message: new RegExp(
              `Schema ${version.replaceAll('.', '\\.')} does not support legacy field 'appContainer'; use 'processContainer' instead`,
            ),
          },
        );

        assert.throws(
          () => resolveExecutableAndArgs({
            version,
            containment: 'seatbelt',
            process: { commandLine: 'echo hi' },
            macos_sandbox: {},
          } as ContainerConfig, {
            executablePath: fakeExe,
            skipPlatformCheck: true,
          }),
          {
            message: new RegExp(
              `Schema ${version.replaceAll('.', '\\.')} does not support legacy field 'macos_sandbox'; use 'seatbelt' instead`,
            ),
          },
        );
      });
    }
  });

  describe('builtinTestServer testing-features gate', () => {
    it('forwards --allow-testing-features when the caller opts in via allowTestingFeatures', () => {
      const config: ContainerConfig = {
        version: '0.6.0-alpha',
        containment: 'process',
        process: { commandLine: 'echo hi' },
        network: { proxy: { builtinTestServer: true } },
      };
      const { args } = resolveExecutableAndArgs(config, {
        executablePath: fakeExe,
        skipPlatformCheck: true,
        allowTestingFeatures: true,
      });
      assert.ok(
        args.includes('--allow-testing-features'),
        'expected --allow-testing-features to be forwarded',
      );
    });

    it('throws when builtinTestServer is used without allowTestingFeatures', () => {
      const config: ContainerConfig = {
        version: '0.6.0-alpha',
        containment: 'process',
        process: { commandLine: 'echo hi' },
        network: { proxy: { builtinTestServer: true } },
      };
      assert.throws(
        () =>
          resolveExecutableAndArgs(config, {
            executablePath: fakeExe,
            skipPlatformCheck: true,
          }),
        { message: /allowTestingFeatures: true/ },
      );
    });

    it('does not forward --allow-testing-features for a non-test proxy', () => {
      const config: ContainerConfig = {
        version: '0.6.0-alpha',
        containment: 'process',
        process: { commandLine: 'echo hi' },
        network: { proxy: { url: 'http://localhost:8080' } },
      };
      const { args } = resolveExecutableAndArgs(config, {
        executablePath: fakeExe,
        skipPlatformCheck: true,
      });
      assert.ok(
        !args.includes('--allow-testing-features'),
        'did not expect --allow-testing-features for a url proxy',
      );
    });
  });

  describe('one-shot telemetry', () => {
    function decodeConfig(args: string[]): ContainerConfig {
      const index = args.indexOf('--config-base64');
      assert.ok(index >= 0, '--config-base64 should be present in args');
      return JSON.parse(
        Buffer.from(args[index + 1], 'base64').toString('utf-8'),
      ) as ContainerConfig;
    }

    it('serializes config telemetry with schema 0.9', () => {
      const config = makeConfig('process');
      config.version = '0.9.0-alpha';
      config.telemetry = { enabled: true };
      const { args } = resolveExecutableAndArgs(config, {
        executablePath: fakeExe,
        skipPlatformCheck: true,
      });

      assert.deepStrictEqual(decodeConfig(args).telemetry, { enabled: true });
    });

    it('leaves config telemetry schema validation to the native parser', () => {
      const config = makeConfig('process');
      config.telemetry = { enabled: true };
      const { args } = resolveExecutableAndArgs(config, {
        executablePath: fakeExe,
        skipPlatformCheck: true,
      });

      const serialized = decodeConfig(args);
      assert.deepStrictEqual(serialized.telemetry, { enabled: true });
      assert.strictEqual(serialized.version, config.version);
    });

    for (const experimental of [true, 'invalid']) {
      it(`leaves malformed experimental value ${JSON.stringify(experimental)} to the native parser`, () => {
        const config = {
          ...makeConfig('process'),
          experimental,
        } as unknown as ContainerConfig;

        const { args } = resolveExecutableAndArgs(config, {
          executablePath: fakeExe,
          skipPlatformCheck: true,
        });

        const decoded = decodeConfig(args) as ContainerConfig & { experimental?: unknown };
        assert.strictEqual(decoded.experimental, experimental);
      });
    }
  });
});
