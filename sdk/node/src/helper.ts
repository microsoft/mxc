// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

import * as path from 'node:path';
import { createRequire } from 'node:module';
import { fileURLToPath } from 'node:url';
import { ContainerConfig } from './types.js';
import { diagLog } from './diagnostic.js';

const require = createRequire(import.meta.url);
const __dirname = path.dirname(fileURLToPath(import.meta.url));

/** SDK version read from package.json at module load time. */
export const SDK_VERSION: string = (() => {
  try {
    const pkgPath = require.resolve('@microsoft/mxc-sdk/package.json');
    return require(pkgPath).version as string;
  } catch {
    try {
      return require(path.resolve(__dirname, '..', 'package.json')).version as string;
    } catch {
      return 'unknown';
    }
  }
})();

let sdkVersionLogged = false;

/** Log the SDK version to the diagnostic console (once per process). */
export function diagLogVersion(): void {
  if (!sdkVersionLogged) {
    sdkVersionLogged = true;
    diagLog(`mxc-sdk v${SDK_VERSION} (PID ${process.pid})`);
  }
}

const legacyContainmentWarned = new Set<string>();

/**
 * Emit a one-shot deprecation hint via the diagnostic console when a caller
 * uses a legacy containment wire value. Dedup'd per legacy value per process
 * so the message doesn't flood the diag stream on repeated conversions.
 *
 * Exposed for tests so the latch can be reset between describes.
 */
export function warnLegacyContainmentOnce(legacy: string, canonical: string): void {
  if (!legacyContainmentWarned.has(legacy)) {
    legacyContainmentWarned.add(legacy);
    diagLog(
      `Containment value '${legacy}' is deprecated; use '${canonical}' instead. ` +
      `The legacy spelling is accepted via a backward-compatibility alias and may be ` +
      `removed in a future SDK release.`,
    );
  }
}

/** @internal Reset the legacy-containment dedup latch. Intended for unit tests. */
export function _resetLegacyContainmentWarnedForTesting(): void {
  legacyContainmentWarned.clear();
}

/**
 * Apply Linux network-policy defaults to a `ContainerConfig`.
 *
 * Linux enforces per-host filtering in one of two ways:
 *   1. **iptables firewall** (`enforcementMode: 'firewall'`) — LXC's
 *      privileged enforcement path. Requires root / CAP_NET_ADMIN.
 *   2. **Cooperative HTTP proxy** (`network.proxy` set) — Bubblewrap's
 *      unprivileged enforcement path. The proxy applies the host policy
 *      for cooperating HTTP clients; raw-socket clients bypass it.
 *
 * Legacy LXC network blocks with no explicit enforcement mode use `'firewall'`
 * because capabilities are Windows-only. Bubblewrap uses firewall only for
 * host lists without a proxy.
 *
 * If the caller explicitly passes `enforcementMode: 'capabilities'` we
 * warn: `'capabilities'` is a Windows/AppContainer concept (a token
 * capability mask) and has no Linux equivalent. The explicit value is left
 * unchanged so native backend validation can report unsupported combinations.
 *
 * Shared between the explicit `'bubblewrap'` / `'lxc'` builders and the
 * abstract `'process'` branch on Linux (which resolves to Bubblewrap
 * server-side).
 *
 * NOTE: when `network.proxy` is configured on Bubblewrap, host filtering
 * is enforced at the proxy layer (unprivileged, no CAP_NET_ADMIN). The
 * Rust config parser explicitly rejects `bubblewrap + proxy + firewall`
 * since the iptables path requires privilege the bwrap backend
 * deliberately avoids. Callers in that mode must leave enforcementMode
 * at its default.
 */
export function applyLinuxNetworkPolicy(config: ContainerConfig): void {
  if (!config.network) {
    return;
  }
  if (config.network.enforcementMode === 'capabilities') {
    console.warn(
      "mxc-sdk: network.enforcementMode='capabilities' has no effect on Linux " +
      "(it is a Windows AppContainer / ProcessContainer concept). The Linux " +
      "runner will not enforce host filtering via capabilities. Use the " +
      "default mode (auto-promotes to 'firewall' for LXC, or use network.proxy " +
      'for unprivileged Bubblewrap enforcement).',
    );
  }
  // LXC cannot enforce Windows AppContainer capabilities, so omitted legacy modes use firewall.
  const isLegacyNetwork =
    config.network.egress === undefined && config.network.ingress === undefined;
  if (
    config.containment === 'lxc' &&
    isLegacyNetwork &&
    config.network.enforcementMode === undefined
  ) {
    config.network.enforcementMode = 'firewall';
  }
  const hasProxy = !!config.network.proxy;
  const hasHostRules =
    !!(config.network.allowedHosts?.length || config.network.blockedHosts?.length);
  if (hasHostRules && !hasProxy) {
    config.network.enforcementMode = 'firewall';
  }
}

const REMOVED_EXECUTOR_OPTION_NAMES = [
  'allowTestingFeatures',
  'containment',
  'debug',
  'dryRun',
  'executablePath',
  'logDir',
  'ptyOptions',
  'skipPlatformCheck',
  'usePty',
] as const;

/**
 * The Node SDK no longer shells out to executor binaries. Keep rejecting the
 * removed option names at runtime so plain-JS callers get an explicit error
 * instead of a silent ignore after the TypeScript surface drops them.
 */
export function removedExecutorOptionName(options: object): string | undefined {
  for (const optionName of REMOVED_EXECUTOR_OPTION_NAMES) {
    if (Object.prototype.hasOwnProperty.call(options, optionName)) {
      return optionName;
    }
  }
  return undefined;
}
