// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.
//
// Pure proxy-availability decision, factored out of test-helpers so it can be
// unit-tested without pulling in the SDK / node-pty integration surface.

import path from 'path';
import fs from 'fs';

export interface ProxyAvailabilityOptions {
  /** The proxy binary filename (e.g. `linux-test-proxy`, `wxc-test-proxy.exe`). */
  binary: string;
  /** Directory the proxy should be sourced from, or null if none resolved. */
  dir: string | null;
  /** Environment to read `MXC_REQUIRE_PROXY_TESTS` from (defaults to process.env). */
  env?: NodeJS.ProcessEnv;
  /** Filesystem probe (defaults to fs.existsSync) — injectable for tests. */
  existsSync?: (p: string) => boolean;
}

/**
 * Decide whether the proxy E2E tests can run.
 *
 * Returns `true` when the proxy binary is present. Returns `false` (skip) when
 * it is absent AND the environment does not require the proxy tests. Throws when
 * the proxy is absent but `MXC_REQUIRE_PROXY_TESTS` is set — in that CI lane a
 * missing fixture and a real proxy regression must not both look green-with-skips.
 */
export function evaluateProxyAvailability(opts: ProxyAvailabilityOptions): boolean {
  const env = opts.env ?? process.env;
  const existsSync = opts.existsSync ?? fs.existsSync;
  let present = false;
  try {
    present = !!opts.dir && existsSync(path.join(opts.dir, opts.binary));
  } catch {
    present = false;
  }
  if (!present && env.MXC_REQUIRE_PROXY_TESTS) {
    throw new Error(
      `${opts.binary} is required (MXC_REQUIRE_PROXY_TESTS is set) but was not found in ` +
        `${opts.dir ?? '<no MXC_TEST_PROXY_DIR / src/target>'} — the proxy E2E tests cannot ` +
        `be skipped in this CI environment. Provide the proxy via MXC_TEST_PROXY_DIR.`,
    );
  }
  return present;
}
