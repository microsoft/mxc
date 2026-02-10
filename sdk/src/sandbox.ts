import * as pty from 'node-pty';
import * as fs from 'fs';
import * as path from 'path';
import * as os from 'os';
import { randomBytes } from "crypto";
import { SandboxPolicy, WxcConfiguration } from './types';
import { findWxcExecutable, getPlatformSupport } from './platform';

/**
 * Generates a random 8-character alphanumeric string for the app container name.
 */
function generateRandomContainerName(): string {
    return randomBytes(4).toString("hex");
}

/**
 * Builds a sandbox payload JSON object from the sandbox configuration.
 * @param script The command line script to execute
 * @param policy The sandbox policy configuration
 * @param workingDirectory Optional working directory path
 * @param containerName Optional container name; if not provided, a random name will be generated
 * @returns The sandbox payload object
 */
export function buildSandboxPayload(
    script: string,
    policy: SandboxPolicy,
    workingDirectory?: string,
    containerName?: string,
): WxcConfiguration {
    // Build capabilities array
    // NOTE: We can add the "permissiveLearningMode" cap here if we add a sandbox debugging flag.
    const capabilities: string[] = [];

    if (policy.network?.allowOutbound) {
        capabilities.push("internetClient");
    }

    if (policy.network?.allowLocalNetwork) {
        capabilities.push("privateNetworkClientServer");
    }

    const config: WxcConfiguration = {
        script,
        workingDirectory,
        appContainer: {
            name: containerName ?? generateRandomContainerName(),
            leastPrivilege: false,
            capabilities,
        },
        filesystem: {
            readwritePaths: policy.filesystem?.readwritePaths,
            readonlyPaths: policy.filesystem?.readonlyPaths,
            deniedPaths: policy.filesystem?.deniedPaths,
            clearPolicyOnExit: true,
        },
    };

    return config;
}

/**
 * Options for spawning a sandboxed process
 */
export interface SandboxSpawnOptions {
  /**
   * Enable debug output from wxc-exec
   */
  debug?: boolean;

  /** 
   * Use the conpty DLL instead of the default winpty backend on Windows 11.
   * This may provide better performance and compatibility.
   */
  useConpty?: boolean;

  /**
   * PTY options to pass to node-pty
   */
  ptyOptions?: pty.IPtyForkOptions;
}

/**
 * Spawn a sandboxed process using wxc-exec and return a node-pty IPty object
 *
 * @param script The command line script to execute
 * @param policy The sandbox policy
 * @param options - Spawn options
 * @param workingDirectory Optional working directory path
 * @param containerName Optional container name; if not provided, a random name will be generated
 * @returns IPty object for interacting with the sandboxed process
 * @throws Error if platform is not supported or wxc-exec is not found
 *
 * @example
 * ```typescript
 * const script = 'python -c "import sys; print(sys.version)"';
 * const policy: SandboxPolicy = {}
 *
 * const result = await spawnSandbox(script, policy);
 * ptyProcess.onData((data) => console.log(data));
 * ptyProcess.onExit((e) => console.log('Exit code:', e.exitCode));
 * ```
 */
export function spawnSandbox(
  script: string,
  policy: SandboxPolicy,
  options: SandboxSpawnOptions = {},
  workingDirectory?: string,
  containerName?: string,
): pty.IPty {
  // Check platform support
  if (!getPlatformSupport()) {
    throw new Error('WXC is currently only supported on Windows 11');
  }

  // Determine wxc-exec path
  const wxcPath = findWxcExecutable();
  if (!wxcPath) {
    throw new Error(
      'wxc-exec.exe not found. Please specify the path using options.wxcPath or ensure it exists in a standard location'
    );
  }

  // Prepare the sandbox policy for wxc-exec
  const config = buildSandboxPayload(script, policy, workingDirectory, containerName);

  // Prepare arguments for wxc-exec
  const args: string[] = [];
  const useBase64 = options.debug ?? true;

  if (useBase64) {
    // Use base64 encoding (no temp files)
    const configJson = JSON.stringify(config);
    const configBase64 = Buffer.from(configJson, 'utf-8').toString('base64');
    args.push('--config-base64', configBase64);
  } else {
    // Create temporary config file
    const tempDir = os.tmpdir();
    const tempFile = path.join(
      tempDir,
      `wxc-config-${Date.now()}-${Math.random().toString(36).substring(7)}.json`
    );
    fs.writeFileSync(tempFile, JSON.stringify(config, null, 2), 'utf-8');
    args.push('--config', tempFile);

    // Note: temp file will be orphaned, but OS will clean it up eventually
    // For better cleanup, user should handle the IPty 'exit' event
  }

  // Add debug flag if requested
  if (options.debug) {
    args.push('--debug');
  }

  // Merge PTY options with defaults
  const ptyOpts: pty.IWindowsPtyForkOptions = {
    name: "xterm-color",
    cols: 120,
    rows: 80,
    cwd: workingDirectory || process.cwd(),
    env: process.env,
    useConpty: options.useConpty,
    ...options.ptyOptions,
  };

  // Spawn wxc-exec with node-pty
  const ptyProcess = pty.spawn(wxcPath, args, ptyOpts);

  return ptyProcess;
}

/**
 * Spawn a sandboxed process and return a promise that resolves with output
 * This is a convenience wrapper around spawnSandbox for non-interactive use cases
 *
 * @param script The command line script to execute
 * @param policy The sandbox policy
 * @param options - Spawn options
 * @param workingDirectory Optional working directory path
 * @param containerName Optional container name; if not provided, a random name will be generated
 * 
 * @returns Promise that resolves with stdout/stderr and exit code
 *
 * @example
 * ```typescript
 * const script = 'python -c "import sys; print(sys.version)"';
 * const policy: SandboxPolicy = {}
 *
 * const result = await spawnSandboxAsync(script, policy);
 * console.log('Output:', result.stdout);
 * console.log('Exit code:', result.exitCode);
 * ```
 */
export function spawnSandboxAsync(
  script: string,
  policy: SandboxPolicy,
  options: SandboxSpawnOptions = {},
  workingDirectory?: string,
  containerName?: string,
): Promise<{ stdout: string; stderr: string; exitCode: number }> {
  return new Promise((resolve, reject) => {
    try {
      const ptyProcess = spawnSandbox(script, policy, options, workingDirectory, containerName);
      let output = '';

      ptyProcess.onData((data: string) => {
        output += data;
      });

      ptyProcess.onExit((event: { exitCode: number; signal?: number }) => {
        // Note: wxc-exec doesn't separate stdout/stderr when using PTY
        // All output is combined
        resolve({
          stdout: output,
          stderr: '',
          exitCode: event.exitCode
        });
      });
    } catch (error) {
      reject(error);
    }
  });
}
