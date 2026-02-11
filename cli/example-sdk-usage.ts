/**
 * Example: Using the WXC SDK from the CLI package
 *
 * This demonstrates how to use the SDK exports from the CLI package
 * for both interactive and non-interactive sandboxed process spawning.
 */

import {
  // Helper functions
  createMinimalConfig,
  createNetworkRestrictedConfig,
  createFilesystemRestrictedConfig
} from './src/index';

import {  // Platform detection
  getPlatformSupport,
  // Sandbox spawning
  spawnSandbox,
  spawnSandboxAsync,
  // Types
  SandboxPolicy
} from '@shschaefer/wxc-sdk';

/**
 * Example 1: Platform Detection
 */
function example1_platformDetection() {
  console.log('=== Example 1: Platform Detection ===\n');

  // Quick check
  if (!getPlatformSupport().isSupported) {
    console.error('WXC is only supported on Windows');
    return false;
  }
  console.log('✓ Platform is supported\n');

  // Detailed information
  const support = getPlatformSupport();
  console.log('Supported:', support.isSupported);
  console.log('Available methods:', support.availableMethods);
  console.log();

  return true;
}

/**
 * Example 2: Interactive Mode with spawnSandbox
 */
function example2_interactiveMode() {
  console.log('=== Example 2: Interactive Mode (spawnSandbox) ===\n');

  if (!getPlatformSupport().isSupported) {
    console.error('Skipping - platform not supported');
    return;
  }

  const config = createMinimalConfig('python -c "print(\'Hello from sandbox!\')"');

  console.log('Config:', JSON.stringify(config, null, 2));
  console.log('\nSpawning sandboxed process...\n');

  try {
    const pty = spawnSandbox(config);

    // Handle output
    pty.onData((data: string) => {
      process.stdout.write(data);
    });

    // Handle exit
    pty.onExit((event: { exitCode: number; signal?: number }) => {
      console.log(`\nProcess exited with code ${event.exitCode}`);
    });
  } catch (error) {
    console.error('Error spawning sandbox:', error);
  }
}

/**
 * Example 3: Async Mode with spawnSandboxAsync
 */
async function example3_asyncMode() {
  console.log('=== Example 3: Async Mode (spawnSandboxAsync) ===\n');

  if (!getPlatformSupport().isSupported) {
    console.error('Skipping - platform not supported');
    return;
  }

  const config: SandboxPolicy = {
    script: 'python -c "import sys; print(f\'Python {sys.version}\')"',
    timeout: 5000
  };

  console.log('Config:', JSON.stringify(config, null, 2));
  console.log('\nRunning sandboxed process...\n');

  try {
    const result = await spawnSandboxAsync(config);
    console.log('Output:', result.stdout);
    console.log('Exit code:', result.exitCode);
  } catch (error) {
    console.error('Error:', error);
  }
}

/**
 * Example 4: Network Restrictions
 */
async function example4_networkRestrictions() {
  console.log('=== Example 4: Network Restrictions ===\n');

  if (!getPlatformSupport().isSupported) {
    console.error('Skipping - platform not supported');
    return;
  }

  const config = createNetworkRestrictedConfig(
    'python -c "print(\'Network restricted mode\')"',
    ['api.github.com']
  );

  console.log('Config:', JSON.stringify(config, null, 2));
  console.log('\nRunning with network restrictions...\n');

  try {
    const result = await spawnSandboxAsync(config);
    console.log('Output:', result.stdout);
    console.log('Exit code:', result.exitCode);
  } catch (error) {
    console.error('Error:', error);
  }
}

/**
 * Example 5: Filesystem Restrictions
 */
async function example5_filesystemRestrictions() {
  console.log('=== Example 5: Filesystem Restrictions ===\n');

  if (!getPlatformSupport().isSupported) {
    console.error('Skipping - platform not supported');
    return;
  }

  const config = createFilesystemRestrictedConfig(
    'python -c "print(\'Filesystem restricted mode\')"',
    ['C:\\temp'],
    ['C:\\Windows\\System32']
  );

  console.log('Config:', JSON.stringify(config, null, 2));
  console.log('\nRunning with filesystem restrictions...\n');

  try {
    const result = await spawnSandboxAsync(config);
    console.log('Output:', result.stdout);
    console.log('Exit code:', result.exitCode);
  } catch (error) {
    console.error('Error:', error);
  }
}

/**
 * Main function
 */
async function main() {
  console.log('WXC SDK Usage Examples (from CLI package)\n');
  console.log('='.repeat(60));
  console.log();

  // Run platform detection example
  const platformSupported = example1_platformDetection();

  if (!platformSupported) {
    console.log('\nPlatform not supported - skipping remaining examples');
    return;
  }

  // Uncomment to run other examples (requires wxc-exec.exe)
  // example2_interactiveMode();
  // await example3_asyncMode();
  // await example4_networkRestrictions();
  // await example5_filesystemRestrictions();
}

// Run if executed directly
if (require.main === module) {
  main().catch(console.error);
}
