/**
 * Example usage of the WXC CLI API
 *
 * Run with: npx ts-node example.ts
 */

import { WxcExecutor, createMinimalConfig, createNetworkRestrictedConfig } from './src';
import * as path from 'path';
import * as fs from 'fs';

async function main() {
  // Path to WXC executable (adjust as needed)
  const wxcPath = path.join(__dirname, '..', 'x64', 'Debug', 'wxc-exec.exe');

  if (!fs.existsSync(wxcPath)) {
    console.error(`WXC executable not found at: ${wxcPath}`);
    console.error('Please build WXC first or specify the correct path');
    process.exit(1);
  }

  const executor = new WxcExecutor(wxcPath);

  console.log('=== Example 1: Minimal Configuration ===');
  const config1 = createMinimalConfig("print('Hello from WXC!')");
  const config1Json = JSON.stringify(config1);
  const config1Base64 = Buffer.from(config1Json).toString('base64');

  const result1 = await executor.run(config1Base64, {
    isBase64: true,
    debug: false
  });

  console.log('Success:', result1.success);
  console.log('Output:', result1.stdout);
  console.log();

  console.log('=== Example 2: Network Restricted ===');
  const config2 = createNetworkRestrictedConfig(
    `
import urllib.request
try:
    response = urllib.request.urlopen('https://api.github.com')
    print('GitHub API accessible')
except Exception as e:
    print(f'Error: {e}')
    `.trim(),
    ['api.github.com']
  );

  const config2Json = JSON.stringify(config2);
  const config2Base64 = Buffer.from(config2Json).toString('base64');

  const result2 = await executor.run(config2Base64, {
    isBase64: true,
    debug: false
  });

  console.log('Success:', result2.success);
  console.log('Output:', result2.stdout);
  console.log();

  console.log('=== Example 3: Run from Config File ===');
  const exampleConfigPath = path.join(__dirname, '..', 'examples', '01_hello_world.json');

  if (fs.existsSync(exampleConfigPath)) {
    const result3 = await executor.run(exampleConfigPath, {
      debug: false
    });

    console.log('Success:', result3.success);
    console.log('Output:', result3.stdout);
  } else {
    console.log('Example config file not found, skipping');
  }
}

main().catch(error => {
  console.error('Error:', error);
  process.exit(1);
});
