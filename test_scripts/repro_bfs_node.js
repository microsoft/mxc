// repro_bfs_node.js
// Reproducer for bfs.sys pushlock deadlock on Windows 25H2+.
// Uses the MXC SDK directly (spawnSandboxAsync with node-pty/ConPTY).
//
// Can be run with or without admin. May need multiple runs to trigger.
// The hang at cleanup after "Done without deadlock" is also a symptom.
//
// USAGE (Admin shell, from mxc repo root):
//   node test_scripts/repro_bfs_node.js [iterations]
//
// PREREQUISITES:
//   - Windows 25H2+ with bfscfg.exe
//   - npm install done in cli/
//   - Take a VM checkpoint first! This WILL freeze the machine.

const path = require('path');
const fs = require('fs');
const os = require('os');

// Note: admin is not strictly required — the deadlock can occur with readonly
// BFS paths too. Running as admin may trigger it faster due to more policy writes.

const sdkPath = path.resolve(__dirname, '..', 'cli', 'node_modules', '@microsoft', 'mxc-sdk');
const { spawnSandboxAsync, getPlatformSupport, getAvailableToolsPolicy } = require(sdkPath);

const iterations = parseInt(process.argv[2]) || 50;

if (!getPlatformSupport().isSupported) {
  console.error('Platform not supported');
  process.exit(1);
}

const rwDir = path.join(os.tmpdir(), 'bfs-repro-rw-' + Date.now());
const roDir = path.join(os.tmpdir(), 'bfs-repro-ro-' + Date.now());
fs.mkdirSync(rwDir, { recursive: true });
fs.mkdirSync(roDir, { recursive: true });
fs.writeFileSync(path.join(roDir, 'input.txt'), 'readonly test data');

const toolsPolicy = getAvailableToolsPolicy(process.env);

async function main() {
  console.log('=== BFS Pushlock Deadlock Reproducer (SDK direct) ===');
  console.log('Iterations:', iterations);
  console.log('RW dir:', rwDir);
  console.log('RO dir:', roDir);
  console.log('Tool paths:', toolsPolicy.readonlyPaths.length, 'readonly,', toolsPolicy.readwritePaths.length, 'readwrite');
  console.log('Note: may need 2+ runs to trigger. Hang at cleanup is also a symptom.');
  console.log('If the system freezes, the bug is confirmed.\n');

  for (let i = 1; i <= iterations; i++) {
    const ts = new Date().toISOString().slice(11, 23);
    const containerName = 'bfs-repro-' + i;
    const scenarioIdx = i % 5;

    let script, policy;

    switch (scenarioIdx) {
      case 0:
        script = 'cmd.exe /c echo Container test successful';
        policy = {
          version: '0.4.0-alpha',
          filesystem: {
            readwritePaths: [rwDir, ...(toolsPolicy.readwritePaths || [])],
            readonlyPaths: [...(toolsPolicy.readonlyPaths || [])],
          },
        };
        break;

      case 1:
        script = 'powershell.exe -NoProfile -Command Write-Output "PowerShell test"';
        policy = {
          version: '0.4.0-alpha',
          filesystem: {
            readwritePaths: [...(toolsPolicy.readwritePaths || [])],
            readonlyPaths: [...(toolsPolicy.readonlyPaths || [])],
          },
        };
        break;

      case 2:
        script = "python -c \"print('Python test')\"";
        policy = {
          version: '0.4.0-alpha',
          filesystem: {
            readwritePaths: [rwDir, ...(toolsPolicy.readwritePaths || [])],
            readonlyPaths: [roDir, ...(toolsPolicy.readonlyPaths || [])],
          },
        };
        break;

      case 3:
        script = 'python -c "f = open(r\'' + path.join(rwDir, 'out.txt').replace(/\\/g, '\\\\') + '\', \'w\'); f.write(\'hello\'); f.close(); print(\'WRITE_OK\')"';
        policy = {
          version: '0.4.0-alpha',
          filesystem: {
            readwritePaths: [rwDir, ...(toolsPolicy.readwritePaths || [])],
            readonlyPaths: [...(toolsPolicy.readonlyPaths || [])],
          },
        };
        break;

      case 4:
        script = 'cmd.exe /c type "' + path.join(roDir, 'input.txt') + '"';
        policy = {
          version: '0.4.0-alpha',
          filesystem: {
            readonlyPaths: [roDir, ...(toolsPolicy.readonlyPaths || [])],
            readwritePaths: [...(toolsPolicy.readwritePaths || [])],
          },
        };
        break;
    }

    try {
      const result = await spawnSandboxAsync(script, policy, {}, rwDir, containerName);
      if (i % 5 === 0) {
        console.log('[' + ts + '] ' + i + '/' + iterations + ' exit=' + result.exitCode);
      }
    } catch (e) {
      if (i % 5 === 0) {
        console.log('[' + ts + '] ' + i + '/' + iterations + ' error: ' + (e.message || '').substring(0, 60));
      }
    }
  }

  console.log('\nDone without deadlock.');
  fs.rmSync(rwDir, { recursive: true, force: true });
  fs.rmSync(roDir, { recursive: true, force: true });
}

main().catch(e => { console.error(e); process.exit(1); });
