// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

import { app, BrowserWindow, dialog, ipcMain } from 'electron';
import * as path from 'path';
import * as pty from 'node-pty';

let mainWindow: BrowserWindow | null = null;
let activePty: pty.IPty | null = null;

function createWindow(): void {
  mainWindow = new BrowserWindow({
    width: 1400,
    height: 900,
    minWidth: 1000,
    minHeight: 700,
    title: 'MXC Playground',
    webPreferences: {
      preload: path.join(__dirname, 'preload.js'),
      contextIsolation: true,
      nodeIntegration: false,
    },
  });

  mainWindow.loadFile(path.join(__dirname, '..', 'renderer', 'index.html'));

  // Open external links in the default browser
  mainWindow.webContents.setWindowOpenHandler(({ url }) => {
    require('electron').shell.openExternal(url);
    return { action: 'deny' };
  });
  mainWindow.webContents.on('will-navigate', (event, url) => {
    if (!url.startsWith('file://')) {
      event.preventDefault();
      require('electron').shell.openExternal(url);
    }
  });

  mainWindow.webContents.on('context-menu', (_event, params) => {
    const { Menu } = require('electron');
    const menu = Menu.buildFromTemplate([
      { role: 'undo' },
      { role: 'redo' },
      { type: 'separator' },
      { role: 'cut' },
      { role: 'copy' },
      { role: 'paste' },
      { role: 'selectAll' },
    ]);
    menu.popup();
  });

  mainWindow.on('closed', () => {
    mainWindow = null;
    killActivePty();
  });
}

function killActivePty(): void {
  if (activePty) {
    try {
      activePty.kill();
    } catch { /* already dead */ }
    activePty = null;
  }
}

function loadSdk(): typeof import('@microsoft/mxc-sdk') {
  return require('@microsoft/mxc-sdk');
}

/** Resolve wxc-exec path — checks extraResources for packaged app, then falls back to SDK discovery. */
function resolveExecutablePath(): string | undefined {
  const fs = require('fs');
  const sdk = loadSdk();

  // Packaged Electron app: binary is in resources/bin/x64/
  if ((process as any).resourcesPath) {
    const arch = process.arch === 'arm64' ? 'arm64' : 'x64';
    const packaged = path.join((process as any).resourcesPath, 'bin', arch, 'wxc-exec.exe');
    if (fs.existsSync(packaged)) {
      return packaged;
    }
  }

  // Dev mode: let SDK discover it normally
  return undefined;
}

function attachPtyListeners(ptyProcess: pty.IPty): void {
  activePty = ptyProcess;

  ptyProcess.onData((data: string) => {
    console.log('[main] pty-data:', data.substring(0, 200));
    mainWindow?.webContents.send('pty-data', data);
  });

  ptyProcess.onExit(({ exitCode }: { exitCode: number }) => {
    console.log('[main] pty-exit: exitCode =', exitCode);
    activePty = null;
    mainWindow?.webContents.send('pty-exit', exitCode);
  });
}

// IPC: Get platform support info
ipcMain.handle('get-platform-support', () => {
  const sdk = loadSdk();
  return sdk.getPlatformSupport();
});

// IPC: Get available tools policy
ipcMain.handle('get-tools-policy', () => {
  const sdk = loadSdk();
  return sdk.getAvailableToolsPolicy();
});

// IPC: Get user profile policy
ipcMain.handle('get-profile-policy', () => {
  const sdk = loadSdk();
  return sdk.getUserProfilePolicy();
});

// IPC: Get temp files policy
ipcMain.handle('get-temp-policy', () => {
  const sdk = loadSdk();
  return sdk.getTemporaryFilesPolicy();
});

// IPC: Simple mode — spawnSandbox(script, policy)
ipcMain.handle('run-sandbox', (_event, scriptText: string, policyJson: string, debug: boolean, experimental: boolean) => {
  killActivePty();
  const sdk = loadSdk();

  try {
    const policy = JSON.parse(policyJson);
    const ptyProcess = sdk.spawnSandbox(scriptText, policy, {
      debug,
      experimental,
      executablePath: resolveExecutablePath(), skipPlatformCheck: true,
    });
    attachPtyListeners(ptyProcess);
    return { success: true };
  } catch (err: any) {
    return { success: false, error: err.message };
  }
});

// IPC: Advanced mode — createConfigFromPolicy + spawnSandboxFromConfig
ipcMain.handle('run-sandbox-advanced', (_event, scriptText: string, policyJson: string, debug: boolean, experimental: boolean) => {
  killActivePty();
  const sdk = loadSdk();

  try {
    const policy = JSON.parse(policyJson);
    const config = sdk.createConfigFromPolicy(policy);
    config.process!.commandLine = scriptText;
    const ptyProcess = sdk.spawnSandboxFromConfig(config, {
      debug,
      experimental,
      executablePath: resolveExecutablePath(), skipPlatformCheck: true,
    });
    attachPtyListeners(ptyProcess);
    return { success: true, config: JSON.stringify(config, null, 2) };
  } catch (err: any) {
    return { success: false, error: err.message };
  }
});

// IPC: Kill active sandbox
ipcMain.handle('kill-sandbox', () => {
  killActivePty();
  return { success: true };
});

// IPC: Validate policy — returns the generated ContainerConfig
ipcMain.handle('validate-policy', (_event, policyJson: string) => {
  try {
    const sdk = loadSdk();
    const policy = JSON.parse(policyJson);
    const config = sdk.createConfigFromPolicy(policy);
    return { valid: true, config: JSON.stringify(config, null, 2) };
  } catch (err: any) {
    return { valid: false, error: err.message };
  }
});

// IPC: Open folder dialog for filesystem path browsing
ipcMain.handle('open-folder-dialog', async () => {
  const result = await dialog.showOpenDialog(mainWindow!, {
    properties: ['openDirectory']
  });
  return result.canceled ? null : result.filePaths[0];
});

// IPC: Detect available shells and resolve paths
ipcMain.handle('detect-shells', async () => {
  const { execSync } = require('child_process');
  const fs = require('fs');
  const pathMod = require('path');

  // Refresh PATH from registry (picks up new installs without app restart)
  try {
    const freshPath = execSync(
      'powershell.exe -NoProfile -Command "[Environment]::GetEnvironmentVariable(\'Path\',\'Machine\') + \';\' + [Environment]::GetEnvironmentVariable(\'Path\',\'User\')"',
      { encoding: 'utf-8', timeout: 5000 }
    ).trim();
    if (freshPath && freshPath.length > 10) {
      process.env.PATH = freshPath;
    }
  } catch { /* keep existing PATH */ }

  const result: Record<string, any> = {
    cmd: { available: true },
    ps51: { available: true },
    ps7: { available: false },
    python: { available: false },
  };

  // PowerShell 7 — use Get-Command for more reliable detection than where.exe
  // (where.exe only searches PATH; gcm also finds app execution aliases and
  // PowerShell-registered commands)
  try {
    const out = execSync(
      'powershell.exe -NoProfile -Command "(Get-Command pwsh.exe -ErrorAction SilentlyContinue -All | ForEach-Object { $_.Source }) -join [char]10"',
      { encoding: 'utf-8', timeout: 10000 }
    ).trim();
    if (out) {
      const paths = out.split('\n').map((p: string) => p.trim()).filter((p: string) => p.length > 0);
      // Prefer non-WindowsApps path, but accept WindowsApps if it's the only one
      var preferred = paths.find((p: string) => !p.includes('WindowsApps'));
      var chosen = preferred || paths[0];
      result.ps7 = { available: true, exe: chosen, rootDir: pathMod.dirname(chosen) };
    }
  } catch {}

  // Python — find the real binary, not the WindowsApps stub or launcher
  try {
    const out = execSync('where.exe python.exe', { encoding: 'utf-8' });
    const paths = out.split('\n').map((p: string) => p.trim()).filter((p: string) => p.length > 0);

    for (const p of paths) {
      // Skip WindowsApps stubs (these open the Store app)
      if (p.includes('WindowsApps')) { continue; }

      // Check if this is a per-user Python install with pythoncore-* layout
      const dir = pathMod.dirname(p);
      const parent = pathMod.dirname(dir);
      try {
        const entries = fs.readdirSync(parent);
        const coreDir = entries.find((e: string) => e.startsWith('pythoncore-'));
        if (coreDir) {
          const realExe = pathMod.join(parent, coreDir, 'python.exe');
          if (fs.existsSync(realExe)) {
            result.python = {
              available: true,
              exe: realExe,
              rootDir: parent,
            };
            break;
          }
        }
      } catch {}

      // Accept any non-WindowsApps python.exe
      // Use the parent directory (e.g., AppData\Local\Programs\Python\) to cover all versions
      var pyDir = pathMod.dirname(p);
      var pyParent = pathMod.dirname(pyDir);
      // If parent looks like a Python root (contains multiple version dirs), use it
      var useParent = false;
      try {
        var siblings = fs.readdirSync(pyParent);
        useParent = siblings.some((s: string) => s.match(/^Python\d/i) || s.startsWith('pythoncore-'));
      } catch {}

      result.python = {
        available: true,
        exe: p,
        rootDir: useParent ? pyParent : pyDir,
      };
      break;
    }

    // Verify Python actually runs (not a stub that opens the Store)
    if (result.python.available && result.python.exe) {
      try {
        execSync('"' + result.python.exe + '" --version', { encoding: 'utf-8', timeout: 5000 });
      } catch {
        result.python = { available: false };
      }
    }
  } catch {}

  // Also check system-wide Python dirs (C:\Python*)
  if (!result.python.available || !result.python.exe) {
    try {
      const entries = fs.readdirSync('C:\\');
      for (const e of entries) {
        if (e.toLowerCase().startsWith('python')) {
          const exe = pathMod.join('C:\\', e, 'python.exe');
          if (fs.existsSync(exe)) {
            result.python = { available: true, exe, rootDir: pathMod.join('C:\\', e) };
            break;
          }
        }
      }
    } catch {}
  }

  // Check if Python install has ALL APPLICATION PACKAGES ACL
  if (result.python.available && result.python.rootDir) {
    try {
      var pyAclOut = execSync('icacls "' + result.python.rootDir + '"', { encoding: 'utf-8', timeout: 5000 });
      var pyHasAcl = pyAclOut.includes('APPLICATION PACKAGES');
      result.python.needsAcl = !pyHasAcl;
      result.python.isPerUser = result.python.rootDir.includes('AppData');
    } catch {
      result.python.needsAcl = false;
    }
  }

  // Check if PS7 install has ALL APPLICATION PACKAGES ACL
  if (result.ps7.available && result.ps7.rootDir) {
    if (result.ps7.rootDir.includes('WindowsApps')) {
      result.ps7.needsAcl = true;
      result.ps7.isPerUser = true;

      // Resolve the actual MSIX package install directory for BFS brokering.
      // WindowsApps has restricted ACLs — the sandbox needs the real package
      // path in readonlyPaths so BFS can broker access.
      try {
        const msixInstallDir = execSync(
          'powershell.exe -NoProfile -Command "(Get-AppxPackage Microsoft.PowerShell | Select-Object -First 1).InstallLocation"',
          { encoding: 'utf-8', timeout: 10000 }
        ).trim();
        if (msixInstallDir && fs.existsSync(msixInstallDir)) {
          result.ps7.msixPackageDir = msixInstallDir;
        }
      } catch { /* Get-AppxPackage unavailable */ }
    } else {
      try {
        var ps7AclOut = execSync('icacls "' + result.ps7.rootDir + '"', { encoding: 'utf-8', timeout: 5000 });
        var ps7HasAcl = ps7AclOut.includes('APPLICATION PACKAGES');
        result.ps7.needsAcl = !ps7HasAcl;
        result.ps7.isPerUser = result.ps7.rootDir.includes('AppData');
      } catch {
        result.ps7.needsAcl = false;
      }
    }
  }

  return result;
});

// IPC: Fix Python ACL (requires admin UAC prompt)
ipcMain.handle('fix-python-acl', async (_event, runtimePath: string) => {
  const { execSync } = require('child_process');
  try {
    execSync(
      'powershell.exe -NoProfile -Command "Start-Process icacls -ArgumentList \'' + runtimePath + ' /grant \\\"ALL APPLICATION PACKAGES:(OI)(CI)(RX)\\\" /T\' -Verb RunAs -Wait"',
      { encoding: 'utf-8', timeout: 60000 }
    );
    var aclOut = execSync('icacls "' + runtimePath + '"', { encoding: 'utf-8', timeout: 5000 });
    return { success: aclOut.includes('APPLICATION PACKAGES') };
  } catch (e: any) {
    return { success: false, error: e.message };
  }
});

// IPC: Install a runtime via winget
ipcMain.handle('install-runtime', async (_event, runtime: string) => {
  const { execSync } = require('child_process');
  const packages: Record<string, string> = {
    python: 'Python.Python.3.14',
    ps7: 'Microsoft.PowerShell',
  };
  const pkg = packages[runtime];
  if (!pkg) { return { success: false, error: 'Unknown runtime: ' + runtime, log: '' }; }

  try {
    // Single elevated script: install + detect path + icacls
    const script = `
$ErrorActionPreference = 'Continue'
Write-Output '=== Installing ${pkg} ==='
winget install ${pkg} --accept-package-agreements --accept-source-agreements 2>&1 | ForEach-Object { $_ }
Write-Output ''
Write-Output '=== Refreshing PATH ==='
$freshPath = [Environment]::GetEnvironmentVariable('Path','Machine') + ';' + [Environment]::GetEnvironmentVariable('Path','User')
$env:PATH = $freshPath
Write-Output ''
Write-Output '=== Finding install location ==='
$exe = Get-Command ${runtime === 'python' ? 'python.exe' : 'pwsh.exe'} -ErrorAction SilentlyContinue | Select-Object -First 1
if ($exe) {
  $dir = Split-Path $exe.Source
  Write-Output "Found at: $dir"
  Write-Output ''
  Write-Output '=== Setting permissions ==='
  icacls $dir /grant "ALL APPLICATION PACKAGES:(OI)(CI)(RX)" /T 2>&1 | Select-Object -First 5
  Write-Output 'Done.'
} else {
  Write-Output 'WARNING: Could not find executable on PATH after install.'
}
`;
    // Write script to temp file and run elevated
    const fs = require('fs');
    const tempScript = require('path').join(require('os').tmpdir(), 'mxc-install.ps1');
    fs.writeFileSync(tempScript, script, 'utf-8');

    const log = execSync(
      'powershell.exe -NoProfile -Command "Start-Process powershell.exe -ArgumentList \'-NoProfile -ExecutionPolicy Bypass -File \\\"' + tempScript + '\\\" > \\\"%TEMP%\\\\mxc-install.log\\\" 2>&1\' -Verb RunAs -Wait; Get-Content $env:TEMP\\mxc-install.log"',
      { encoding: 'utf-8', timeout: 180000 }
    );

    // Clean up
    try { fs.unlinkSync(tempScript); } catch {}

    // Refresh PATH in this process
    try {
      const freshPath = execSync(
        'powershell.exe -NoProfile -Command "[Environment]::GetEnvironmentVariable(\'Path\',\'Machine\') + \';\' + [Environment]::GetEnvironmentVariable(\'Path\',\'User\')"',
        { encoding: 'utf-8', timeout: 5000 }
      ).trim();
      if (freshPath && freshPath.length > 10) { process.env.PATH = freshPath; }
    } catch {}

    return { success: true, log };
  } catch (e: any) {
    return { success: false, error: e.message, log: '' };
  }
});

// IPC: Detect all Python versions installed
ipcMain.handle('detect-python-versions', async () => {
  const { execSync } = require('child_process');
  const fs = require('fs');
  const pathMod = require('path');
  const versions: { version: string; exe: string; rootDir: string; hasAcl: boolean }[] = [];

  // Check common install locations
  const searchDirs = [
    'C:\\Program Files',
    'C:\\Program Files (x86)',
    process.env.LOCALAPPDATA ? pathMod.join(process.env.LOCALAPPDATA, 'Programs', 'Python') : '',
    process.env.LOCALAPPDATA ? pathMod.join(process.env.LOCALAPPDATA, 'Python') : '',
  ].filter(Boolean);

  for (const base of searchDirs) {
    try {
      const entries = fs.readdirSync(base);
      for (const e of entries) {
        if (!e.match(/^Python\d/i) && !e.startsWith('pythoncore-')) { continue; }
        const exe = pathMod.join(base, e, 'python.exe');
        if (!fs.existsSync(exe)) { continue; }
        // Get version
        try {
          const ver = execSync('"' + exe + '" --version', { encoding: 'utf-8', timeout: 5000 }).trim();
          const verMatch = ver.match(/Python\s+(\S+)/);
          // Check ACL
          var aclOut = execSync('icacls "' + pathMod.join(base, e) + '"', { encoding: 'utf-8', timeout: 5000 });
          versions.push({
            version: verMatch ? verMatch[1] : e,
            exe,
            rootDir: pathMod.join(base, e),
            hasAcl: aclOut.includes('APPLICATION PACKAGES'),
          });
        } catch { /* skip broken installs */ }
      }
    } catch { /* dir doesn't exist */ }
  }

  return versions;
});

// IPC: Ensure directories exist for write scenarios
ipcMain.handle('ensure-dirs', (_event, dirs: string[]) => {
  const fs = require('fs');
  for (const dir of dirs) {
    try {
      fs.mkdirSync(dir, { recursive: true });
    } catch { /* ignore */ }
  }
  return { success: true };
});

ipcMain.handle('save-log-file', async (_event, content: string) => {
  const fs = require('fs');
  const { dialog } = require('electron');
  const result = await dialog.showSaveDialog({
    title: 'Save Run All Log',
    defaultPath: 'mxc-playground-results.log',
    filters: [{ name: 'Log Files', extensions: ['log', 'txt'] }],
  });
  if (!result.canceled && result.filePath) {
    fs.writeFileSync(result.filePath, content, 'utf-8');
    return { success: true, path: result.filePath };
  }
  return { success: false };
});

// IPC: Get test script path and content
ipcMain.handle('get-test-script', (_event, scriptName: string) => {
  const fs = require('fs');
  let scriptDir: string;
  if ((process as any).resourcesPath) {
    scriptDir = path.join((process as any).resourcesPath, 'test-scripts');
  } else {
    scriptDir = path.join(__dirname, '..', '..', 'test-scripts');
  }
  const scriptPath = path.join(scriptDir, scriptName);
  try {
    const content = fs.readFileSync(scriptPath, 'utf-8');
    return { success: true, path: scriptPath, content };
  } catch (e: any) {
    return { success: false, error: e.message };
  }
});

// IPC: Run sandbox with raw JSON config (bypass policy creation)
ipcMain.handle('run-sandbox-raw', (_event, configJson: string, debug: boolean, experimental: boolean) => {
  console.log('[main] run-sandbox-raw: received IPC call');
  console.log('[main] run-sandbox-raw: config =', configJson);
  console.log('[main] run-sandbox-raw: debug =', debug, 'experimental =', experimental);
  killActivePty();
  const sdk = loadSdk();

  try {
    const config = JSON.parse(configJson);
    const execPath = resolveExecutablePath();
    console.log('[main] run-sandbox-raw: resolved executable =', execPath ?? '(SDK default)');
    console.log('[main] run-sandbox-raw: calling spawnSandboxFromConfig...');
    const ptyProcess = sdk.spawnSandboxFromConfig(config, {
      debug,
      experimental,
      executablePath: execPath, skipPlatformCheck: true,
    });
    console.log('[main] run-sandbox-raw: PTY process spawned, pid =', ptyProcess.pid);

    attachPtyListeners(ptyProcess);
    return { success: true, config };
  } catch (e: any) {
    console.error('[main] run-sandbox-raw: ERROR:', e.message, e.stack);
    return { success: false, error: e.message };
  }
});

app.whenReady().then(createWindow);

app.on('window-all-closed', () => {
  killActivePty();
  app.quit();
});
