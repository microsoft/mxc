// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

var mxc = (window as any).mxc;

// ============================================================
// Scenarios
// ============================================================

interface Scenario {
  id: string;
  name: string;
  category: string;
  categoryIcon: string;
  description: string;
  expectedOutcome: 'succeed' | 'be-blocked' | 'show-error';
  expectedLabel: string;
  script: string;
  policy: any;
  shell: 'cmd' | 'ps51' | 'ps7' | 'python' | 'networking' | 'filesystem';
  containment?: 'appcontainer' | 'windows_sandbox' | 'microvm' | 'hyperlight';
  requiresV05?: boolean;
  /** If set, output must contain this string for a PASS verdict */
  successMarker?: string;
  /** If set, output containing this string means the script itself reported failure */
  failureMarker?: string;
  /** If set, resolve this test-script file and use it as the script command */
  testScript?: { file: string; shell: string; args?: string };
}

// Shell detection — cached after init
var shellAvailability: Record<string, boolean> = {
  cmd: true,
  ps51: true,
  ps7: false,
  python: false,
  networking: true,
  filesystem: true,
};

// Resolved shell paths (populated by detect-shells)
var shellPaths: Record<string, { exe?: string; rootDir?: string; needsAcl?: boolean; msixPackageDir?: string }> = {};

var SHELL_BADGES: Record<string, string> = {
  cmd: '🟢',
  ps51: '🔵',
  ps7: '🟣',
  python: '🐍',
  networking: '🌐',
  filesystem: '📁',
};

var SHELL_LABELS: Record<string, string> = {
  cmd: '⬛ cmd.exe',
  ps51: '🔷 PowerShell 5.1',
  ps7: '🟦 PowerShell 7+',
  python: '🐍 Python',
  networking: '🌐 Networking',
  filesystem: '📁 Filesystem',
};

var SHELL_SHORT: Record<string, string> = {
  cmd: 'cmd',
  ps51: 'PS 5.1',
  ps7: 'PS 7',
  python: 'Python',
  networking: 'Network',
  filesystem: 'FS',
};

function updateRunAllLabel(): void {
  var shell = $sel('shellSelect').value;
  var name = SHELL_SHORT[shell] || shell;
  $('btnRunAll').textContent = '▶▶ Run All ' + name + ' Tests';
}

function updatePythonAclWarning(): void {
  var shell = $sel('shellSelect').value;
  if (shell !== 'python' && shell !== 'ps7') {
    $('pythonAclWarning').classList.add('hidden');
    return;
  }

  var isInstalled = shellAvailability[shell] !== false;
  var name = shell === 'python' ? 'Python' : 'PowerShell 7';

  if (!isInstalled) {
    if (shell === 'python') {
      $('pythonAclWarning').innerHTML =
        '<div>⚠️ ' + name + ' is not installed.</div>' +
        '<div style="font-size:11px; margin-top:6px;">Install via terminal:</div>' +
        '<code style="display:block; margin:4px 0; padding:4px 8px; background:var(--bg-input); border-radius:4px; font-size:11px; user-select:all;">winget install Python.Python.3.14</code>' +
        '<div style="font-size:11px; color:var(--text-muted); margin-top:6px;">Click 🔄 after installation to refresh.</div>';
    } else {
      $('pythonAclWarning').innerHTML =
        '<div>⚠️ ' + name + ' is not installed.</div>' +
        '<div style="font-size:11px; margin-top:6px;"><a href="https://learn.microsoft.com/en-us/powershell/scripting/install/install-powershell-on-windows?view=powershell-7.6#install-the-msi-package" target="_blank" style="color:var(--accent);">Install the MSI package →</a></div>' +
        '<div style="font-size:11px; color:var(--text-dim); margin-top:4px;">ℹ️ Only MSI-installed PowerShell 7+ is supported. MSIX and Microsoft Store versions are not yet supported.</div>' +
        '<div style="font-size:11px; color:var(--text-muted); margin-top:6px;">Click 🔄 after installation to refresh.</div>';
    }
    $('pythonAclWarning').classList.remove('hidden');
    return;
  }

  $('pythonAclWarning').classList.add('hidden');
}

function updateShellDropdown(): void {
  var select = document.getElementById('shellSelect') as HTMLSelectElement;
  for (var i = 0; i < select.options.length; i++) {
    var opt = select.options[i];
    var shell = opt.value;
    if (shell === 'custom' || shell === 'rawjson') { continue; }
    var avail = shellAvailability[shell] !== false;
    var label = SHELL_LABELS[shell] || shell;
    opt.textContent = avail ? label : label + ' (not installed)';
    opt.style.opacity = avail ? '1' : '0.6';
  }
}

var SCENARIOS: Scenario[] = [
  // ========== cmd.exe ==========
  { id: 'cmd-hello', name: 'Echo Hello', category: 'Quick Tests', categoryIcon: '🎯', shell: 'cmd',
    description: 'Runs a simple echo command to verify basic execution.',
    expectedOutcome: 'succeed', expectedLabel: 'Should succeed',
    script: 'cmd.exe /c echo Hello from sandbox!',
    policy: { ui: { allowWindows: true } }, successMarker: 'Hello from sandbox!' },
  { id: 'cmd-fs-read', name: 'Read system file', category: 'File Access Tests', categoryIcon: '📁', shell: 'cmd',
    description: 'Reads the hosts file using read-only access.',
    expectedOutcome: 'succeed', expectedLabel: 'Should succeed',
    script: 'cmd.exe /c type C:\\Windows\\System32\\drivers\\etc\\hosts',
    policy: { filesystem: { readonlyPaths: ['C:\\Windows\\System32\\drivers\\etc'] }, ui: { allowWindows: true } },
    successMarker: 'sample HOSTS file' },
  { id: 'cmd-fs-read-blocked', name: 'Read without permission', category: 'File Access Tests', categoryIcon: '📁', shell: 'cmd',
    description: 'Tries to read from a user directory without filesystem access. Should be denied.',
    expectedOutcome: 'be-blocked', expectedLabel: 'Should be blocked',
    script: 'cmd.exe /c type "%USERPROFILE%\\NTUSER.DAT"',
    policy: { ui: { allowWindows: true } } },
  { id: 'cmd-fs-write-spaces', name: 'Write to path with spaces', category: 'File Access Tests', categoryIcon: '📁', shell: 'cmd',
    description: 'Writes to a path containing spaces.',
    expectedOutcome: 'succeed', expectedLabel: 'Should succeed',
    script: 'cmd.exe /c echo SUCCESS > "C:\\Users\\Public\\mxc bfs test\\test_output.txt" && type "C:\\Users\\Public\\mxc bfs test\\test_output.txt"',
    policy: { filesystem: { readwritePaths: ['C:\\Users\\Public\\mxc bfs test'] } },
    requiresV05: true, successMarker: 'SUCCESS' },
  { id: 'cmd-net-ok', name: 'Internet allowed', category: 'Network Tests', categoryIcon: '🌐', shell: 'cmd',
    description: 'Makes an HTTPS request with outbound network enabled.',
    expectedOutcome: 'succeed', expectedLabel: 'Should succeed',
    script: 'curl.exe -s --max-time 10 https://www.example.com',
    policy: { network: { allowOutbound: true }, ui: { allowWindows: true } },
    successMarker: 'Example Domain' },
  { id: 'cmd-net-blocked', name: 'Internet blocked', category: 'Network Tests', categoryIcon: '🌐', shell: 'cmd',
    description: 'Tries to reach example.com with no network access. Should fail.',
    expectedOutcome: 'be-blocked', expectedLabel: 'Should be blocked',
    script: 'curl.exe -s --max-time 5 https://www.example.com',
    policy: { ui: { allowWindows: true } }, failureMarker: 'Example Domain' },
  { id: 'cmd-win32k-off', name: 'Win32k disabled', category: 'Desktop & UI Tests', categoryIcon: '🖥️', shell: 'cmd',
    description: 'Runs with Win32k disabled. cmd.exe does not need Win32k so it should still work.',
    expectedOutcome: 'succeed', expectedLabel: 'Should succeed',
    script: 'cmd.exe /c echo PASS: Win32k disabled', policy: { ui: { allowWindows: false } },
    requiresV05: true, successMarker: 'PASS:' },
  { id: 'cmd-timeout', name: 'Timeout', category: 'Error Cases', categoryIcon: '⚠️', shell: 'cmd',
    description: 'Runs a command that waits 30 seconds with a 5-second timeout.',
    expectedOutcome: 'be-blocked', expectedLabel: 'Should be terminated',
    script: 'cmd.exe /c ping -n 30 127.0.0.1',
    policy: { ui: { allowWindows: true }, timeoutMs: 5000 } },
  { id: 'cmd-bad-exe', name: 'Non-existent executable', category: 'Error Cases', categoryIcon: '⚠️', shell: 'cmd',
    description: 'Tries to run an executable that does not exist.',
    expectedOutcome: 'show-error', expectedLabel: 'Should fail',
    script: 'this-command-does-not-exist-12345',
    policy: { ui: { allowWindows: true } } },
  { id: 'cmd-full-access', name: 'Full access', category: 'Combined Tests', categoryIcon: '🔄', shell: 'cmd',
    description: 'Writes a file and reads it back. Exercises filesystem + desktop together.',
    expectedOutcome: 'succeed', expectedLabel: 'Should succeed',
    script: 'cmd.exe /c echo CMD_WRITE_OK > C:\\temp\\mxc-full-test\\cmd-result.txt && type C:\\temp\\mxc-full-test\\cmd-result.txt && echo ALL_OK',
    policy: { filesystem: { readwritePaths: ['C:\\temp\\mxc-full-test'] }, ui: { allowWindows: true } },
    successMarker: 'ALL_OK' },

  // ========== PowerShell 5.1 ==========
  { id: 'ps51-hello', name: 'Echo Hello', category: 'Quick Tests', categoryIcon: '🎯', shell: 'ps51',
    description: 'Runs Write-Output to verify PowerShell works inside the sandbox.',
    expectedOutcome: 'succeed', expectedLabel: 'Should succeed',
    script: 'powershell.exe -Command "Write-Output \'Hello from PowerShell\'"',
    policy: { ui: { allowWindows: true } }, successMarker: 'Hello from PowerShell' },
  { id: 'ps51-version', name: 'Version info', category: 'Quick Tests', categoryIcon: '🎯', shell: 'ps51',
    description: 'Displays the PowerShell version table.',
    expectedOutcome: 'succeed', expectedLabel: 'Should succeed',
    script: 'powershell.exe -Command "$PSVersionTable"',
    policy: { ui: { allowWindows: true } }, successMarker: 'PSVersion' },
  { id: 'ps51-fs-write', name: 'Write to allowed folder', category: 'File Access Tests', categoryIcon: '📁', shell: 'ps51',
    description: 'Writes a file to a brokered temp directory.',
    expectedOutcome: 'succeed', expectedLabel: 'Should succeed',
    script: 'powershell.exe -NoProfile -Command "Set-Content -Path C:\\temp\\mxc-write-test\\ps-output.txt -Value hello; Write-Output WRITE_OK"',
    policy: { filesystem: { readwritePaths: ['C:\\temp\\mxc-write-test'] }, ui: { allowWindows: true } },
    successMarker: 'WRITE_OK' },
  { id: 'ps51-fs-write-blocked', name: 'Write without permission', category: 'File Access Tests', categoryIcon: '📁', shell: 'ps51',
    description: 'Tries to write to C:\\Windows. Access should be denied.',
    expectedOutcome: 'be-blocked', expectedLabel: 'Should be blocked',
    script: 'powershell.exe -Command "try { Set-Content -Path \\"C:\\Windows\\mxc-test.txt\\" -Value \\"test\\" -ErrorAction Stop; Write-Output \\"UNEXPECTED\\" } catch { Write-Output \\"EXPECTED: $_\\" }"',
    policy: { ui: { allowWindows: true } }, failureMarker: 'UNEXPECTED' },
  { id: 'ps51-fs-read-root', name: 'Read from C:\\ root', category: 'File Access Tests', categoryIcon: '📁', shell: 'ps51',
    description: 'Lists C:\\ as a read-only path. Tests trailing backslash handling.',
    expectedOutcome: 'succeed', expectedLabel: 'Should succeed',
    script: 'powershell.exe -NoProfile -Command "Get-ChildItem C:\\ | Select-Object -First 3 | ForEach-Object { Write-Output $_.Name }; Write-Output READ_ROOT_OK"',
    policy: { filesystem: { readonlyPaths: ['C:\\'] }, ui: { allowWindows: true } },
    requiresV05: true, successMarker: 'READ_ROOT_OK' },
  { id: 'ps51-net-ok', name: 'Internet allowed', category: 'Network Tests', categoryIcon: '🌐', shell: 'ps51',
    description: 'Makes an HTTPS request with outbound network enabled.',
    expectedOutcome: 'succeed', expectedLabel: 'Should succeed',
    script: 'powershell.exe -NoProfile -Command "$ProgressPreference=\'SilentlyContinue\'; (Invoke-WebRequest -Uri \'https://www.example.com\' -UseBasicParsing -TimeoutSec 10).Content"',
    policy: { network: { allowOutbound: true }, ui: { allowWindows: true } },
    successMarker: 'Example Domain' },
  { id: 'ps51-net-blocked',name: 'Internet blocked', category: 'Network Tests', categoryIcon: '🌐', shell: 'ps51',
    description: 'Tries to make an HTTPS request with no network access. Should fail.',
    expectedOutcome: 'be-blocked', expectedLabel: 'Should be blocked',
    script: 'powershell.exe -NoProfile -Command "try { $h=New-Object -ComObject WinHttp.WinHttpRequest.5.1; $h.Open(\'GET\',\'https://www.example.com\',$false); $h.Send(); Write-Output $h.ResponseText } catch { Write-Output \'BLOCKED\' }"',
    policy: { ui: { allowWindows: true } }, failureMarker: 'Example Domain' },
  { id: 'ps51-win32k-off', name: 'Win32k disabled', category: 'Desktop & UI Tests', categoryIcon: '🖥️', shell: 'ps51',
    description: 'Runs with Win32k disabled. PowerShell needs Win32k and should fail.',
    expectedOutcome: 'be-blocked', expectedLabel: 'Should fail (needs Win32k)',
    script: 'powershell.exe -NoProfile -Command "Write-Output PS_OK"',
    policy: { ui: { allowWindows: false } }, requiresV05: true },
  { id: 'ps51-timeout', name: 'Timeout', category: 'Error Cases', categoryIcon: '⚠️', shell: 'ps51',
    description: 'Runs a sleep with a 5-second timeout.',
    expectedOutcome: 'be-blocked', expectedLabel: 'Should be terminated',
    script: 'powershell.exe -NoProfile -Command Start-Sleep -Seconds 30',
    policy: { ui: { allowWindows: true }, timeoutMs: 5000 } },
  { id: 'ps51-full-access', name: 'Full access', category: 'Combined Tests', categoryIcon: '🔄', shell: 'ps51',
    description: 'Writes a file, reads it back, reports environment info.',
    expectedOutcome: 'succeed', expectedLabel: 'Should succeed',
    script: 'powershell.exe -NoProfile -Command "Set-Content -Path C:\\temp\\mxc-full-test\\result.txt -Value \'STEP1_OK\'; $c=Get-Content C:\\temp\\mxc-full-test\\result.txt; Write-Output $c; Write-Output (\'User: \' + $env:USERNAME); Write-Output \'ALL_OK\'"',
    policy: { filesystem: { readwritePaths: ['C:\\temp\\mxc-full-test'] }, ui: { allowWindows: true } },
    successMarker: 'ALL_OK' },

  // ========== PowerShell 7 ==========
  { id: 'ps7-hello', name: 'Echo Hello', category: 'Quick Tests', categoryIcon: '🎯', shell: 'ps7',
    description: 'Runs a hello world in PowerShell 7+.',
    expectedOutcome: 'succeed', expectedLabel: 'Should succeed',
    script: 'pwsh.exe -NoProfile -Command "Write-Output \'Hello from PowerShell 7\'"',
    policy: { ui: { allowWindows: true } }, successMarker: 'Hello from PowerShell 7' },
  { id: 'ps7-version', name: 'Version info', category: 'Quick Tests', categoryIcon: '🎯', shell: 'ps7',
    description: 'Gets PowerShell 7 version table.',
    expectedOutcome: 'succeed', expectedLabel: 'Should succeed',
    script: 'pwsh.exe -NoProfile -Command $PSVersionTable',
    policy: { ui: { allowWindows: true } }, successMarker: 'PSVersion' },
  { id: 'ps7-fs-write', name: 'Write to allowed folder', category: 'File Access Tests', categoryIcon: '📁', shell: 'ps7',
    description: 'Writes a file to a brokered path.',
    expectedOutcome: 'succeed', expectedLabel: 'Should succeed',
    script: 'pwsh.exe -NoProfile -Command "Set-Content -Path C:\\temp\\mxc-write-test\\ps7-output.txt -Value hello; Write-Output WRITE_OK"',
    policy: { ui: { allowWindows: true }, filesystem: { readwritePaths: ['C:\\temp\\mxc-write-test'] } },
    successMarker: 'WRITE_OK' },
  { id: 'ps7-fs-read', name: 'Read system file', category: 'File Access Tests', categoryIcon: '📁', shell: 'ps7',
    description: 'Reads the hosts file from a brokered read-only path.',
    expectedOutcome: 'succeed', expectedLabel: 'Should succeed',
    script: 'pwsh.exe -NoProfile -Command Get-Content C:\\Windows\\System32\\drivers\\etc\\hosts',
    policy: { ui: { allowWindows: true }, filesystem: { readonlyPaths: ['C:\\Windows\\System32\\drivers\\etc'] } },
    successMarker: 'sample HOSTS file' },
  { id: 'ps7-fs-write-blocked', name: 'Write without permission', category: 'File Access Tests', categoryIcon: '📁', shell: 'ps7',
    description: 'Tries to write to a system directory. Should be denied.',
    expectedOutcome: 'be-blocked', expectedLabel: 'Should be blocked',
    script: 'pwsh.exe -NoProfile -Command "try { Set-Content C:\\Windows\\test.txt -Value fail -ErrorAction Stop; exit 1 } catch { Write-Output BLOCKED; exit 0 }"',
    policy: { ui: { allowWindows: true } } },
  { id: 'ps7-net-ok', name: 'Internet allowed', category: 'Network Tests', categoryIcon: '🌐', shell: 'ps7',
    description: 'Makes an HTTPS request with outbound network enabled.',
    expectedOutcome: 'succeed', expectedLabel: 'Should succeed',
    script: 'pwsh.exe -NoProfile -Command "(Invoke-WebRequest -Uri \'https://www.example.com\' -UseBasicParsing -TimeoutSec 10).Content"',
    policy: { network: { allowOutbound: true }, ui: { allowWindows: true } },
    successMarker: 'Example Domain' },
  { id: 'ps7-net-blocked', name: 'Internet blocked', category: 'Network Tests', categoryIcon: '🌐', shell: 'ps7',
    description: 'Tries to make an HTTPS request with no network access. Should fail.',
    expectedOutcome: 'be-blocked', expectedLabel: 'Should be blocked',
    script: 'pwsh.exe -NoProfile -Command "try { (Invoke-WebRequest -Uri \'https://www.example.com\' -UseBasicParsing -TimeoutSec 5).Content } catch { Write-Output \'BLOCKED\' }"',
    policy: { ui: { allowWindows: true } }, failureMarker: 'Example Domain' },
  { id: 'ps7-win32k-off', name: 'Win32k disabled', category: 'Desktop & UI Tests', categoryIcon: '🖥️', shell: 'ps7',
    description: 'Runs with Win32k disabled. PowerShell 7 needs Win32k and should fail.',
    expectedOutcome: 'be-blocked', expectedLabel: 'Should fail (needs Win32k)',
    script: 'pwsh.exe -NoProfile -Command "Write-Output PS7_OK"',
    policy: { ui: { allowWindows: false } }, requiresV05: true },
  { id: 'ps7-timeout', name: 'Timeout', category: 'Error Cases', categoryIcon: '⚠️', shell: 'ps7',
    description: 'Runs a sleep with a 5-second timeout.',
    expectedOutcome: 'be-blocked', expectedLabel: 'Should be terminated',
    script: 'pwsh.exe -NoProfile -Command Start-Sleep -Seconds 30',
    policy: { ui: { allowWindows: true }, timeoutMs: 5000 } },
  { id: 'ps7-full-access', name: 'Full access', category: 'Combined Tests', categoryIcon: '🔄', shell: 'ps7',
    description: 'Writes a file, reads it back, reports environment info.',
    expectedOutcome: 'succeed', expectedLabel: 'Should succeed',
    script: 'pwsh.exe -NoProfile -Command "Set-Content -Path C:\\temp\\mxc-full-test\\ps7-result.txt -Value \'STEP1_OK\'; $c=Get-Content C:\\temp\\mxc-full-test\\ps7-result.txt; Write-Output $c; Write-Output (\'User: \' + $env:USERNAME); Write-Output \'ALL_OK\'"',
    policy: { filesystem: { readwritePaths: ['C:\\temp\\mxc-full-test'] }, ui: { allowWindows: true } },
    successMarker: 'ALL_OK' },

  // ========== Python ==========
  { id: 'py-hello', name: 'Echo Hello', category: 'Quick Tests', categoryIcon: '🎯', shell: 'python',
    description: 'Runs a hello world in Python.',
    expectedOutcome: 'succeed', expectedLabel: 'Should succeed',
    script: 'python -c "print(\'Hello from Python\')"',
    policy: { ui: { allowWindows: true } }, successMarker: 'Hello from Python' },
  { id: 'py-version', name: 'Version info', category: 'Quick Tests', categoryIcon: '🎯', shell: 'python',
    description: 'Gets Python version.',
    expectedOutcome: 'succeed', expectedLabel: 'Should succeed',
    script: 'python -c "import sys; print(f\'Python {sys.version}\')"',
    policy: { ui: { allowWindows: true } }, successMarker: 'Python' },
  { id: 'py-fs-write', name: 'Write to allowed folder', category: 'File Access Tests', categoryIcon: '📁', shell: 'python',
    description: 'Writes a file to a brokered read-write path.',
    expectedOutcome: 'succeed', expectedLabel: 'Should succeed',
    script: 'python -c "f=open(r\'C:\\temp\\mxc-write-test\\py-output.txt\',\'w\'); f.write(\'hello\'); f.close(); print(\'WRITE_OK\')"',
    policy: { ui: { allowWindows: true }, filesystem: { readwritePaths: ['C:\\temp\\mxc-write-test'] } },
    successMarker: 'WRITE_OK' },
  { id: 'py-fs-read', name: 'Read system file', category: 'File Access Tests', categoryIcon: '📁', shell: 'python',
    description: 'Reads the hosts file from a brokered read-only path.',
    expectedOutcome: 'succeed', expectedLabel: 'Should succeed',
    script: 'python -c "print(open(r\'C:\\Windows\\System32\\drivers\\etc\\hosts\').read()[:200])"',
    policy: { ui: { allowWindows: true }, filesystem: { readonlyPaths: ['C:\\Windows\\System32\\drivers\\etc'] } },
    successMarker: 'sample HOSTS file' },
  { id: 'py-net-ok', name: 'Internet allowed', category: 'Network Tests', categoryIcon: '🌐', shell: 'python',
    description: 'Makes an HTTPS request with outbound network enabled.',
    expectedOutcome: 'succeed', expectedLabel: 'Should succeed',
    script: 'python -c "import urllib.request; print(urllib.request.urlopen(\'https://www.example.com\',timeout=10).read().decode()[:200])"',
    policy: { network: { allowOutbound: true }, ui: { allowWindows: true } },
    successMarker: 'Example Domain' },
  { id: 'py-net-blocked', name: 'Internet blocked', category: 'Network Tests', categoryIcon: '🌐', shell: 'python',
    description: 'Tries to make an HTTPS request with no network access. Should fail.',
    expectedOutcome: 'be-blocked', expectedLabel: 'Should be blocked',
    script: 'python -c "import urllib.request; print(urllib.request.urlopen(\'https://www.example.com\',timeout=5).read().decode())"',
    policy: { ui: { allowWindows: true } }, failureMarker: 'Example Domain' },
  { id: 'py-timeout', name: 'Timeout', category: 'Error Cases', categoryIcon: '⚠️', shell: 'python',
    description: 'Runs a sleep with a 5-second timeout.',
    expectedOutcome: 'be-blocked', expectedLabel: 'Should be terminated',
    script: 'python -c "import time; time.sleep(30)"',
    policy: { ui: { allowWindows: true }, timeoutMs: 5000 } },
  { id: 'py-full-access', name: 'Full access', category: 'Combined Tests', categoryIcon: '🔄', shell: 'python',
    description: 'Writes a file, reads it back using Python.',
    expectedOutcome: 'succeed', expectedLabel: 'Should succeed',
    script: 'python -c "f=open(r\'C:\\temp\\mxc-full-test\\py-result.txt\',\'w\'); f.write(\'STEP1_OK\'); f.close(); c=open(r\'C:\\temp\\mxc-full-test\\py-result.txt\').read(); print(c); print(\'ALL_OK\')"',
    policy: { filesystem: { readwritePaths: ['C:\\temp\\mxc-full-test'] }, ui: { allowWindows: true } },
    successMarker: 'ALL_OK' },

  // ========== Windows Sandbox ==========
  { id: 'ws-echo', name: 'Echo Hello', category: 'Quick Tests', categoryIcon: '🎯', shell: 'cmd',
    containment: 'windows_sandbox',
    description: 'Runs a simple echo command inside the Windows Sandbox VM.',
    expectedOutcome: 'succeed', expectedLabel: 'Should succeed',
    script: 'echo Hello from sandbox!',
    policy: {}, successMarker: 'Hello from sandbox!' },
  { id: 'ws-python', name: 'Python version', category: 'Quick Tests', categoryIcon: '🎯', shell: 'python',
    containment: 'windows_sandbox',
    description: 'Runs Python inside the sandbox to verify the mapped host Python works.',
    expectedOutcome: 'succeed', expectedLabel: 'Should succeed',
    script: 'python -S -B -c "import sys; print(\'Hello from Windows Sandbox!\'); print(f\'Python version: {sys.version}\'); print(\'Script executed successfully in sandbox isolation\')"',
    policy: {}, successMarker: 'executed successfully' },
  { id: 'ws-ps-hello', name: 'PowerShell hello', category: 'Quick Tests', categoryIcon: '🎯', shell: 'ps51',
    containment: 'windows_sandbox',
    description: 'Runs PowerShell inside the sandbox and prints version info.',
    expectedOutcome: 'succeed', expectedLabel: 'Should succeed',
    script: 'powershell -NoProfile -Command "Write-Output \'PowerShell works\'; $PSVersionTable.PSVersion.ToString()"',
    policy: {}, successMarker: 'PowerShell works' },
  { id: 'ws-ps-env', name: 'PowerShell environment', category: 'Quick Tests', categoryIcon: '🎯', shell: 'ps51',
    containment: 'windows_sandbox',
    description: 'Shows environment info (computer name, user, process count) inside the sandbox.',
    expectedOutcome: 'succeed', expectedLabel: 'Should succeed',
    script: 'powershell -NoProfile -Command "Write-Output (\'ComputerName=\' + $env:COMPUTERNAME); Write-Output (\'User=\' + $env:USERNAME); Write-Output (\'ProcessCount=\' + (Get-Process | Measure-Object).Count)"',
    policy: {}, successMarker: 'ComputerName=' },
  { id: 'ws-stderr', name: 'Stdout & stderr', category: 'Quick Tests', categoryIcon: '🎯', shell: 'cmd',
    containment: 'windows_sandbox',
    description: 'Writes to both stdout and stderr. Both should be captured.',
    expectedOutcome: 'succeed', expectedLabel: 'Should succeed',
    script: 'echo stdout-message && echo stderr-message 1>&2',
    policy: {}, successMarker: 'stdout-message' },
  { id: 'ws-exit-code', name: 'Exit code', category: 'Error Cases', categoryIcon: '⚠️', shell: 'cmd',
    containment: 'windows_sandbox',
    description: 'Exits with code 42. Verifies exit codes are propagated from the sandbox.',
    expectedOutcome: 'show-error', expectedLabel: 'Should exit 42',
    script: 'exit /b 42',
    policy: {} },
  { id: 'ws-timeout', name: 'Timeout', category: 'Error Cases', categoryIcon: '⚠️', shell: 'cmd',
    containment: 'windows_sandbox',
    description: 'Runs a long ping with a 5-second timeout. Should be terminated.',
    expectedOutcome: 'be-blocked', expectedLabel: 'Should be terminated',
    script: 'ping -n 30 127.0.0.1',
    policy: { timeoutMs: 5000 } },

  // ========== MicroVM (NanVix) ==========
  { id: 'mv-hello', name: 'Hello from MicroVM', category: 'Quick Tests', categoryIcon: '🎯', shell: 'python',
    containment: 'microvm',
    description: 'Runs a simple Python script inside the NanVix micro-VM.',
    expectedOutcome: 'succeed', expectedLabel: 'Should succeed',
    script: "x = 42\ny = 58\nprint('Hello from MicroVM! sum=%d' % (x + y))",
    policy: {}, successMarker: 'Hello from MicroVM!' },
  { id: 'mv-stdlib', name: 'Stdlib (json, math, hashlib)', category: 'Quick Tests', categoryIcon: '🎯', shell: 'python',
    containment: 'microvm',
    description: 'Imports json, math, hashlib to verify the CPython stdlib is available.',
    expectedOutcome: 'succeed', expectedLabel: 'Should succeed',
    script: "import json, math, hashlib\ndata = {'pi': math.pi, 'e': math.e, 'hash': hashlib.sha256(b'nanvix').hexdigest()[:16]}\nprint(json.dumps(data))",
    policy: {}, successMarker: 'pi' },
  { id: 'mv-multiline', name: 'Fibonacci (multiline)', category: 'Quick Tests', categoryIcon: '🎯', shell: 'python',
    containment: 'microvm',
    description: 'Runs a multi-line Fibonacci function to verify complex scripts work.',
    expectedOutcome: 'succeed', expectedLabel: 'Should succeed',
    script: "def fib(n):\n    a, b = 0, 1\n    for _ in range(n):\n        a, b = b, a + b\n    return a\n\nfor i in range(10):\n    print(f'fib({i}) = {fib(i)}')",
    policy: {}, successMarker: 'fib(9) = 34' },
  { id: 'mv-large-output', name: 'Large output (1000 lines)', category: 'Quick Tests', categoryIcon: '🎯', shell: 'python',
    containment: 'microvm',
    description: 'Prints 1000 lines to verify large output streaming works.',
    expectedOutcome: 'succeed', expectedLabel: 'Should succeed',
    script: "for i in range(1000):\n    print(f'line {i}: ' + 'x' * 80)",
    policy: {}, successMarker: 'line 999' },
  { id: 'mv-exit-code', name: 'Exit code 42', category: 'Error Cases', categoryIcon: '⚠️', shell: 'python',
    containment: 'microvm',
    description: 'Exits with code 42. Verifies exit codes propagate from the micro-VM.',
    expectedOutcome: 'show-error', expectedLabel: 'Should exit 42',
    script: 'import sys; sys.exit(42)',
    policy: {} },
  { id: 'mv-error', name: 'Python error', category: 'Error Cases', categoryIcon: '⚠️', shell: 'python',
    containment: 'microvm',
    description: 'Raises a ValueError. Verifies stderr capture from the micro-VM.',
    expectedOutcome: 'show-error', expectedLabel: 'Should show error',
    script: "raise ValueError('intentional test error')",
    policy: {} },
  { id: 'mv-timeout', name: 'Timeout', category: 'Error Cases', categoryIcon: '⚠️', shell: 'python',
    containment: 'microvm',
    description: 'Sleeps for 120s with a 5s timeout. MicroVM adds 60s boot grace, so actual ~65s.',
    expectedOutcome: 'be-blocked', expectedLabel: 'Should be terminated',
    script: "import time; time.sleep(120); print('should not reach here')",
    policy: { timeoutMs: 5000 } },

  // ========== MicroVM — Filesystem ==========
  { id: 'mv-fs-write-read', name: 'Write & read file (FS mount)', category: 'Filesystem', categoryIcon: '📁', shell: 'filesystem',
    containment: 'microvm',
    description: 'Writes a file to a readwritePaths mount and reads it back. Verifies staging dir works.',
    expectedOutcome: 'succeed', expectedLabel: 'Should succeed',
    script: "import os\ntest_dir = 'C:\\\\Users\\\\Public\\\\MXCPlaygroundTests'\nfpath = os.path.join(test_dir, 'mxc-mv-test.txt')\ntry:\n    with open(fpath, 'w') as f:\n        f.write('hello from microvm')\n    with open(fpath) as f:\n        data = f.read()\n    print('Read back:', data)\n    assert data == 'hello from microvm', 'mismatch!'\n    print('MV FS write/read OK')\nfinally:\n    try: os.remove(fpath)\n    except OSError: pass",
    policy: { filesystem: { readwritePaths: ['C:\\Users\\Public\\MXCPlaygroundTests'] } }, successMarker: 'MV FS write/read OK' },
  { id: 'mv-fs-list-dir', name: 'List directory contents', category: 'Filesystem', categoryIcon: '📁', shell: 'filesystem',
    containment: 'microvm',
    description: 'Creates and lists files in a readwritePaths mount. Verifies directory operations.',
    expectedOutcome: 'succeed', expectedLabel: 'Should succeed',
    script: "import os\ntest_dir = 'C:\\\\Users\\\\Public\\\\MXCPlaygroundTests'\nnames = ['mxc-a.txt', 'mxc-b.txt', 'mxc-c.txt']\ntry:\n    for name in names:\n        with open(os.path.join(test_dir, name), 'w') as f:\n            f.write(name)\n    entries = [e for e in os.listdir(test_dir) if e.startswith('mxc-')]\n    print('MXC files:', sorted(entries))\n    assert 'mxc-a.txt' in entries and 'mxc-c.txt' in entries\n    print('MV dir listing OK')\nfinally:\n    for name in names:\n        try: os.remove(os.path.join(test_dir, name))\n        except OSError: pass",
    policy: { filesystem: { readwritePaths: ['C:\\Users\\Public\\MXCPlaygroundTests'] } }, successMarker: 'MV dir listing OK' },

  // ========== MicroVM — Stdlib ==========
  { id: 'mv-stdlib-broad', name: 'Stdlib (re, datetime, collections)', category: 'Quick Tests', categoryIcon: '🎯', shell: 'python',
    containment: 'microvm',
    description: 'Imports re, datetime, collections to verify broader stdlib availability.',
    expectedOutcome: 'succeed', expectedLabel: 'Should succeed',
    script: "import re, datetime, collections\nm = re.match(r'(\\w+)@(\\w+)', 'user@host')\nprint('regex:', m.group(1), m.group(2))\nnow = datetime.datetime(2025, 1, 15, 12, 0)\nprint('datetime:', now.isoformat())\nc = collections.Counter('abracadabra')\nprint('counter:', c.most_common(3))\nprint('broad stdlib OK')",
    policy: {}, successMarker: 'broad stdlib OK' },
  { id: 'mv-memory', name: 'Memory stress (10MB list)', category: 'Quick Tests', categoryIcon: '🎯', shell: 'python',
    containment: 'microvm',
    description: 'Allocates a 10MB list to verify the VM handles non-trivial memory.',
    expectedOutcome: 'succeed', expectedLabel: 'Should succeed',
    script: "data = list(range(1_000_000))\nprint('Allocated', len(data), 'items')\nprint('Sum:', sum(data[:100]))\nprint('Memory OK')",
    policy: {}, successMarker: 'Memory OK' },
  { id: 'hl-hello', name: 'Hello from Hyperlight', category: 'Quick Tests', categoryIcon: '🎯', shell: 'python',
    containment: 'hyperlight',
    description: 'Runs a simple Python script inside the Hyperlight+Unikraft micro-VM.',
    expectedOutcome: 'succeed', expectedLabel: 'Should succeed',
    script: "x = 42\ny = 58\nprint('Hello from Hyperlight! sum=%d' % (x + y))",
    policy: {}, successMarker: 'Hello from Hyperlight!' },
  { id: 'hl-stdlib', name: 'Stdlib (json, math, hashlib)', category: 'Quick Tests', categoryIcon: '🎯', shell: 'python',
    containment: 'hyperlight',
    description: 'Imports json, math, hashlib to verify CPython stdlib is available in Hyperlight.',
    expectedOutcome: 'succeed', expectedLabel: 'Should succeed',
    script: "import json, math, hashlib\ndata = {'pi': math.pi, 'e': math.e, 'hash': hashlib.sha256(b'hyperlight').hexdigest()[:16]}\nprint(json.dumps(data))",
    policy: {}, successMarker: 'pi' },
  { id: 'hl-multiline', name: 'Fibonacci (multiline)', category: 'Quick Tests', categoryIcon: '🎯', shell: 'python',
    containment: 'hyperlight',
    description: 'Runs a multi-line Fibonacci function to verify complex scripts work in Hyperlight.',
    expectedOutcome: 'succeed', expectedLabel: 'Should succeed',
    script: "def fib(n):\n    a, b = 0, 1\n    for _ in range(n):\n        a, b = b, a + b\n    return a\n\nfor i in range(10):\n    print(f'fib({i}) = {fib(i)}')",
    policy: {}, successMarker: 'fib(9) = 34' },
  { id: 'hl-large-output', name: 'Large output (1000 lines)', category: 'Quick Tests', categoryIcon: '🎯', shell: 'python',
    containment: 'hyperlight',
    description: 'Prints 1000 lines to verify large output streaming works in Hyperlight.',
    expectedOutcome: 'succeed', expectedLabel: 'Should succeed',
    script: "for i in range(1000):\n    print(f'line {i}: ' + 'x' * 80)",
    policy: {}, successMarker: 'line 999' },
  { id: 'hl-exit-code', name: 'Exit code 42', category: 'Error Cases', categoryIcon: '⚠️', shell: 'python',
    containment: 'hyperlight',
    description: 'Exits with code 42. Verifies exit codes propagate from Hyperlight.',
    expectedOutcome: 'show-error', expectedLabel: 'Should exit 42',
    script: 'import sys; sys.exit(42)',
    policy: {} },
  { id: 'hl-error', name: 'Python error', category: 'Error Cases', categoryIcon: '⚠️', shell: 'python',
    containment: 'hyperlight',
    description: 'Raises a ValueError. Verifies stderr capture from Hyperlight.',
    expectedOutcome: 'show-error', expectedLabel: 'Should show error',
    script: "raise ValueError('intentional test error')",
    policy: {} },
  { id: 'hl-timeout', name: 'Timeout', category: 'Error Cases', categoryIcon: '⚠️', shell: 'python',
    containment: 'hyperlight',
    description: 'Sleeps for 120s with a 5s timeout. Should be terminated by the host.',
    expectedOutcome: 'be-blocked', expectedLabel: 'Should be terminated',
    script: "import time; time.sleep(120); print('should not reach here')",
    policy: { timeoutMs: 5000 } },

  // ========== Hyperlight — Networking ==========
  { id: 'hl-net-socket-api', name: 'Socket API available', category: 'Networking', categoryIcon: '🌐', shell: 'networking',
    containment: 'hyperlight',
    description: 'Verifies the socket module loads and socket creation works (no actual connection).',
    expectedOutcome: 'succeed', expectedLabel: 'Should succeed',
    script: "import socket\ns = socket.socket(socket.AF_INET, socket.SOCK_STREAM)\nprint('Socket created:', s.fileno())\nprint('Family:', s.family.name)\nprint('Type:', s.type.name)\ns.close()\nprint('Socket API OK')",
    policy: { network: { enabled: true } }, successMarker: 'Socket API OK' },
  { id: 'hl-net-modules', name: 'Network stdlib modules', category: 'Networking', categoryIcon: '🌐', shell: 'networking',
    containment: 'hyperlight',
    description: 'Imports ssl, http.client, urllib to verify network stdlib is available.',
    expectedOutcome: 'succeed', expectedLabel: 'Should succeed',
    script: "import ssl\nimport http.client\nimport urllib.request\nimport urllib.parse\nprint('ssl version:', ssl.OPENSSL_VERSION)\nprint('http.client OK')\nprint('urllib OK')\nprint('Net modules OK')",
    policy: {}, successMarker: 'Net modules OK' },
  { id: 'hl-net-http-allow', name: 'HTTP GET (network on)', category: 'Networking', categoryIcon: '🌐', shell: 'networking',
    containment: 'hyperlight',
    description: 'Makes an HTTP GET request with networking enabled. Verifies real outbound connectivity.',
    expectedOutcome: 'succeed', expectedLabel: 'Should succeed',
    script: "import urllib.request\nresp = urllib.request.urlopen('http://httpbin.org/get', timeout=10)\nprint('HTTP status:', resp.status)\nprint('Network works!')",
    policy: { network: { enabled: true } }, successMarker: 'Network works!' },
  { id: 'hl-net-http-blocked', name: 'HTTP GET (network off)', category: 'Networking', categoryIcon: '🌐', shell: 'networking',
    containment: 'hyperlight',
    description: 'Attempts HTTP GET with networking disabled. Should fail to connect (verdict passes when blocked).',
    expectedOutcome: 'succeed', expectedLabel: 'Should block network request',
    script: "import urllib.request\ntry:\n    urllib.request.urlopen('http://httpbin.org/get', timeout=5)\n    print('ERROR: request should have failed')\nexcept Exception as e:\n    print('Correctly blocked:', type(e).__name__)",
    policy: {}, successMarker: 'Correctly blocked', failureMarker: 'ERROR: request should have failed' },

  // ========== Hyperlight — Filesystem ==========
  { id: 'hl-fs-write-read', name: 'Write & read file', category: 'Filesystem', categoryIcon: '📁', shell: 'filesystem',
    containment: 'hyperlight',
    description: 'Writes a file to a mounted directory and reads it back. Verifies FS mount works.',
    expectedOutcome: 'succeed', expectedLabel: 'Should succeed',
    script: "import os, tempfile\ntd = tempfile.mkdtemp()\nfpath = os.path.join(td, 'test.txt')\nwith open(fpath, 'w') as f:\n    f.write('hello from hyperlight')\nwith open(fpath) as f:\n    data = f.read()\nprint('Read back:', data)\nassert data == 'hello from hyperlight', 'mismatch!'\nprint('FS write/read OK')",
    policy: {}, successMarker: 'FS write/read OK' },
  { id: 'hl-fs-stdlib-os', name: 'os module (cwd, pid, env)', category: 'Filesystem', categoryIcon: '📁', shell: 'filesystem',
    containment: 'hyperlight',
    description: 'Uses os module to check cwd, pid, and environment. Verifies OS-level introspection.',
    expectedOutcome: 'succeed', expectedLabel: 'Should succeed',
    script: "import os\nprint('PID:', os.getpid())\nprint('CWD:', os.getcwd())\nprint('ENV keys:', len(os.environ))\nprint('os module OK')",
    policy: {}, successMarker: 'os module OK' },

  // ========== Hyperlight — Networking (advanced) ==========
  // ========== Hyperlight — Stdlib & ML stack ==========
  { id: 'hl-stdlib-broad', name: 'Stdlib (re, datetime, collections)', category: 'Quick Tests', categoryIcon: '🎯', shell: 'python',
    containment: 'hyperlight',
    description: 'Imports re, datetime, collections to verify broader stdlib availability.',
    expectedOutcome: 'succeed', expectedLabel: 'Should succeed',
    script: "import re, datetime, collections\nm = re.match(r'(\\w+)@(\\w+)', 'user@host')\nprint('regex:', m.group(1), m.group(2))\nnow = datetime.datetime(2025, 1, 15, 12, 0)\nprint('datetime:', now.isoformat())\nc = collections.Counter('abracadabra')\nprint('counter:', c.most_common(3))\nprint('broad stdlib OK')",
    policy: {}, successMarker: 'broad stdlib OK' },
  { id: 'hl-numpy', name: 'numpy import & compute', category: 'Quick Tests', categoryIcon: '🎯', shell: 'python',
    containment: 'hyperlight',
    description: 'Imports numpy and does basic array ops. Verifies the preloaded ML stack.',
    expectedOutcome: 'succeed', expectedLabel: 'Should succeed',
    script: "import numpy as np\narr = np.arange(100).reshape(10, 10)\nprint('Shape:', arr.shape)\nprint('Sum:', arr.sum())\nprint('Mean:', arr.mean())\nprint('numpy OK')",
    policy: {}, successMarker: 'numpy OK' },
  { id: 'hl-memory', name: 'Memory stress (10MB list)', category: 'Quick Tests', categoryIcon: '🎯', shell: 'python',
    containment: 'hyperlight',
    description: 'Allocates a 10MB list to verify the VM handles non-trivial memory.',
    expectedOutcome: 'succeed', expectedLabel: 'Should succeed',
    script: "data = list(range(1_000_000))\nprint('Allocated', len(data), 'items')\nprint('Sum:', sum(data[:100]))\nprint('Memory OK')",
    policy: {}, successMarker: 'Memory OK' },
];

// ============================================================
// State
// ============================================================

var state = {
  currentView: 'main' as 'welcome' | 'main',
  selectedScenario: null as Scenario | null,
  customScript: '',
  version: '0.5.0-dev',
  timeoutSeconds: 30,
  advancedMode: false,
  // Filesystem
  fsEnabled: false,
  rwPaths: [] as string[],
  roPaths: [] as string[],
  fsIncludeTools: false,
  fsIncludeTemp: false,
  // Network
  netEnabled: false,
  // UI
  uiAllowWindows: true,
  uiClipboard: 'none' as string,
  uiInjection: false,
  // Running
  running: false,
  // Track original scenario policy for modification detection
  scenarioPolicySnapshot: '' as string,
  // JSON tab
  activeJsonTab: null as string | null,
  // Section visibility
  permissionsOpen: false,
  advancedOpen: false,
  terminalOpen: true,
};

// ============================================================
// DOM Helpers
// ============================================================

function $(id: string): HTMLElement {
  return document.getElementById(id)!;
}

function $sel(id: string): HTMLSelectElement {
  return document.getElementById(id) as HTMLSelectElement;
}

function $chk(id: string): HTMLInputElement {
  return document.getElementById(id) as HTMLInputElement;
}

function $num(id: string): HTMLInputElement {
  return document.getElementById(id) as HTMLInputElement;
}

// ============================================================
// ANSI Stripping
// ============================================================

function stripAnsi(text: string): string {
  return text
    .replace(/\x1b\[[0-9;]*[a-zA-Z]/g, '')
    .replace(/\x1b\][^\x07]*\x07/g, '')
    .replace(/\x1b\[\?[0-9;]*[a-zA-Z]/g, '');
}

// ============================================================
// JSON Syntax Highlighting
// ============================================================

function highlightJson(json: string): string {
  return json.replace(
    /("(?:\\.|[^"\\])*")\s*:/g,
    '<span class="json-key">$1</span>:'
  ).replace(
    /:\s*("(?:\\.|[^"\\])*")/g,
    function(match, val) { return ': <span class="json-string">' + val + '</span>'; }
  ).replace(
    /:\s*(\d+(?:\.\d+)?)/g,
    ': <span class="json-number">$1</span>'
  ).replace(
    /:\s*(true|false)/g,
    ': <span class="json-boolean">$1</span>'
  ).replace(
    /:\s*(null)/g,
    ': <span class="json-null">$1</span>'
  );
}

// ============================================================
// Terminal
// ============================================================

function termClear(): void {
  $('terminal').innerHTML = '';
}

function termWrite(text: string, cls: string): void {
  var el = $('terminal');
  var span = document.createElement('span');
  span.className = cls;
  span.textContent = text + '\n';
  el.appendChild(span);
  el.scrollTop = el.scrollHeight;
}

function termInfo(msg: string): void { termWrite(msg, 'line-info'); }
function termSuccess(msg: string): void { termWrite(msg, 'line-success'); }
function termError(msg: string): void { termWrite(msg, 'line-error'); }
function termDim(msg: string): void { termWrite(msg, 'line-dim'); }
function termOutput(text: string): void { termWrite(text, 'line-output'); }

// ============================================================
// Auto-detect advanced mode
// ============================================================

function isAdvancedNeeded(): boolean {
  var isolation = $sel('uiIsolation').value;
  var desktopControl = $chk('uiDesktopControl').checked;
  var systemSettings = $sel('uiSystemSettings').value;
  var ime = $chk('uiIME').checked;
  if (isolation !== 'container') return true;
  if (desktopControl) return true;
  if (systemSettings !== 'none') return true;
  if (ime) return true;
  if (state.version === '0.5.0-dev') return true;
  return false;
}

// ============================================================
// Build Policy
// ============================================================

function buildPolicy(): any {
  var policy: any = { version: state.version };

  // Filesystem
  if (state.fsEnabled) {
    var rwPaths = state.rwPaths.slice();
    var roPaths = state.roPaths.slice();
    if (rwPaths.length > 0 || roPaths.length > 0) {
      policy.filesystem = {};
      if (rwPaths.length > 0) policy.filesystem.readwritePaths = rwPaths;
      if (roPaths.length > 0) policy.filesystem.readonlyPaths = roPaths;
    }
  }

  // Network
  if (state.netEnabled) {
    policy.network = { allowOutbound: true };
    var proxyVal = $sel('proxySelect').value;
    if (proxyVal === 'builtin') {
      policy.network.proxy = { builtinTestServer: true };
    } else if (proxyVal === 'localhost') {
      var port = parseInt($num('proxyPort').value, 10);
      if (port > 0 && port <= 65535) {
        policy.network.proxy = { localhost: port };
      }
    } else if (proxyVal === 'url') {
      var urlVal = ($('proxyUrl') as HTMLInputElement).value.trim();
      if (urlVal) {
        policy.network.proxy = { url: urlVal };
      }
    }
  }

  // UI
  policy.ui = { allowWindows: state.uiAllowWindows };
  if (state.uiClipboard !== 'none') policy.ui.clipboard = state.uiClipboard;
  if (state.uiInjection) policy.ui.allowInputInjection = true;

  // Timeout
  if (state.timeoutSeconds > 0) {
    policy.timeoutMs = state.timeoutSeconds * 1000;
  }

  // Auto-include Python path for Python scenarios
  if (state.selectedScenario?.shell === 'python' && shellPaths.python?.rootDir) {
    policy.filesystem = policy.filesystem || {};
    policy.filesystem.readwritePaths = policy.filesystem.readwritePaths || [];
    if (policy.filesystem.readwritePaths.indexOf(shellPaths.python.rootDir) === -1) {
      policy.filesystem.readwritePaths.push(shellPaths.python.rootDir);
    }
  }

  // Auto-include PS7 path for PS7 scenarios
  if (state.selectedScenario?.shell === 'ps7' && shellPaths.ps7?.rootDir) {
    policy.filesystem = policy.filesystem || {};
    policy.filesystem.readonlyPaths = policy.filesystem.readonlyPaths || [];
    if (policy.filesystem.readonlyPaths.indexOf(shellPaths.ps7.rootDir) === -1) {
      policy.filesystem.readonlyPaths.push(shellPaths.ps7.rootDir);
    }
    // For MSIX installs (WindowsApps), also add the resolved package directory
    // so backends that enforce filesystem policy (BaseContainer, Windows Sandbox,
    // LXC, seatbelt) can grant access to the actual PS7 binaries/DLLs.
    // AppContainer ignores filesystem policy and will fall back to ambient DACLs.
    if (shellPaths.ps7.msixPackageDir) {
      if (policy.filesystem.readonlyPaths.indexOf(shellPaths.ps7.msixPackageDir) === -1) {
        policy.filesystem.readonlyPaths.push(shellPaths.ps7.msixPackageDir);
      }
    }
  }

  return policy;
}

// ============================================================
// Get current script
// ============================================================

function getCurrentScript(): string {
  var script = '';
  if (state.selectedScenario && state.selectedScenario.id !== 'custom') {
    script = state.selectedScenario.script;
  } else {
    script = state.customScript || '';
  }

  // Replace bare 'python' with resolved full path for BaseContainer compatibility
  // (skip for Windows Sandbox — it uses mapped Python from the host)
  var containment = $sel('containmentSelect').value;
  if (containment !== 'windows_sandbox' && containment !== 'microvm' && containment !== 'hyperlight' && shellPaths.python?.exe && script.match(/^python\s/)) {
    script = '"' + shellPaths.python.exe + '"' + script.substring(6);
  }

  return script;
}

// ============================================================
// Containment badge
// ============================================================

var CONTAINMENT_LABELS: Record<string, string> = {
  appcontainer: 'Base Process Container',
  windows_sandbox: 'Windows Sandbox',
  microvm: 'MicroVM (NanVix)',
  hyperlight: 'Hyperlight',
  wslc: 'WSLC',
  lxc: 'LXC',
  vm: 'VM',
};

function updateContainmentDropdown(): void {
  var version = state.version;
  var select = $sel('containmentSelect');
  var isV05 = version === '0.5.0-dev';

  for (var i = 0; i < select.options.length; i++) {
    var opt = select.options[i];
    if (opt.value === 'appcontainer') {
      opt.textContent = isV05 ? '🛡️ Base Process Container' : '🛡️ AppContainer';
    } else {
      // Experimental types only on 0.5.0+
      opt.disabled = !isV05;
      opt.style.display = isV05 ? '' : 'none';
    }
  }

  // If on 0.4.0 and an experimental type was selected, reset to appcontainer
  if (!isV05 && select.value !== 'appcontainer') {
    select.value = 'appcontainer';
    select.dispatchEvent(new Event('change'));
  }
}

function isExperimentalContainment(): boolean {
  return $sel('containmentSelect').value !== 'appcontainer';
}

// Cached platform support result for badge updates
var cachedPlatformSupport: { isSupported: boolean; reason?: string } | null = null;

/** Update the platform badge based on the selected containment backend. */
function updatePlatformBadgeForContainment(containment: string): void {
  if (containment === 'microvm' || containment === 'hyperlight') {
    // HL/MV don't depend on a specific Windows build version
    var label = CONTAINMENT_LABELS[containment] || containment;
    $('platformBadge').textContent = '✓ ' + label + ' (no OS version requirement)';
  } else if (cachedPlatformSupport) {
    // Restore the real platform check result
    $('platformBadge').textContent = cachedPlatformSupport.isSupported
      ? '✓ Platform supported'
      : '✗ ' + (cachedPlatformSupport.reason || 'Not supported');
  }
}

// ============================================================
// Policy summary
// ============================================================

function isVmBackend(): boolean {
  var c = $sel('containmentSelect').value;
  return c === 'microvm' || c === 'hyperlight' || c === 'windows_sandbox';
}

function getPermsSummary(): string {
  if (isVmBackend()) {
    var label = CONTAINMENT_LABELS[$sel('containmentSelect').value] || $sel('containmentSelect').value;
    return label + ' — VM-level isolation';
  }
  var fs = state.fsEnabled ? 'limited' : 'off';
  var net = state.netEnabled ? 'on' : 'off';
  var ui = state.uiAllowWindows ? 'on' : 'off';
  return 'Files: ' + fs + ' · Internet: ' + net + ' · Desktop: ' + ui;
}

function updatePermsSummary(): void {
  var summary = getPermsSummary();
  $('permissionsSummaryLine').textContent = summary;
  if (isVmBackend()) {
    $('runSummary').textContent = summary;
  } else {
    $('runSummary').textContent = 'Internet: ' + (state.netEnabled ? 'on' : 'off') +
      ' · Files: ' + (state.fsEnabled ? 'limited' : 'off') +
      ' · Desktop: ' + (state.uiAllowWindows ? 'on' : 'off');
  }
}

// ============================================================
// Path list rendering
// ============================================================

function renderPathList(containerId: string, paths: string[], onRemove: (index: number) => void): void {
  var container = $(containerId);
  container.innerHTML = '';
  if (paths.length === 0) {
    var empty = document.createElement('div');
    empty.className = 'path-empty';
    empty.textContent = 'No folders added';
    container.appendChild(empty);
    return;
  }
  paths.forEach(function(p, i) {
    var item = document.createElement('div');
    item.className = 'path-item';

    var text = document.createElement('span');
    text.className = 'path-text';
    text.textContent = p;
    text.title = p;
    item.appendChild(text);

    var removeBtn = document.createElement('button');
    removeBtn.className = 'path-remove';
    removeBtn.textContent = '×';
    removeBtn.title = 'Remove';
    removeBtn.addEventListener('click', function() {
      onRemove(i);
    });
    item.appendChild(removeBtn);

    container.appendChild(item);
  });
}

function refreshPathLists(): void {
  renderPathList('rwPathList', state.rwPaths, function(i) {
    state.rwPaths.splice(i, 1);
    refreshPathLists();
    updateDevSidebar();
  });
  renderPathList('roPathList', state.roPaths, function(i) {
    state.roPaths.splice(i, 1);
    refreshPathLists();
    updateDevSidebar();
  });
}

// ============================================================
// Result card
// ============================================================

function setResultIdle(): void {
  var card = $('resultCard');
  card.className = 'result-card result-idle';
  $('resultIcon').textContent = '💡';
  $('resultTitle').textContent = 'Select a scenario and click Run in Sandbox';
  $('resultDetail').textContent = '';
  $('resultActions').classList.add('hidden');
  $('resultActions').innerHTML = '';
}

function setResultRunning(): void {
  var card = $('resultCard');
  card.className = 'result-card result-running';
  $('resultIcon').textContent = '⏳';
  $('resultTitle').textContent = 'Running…';
  $('resultDetail').textContent = 'Script is executing inside the sandbox';
  $('resultActions').classList.add('hidden');
}

function setResultSuccess(exitCode: number): void {
  var card = $('resultCard');
  card.className = 'result-card result-success';
  $('resultIcon').textContent = '✅';
  $('resultTitle').textContent = 'Script completed successfully (exit code ' + formatExitCode(exitCode) + ')';
  $('resultDetail').textContent = '';
  showResultActions('success');
}

function setResultError(exitCode: number): void {
  var card = $('resultCard');
  card.className = 'result-card result-error';
  $('resultIcon').textContent = '❌';
  if (exitCode === -1) {
    $('resultTitle').textContent = 'Script was blocked — access denied';
  } else {
    $('resultTitle').textContent = 'Script failed (exit code ' + formatExitCode(exitCode) + ')';
  }
  $('resultDetail').textContent = '';
  showResultActions('error');
}

function showResultActions(type: string): void {
  var container = $('resultActions');
  container.innerHTML = '';
  container.classList.remove('hidden');

  var suggestions: { label: string; action: () => void }[] = [];

  if (type === 'error') {
    if (!state.netEnabled) {
      suggestions.push({
        label: '🌐 Try with internet enabled',
        action: function() {
          $chk('netToggle').checked = true;
          state.netEnabled = true;
          updatePermsSummary();
          updateNetDetails();
        },
      });
    }
    if (!state.fsEnabled) {
      suggestions.push({
        label: '📁 Try with file access',
        action: function() {
          $chk('fsToggle').checked = true;
          state.fsEnabled = true;
          updatePermsSummary();
          updateFsDetails();
        },
      });
    }
  }

  suggestions.forEach(function(s) {
    var btn = document.createElement('button');
    btn.className = 'btn btn-small btn-text';
    btn.textContent = s.label;
    btn.addEventListener('click', s.action);
    container.appendChild(btn);
  });
}

// ============================================================
// Toggle visibility helpers
// ============================================================

function updateFsDetails(): void {
  var details = $('fsDetails');
  if (state.fsEnabled) {
    details.classList.remove('hidden');
  } else {
    details.classList.add('hidden');
  }
}

function updateNetDetails(): void {
  var details = $('netDetails');
  if (state.netEnabled) {
    details.classList.remove('hidden');
    $('proxySection').style.display = '';
  } else {
    details.classList.add('hidden');
    $('proxySection').style.display = 'none';
  }
}

function updateUiDetails(): void {
  var isV05 = state.version === '0.5.0-dev';
  var shell = $sel('shellSelect').value;
  var isBuiltinUnavailable = (shell === 'ps7' || shell === 'python') && !shellAvailability[shell];

  // Desktop UI Access and Advanced only exist for 0.5.0+, and only when runtime is available
  var showAdvanced = isV05 && !isBuiltinUnavailable;
  $('uiGroupWrapper').classList.toggle('hidden', !showAdvanced);
  $('advancedSectionWrapper').classList.toggle('hidden', !showAdvanced);

  if (state.uiAllowWindows) {
    $('uiNoteOn').classList.remove('hidden');
    $('uiNoteOff').classList.add('hidden');
    $('uiClipboardRow').classList.remove('hidden');
  } else {
    $('uiNoteOn').classList.add('hidden');
    $('uiNoteOff').classList.remove('hidden');
    $('uiClipboardRow').classList.add('hidden');
  }
}

// ============================================================
// Scenario loading
// ============================================================

function populateScenarios(): void {
  var shell = $sel('shellSelect').value;
  if (shell === 'custom') return;

  var select = $sel('scenarioSelect');
  select.innerHTML = '';

  var containment = $sel('containmentSelect').value;
  var isRawBackend = containment === 'windows_sandbox' || containment === 'microvm' || containment === 'hyperlight';
  var filtered = SCENARIOS.filter(function(s) {
    if (s.shell !== shell) return false;
    if (isRawBackend) return s.containment === containment;
    return !s.containment || s.containment === 'appcontainer';
  });

  // Group by category
  var categories: string[] = [];
  filtered.forEach(function(s) {
    if (categories.indexOf(s.category) === -1) categories.push(s.category);
  });

  categories.forEach(function(cat) {
    var group = document.createElement('optgroup');
    var icon = '';
    filtered.forEach(function(s) {
      if (s.category === cat) icon = s.categoryIcon;
    });
    group.label = icon + ' ' + cat;
    filtered.forEach(function(s) {
      if (s.category !== cat) return;
      // Hide scenarios requiring 0.5.0+ when on 0.4.0
      if (s.requiresV05 && state.version !== '0.5.0-dev') { return; }
      var opt = document.createElement('option');
      opt.value = s.id;
      var marker = s.expectedOutcome === 'succeed' ? '✓' : '✗';
      opt.textContent = marker + ' ' + s.name;
      group.appendChild(opt);
    });
    select.appendChild(group);
  });

  // Auto-select first enabled scenario
  var firstEnabled = select.querySelector('option:not([disabled])') as HTMLOptionElement;
  if (firstEnabled) {
    select.value = firstEnabled.value;
    loadScenario(firstEnabled.value);
  }
}

function loadScenario(id: string): void {
  if (id === 'custom') {
    state.selectedScenario = null;
    $('scenarioDesc').textContent = 'Write your own script and configure policy.';
    $('scenarioOutcome').textContent = '';
    $('scenarioOutcome').className = 'outcome-badge';
    $('scriptSection').classList.remove('hidden');
    return;
  }

  var scenario = SCENARIOS.filter(function(s) { return s.id === id; })[0];
  if (!scenario) return;

  state.selectedScenario = scenario;

  // Update scenario info
  var shellBadge = SHELL_BADGES[scenario.shell] || '';
  var shellAvail = shellAvailability[scenario.shell] !== false;
  $('scenarioDesc').textContent = scenario.description;
  $('scenarioOutcome').textContent = scenario.expectedLabel;
  $('scenarioOutcome').className = 'outcome-badge ' + scenario.expectedOutcome;

  if (!shellAvail) {
    $('scenarioDesc').textContent = '⚠️ ' + scenario.shell + ' is not installed. ' + scenario.description;
  }

  // Collapse script section for presets
  $('scriptSection').classList.add('hidden');

  // Version comes from global dropdown, not per-scenario

  // Filesystem
  if (scenario.policy.filesystem) {
    state.fsEnabled = true;
    state.rwPaths = (scenario.policy.filesystem.readwritePaths || []).slice();
    state.roPaths = (scenario.policy.filesystem.readonlyPaths || []).slice();
  } else {
    state.fsEnabled = false;
    state.rwPaths = [];
    state.roPaths = [];
  }
  $chk('fsToggle').checked = state.fsEnabled;
  updateFsDetails();
  refreshPathLists();

  // Network
  state.netEnabled = !!(scenario.policy.network && scenario.policy.network.allowOutbound);
  $chk('netToggle').checked = state.netEnabled;

  // Proxy
  if (scenario.policy.network && scenario.policy.network.proxy) {
    var p = scenario.policy.network.proxy;
    if (p.builtinTestServer) {
      $sel('proxySelect').value = 'builtin';
    } else if (p.localhost) {
      $sel('proxySelect').value = 'localhost';
      $num('proxyPort').value = p.localhost.toString();
    } else if (p.url) {
      $sel('proxySelect').value = 'url';
      ($('proxyUrl') as HTMLInputElement).value = p.url;
    }
  } else {
    $sel('proxySelect').value = 'none';
  }
  $('proxyPort').style.display = $sel('proxySelect').value === 'localhost' ? '' : 'none';
  $('proxyUrl').style.display = $sel('proxySelect').value === 'url' ? '' : 'none';

  updateNetDetails();

  // UI
  state.uiAllowWindows = scenario.policy.ui ? scenario.policy.ui.allowWindows !== false : true;
  $chk('uiToggle').checked = state.uiAllowWindows;
  state.uiClipboard = (scenario.policy.ui && scenario.policy.ui.clipboard) || 'none';
  $sel('uiClipboard').value = state.uiClipboard;
  state.uiInjection = !!(scenario.policy.ui && scenario.policy.ui.allowInputInjection);
  $chk('uiInjection').checked = state.uiInjection;
  updateUiDetails();

  // Include helpers — default ON for scenarios
  state.fsIncludeTools = true;
  state.fsIncludeTemp = true;
  $chk('fsIncludeTools').checked = true;
  $chk('fsIncludeTemp').checked = true;

  // Timeout from scenario policy
  if (scenario.policy.timeoutMs) {
    state.timeoutSeconds = scenario.policy.timeoutMs / 1000;
  } else {
    state.timeoutSeconds = 30;
  }
  ($('timeoutInput') as HTMLInputElement).value = state.timeoutSeconds.toString();

  updatePermsSummary();
  setResultIdle();
  termClear();
  termInfo('Loaded scenario: ' + scenario.name);
  termDim(scenario.description);
  termDim('Expected: ' + scenario.expectedLabel);

  // Snapshot the policy so we can detect user modifications later
  state.scenarioPolicySnapshot = JSON.stringify(buildPolicy());

  updateDevSidebar();
}

// ============================================================
// Raw-backend config builder (shared by run + dev sidebar)
// ============================================================

function buildRawBackendConfig(
  containment: string,
  scenario: Scenario | null,
  script: string,
  timeoutSeconds: number,
): any {
  var scenarioPolicy: any = scenario ? scenario.policy : {};
  var timeoutMs = timeoutSeconds > 0 ? timeoutSeconds * 1000 : 0;
  var config: any = {
    containment: containment,
    process: {
      commandLine: script,
      timeout: timeoutMs,
    },
  };
  if (scenarioPolicy.network && scenarioPolicy.network.enabled) {
    config.network = { defaultPolicy: 'allow' };
    if (scenarioPolicy.network.allowedHosts) {
      config.network.allowedHosts = scenarioPolicy.network.allowedHosts;
    }
    if (scenarioPolicy.network.blockedHosts) {
      config.network.blockedHosts = scenarioPolicy.network.blockedHosts;
    }
  }
  if (scenarioPolicy.filesystem) {
    config.filesystem = {};
    if (scenarioPolicy.filesystem.readwritePaths) {
      config.filesystem.readwritePaths = scenarioPolicy.filesystem.readwritePaths;
    }
    if (scenarioPolicy.filesystem.readonlyPaths) {
      config.filesystem.readonlyPaths = scenarioPolicy.filesystem.readonlyPaths;
    }
  }
  // Hyperlight defaults to network-allowed when `network` is omitted; explicitly
  // block unless the scenario opts in. MicroVM/NanVix rejects `defaultPolicy: block`,
  // so leave its network field unset in that case.
  if (containment === 'hyperlight' && !config.network) {
    config.network = { defaultPolicy: 'block' };
  }
  if (scenarioPolicy.timeoutMs) {
    config.process.timeout = scenarioPolicy.timeoutMs;
  }
  return config;
}

// ============================================================
// Run / Kill
// ============================================================

async function runSandbox(): Promise<void> {
  if (state.running) return;

  // Raw JSON Config mode — bypass policy builder entirely
  var currentShell = $sel('shellSelect').value;
  if (currentShell === 'rawjson') {
    var rawJson = ($('rawJsonText') as HTMLTextAreaElement).value.trim();
    if (!rawJson) {
      termError('No JSON config provided');
      return;
    }

    // Apply Hyperlight default-block defense-in-depth: if the user-pasted config
    // targets Hyperlight and omits `network`, inject `{ defaultPolicy: 'block' }`
    // so we don't silently inherit the backend's default-allow.
    try {
      var rawParsed = JSON.parse(rawJson);
      if (rawParsed && rawParsed.containment === 'hyperlight' && !rawParsed.network) {
        rawParsed.network = { defaultPolicy: 'block' };
        rawJson = JSON.stringify(rawParsed);
        termDim('[Playground] Hyperlight: injected network.defaultPolicy=block (no network field provided)');
      }
    } catch {
      // Let the backend surface the parse error.
    }

    state.running = true;
    if (!runAllInProgress) {
      ($('btnRun') as HTMLButtonElement).disabled = true;
      $('btnKill').classList.remove('hidden');
      $('btnRun').classList.add('hidden');
      setResultRunning();
      termClear();
    }
    terminalFullText = '';

    termInfo('[Playground] Running MXC JSON config');
    termInfo('[MXC] API: spawnSandboxFromConfig');

    var rawDebug = (document.getElementById('debugToggle') as HTMLInputElement).checked;
    var rawExperimental = (document.getElementById('experimentalToggle') as HTMLInputElement).checked;
    var result = await mxc.runSandboxRaw(rawJson, rawDebug, rawExperimental);
    if (!result.success) {
      termError('[MXC] Failed to start sandbox: ' + result.error);
      onSandboxExit(-1);
    } else {
      termDim('[MXC] Config accepted');
    }
    return;
  }

  // Windows Sandbox / MicroVM mode — build raw wxc-exec JSON config and use runSandboxRaw
  var currentContainment = $sel('containmentSelect').value;
  if (currentContainment === 'windows_sandbox' || currentContainment === 'microvm' || currentContainment === 'hyperlight') {
    var rawScript = state.selectedScenario ? state.selectedScenario.script : (state.customScript || '').trim();
    if (!rawScript) {
      termError('No script specified');
      return;
    }

    var rawConfig: any = buildRawBackendConfig(
      currentContainment,
      state.selectedScenario,
      rawScript,
      state.timeoutSeconds,
    );

    // MicroVM staging requires readwritePaths to exist on the host. Pre-create
    // any dirs the scenario mounts (e.g. C:\Users\Public\MXCPlaygroundTests).
    if (currentContainment === 'microvm' && rawConfig.filesystem && rawConfig.filesystem.readwritePaths) {
      try {
        var ensureDirsResult = await mxc.ensureDirs(rawConfig.filesystem.readwritePaths);
        if (ensureDirsResult && typeof ensureDirsResult === 'object') {
          if ((ensureDirsResult as any).success === false) {
            throw new Error((ensureDirsResult as any).error || (ensureDirsResult as any).message || 'Unknown error');
          }
          if (Array.isArray(ensureDirsResult)) {
            var failedEnsureDir = ensureDirsResult.find(function (entry: any) {
              return entry && typeof entry === 'object' && entry.success === false;
            });
            if (failedEnsureDir) {
              throw new Error(failedEnsureDir.error || failedEnsureDir.message || 'Unknown error');
            }
          }
        }
      } catch (e: any) {
        termError('[Playground] Failed to pre-create RW mount dirs: ' + (e && e.message ? e.message : String(e)));
        onSandboxExit(-1);
        return;
      }
    }

    state.running = true;
    if (!runAllInProgress) {
      ($('btnRun') as HTMLButtonElement).disabled = true;
      $('btnKill').classList.remove('hidden');
      $('btnRun').classList.add('hidden');
      setResultRunning();
      termClear();
    }
    terminalFullText = '';

    var backendLabel = CONTAINMENT_LABELS[currentContainment] || currentContainment;
    termInfo('[Playground] Running via ' + backendLabel);
    if (state.selectedScenario) {
      termInfo('[Playground] Scenario: ' + state.selectedScenario.name + ' (' + state.selectedScenario.id + ')');
    }
    termInfo('[Playground] Script: ' + rawScript);
    termInfo('[MXC] API: spawnSandboxFromConfig (raw config)');
    if (currentContainment === 'windows_sandbox') {
      termDim('[MXC] Note: First run may take 3-5 minutes while the sandbox VM boots.');
    } else if (currentContainment === 'microvm') {
      termDim('[MXC] Note: MicroVM boot adds ~60s grace period to the script timeout.');
    } else if (currentContainment === 'hyperlight') {
      termDim('[MXC] Note: First run may take longer while Hyperlight warms up the snapshot.');
    }

    var rawDebug = (document.getElementById('debugToggle') as HTMLInputElement).checked;
    var rawResult = await mxc.runSandboxRaw(JSON.stringify(rawConfig), rawDebug, true);
    if (!rawResult.success) {
      termError('[MXC] Failed to start sandbox: ' + rawResult.error);
      onSandboxExit(-1);
    } else {
      termDim('[MXC] Config accepted');
    }
    return;
  }

  var script = getCurrentScript();

  // Resolve test script file if scenario uses one
  if (state.selectedScenario?.testScript) {
    var ts = state.selectedScenario.testScript;
    var scriptInfo = await mxc.getTestScript(ts.file);
    if (scriptInfo.success) {
      script = ts.shell + ' -NoProfile -ExecutionPolicy Bypass -File "' + scriptInfo.path + '"' + (ts.args ? ' ' + ts.args : '');
      termDim('[Playground] Using test script: ' + scriptInfo.path);
    } else {
      termError('[Playground] Could not find test script: ' + ts.file + ' — ' + scriptInfo.error);
      return;
    }
  }

  if (!script.trim()) {
    termError('No script specified');
    return;
  }

  // Warn and trim leading/trailing whitespace
  if (script !== script.trim()) {
    script = script.trim();
    termDim('[Playground] ⚠ Trimmed leading/trailing whitespace from script');
  }

  state.running = true;
  if (!runAllInProgress) {
    ($('btnRun') as HTMLButtonElement).disabled = true;
    $('btnKill').classList.remove('hidden');
    $('btnRun').classList.add('hidden');
    setResultRunning();
    termClear();
  }
  terminalFullText = '';

  var policy = buildPolicy();

  // Detect if user modified the pre-made scenario's settings
  var scenarioModified = false;
  if (state.selectedScenario && state.scenarioPolicySnapshot) {
    var currentSnapshot = JSON.stringify(policy);
    if (currentSnapshot !== state.scenarioPolicySnapshot) {
      scenarioModified = true;
      termDim('[Playground] ⚠ Note: You modified settings from the original scenario. Verdict may not match the expected outcome.');
    }
  }

  // Merge auto-include paths
  try {
    if (state.fsIncludeTools) {
      var tools = await mxc.getToolsPolicy();
      if (tools.readonlyPaths) {
        policy.filesystem = policy.filesystem || {};
        policy.filesystem.readonlyPaths = (policy.filesystem.readonlyPaths || []).concat(tools.readonlyPaths);
      }
    }
    if (state.fsIncludeTemp) {
      var temp = await mxc.getTempPolicy();
      if (temp.readwritePaths) {
        policy.filesystem = policy.filesystem || {};
        policy.filesystem.readwritePaths = (policy.filesystem.readwritePaths || []).concat(temp.readwritePaths);
      }
    }
  } catch (e: any) {
    termError('Failed to get auto-include paths: ' + e.message);
  }

  // Auto-add test-scripts directory to readonlyPaths if using a test script
  if (state.selectedScenario?.testScript) {
    var scriptInfo2 = await mxc.getTestScript(state.selectedScenario.testScript.file);
    if (scriptInfo2.success) {
      var scriptDir = scriptInfo2.path.substring(0, scriptInfo2.path.lastIndexOf('\\'));
      policy.filesystem = policy.filesystem || {};
      policy.filesystem.readonlyPaths = policy.filesystem.readonlyPaths || [];
      if (policy.filesystem.readonlyPaths.indexOf(scriptDir) === -1) {
        policy.filesystem.readonlyPaths.push(scriptDir);
      }
    }
  }

  // Ensure write directories exist before running
  var allWritePaths = policy.filesystem?.readwritePaths || [];
  if (allWritePaths.length > 0) {
    termDim('[Playground] Setup: ensuring directories exist — ' + allWritePaths.join(', '));
    await mxc.ensureDirs(allWritePaths);
  }

  var policyJson = JSON.stringify(policy, null, 2);

  var useAdvanced = isAdvancedNeeded();

  termInfo('[Playground] Running via @microsoft/mxc-sdk');
  if (state.selectedScenario) {
    termInfo('[Playground] Scenario: ' + state.selectedScenario.name + ' (' + state.selectedScenario.id + ')');
  }
  termInfo('[Playground] Script: ' + script);
  if (useAdvanced) {
    termInfo('[MXC] API: createConfigFromPolicy → spawnSandboxFromConfig');
  } else {
    termInfo('[MXC] API: spawnSandbox()');
  }
  termInfo('[MXC] Schema: ' + state.version);

  const debugEnabled = (document.getElementById('debugToggle') as HTMLInputElement).checked;
  const experimentalEnabled = (document.getElementById('experimentalToggle') as HTMLInputElement).checked;

  if (useAdvanced) {
    var result = await mxc.runSandboxAdvanced(script, policyJson, debugEnabled, experimentalEnabled);
    if (!result.success) {
      termError('[MXC] Failed to start sandbox: ' + result.error);
      onSandboxExit(-1);
    } else if (result.config) {
      termDim('[MXC] Config generated successfully');
    }
  } else {
    var result = await mxc.runSandbox(script, policyJson, debugEnabled, experimentalEnabled);
    if (!result.success) {
      termError('[MXC] Failed to start sandbox: ' + result.error);
      onSandboxExit(-1);
    }
  }
}

async function killSandbox(): Promise<void> {
  termInfo('[Playground] Stopping sandbox…');
  await mxc.killSandbox();
  onSandboxExit(-1);
}

// ============================================================
// Run All Scenarios
// ============================================================

var runAllResolve: ((result: { exitCode: number; pass: boolean; scenario?: Scenario; output: string }) => void) | null = null;
var runAllInProgress = false;

async function runAllScenarios(): Promise<void> {
  if (runAllInProgress || state.running) { return; }
  runAllInProgress = true;
  ($('btnRun') as HTMLButtonElement).disabled = true;
  ($('btnRunAll') as HTMLButtonElement).disabled = true;
  $('btnRunAll').textContent = '⏳ Running…';

  var debugEnabled = (document.getElementById('debugToggle') as HTMLInputElement).checked;
  var version = state.version;
  var currentShell = $sel('shellSelect').value;

  // Filter scenarios: current shell, containment, available runtimes, version-appropriate
  var currentContainment = $sel('containmentSelect').value;
  var isRawBackend = currentContainment === 'windows_sandbox' || currentContainment === 'microvm' || currentContainment === 'hyperlight';
  var scenariosToRun = SCENARIOS.filter(function(s) {
    // When the user picks "python" on a raw backend (MicroVM/Hyperlight), also
    // pull in the pseudo-shell categories (networking, filesystem) since those
    // scenarios are Python-backed and would otherwise be silently skipped.
    var shellMatch = (s.shell === currentShell);
    if (!shellMatch && isRawBackend && currentShell === 'python' &&
        (s.shell === 'networking' || s.shell === 'filesystem')) {
      shellMatch = true;
    }
    if (!shellMatch) { return false; }
    if (isRawBackend) { if (s.containment !== currentContainment) return false; }
    else { if (s.containment === 'windows_sandbox' || s.containment === 'microvm' || s.containment === 'hyperlight') return false; }
    if (s.shell === 'ps7' && !shellAvailability['ps7']) { return false; }
    if (s.shell === 'python' && !shellAvailability['python']) { return false; }
    if (s.requiresV05 && version !== '0.5.0-dev') { return false; }
    return true;
  });

  var logLines: string[] = [];
  var passed = 0;
  var failed = 0;
  var total = scenariosToRun.length;
  var results: { scenario: Scenario; verdict: string; pass: boolean; exitCode: number }[] = [];

  logLines.push('=== MXC Playground — Run All Results ===');
  logLines.push('Date: ' + new Date().toISOString());
  logLines.push('Schema: ' + version);
  logLines.push('Runtime: ' + currentShell);
  logLines.push('Debug: ' + (debugEnabled ? 'ON' : 'OFF'));
  logLines.push('Scenarios: ' + total);
  logLines.push('');

  // Show running state in result card
  $('resultCard').className = 'result-card result-running';
  $('resultIcon').textContent = '⏳';
  $('resultTitle').textContent = 'Running all ' + total + ' tests…';
  $('resultDetail').textContent = '0/' + total + ' complete';

  termClear();
  termInfo('[Playground] ▶▶ Running all ' + total + ' tests for ' + currentShell + '…');
  termInfo('');

  for (var i = 0; i < scenariosToRun.length; i++) {
    var scenario = scenariosToRun[i];
    logLines.push('--- [' + (i + 1) + '/' + total + '] ' + scenario.name + ' (' + scenario.id + ') ---');

    // Update progress
    $('resultDetail').textContent = (i) + '/' + total + ' complete — running: ' + scenario.name;

    // Load the scenario into state
    loadScenario(scenario.id);

    // Wait a tick for UI to update
    await new Promise(function(r) { setTimeout(r, 100); });

    // Create a promise that resolves when the sandbox exits
    var resultPromise = new Promise<{ exitCode: number; pass: boolean; scenario?: Scenario; output: string }>(function(resolve) {
      runAllResolve = resolve;
    });

    // Run it
    await runSandbox();

    // Wait for it to finish
    var result = await resultPromise;

    var verdict = result.pass ? '✅ PASS' : '❌ FAIL';
    if (result.pass) { passed++; } else { failed++; }
    results.push({ scenario, verdict, pass: result.pass, exitCode: result.exitCode });

    logLines.push('Script: ' + scenario.script);
    logLines.push('Expected: ' + scenario.expectedOutcome + ' (' + scenario.expectedLabel + ')');
    logLines.push('Exit code: ' + result.exitCode);
    logLines.push('Verdict: ' + verdict);
    logLines.push('');
    logLines.push('--- Output ---');
    logLines.push(result.output || '(no output)');
    logLines.push('--- End ---');
    logLines.push('');

    termInfo('[Playground] [' + (i + 1) + '/' + total + '] ' + verdict + ' — ' + scenario.name);
  }

  // Summary
  logLines.push('=== SUMMARY ===');
  logLines.push('Total: ' + total + '  Passed: ' + passed + '  Failed: ' + failed);
  logLines.push('');

  termInfo('');

  // Render test report in terminal
  termWrite('━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━', 'line-info');
  termWrite('  TEST REPORT — ' + currentShell.toUpperCase() + '  (' + new Date().toLocaleString() + ')', 'line-info');
  termWrite('━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━', 'line-info');
  termWrite('', 'line-info');

  for (var r = 0; r < results.length; r++) {
    var res = results[r];
    var icon = res.pass ? '✅' : '❌';
    var label = res.scenario.name;
    var exitStr = res.exitCode === 0 ? '' : '  (exit ' + res.exitCode + ')';
    termWrite('  ' + icon + '  ' + label + exitStr, res.pass ? 'line-success' : 'line-error');
  }

  termWrite('', 'line-info');
  var summaryLine = '  ' + passed + ' passed, ' + failed + ' failed — ' + total + ' total';
  if (failed === 0) {
    termWrite('  ✅ ALL TESTS PASSED', 'line-success');
  } else {
    termWrite('  ❌ ' + failed + ' TEST(S) FAILED', 'line-error');
  }
  termWrite(summaryLine, 'line-info');
  termWrite('━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━', 'line-info');

  // Update result card
  if (failed === 0) {
    $('resultCard').className = 'result-card result-success';
    $('resultIcon').textContent = '✅';
    $('resultTitle').textContent = 'All ' + total + ' tests passed';
  } else {
    $('resultCard').className = 'result-card result-error';
    $('resultIcon').textContent = '❌';
    $('resultTitle').textContent = passed + ' passed, ' + failed + ' failed';
  }
  $('resultDetail').textContent = currentShell + ' · ' + version + ' · ' + new Date().toLocaleTimeString();

  // Offer optional save via a link in the terminal
  var logContent = logLines.join('\n');
  termWrite('', 'line-info');
  var saveLink = document.createElement('div');
  saveLink.className = 'line-info';
  saveLink.innerHTML = '<a href="#" id="saveReportLink" style="color:var(--accent); cursor:pointer; text-decoration:underline;">💾 Save report to file…</a>';
  $('terminal').appendChild(saveLink);
  $('terminal').scrollTop = $('terminal').scrollHeight;
  document.getElementById('saveReportLink')!.addEventListener('click', async function(e) {
    e.preventDefault();
    var saveResult = await mxc.saveLogFile(logContent);
    if (saveResult.success) {
      termSuccess('[Playground] Log saved to: ' + saveResult.path);
    }
  });

  runAllInProgress = false;
  ($('btnRun') as HTMLButtonElement).disabled = false;
  ($('btnRunAll') as HTMLButtonElement).disabled = false;
  updateRunAllLabel();
}

function onSandboxExit(exitCode: number): void {
  state.running = false;
  if (!runAllInProgress) {
    ($('btnRun') as HTMLButtonElement).disabled = false;
    $('btnRun').classList.remove('hidden');
    $('btnKill').classList.add('hidden');
  }

  // Assertion-based verdict
  var scenario = state.selectedScenario;
  var isCustomMode = !scenario || $sel('shellSelect').value === 'custom' || $sel('shellSelect').value === 'rawjson';

  // For custom/raw JSON: no expected outcome — show neutral result
  if (isCustomMode) {
    var analysis = exitCode !== 0 ? analyzeOutput(terminalFullText, exitCode) : null;
    if (exitCode === 0) {
      termDim('[Playground] ⚠ Completed (exit code 0) — inspect output to verify the result');
      var card = $('resultCard');
      card.className = 'result-card result-neutral';
      $('resultIcon').textContent = '⚠';
      $('resultTitle').textContent = 'Completed — exit code 0';
      $('resultDetail').textContent = 'Custom script finished. Review the output above to confirm it worked as expected.';
      showResultActions('success');
    } else {
      termError('[Playground] ⚠ Completed with exit code ' + formatExitCode(exitCode) + ' — inspect output');
      var card = $('resultCard');
      card.className = 'result-card result-neutral';
      $('resultIcon').textContent = '⚠';
      $('resultTitle').textContent = 'Completed — exit code ' + formatExitCode(exitCode);
      $('resultDetail').textContent = analysis ? analysis.explanation + ' 💡 ' + analysis.suggestion : 'Non-zero exit code. Review the output above.';
      showResultActions('error');
    }

    if (runAllResolve) {
      runAllResolve({ exitCode, pass: exitCode === 0, scenario: scenario || undefined, output: terminalFullText });
      runAllResolve = null;
    }
    terminalFullText = '';
    return;
  }

  var expected = scenario.expectedOutcome || 'succeed';
  var actualOutcome = exitCode === 0 ? 'succeed' : 'be-blocked';

  // Output-based validation: check successMarker/failureMarker in terminal output
  var termLower = terminalFullText.toLowerCase();
  var outputOverride = false;
  if (scenario && exitCode === 0) {
    if (scenario.failureMarker && terminalFullText.includes(scenario.failureMarker)) {
      // Script printed its own failure marker — the operation didn't actually work
      actualOutcome = 'be-blocked';
      outputOverride = true;
      termDim('[Playground] Output contains failure marker: "' + scenario.failureMarker + '"');
    } else if (scenario.successMarker && !terminalFullText.includes(scenario.successMarker)) {
      // Script didn't print expected success marker — something went wrong
      actualOutcome = 'be-blocked';
      outputOverride = true;
      termDim('[Playground] Output missing expected marker: "' + scenario.successMarker + '"');
    }
  }

  // For "be-blocked" scenarios: check terminal for denial markers (script may catch and exit 0)
  var blockedInOutput = termLower.includes('blocked') || termLower.includes('access denied') ||
    termLower.includes('is denied') || termLower.includes('could not be resolved') ||
    termLower.includes('permissionerror') || termLower.includes('unauthorized');
  if (expected === 'be-blocked' && exitCode === 0 && blockedInOutput) {
    actualOutcome = 'be-blocked';
  }

  var verdictPass = (expected === actualOutcome) ||
    (expected === 'be-blocked' && exitCode !== 0) ||
    (expected === 'show-error' && exitCode !== 0);

  // Error analysis
  var analysis = exitCode !== 0 ? analyzeOutput(terminalFullText, exitCode) : null;

  if (verdictPass && exitCode === 0) {
    termSuccess('[Playground] ✅ PASS — Script succeeded as expected (exit code 0)');
    setResultSuccess(exitCode);
    $('resultDetail').textContent = scenario ? 'Expected: ' + scenario.expectedLabel : '';
  } else if (verdictPass && exitCode !== 0) {
    // Expected failure — this is a PASS
    var card = $('resultCard');
    card.className = 'result-card result-success';
    $('resultIcon').textContent = '✅';
    $('resultTitle').textContent = 'PASS — Script was blocked as expected (exit code ' + formatExitCode(exitCode) + ')';
    $('resultDetail').textContent = analysis ? analysis.explanation : (scenario ? scenario.expectedLabel : '');
    termSuccess('[Playground] ✅ PASS — Blocked as expected (exit code ' + formatExitCode(exitCode) + ')');
    showResultActions('success');
  } else if (!verdictPass && exitCode === 0) {
    // Expected failure but it succeeded — unexpected
    var card = $('resultCard');
    card.className = 'result-card result-error';
    $('resultIcon').textContent = '⚠️';
    $('resultTitle').textContent = 'UNEXPECTED — Script succeeded but was expected to be blocked';
    $('resultDetail').textContent = 'The sandbox may not be enforcing the expected restriction.';
    termError('[Playground] ⚠️ UNEXPECTED — Succeeded but expected: ' + (scenario?.expectedLabel || 'blocked'));
    showResultActions('error');
  } else {
    // Unexpected failure
    termError('[Playground] ❌ FAIL — exit code ' + formatExitCode(exitCode));
    setResultError(exitCode);
    if (analysis) {
      $('resultTitle').textContent = analysis.title;
      $('resultDetail').textContent = analysis.explanation + ' 💡 ' + analysis.suggestion;
    }
  }

  // If running all scenarios, notify the runner (capture output before clearing)
  if (runAllResolve) {
    runAllResolve({ exitCode, pass: verdictPass, scenario: scenario || undefined, output: terminalFullText });
    runAllResolve = null;
  }

  terminalFullText = '';
}

// ============================================================
// Error pattern analysis
// ============================================================

var ERROR_PATTERNS = [
  { pattern: 'CreateProcessW failed', title: 'Process creation failed', explanation: 'Windows could not create the sandboxed process. The executable may not be accessible inside the container.', suggestion: 'Add the executable\'s directory to File Access read-only paths.' },
  { pattern: 'CreateProcessW failed.*0x80070002', title: 'Executable not found', explanation: 'The executable was not found inside the container.', suggestion: 'The executable was not found. Enable \'Include common tools\' in File Access to add PATH directories.' },
  { pattern: '0x80070005', title: 'Access denied (firewall)', explanation: 'An operation was denied, possibly due to firewall rules.', suggestion: 'Firewall rules require administrator privileges. Try running the app as administrator.' },
  { pattern: 'firewall rule blocked', title: 'Firewall blocked', explanation: 'A firewall rule blocked the operation.', suggestion: 'Firewall rules require administrator privileges. Try running the app as administrator.' },
  { pattern: 'Experimental_CreateProcessInSandbox failed', title: 'Sandbox API failed', explanation: 'The CreateProcessInSandbox API returned an error. Check the error code for details.', suggestion: 'Enable Debug Mode for more details.' },
  { pattern: 'LoadLibraryExW(processmodel.dll) failed', title: 'BaseContainer not available', explanation: 'processmodel.dll could not be loaded. BaseContainer requires Windows builds that support the v0.5.0+ schema.', suggestion: 'Use version 0.4.0-alpha instead of 0.5.0-dev.' },
  { pattern: 'Access is denied', title: 'Access denied', explanation: 'The script tried to access a resource that the sandbox blocks.', suggestion: 'Enable File Access and add the needed path, or enable Internet if the script needs network.' },
  { pattern: 'is not recognized', title: 'Command not found', explanation: 'The command was not found inside the sandbox. PATH directories may not be accessible.', suggestion: 'Enable "Include common tools" in File Access to add PATH directories.' },
  { pattern: 'The remote name could not be resolved', title: 'DNS resolution failed', explanation: 'The script could not resolve a hostname. Internet access may be blocked.', suggestion: 'Enable Internet access in the Policy section.' },
  { pattern: 'network is not available', title: 'Network blocked', explanation: 'Outbound network connections are blocked by the sandbox policy.', suggestion: 'Enable "Allow internet access" in Policy.' },
  { pattern: 'version is required', title: 'Missing version', explanation: 'The sandbox policy requires a version field.', suggestion: 'This is a bug in the playground — please report it.' },
  { pattern: 'newer than supported', title: 'Version too new', explanation: 'The schema version is newer than what the SDK supports.', suggestion: 'Use version 0.4.0-alpha or 0.5.0-dev.' },
  { pattern: 'The system cannot find the file', title: 'File not found', explanation: 'The executable or file was not found. It may not be accessible from inside the container.', suggestion: 'Add the file\'s directory to read-only paths in File Access.' },
  { pattern: 'PermissionError', title: 'Permission denied (Python)', explanation: 'Python could not access a file or directory due to sandbox restrictions.', suggestion: 'Add the path to read-write or read-only paths in File Access.' },
  { pattern: 'script is required', title: 'No script provided', explanation: 'No command was provided to run.', suggestion: 'Enter a script command or select a scenario.' },
  { pattern: 'WIN32_ERROR(1920)', title: 'File cannot be accessed', explanation: 'The executable cannot be loaded by the sandbox. The install directory may not be accessible to the container process.', suggestion: 'The runtime may need its install directory added to File Access. Try clicking 🔄 refresh and running again.' },
];

var EXIT_CODE_PATTERNS: Record<number, { title: string; explanation: string; suggestion: string }> = {};
EXIT_CODE_PATTERNS[-1073741502] = { // 0xC0000142 STATUS_DLL_INIT_FAILED
  title: 'DLL init failed (Win32k)',
  explanation: 'A required DLL could not initialize. This usually means the process needs Win32k (desktop UI access).',
  suggestion: 'Enable Desktop UI Access in the Policy section, or switch to cmd.exe which does not need Win32k.'
};
EXIT_CODE_PATTERNS[1920] = { // ERROR_FILE_CANNOT_BE_ACCESSED
  title: 'File cannot be accessed',
  explanation: 'The executable cannot be accessed from inside the container. MSIX/Store packages install to a protected location that the container cannot reach.',
  suggestion: 'For PowerShell 7+, install the MSI package instead of the MSIX/Store version. See https://learn.microsoft.com/en-us/powershell/scripting/install/install-powershell-on-windows'
};

function analyzeOutput(terminalText: string, exitCode: number): { title: string; explanation: string; suggestion: string } | null {
  // Check exit code first — with dynamic paths
  if (exitCode === -1073741790) { // 0xC0000022 STATUS_ACCESS_DENIED
    var aclPath = shellPaths.python?.rootDir || '';
    var isPerUser = aclPath.includes('AppData');
    return {
      title: 'Access denied (ACL)',
      explanation: isPerUser
        ? 'Per-user Python installs lack the sandbox ACL. The sandbox runs under a restricted identity that cannot access per-user directories.'
        : 'The executable directory lacks the ALL APPLICATION PACKAGES ACL required for sandbox access.',
      suggestion: isPerUser
        ? 'Fix: reinstall Python with "winget install Python.Python.3.14" which installs to a location accessible by the container.'
        : 'Run as admin: icacls "' + aclPath + '" /grant "ALL APPLICATION PACKAGES:(OI)(CI)(RX)" /T',
    };
  }
  if (EXIT_CODE_PATTERNS[exitCode]) {
    return EXIT_CODE_PATTERNS[exitCode];
  }
  for (var p of ERROR_PATTERNS) {
    if (terminalText.includes(p.pattern)) {
      return p;
    }
  }
  return null;
}

// ============================================================
// PTY handlers
// ============================================================

var terminalFullText = '';
var ptyLineBuffer = '';

mxc.onPtyData(function(data: string) {
  var clean = stripAnsi(data);
  terminalFullText += clean;
  // termWrite() appends '\n' to each call, so split chunks on newline and
  // hold the final (possibly partial) fragment until the next chunk to avoid
  // mid-line breaks or duplicate blank lines. Blank lines from the underlying
  // stdout are preserved.
  ptyLineBuffer += clean;
  var lines = ptyLineBuffer.split('\n');
  ptyLineBuffer = lines.pop() || '';
  for (var i = 0; i < lines.length; i++) {
    // Strip trailing \r from CRLF sequences so the terminal doesn't render
    // a stray carriage return.
    termOutput(lines[i].replace(/\r+$/, ''));
  }
});

mxc.onPtyExit(function(exitCode: number) {
  // Flush any remaining buffered output
  var tail = ptyLineBuffer.replace(/\r+$/, '');
  if (tail.length > 0) {
    termOutput(tail);
  }
  ptyLineBuffer = '';
  // Small delay to let pending PTY data events flush before verdict
  setTimeout(function() { onSandboxExit(exitCode); }, 100);
});

// ============================================================
// JSON panel
// ============================================================

function showJsonPanel(tab: string): void {
  if (state.activeJsonTab === tab) {
    // Toggle off
    state.activeJsonTab = null;
    $('jsonPanel').classList.add('hidden');
    $('tabPolicy').classList.remove('active');
    $('tabConfig').classList.remove('active');
    return;
  }

  state.activeJsonTab = tab;
  $('tabPolicy').classList.toggle('active', tab === 'policy');
  $('tabConfig').classList.toggle('active', tab === 'config');
  $('jsonPanel').classList.remove('hidden');

  if (tab === 'policy') {
    var containment = $sel('containmentSelect').value;
    if (containment === 'windows_sandbox' || containment === 'microvm' || containment === 'hyperlight') {
      var rawScript = state.selectedScenario ? state.selectedScenario.script : (state.customScript || '').trim();
      var rawConfig = buildRawBackendConfig(
        containment,
        state.selectedScenario,
        rawScript || '(no script)',
        state.timeoutSeconds,
      );
      $('jsonContent').innerHTML = highlightJson(escapeHtml(JSON.stringify(rawConfig, null, 2)));
    } else {
      var policyStr = JSON.stringify(buildPolicy(), null, 2);
      $('jsonContent').innerHTML = highlightJson(escapeHtml(policyStr));
    }
  } else {
    var containment2 = $sel('containmentSelect').value;
    if (containment2 === 'windows_sandbox' || containment2 === 'microvm' || containment2 === 'hyperlight') {
      var rawScript2 = state.selectedScenario ? state.selectedScenario.script : (state.customScript || '').trim();
      var rawConfig2 = buildRawBackendConfig(
        containment2,
        state.selectedScenario,
        rawScript2 || '(no script)',
        state.timeoutSeconds,
      );
      $('jsonContent').innerHTML = highlightJson(escapeHtml(JSON.stringify(rawConfig2, null, 2)));
    } else {
      $('jsonContent').innerHTML = '<span class="line-dim">Loading config…</span>';
      var policyJson = JSON.stringify(buildPolicy());
      mxc.validatePolicy(policyJson).then(function(result: any) {
        if (result.valid) {
          var formatted = JSON.stringify(JSON.parse(result.config), null, 2);
          $('jsonContent').innerHTML = highlightJson(escapeHtml(formatted));
        } else {
          $('jsonContent').innerHTML = '<span class="line-error">Error: ' + escapeHtml(result.error) + '</span>';
        }
      });
    }
  }
}

function escapeHtml(str: string): string {
  return str.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;');
}

function formatExitCode(code: number): string {
  if (code === -1 || code === 0) { return code.toString(); }
  if (code < 0) {
    // Negative = unsigned 32-bit NTSTATUS
    return '0x' + ((code >>> 0).toString(16)).toUpperCase();
  }
  if (code > 255) {
    return '0x' + code.toString(16).toUpperCase();
  }
  return code.toString();
}

// ============================================================
// Dev sidebar
// ============================================================

function updateDevSidebar(): void {
  if ($('devSidebar').classList.contains('hidden')) return;

  var currentShell = $sel('shellSelect').value;
  var currentContainment = $sel('containmentSelect').value;

  // Windows Sandbox / MicroVM / Hyperlight mode — show the raw config
  if ((currentContainment === 'windows_sandbox' || currentContainment === 'microvm' || currentContainment === 'hyperlight') && currentShell !== 'rawjson') {
    var rawScript = state.selectedScenario ? state.selectedScenario.script : (state.customScript || '').trim();
    var rawConfig = buildRawBackendConfig(
      currentContainment,
      state.selectedScenario,
      rawScript || '(no script)',
      state.timeoutSeconds,
    );
    var backendName = CONTAINMENT_LABELS[currentContainment] || currentContainment;
    $('devPolicyJson').innerHTML = '<span class="line-dim">N/A — ' + backendName + ' bypasses policy generation</span>';
    $('devConfigJson').innerHTML = highlightJson(escapeHtml(JSON.stringify(rawConfig, null, 2)));
    return;
  }

  // Raw JSON mode — show only the raw config, no policy
  if (currentShell === 'rawjson') {
    $('devPolicyJson').innerHTML = '<span class="line-dim">N/A — MXC JSON mode skips policy generation</span>';
    var rawText = ($('rawJsonText') as HTMLTextAreaElement).value.trim();
    if (rawText) {
      try {
        var parsed = JSON.parse(rawText);
        var formatted = JSON.stringify(parsed, null, 2);
        $('devConfigJson').innerHTML = highlightJson(escapeHtml(formatted));
      } catch (e: any) {
        $('devConfigJson').innerHTML = '<span class="line-error">Invalid JSON: ' + escapeHtml(e.message) + '</span>';
      }
    } else {
      $('devConfigJson').innerHTML = '<span class="line-dim">Paste a ContainerConfig JSON above</span>';
    }
    return;
  }

  var policy = buildPolicy();
  var policyStr = JSON.stringify(policy, null, 2);
  $('devPolicyJson').innerHTML = highlightJson(escapeHtml(policyStr));

  $('devConfigJson').innerHTML = '<span class="line-dim">Loading…</span>';
  var policyJson = JSON.stringify(policy);
  mxc.validatePolicy(policyJson).then(function(result: any) {
    if (result.valid) {
      var config = JSON.parse(result.config);
      config.process.commandLine = getCurrentScript();
      // Overlay advanced process container UI fields
      if (config.appContainer && config.appContainer.ui) {
        config.appContainer.ui.isolation = $sel('uiIsolation').value || 'container';
        config.appContainer.ui.desktopSystemControl = $chk('uiDesktopControl').checked || false;
        config.appContainer.ui.systemSettings = $sel('uiSystemSettings').value || 'none';
        config.appContainer.ui.ime = $chk('uiIME').checked || false;
      }
      var formatted = JSON.stringify(config, null, 2);
      $('devConfigJson').innerHTML = highlightJson(escapeHtml(formatted));
    } else {
      $('devConfigJson').innerHTML = '<span class="line-error">Error: ' + escapeHtml(result.error) + '</span>';
    }
  });
}

// ============================================================
// View switching
// ============================================================

function showMainView(): void {
  state.currentView = 'main';
  $('welcomeView').classList.add('hidden');
  $('mainView').classList.remove('hidden');
}

function showWelcomeView(): void {
  state.currentView = 'welcome';
  $('welcomeView').classList.remove('hidden');
  $('mainView').classList.add('hidden');
}

// ============================================================
// Init
// ============================================================

function init(): void {
  populateScenarios();
  updatePermsSummary();
  refreshPathLists();
  updateFsDetails();
  updateNetDetails();
  updateUiDetails();

  // Detect available shells and re-render scenario list
  mxc.detectShells().then(function(shells: Record<string, any>) {
    // Map new format to availability booleans
    for (var key in shells) {
      if (typeof shells[key] === 'object') {
        shellAvailability[key] = shells[key].available;
        if (shells[key].exe) {
          shellPaths[key] = { exe: shells[key].exe, rootDir: shells[key].rootDir, needsAcl: shells[key].needsAcl, msixPackageDir: shells[key].msixPackageDir };
        }
      } else {
        shellAvailability[key] = !!shells[key];
      }
    }
    updateShellDropdown();
    populateScenarios();
  }).catch(function() { /* use defaults */ });

  // Platform check
  mxc.getPlatformSupport().then(function(info: any) {
    cachedPlatformSupport = info;
    $('platformBadge').textContent = info.isSupported
      ? '✓ Platform supported'
      : '✗ ' + (info.reason || 'Not supported');
  });

  // === Welcome view buttons ===
  $('btnTrySample').addEventListener('click', function() {
    showMainView();
    $sel('shellSelect').value = 'cmd';
    $('categoryRow').classList.remove('hidden');
    $('scriptSection').classList.add('hidden');
    populateScenarios();
    $sel('scenarioSelect').value = 'basic-cmd';
    loadScenario('basic-cmd');
    runSandbox();
  });

  $('btnStartScratch').addEventListener('click', function() {
    showMainView();
    $sel('shellSelect').value = 'custom';
    $('categoryRow').classList.add('hidden');
    $('scriptSection').classList.remove('hidden');
    state.selectedScenario = null;
    loadScenario('custom');
  });

  $('welcomeShowStartup').addEventListener('change', function() {
    if (!$chk('welcomeShowStartup').checked) {
      localStorage.setItem('mxc-hide-welcome', '1');
    } else {
      localStorage.removeItem('mxc-hide-welcome');
    }
  });

  $('welcomeLearnMore').addEventListener('click', function(e) {
    e.preventDefault();
    showMainView();
    ($('helpDialog') as HTMLDialogElement).showModal();
  });

  // === Refresh shells ===
  $('btnRefreshShells').addEventListener('click', function() {
    var btn = $('btnRefreshShells');
    btn.textContent = '⏳';
    btn.setAttribute('disabled', 'true');
    mxc.detectShells().then(function(shells: Record<string, any>) {
      var found: string[] = [];
      var notFound: string[] = [];
      for (var key in shells) {
        if (typeof shells[key] === 'object') {
          shellAvailability[key] = shells[key].available;
          if (shells[key].exe) {
            shellPaths[key] = { exe: shells[key].exe, rootDir: shells[key].rootDir, needsAcl: shells[key].needsAcl, msixPackageDir: shells[key].msixPackageDir };
          }
        } else {
          shellAvailability[key] = !!shells[key];
        }
        var label = SHELL_LABELS[key] || key;
        if (shellAvailability[key]) { found.push(label); }
        else if (key !== 'cmd' && key !== 'ps51') { notFound.push(label); }
      }
      updateShellDropdown();
      populateScenarios();
      btn.textContent = '🔄';
      btn.removeAttribute('disabled');
      // Show summary in scenario description area
      var msg = '✅ Found: ' + (found.length > 0 ? found.join(', ') : 'none');
      if (notFound.length > 0) { msg += '\n❌ Not found: ' + notFound.join(', '); }
      $('refreshStatus').classList.remove('hidden');
      $('refreshStatusText').innerText = msg;
      // Re-trigger shell change to update button visibility
      $sel('shellSelect').dispatchEvent(new Event('change'));
      updatePythonAclWarning();
    }).catch(function() {
      btn.textContent = '🔄';
      btn.removeAttribute('disabled');
    });
  });

  $('btnDismissRefresh').addEventListener('click', function() {
    $('refreshStatus').classList.add('hidden');
  });

  // === Containment select ===
  $sel('containmentSelect').addEventListener('change', function() {
    var containment = $sel('containmentSelect').value;
    if (containment === 'windows_sandbox') {
      // Windows Sandbox — show runtime/scenarios, auto-enable experimental
      $('runtimeRow').classList.remove('hidden');
      $sel('shellSelect').disabled = false;
      $('experimentalCaution').classList.add('hidden');
      // Hide policy controls — WS ignores filesystem/network/UI policies
      $('policySectionWrapper').classList.add('hidden');
      $('advancedSectionWrapper').classList.add('hidden');
      $('uiGroupWrapper').classList.add('hidden');
      // Auto-enable experimental (WS requires it) and lock the toggle
      ($('experimentalToggle') as HTMLInputElement).checked = true;
      ($('experimentalToggle') as HTMLInputElement).disabled = true;
      // Hide PowerShell 7+ runtime — not available in WS VM. Also hide the
      // pseudo-shells (networking/filesystem) which only apply to MV/HL.
      var shellOpts = $sel('shellSelect').options;
      for (var i = 0; i < shellOpts.length; i++) {
        var sv = shellOpts[i].value;
        if (sv === 'ps7' || sv === 'networking' || sv === 'filesystem') {
          (shellOpts[i] as HTMLOptionElement).hidden = true;
        }
      }
      if ($sel('shellSelect').value === 'rawjson' || $sel('shellSelect').value === 'ps7') {
        $sel('shellSelect').value = 'cmd';
        $sel('shellSelect').dispatchEvent(new Event('change'));
      } else {
        populateScenarios();
      }
    } else if (containment === 'microvm') {
      // MicroVM (NanVix) — the policy-generator UI is hidden because MicroVM
      // does not consume the SandboxPolicy schema; scenarios may still set
      // filesystem (and other) fields in the raw config sent to wxc-exec.
      $('runtimeRow').classList.remove('hidden');
      $sel('shellSelect').disabled = false;
      $('experimentalCaution').classList.add('hidden');
      $('policySectionWrapper').classList.add('hidden');
      $('advancedSectionWrapper').classList.add('hidden');
      $('uiGroupWrapper').classList.add('hidden');
      ($('experimentalToggle') as HTMLInputElement).checked = true;
      ($('experimentalToggle') as HTMLInputElement).disabled = true;
      // MicroVM supports Python + Filesystem test categories
      var mvOpts = $sel('shellSelect').options;
      for (var mi = 0; mi < mvOpts.length; mi++) {
        var v = mvOpts[mi].value;
        (mvOpts[mi] as HTMLOptionElement).hidden = (v !== 'python' && v !== 'filesystem' && v !== 'custom' && v !== 'rawjson');
      }
      $sel('shellSelect').value = 'python';
      $sel('shellSelect').dispatchEvent(new Event('change'));
      updatePlatformBadgeForContainment(containment);
    } else if (containment === 'hyperlight') {
      // Hyperlight — the policy-generator UI is hidden because Hyperlight
      // does not consume the SandboxPolicy schema; scenarios may still set
      // filesystem/network fields in the raw config sent to wxc-exec.
      $('runtimeRow').classList.remove('hidden');
      $sel('shellSelect').disabled = false;
      $('experimentalCaution').classList.add('hidden');
      $('policySectionWrapper').classList.add('hidden');
      $('advancedSectionWrapper').classList.add('hidden');
      $('uiGroupWrapper').classList.add('hidden');
      ($('experimentalToggle') as HTMLInputElement).checked = true;
      ($('experimentalToggle') as HTMLInputElement).disabled = true;
      // Hyperlight supports Python + Networking + Filesystem test categories
      var hlOpts = $sel('shellSelect').options;
      for (var hi = 0; hi < hlOpts.length; hi++) {
        var hv = hlOpts[hi].value;
        (hlOpts[hi] as HTMLOptionElement).hidden = (hv !== 'python' && hv !== 'networking' && hv !== 'filesystem' && hv !== 'custom' && hv !== 'rawjson');
      }
      $sel('shellSelect').value = 'python';
      $sel('shellSelect').dispatchEvent(new Event('change'));
      updatePlatformBadgeForContainment(containment);
    } else if (containment !== 'appcontainer') {
      // Other experimental containment — hide runtime, force MXC JSON mode
      $('runtimeRow').classList.add('hidden');
      $('categoryRow').classList.add('hidden');
      $('policySectionWrapper').classList.remove('hidden');
      // Restore PowerShell runtimes (but keep pseudo-shells hidden — they only
      // apply to MicroVM/Hyperlight, where Python is the runtime).
      var shellOpts2 = $sel('shellSelect').options;
      for (var j = 0; j < shellOpts2.length; j++) {
        var sv2 = shellOpts2[j].value;
        (shellOpts2[j] as HTMLOptionElement).hidden = (sv2 === 'networking' || sv2 === 'filesystem');
      }
      $sel('shellSelect').value = 'rawjson';
      $sel('shellSelect').dispatchEvent(new Event('change'));
      $('experimentalCaution').classList.remove('hidden');
      ($('experimentalToggle') as HTMLInputElement).disabled = false;
    } else {
      // Process Container — show runtime
      $('runtimeRow').classList.remove('hidden');
      $sel('shellSelect').disabled = false;
      $('experimentalCaution').classList.add('hidden');
      $('policySectionWrapper').classList.remove('hidden');
      ($('experimentalToggle') as HTMLInputElement).disabled = false;
      // Restore PowerShell runtimes (but keep pseudo-shells hidden — they only
      // apply to MicroVM/Hyperlight, where Python is the runtime).
      var shellOpts3 = $sel('shellSelect').options;
      for (var k = 0; k < shellOpts3.length; k++) {
        var sv3 = shellOpts3[k].value;
        (shellOpts3[k] as HTMLOptionElement).hidden = (sv3 === 'networking' || sv3 === 'filesystem');
      }
      if ($sel('shellSelect').value === 'rawjson') {
        $sel('shellSelect').value = 'cmd';
        $sel('shellSelect').dispatchEvent(new Event('change'));
      } else {
        populateScenarios();
      }
      updatePlatformBadgeForContainment(containment);
    }
    updateContainmentDropdown();
    updateDevSidebar();
    updatePermsSummary();
  });

  // === Scenario select ===
  $sel('shellSelect').addEventListener('change', function() {
    var shell = $sel('shellSelect').value;
    if (shell === 'custom') {
      $('categoryRow').classList.add('hidden');
      $('scriptSection').classList.remove('hidden');
      $('rawJsonSection').classList.add('hidden');
      if ($sel('containmentSelect').value !== 'windows_sandbox' && $sel('containmentSelect').value !== 'microvm' && $sel('containmentSelect').value !== 'hyperlight') {
        $('policySectionWrapper').classList.remove('hidden');
      }
      $('btnRun').classList.remove('hidden');
      $('btnRunAll').classList.add('hidden');
      updateUiDetails();
      state.selectedScenario = null;
      $('scenarioDesc').textContent = 'Write your own script and configure policy.';
      $('scenarioOutcome').textContent = '';
      $('scenarioOutcome').className = 'outcome-badge';
      updateDevSidebar();
      updateContainmentDropdown();
    } else if (shell === 'rawjson') {
      $('categoryRow').classList.add('hidden');
      $('scriptSection').classList.add('hidden');
      $('rawJsonSection').classList.remove('hidden');
      $('policySectionWrapper').classList.add('hidden');
      $('advancedSectionWrapper').classList.add('hidden');
      $('uiGroupWrapper').classList.add('hidden');
      $('btnRun').classList.remove('hidden');
      $('btnRunAll').classList.add('hidden');
      state.selectedScenario = null;
      $('scenarioDesc').textContent = 'Paste a ContainerConfig JSON. Runs via spawnSandboxFromConfig — no policy generation step.';
      $('scenarioOutcome').textContent = '';
      $('scenarioOutcome').className = 'outcome-badge';
      $chk('experimentalToggle').checked = true;
      updateDevSidebar();
      updateContainmentDropdown();
    } else {
      var shellAvail = shellAvailability[shell] !== false;
      if (shellAvail) {
        $('categoryRow').classList.remove('hidden');
        populateScenarios();
        $('btnRun').classList.remove('hidden');
        $('btnRunAll').classList.remove('hidden');
        if ($sel('containmentSelect').value !== 'windows_sandbox' && $sel('containmentSelect').value !== 'microvm' && $sel('containmentSelect').value !== 'hyperlight') {
          $('policySectionWrapper').classList.remove('hidden');
        }
        if (document.getElementById('advancedSectionWrapper')) {
          $('advancedSectionWrapper').classList.remove('hidden');
        }
      } else {
        $('categoryRow').classList.add('hidden');
        $('btnRun').classList.add('hidden');
        $('btnRunAll').classList.add('hidden');
        $('policySectionWrapper').classList.add('hidden');
        if (document.getElementById('advancedSectionWrapper')) {
          $('advancedSectionWrapper').classList.add('hidden');
        }
        // Clear stale content from previous mode
        $('scenarioDesc').textContent = '';
        $('scenarioOutcome').textContent = '';
        $('scenarioOutcome').className = 'outcome-badge';
        state.selectedScenario = null;
      }
      $('scriptSection').classList.add('hidden');
      $('rawJsonSection').classList.add('hidden');
      updateUiDetails();
      updateDevSidebar();
      updateContainmentDropdown();
    }
    updatePythonAclWarning();
    updateRunAllLabel();
  });

  $sel('scenarioSelect').addEventListener('change', function() {
    loadScenario($sel('scenarioSelect').value);
  });

  // === Raw JSON textarea live update ===
  // === JSON Editor Dialog ===
  function updateJsonEditorPreview(): void {
    var text = ($('rawJsonText') as HTMLTextAreaElement).value.trim();
    if (!text) {
      $('jsonEditorPreview').innerHTML = '<span class="line-dim">Enter JSON above</span>';
      return;
    }
    try {
      var parsed = JSON.parse(text);

      // Sync schema version dropdown from pasted config
      if (parsed.version) {
        var versionSelect = $sel('versionSelect');
        for (var i = 0; i < versionSelect.options.length; i++) {
          if (versionSelect.options[i].value === parsed.version) {
            versionSelect.value = parsed.version;
            state.version = parsed.version;
            break;
          }
        }
      }

      // Sync containment dropdown from pasted config
      if (parsed.containment) {
        var containmentSelect = $sel('containmentSelect');
        for (var j = 0; j < containmentSelect.options.length; j++) {
          if (containmentSelect.options[j].value === parsed.containment) {
            containmentSelect.value = parsed.containment;
            break;
          }
        }
        updateContainmentDropdown();
      }

      var info = '<span style="color:#4ec9b0;">✓ Valid JSON</span>';
      if (parsed.version) { info += ' · version: ' + parsed.version; }
      if (parsed.process?.commandLine) { info += ' · <code>' + escapeHtml(parsed.process.commandLine) + '</code>'; }
      if (parsed.containment) { info += ' · containment: ' + parsed.containment; }
      $('jsonEditorPreview').innerHTML = info;
    } catch (e: any) {
      $('jsonEditorPreview').innerHTML = '<span class="line-error">✗ ' + escapeHtml(e.message) + '</span>';
    }
  }

  $('btnOpenJsonEditor').addEventListener('click', function() {
    ($('jsonEditorDialog') as HTMLDialogElement).showModal();
    updateJsonEditorPreview();
  });
  $('jsonEditorClose').addEventListener('click', function() {
    ($('jsonEditorDialog') as HTMLDialogElement).close();
    updateDevSidebar();
  });
  $('rawJsonText').addEventListener('input', function() {
    updateJsonEditorPreview();
    updateContainmentDropdown();
    updateDevSidebar();
  });
  $('jsonEditorApply').addEventListener('click', function() {
    ($('jsonEditorDialog') as HTMLDialogElement).close();
    updateContainmentDropdown();
    updateDevSidebar();
  });
  $('jsonEditorRun').addEventListener('click', function() {
    ($('jsonEditorDialog') as HTMLDialogElement).close();
    runSandbox();
  });

  // === Drag & drop JSON files ===
  var rawArea = $('rawJsonText') as HTMLTextAreaElement;
  rawArea.addEventListener('dragover', function(e: DragEvent) {
    e.preventDefault();
    rawArea.style.borderColor = 'var(--accent)';
  });
  rawArea.addEventListener('dragleave', function() {
    rawArea.style.borderColor = '';
  });
  rawArea.addEventListener('drop', function(e: DragEvent) {
    e.preventDefault();
    rawArea.style.borderColor = '';
    if (e.dataTransfer && e.dataTransfer.files.length > 0) {
      var file = e.dataTransfer.files[0];
      if (file.name.endsWith('.json')) {
        var reader = new FileReader();
        reader.onload = function() {
          var text = reader.result as string;
          try { rawArea.value = JSON.stringify(JSON.parse(text), null, 2); }
          catch { rawArea.value = text; }
          updateJsonEditorPreview();
          updateDevSidebar();
        };
        reader.readAsText(file);
      }
    }
  });

  // Drag & drop anywhere on the window opens the JSON editor
  document.body.addEventListener('dragover', function(e: DragEvent) { e.preventDefault(); });
  document.body.addEventListener('drop', function(e: DragEvent) {
    e.preventDefault();
    if (e.dataTransfer && e.dataTransfer.files.length > 0) {
      var file = e.dataTransfer.files[0];
      if (file.name.endsWith('.json')) {
        var reader = new FileReader();
        reader.onload = function() {
          var text = reader.result as string;
          try { ($('rawJsonText') as HTMLTextAreaElement).value = JSON.stringify(JSON.parse(text), null, 2); }
          catch { ($('rawJsonText') as HTMLTextAreaElement).value = text; }
          showMainView();
          $sel('shellSelect').value = 'rawjson';
          $sel('shellSelect').dispatchEvent(new Event('change'));
          ($('jsonEditorDialog') as HTMLDialogElement).showModal();
          updateJsonEditorPreview();
          updateDevSidebar();
        };
        reader.readAsText(file);
      }
    }
  });

  // === Version select (sidebar) ===
  $sel('versionSelect').addEventListener('change', function() {
    state.version = $sel('versionSelect').value;
    // Auto-toggle experimental: on for 0.5.0+, off for 0.4.0
    $chk('experimentalToggle').checked = state.version === '0.5.0-dev';
    populateScenarios();
    updateUiDetails();
    updateContainmentDropdown();
    updateDevSidebar();

    // Sync version into MXC JSON editor if in that mode
    if ($sel('shellSelect').value === 'rawjson') {
      var text = ($('rawJsonText') as HTMLTextAreaElement).value.trim();
      if (text) {
        try {
          var parsed = JSON.parse(text);
          parsed.version = state.version;
          ($('rawJsonText') as HTMLTextAreaElement).value = JSON.stringify(parsed, null, 2);
          updateJsonEditorPreview();
        } catch { /* leave as-is if invalid */ }
      }
    }
  });

  // === Script textarea ===
  ($('scriptText') as HTMLTextAreaElement).addEventListener('input', function() {
    state.customScript = ($('scriptText') as HTMLTextAreaElement).value;
    updateDevSidebar();
  });

  // === Policy toggle ===
  $('permissionsToggle').addEventListener('click', function() {
    state.permissionsOpen = !state.permissionsOpen;
    $('permissionsBody').classList.toggle('hidden', !state.permissionsOpen);
    $('permissionsChevron').classList.toggle('open', state.permissionsOpen);
    if (state.permissionsOpen) {
      $('permissionsSummaryLine').classList.add('hidden');
    } else {
      $('permissionsSummaryLine').classList.remove('hidden');
    }
  });

  // === File access toggle ===
  $chk('fsToggle').addEventListener('change', function() {
    state.fsEnabled = $chk('fsToggle').checked;
    updateFsDetails();
    updatePermsSummary();
    updateDevSidebar();
  });

  // === File path buttons ===
  $('rwBrowse').addEventListener('click', async function() {
    var folder = await mxc.openFolderDialog();
    if (folder) {
      state.rwPaths.push(folder);
      refreshPathLists();
      updateDevSidebar();
    }
  });
  $('rwManual').addEventListener('click', function() {
    var input = ($('rwManualInput') as HTMLInputElement).value.trim();
    if (input) {
      state.rwPaths.push(input);
      ($('rwManualInput') as HTMLInputElement).value = '';
      refreshPathLists();
      updateDevSidebar();
    }
  });
  $('roBrowse').addEventListener('click', async function() {
    var folder = await mxc.openFolderDialog();
    if (folder) {
      state.roPaths.push(folder);
      refreshPathLists();
      updateDevSidebar();
    }
  });
  $('roManual').addEventListener('click', function() {
    var input = ($('roManualInput') as HTMLInputElement).value.trim();
    if (input) {
      state.roPaths.push(input);
      ($('roManualInput') as HTMLInputElement).value = '';
      refreshPathLists();
      updateDevSidebar();
    }
  });

  // === Include checkboxes ===
  $chk('fsIncludeTools').addEventListener('change', function() {
    state.fsIncludeTools = $chk('fsIncludeTools').checked;
  });
  $chk('fsIncludeTemp').addEventListener('change', function() {
    state.fsIncludeTemp = $chk('fsIncludeTemp').checked;
  });

  // === Network toggle ===
  $chk('netToggle').addEventListener('change', function() {
    state.netEnabled = $chk('netToggle').checked;
    updateNetDetails();
    updatePermsSummary();
    updateDevSidebar();
  });

  // === UI toggle ===
  $chk('uiToggle').addEventListener('change', function() {
    state.uiAllowWindows = $chk('uiToggle').checked;
    updateUiDetails();
    updatePermsSummary();
    updateDevSidebar();
  });

  $sel('uiClipboard').addEventListener('change', function() {
    state.uiClipboard = $sel('uiClipboard').value;
    updateDevSidebar();
  });

  $chk('uiInjection').addEventListener('change', function() {
    state.uiInjection = $chk('uiInjection').checked;
    updateDevSidebar();
  });

  ($('timeoutInput') as HTMLInputElement).addEventListener('change', function() {
    state.timeoutSeconds = parseInt((this as HTMLInputElement).value, 10) || 0;
    updateDevSidebar();
  });

  // === Advanced toggle ===
  $('advancedToggle').addEventListener('click', function() {
    state.advancedOpen = !state.advancedOpen;
    $('advancedBody').classList.toggle('hidden', !state.advancedOpen);
    $('advancedChevron').classList.toggle('open', state.advancedOpen);
  });

  // === Container type toggle ===
  // === Advanced UI field listeners ===
  $sel('uiIsolation').addEventListener('change', function() {
    updateDevSidebar();
  });
  $sel('uiSystemSettings').addEventListener('change', function() {
    updateDevSidebar();
  });
  $chk('uiDesktopControl').addEventListener('change', function() {
    updateDevSidebar();
  });
  $chk('uiIME').addEventListener('change', function() {
    updateDevSidebar();
  });

  // === Proxy listeners ===
  $sel('proxySelect').addEventListener('change', function() {
    var val = $sel('proxySelect').value;
    $('proxyPort').style.display = val === 'localhost' ? '' : 'none';
    $('proxyUrl').style.display = val === 'url' ? '' : 'none';
    updateDevSidebar();
  });
  $num('proxyPort').addEventListener('change', function() {
    updateDevSidebar();
  });
  $('proxyUrl').addEventListener('input', function() {
    updateDevSidebar();
  });

  // === Copy buttons in dev sidebar ===
  $('copyPolicy').addEventListener('click', function() {
    navigator.clipboard.writeText($('devPolicyJson').textContent || '');
    (this as HTMLElement).textContent = '✅';
    var btn = this as HTMLElement;
    setTimeout(function() { btn.textContent = '📋'; }, 1000);
  });
  $('copyConfig').addEventListener('click', function() {
    navigator.clipboard.writeText($('devConfigJson').textContent || '');
    (this as HTMLElement).textContent = '✅';
    var btn = this as HTMLElement;
    setTimeout(function() { btn.textContent = '📋'; }, 1000);
  });

  // === Dev mode toggle ===
  $('devModeToggle').addEventListener('change', function() {
    var sidebar = $('devSidebar');
    if ((this as HTMLInputElement).checked) {
      sidebar.classList.remove('hidden');
      updateDevSidebar();
    } else {
      sidebar.classList.add('hidden');
    }
  });

  // === Run / Kill / Run All ===
  $('btnRun').addEventListener('click', function() {
    runSandbox();
  });
  $('btnRunAll').addEventListener('click', function() {
    runAllScenarios();
  });
  $('btnKill').addEventListener('click', function() {
    killSandbox();
  });

  // === Terminal toggle ===
  $('terminalToggle').addEventListener('click', function() {
    state.terminalOpen = !state.terminalOpen;
    $('terminal').classList.toggle('hidden', !state.terminalOpen);
    $('terminalChevron').classList.toggle('collapsed', !state.terminalOpen);
  });

  // === JSON tabs ===
  $('tabPolicy').addEventListener('click', function() {
    showJsonPanel('policy');
  });
  $('tabConfig').addEventListener('click', function() {
    showJsonPanel('config');
  });
  $('jsonCopy').addEventListener('click', function() {
    var text = $('jsonContent').textContent || '';
    navigator.clipboard.writeText(text);
  });

  // === Help ===
  $('btnHelp').addEventListener('click', function() {
    ($('helpDialog') as HTMLDialogElement).showModal();
  });
  $('helpClose').addEventListener('click', function() {
    ($('helpDialog') as HTMLDialogElement).close();
  });

  // === Decide initial view ===
  showMainView();
  loadScenario('custom');
  updateDevSidebar();
}

document.addEventListener('DOMContentLoaded', init);
