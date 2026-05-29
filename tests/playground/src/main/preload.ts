// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

import { contextBridge, ipcRenderer } from 'electron';

contextBridge.exposeInMainWorld('mxc', {
  getPlatformSupport: () => ipcRenderer.invoke('get-platform-support'),
  getToolsPolicy: () => ipcRenderer.invoke('get-tools-policy'),
  getProfilePolicy: () => ipcRenderer.invoke('get-profile-policy'),
  getTempPolicy: () => ipcRenderer.invoke('get-temp-policy'),
  runSandbox: (script: string, policyJson: string, debug: boolean, experimental: boolean) =>
    ipcRenderer.invoke('run-sandbox', script, policyJson, debug, experimental),
  runSandboxAdvanced: (script: string, policyJson: string, debug: boolean, experimental: boolean) =>
    ipcRenderer.invoke('run-sandbox-advanced', script, policyJson, debug, experimental),
  killSandbox: () => ipcRenderer.invoke('kill-sandbox'),
  validatePolicy: (policyJson: string) =>
    ipcRenderer.invoke('validate-policy', policyJson),
  onPtyData: (callback: (data: string) => void) => {
    ipcRenderer.on('pty-data', (_event, data) => callback(data));
  },
  onPtyExit: (callback: (exitCode: number) => void) => {
    ipcRenderer.on('pty-exit', (_event, exitCode) => callback(exitCode));
  },
  openFolderDialog: () => ipcRenderer.invoke('open-folder-dialog'),
  detectShells: () => ipcRenderer.invoke('detect-shells'),
  ensureDirs: (dirs: string[]) => ipcRenderer.invoke('ensure-dirs', dirs),
  saveLogFile: (content: string) => ipcRenderer.invoke('save-log-file', content),
  getTestScript: (name: string) => ipcRenderer.invoke('get-test-script', name),
  fixPythonAcl: (path: string) => ipcRenderer.invoke('fix-python-acl', path),
  installRuntime: (runtime: string) => ipcRenderer.invoke('install-runtime', runtime),
  detectPythonVersions: () => ipcRenderer.invoke('detect-python-versions'),
  runSandboxRaw: (configJson: string, debug: boolean, experimental: boolean) =>
    ipcRenderer.invoke('run-sandbox-raw', configJson, debug, experimental),
});
