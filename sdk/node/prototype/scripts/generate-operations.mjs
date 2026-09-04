// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

import { existsSync, mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const root = join(dirname(fileURLToPath(import.meta.url)), '..');
const check = process.argv.includes('--check');
const resultTypes = {
  string: 'string',
  availableBackends: 'readonly AvailableBackend[]',
  platformSupport: 'NativePlatformSupport',
  runSandboxResult: 'RunSandboxResult',
  stateAwareEnvelope: 'StateAwareEnvelope',
  waitResult: 'WaitResult',
};
const typeConverters = {
  string: 'expectString',
  availableBackends: 'expectAvailableBackends',
  platformSupport: 'expectPlatformSupport',
  runSandboxResult: 'expectRunSandboxResult',
  stateAwareEnvelope: 'expectJson',
  waitResult: 'expectWaitResult',
};

function invariant(condition, message) {
  if (!condition) throw new Error(`Invalid generated Diplomat ABI: ${message}`);
}

const defaultIncludeDirectory = resolve(root, '..', '..', '..', 'src', 'target', 'diplomat-bindings', 'c');
const includeDirectory = resolve(process.env.MXC_DIPLOMAT_INCLUDE_DIR ?? defaultIncludeDirectory);
invariant(existsSync(includeDirectory), `header directory does not exist: ${includeDirectory}`);

function header(name) {
  const path = join(includeDirectory, name);
  invariant(existsSync(path), `missing generated header ${name}`);
  return readFileSync(path, 'utf8');
}

function writer(handle, method) {
  const source = header(`${handle}.h`);
  const symbol = `${handle}_${method}`;
  invariant(
    new RegExp(`\\b${symbol}_result\\s+${symbol}\\(const\\s+${handle}\\*\\s+self,\\s*DiplomatWrite\\*\\s+write\\);`).test(source),
    `missing DiplomatWrite getter ${symbol}`,
  );
  return symbol;
}

function scalar(handle, method, type) {
  const symbol = `${handle}_${method}`;
  invariant(
    new RegExp(`\\b${type}\\s+${symbol}\\(const\\s+${handle}\\*\\s+self\\);`).test(header(`${handle}.h`)),
    `missing ${type} getter ${symbol}`,
  );
  return symbol;
}

function destructor(handle) {
  const symbol = `${handle}_destroy`;
  invariant(
    new RegExp(`\\bvoid\\s+${symbol}\\(${handle}\\*\\s+self\\);`).test(header(`${handle}.h`)),
    `missing destructor ${symbol}`,
  );
  return symbol;
}

function entry(method) {
  const source = header('MxcDiplomat.h');
  const symbol = `MxcDiplomat_${method}`;
  const declaration = new RegExp(
    `typedef\\s+struct\\s+${symbol}_result\\s*\\{\\s*union\\s*\\{\\s*(MxcDiplomat\\w+)\\*\\s+ok;\\s*MxcDiplomatError\\*\\s+err;\\s*\\};\\s*bool\\s+is_ok;\\s*\\}\\s*${symbol}_result;\\s*${symbol}_result\\s+${symbol}\\(([^)]*)\\);`,
    's',
  ).exec(source);
  invariant(declaration !== null, `missing opaque result declaration for ${symbol}`);
  return { symbol, handle: declaration[1], parameters: declaration[2].trim() };
}

const version = entry('version');
const discover = entry('discover');
const run = entry('run');
const stateAware = ['provision', 'start', 'stop', 'deprovision'].map(entry);
invariant(version.parameters === 'void', 'MxcDiplomat_version must not take arguments');
invariant(discover.parameters === 'void', 'MxcDiplomat_discover must not take arguments');
invariant(run.parameters === 'DiplomatStringView request_json', 'MxcDiplomat_run request changed');
invariant(version.handle === 'MxcDiplomatVersion', 'MxcDiplomat_version result changed');
invariant(discover.handle === 'MxcDiplomatDiscovery', 'MxcDiplomat_discover result changed');
invariant(run.handle === 'MxcDiplomatRunResult', 'MxcDiplomat_run result changed');
for (const operation of stateAware) {
  invariant(
    operation.parameters === 'DiplomatStringView request_json, bool dry_run, bool experimental' &&
      operation.handle === 'MxcDiplomatStateAwareEnvelope',
    `${operation.symbol} signature changed`,
  );
}
invariant(
  /MxcDiplomat_exec_attached_result\s+MxcDiplomat_exec_attached\(DiplomatStringView request_json, bool experimental\);/
    .test(header('MxcDiplomat.h')),
  'MxcDiplomat_exec_attached signature changed',
);

const bridge = {
  versionValue: writer(version.handle, 'value'),
  versionDestroy: destructor(version.handle),
  discoverBackends: writer(discover.handle, 'available_backends_json'),
  discoverPlatformSupport: writer(discover.handle, 'platform_support_json'),
  discoverDestroy: destructor(discover.handle),
  runExitCode: scalar(run.handle, 'exit_code', 'int32_t'),
  runTimedOut: scalar(run.handle, 'timed_out', 'bool'),
  runStdout: writer(run.handle, 'stdout'),
  runStderr: writer(run.handle, 'stderr'),
  runHasOutputMetadata: scalar(run.handle, 'has_output_metadata', 'bool'),
  runOutputMetadata: writer(run.handle, 'output_metadata_json'),
  runWarnings: writer(run.handle, 'warnings_json'),
  runDestroy: destructor(run.handle),
  errorCode: scalar('MxcDiplomatError', 'code', 'MxcDiplomatErrorCode'),
  errorMessage: writer('MxcDiplomatError', 'message'),
  errorHasOperation: scalar('MxcDiplomatError', 'has_operation', 'bool'),
  errorOperation: writer('MxcDiplomatError', 'operation'),
  errorHasNativeCode: scalar('MxcDiplomatError', 'has_native_code', 'bool'),
  errorNativeCode: writer('MxcDiplomatError', 'native_code'),
  errorHasRemediation: scalar('MxcDiplomatError', 'has_remediation', 'bool'),
  errorRemediation: writer('MxcDiplomatError', 'remediation'),
  errorDestroy: destructor('MxcDiplomatError'),
  stateAwareResponse: writer('MxcDiplomatStateAwareEnvelope', 'response_json'),
  stateAwareDestroy: destructor('MxcDiplomatStateAwareEnvelope'),
};

function assertExactSymbols(label, actual, expected) {
  const unexpected = [...actual].filter((symbol) => !expected.has(symbol));
  const missing = [...expected].filter((symbol) => !actual.has(symbol));
  invariant(
    unexpected.length === 0 && missing.length === 0,
    `${label} drifted (unexpected: ${unexpected.join(', ') || 'none'}; missing: ${missing.join(', ') || 'none'})`,
  );
}

function exportedMembers(handle) {
  return new Set([...header(`${handle}.h`).matchAll(
    new RegExp(`\\b(${handle}_[A-Za-z0-9_]+)\\s*\\(`, 'g'),
  )].map((match) => match[1]));
}

assertExactSymbols(
  'MxcDiplomat operations',
  new Set([...header('MxcDiplomat.h').matchAll(/\b(MxcDiplomat_[a-z][A-Za-z0-9_]*)\s*\(/g)]
    .map((match) => match[1])),
  new Set([
    version.symbol,
    discover.symbol,
    run.symbol,
    'MxcDiplomat_spawn',
    'MxcDiplomat_provision',
    'MxcDiplomat_start',
    'MxcDiplomat_stop',
    'MxcDiplomat_deprovision',
    'MxcDiplomat_exec',
    'MxcDiplomat_exec_attached',
    'MxcDiplomat_destroy',
  ]),
);
assertExactSymbols('MxcDiplomatVersion methods', exportedMembers(version.handle),
  new Set([bridge.versionValue, bridge.versionDestroy]));
assertExactSymbols('MxcDiplomatDiscovery methods', exportedMembers(discover.handle),
  new Set([bridge.discoverBackends, bridge.discoverPlatformSupport, bridge.discoverDestroy]));
assertExactSymbols('MxcDiplomatRunResult methods', exportedMembers(run.handle),
  new Set([
    bridge.runExitCode, bridge.runTimedOut, bridge.runStdout, bridge.runStderr,
    bridge.runHasOutputMetadata, bridge.runOutputMetadata, bridge.runWarnings, bridge.runDestroy,
  ]));
assertExactSymbols('MxcDiplomatError methods', exportedMembers('MxcDiplomatError'),
  new Set([
    bridge.errorCode, bridge.errorMessage, bridge.errorHasOperation, bridge.errorOperation,
    bridge.errorHasNativeCode, bridge.errorNativeCode, bridge.errorHasRemediation,
    bridge.errorRemediation, bridge.errorDestroy,
  ]));
assertExactSymbols('MxcDiplomatStateAwareEnvelope methods',
  exportedMembers('MxcDiplomatStateAwareEnvelope'),
  new Set([bridge.stateAwareResponse, bridge.stateAwareDestroy]));

const runtimeHeader = header('diplomat_runtime.h');
for (const symbol of [
  'diplomat_buffer_write_create',
  'diplomat_buffer_write_get_bytes',
  'diplomat_buffer_write_len',
  'diplomat_buffer_write_destroy',
]) {
  invariant(new RegExp(`\\b${symbol}\\(`).test(runtimeHeader), `missing runtime helper ${symbol}`);
}

const errorCodes = [...header('MxcDiplomatErrorCode.d.h').matchAll(
  /^\s*(MxcDiplomatErrorCode_[A-Za-z0-9_]+)\s*=/gm,
)].map((match) => ({
  native: match[1],
  wire: match[1]
    .replace('MxcDiplomatErrorCode_', '')
    .replace(/([a-z0-9])([A-Z])/g, '$1_$2')
    .toLowerCase(),
}));
invariant(errorCodes.length > 0, 'MxcDiplomatErrorCode enum is empty');

const description = {
  ffi: {
    library: 'mxc_ffi',
    errorCodes,
    supportSymbols: [
      { symbol: 'diplomat_buffer_write_create', signature: 'DiplomatBufferWriteCreate' },
      { symbol: 'diplomat_buffer_write_get_bytes', signature: 'DiplomatBufferWriteGetBytes' },
      { symbol: 'diplomat_buffer_write_len', signature: 'DiplomatBufferWriteLen' },
      { symbol: 'diplomat_buffer_write_destroy', signature: 'DiplomatBufferWriteDestroy' },
      { symbol: bridge.versionValue, signature: 'MxcDiplomatVersionValue' },
      { symbol: bridge.versionDestroy, signature: 'MxcDiplomatVersionDestroy' },
      { symbol: bridge.discoverBackends, signature: 'MxcDiplomatDiscoveryAvailableBackendsJson' },
      { symbol: bridge.discoverPlatformSupport, signature: 'MxcDiplomatDiscoveryPlatformSupportJson' },
      { symbol: bridge.discoverDestroy, signature: 'MxcDiplomatDiscoveryDestroy' },
      { symbol: bridge.runExitCode, signature: 'MxcDiplomatRunResultExitCode' },
      { symbol: bridge.runTimedOut, signature: 'MxcDiplomatRunResultTimedOut' },
      { symbol: bridge.runStdout, signature: 'MxcDiplomatRunResultStdout' },
      { symbol: bridge.runStderr, signature: 'MxcDiplomatRunResultStderr' },
      { symbol: bridge.runHasOutputMetadata, signature: 'MxcDiplomatRunResultHasOutputMetadata' },
      { symbol: bridge.runOutputMetadata, signature: 'MxcDiplomatRunResultOutputMetadataJson' },
      { symbol: bridge.runWarnings, signature: 'MxcDiplomatRunResultWarningsJson' },
      { symbol: bridge.runDestroy, signature: 'MxcDiplomatRunResultDestroy' },
      { symbol: bridge.errorCode, signature: 'MxcDiplomatErrorCodeGetter' },
      { symbol: bridge.errorMessage, signature: 'MxcDiplomatErrorMessage' },
      { symbol: bridge.errorHasOperation, signature: 'MxcDiplomatErrorHasOperation' },
      { symbol: bridge.errorOperation, signature: 'MxcDiplomatErrorOperation' },
      { symbol: bridge.errorHasNativeCode, signature: 'MxcDiplomatErrorHasNativeCode' },
      { symbol: bridge.errorNativeCode, signature: 'MxcDiplomatErrorNativeCode' },
      { symbol: bridge.errorHasRemediation, signature: 'MxcDiplomatErrorHasRemediation' },
      { symbol: bridge.errorRemediation, signature: 'MxcDiplomatErrorRemediation' },
      { symbol: bridge.errorDestroy, signature: 'MxcDiplomatErrorDestroy' },
      { symbol: bridge.stateAwareResponse, signature: 'MxcDiplomatStateAwareEnvelopeResponseJson' },
      { symbol: bridge.stateAwareDestroy, signature: 'MxcDiplomatStateAwareEnvelopeDestroy' },
    ],
  },
  operations: [
    {
      id: 'version',
      js: { sync: 'getVersion', documentation: 'Gets the version reported by the generated Diplomat API.' },
      call: { kind: 'version', symbol: version.symbol },
      result: 'string',
    },
    {
      id: 'availableBackends',
      js: { sync: 'getAvailableBackends', documentation: 'Gets the containment backends reported by Diplomat discovery.' },
      call: { kind: 'discoverBackends', symbol: discover.symbol },
      result: 'availableBackends',
    },
    {
      id: 'platformSupport',
      js: { sync: 'getPlatformSupport', documentation: 'Gets platform support reported by Diplomat discovery.' },
      call: { kind: 'discoverPlatformSupport', symbol: discover.symbol },
      result: 'platformSupport',
    },
    {
      id: 'run',
      js: { sync: 'runSandboxSync', async: 'runSandbox', documentation: 'Runs one serialized MXC request to completion.' },
      call: { kind: 'run', symbol: run.symbol },
      argument: 'json',
      result: 'runSandboxResult',
    },
    ...stateAware.map((operation) => ({
      id: operation.symbol.replace('MxcDiplomat_', ''),
      js: {
        sync: `${operation.symbol.replace('MxcDiplomat_', '')}SandboxSync`,
        async: `${operation.symbol.replace('MxcDiplomat_', '')}Sandbox`,
        documentation: `Runs the generated ${operation.symbol} state-aware request.`,
      },
      call: { kind: 'stateAware', symbol: operation.symbol },
      argument: 'stateAware',
      result: 'stateAwareEnvelope',
    })),
    {
      id: 'execAttached',
      js: {
        sync: 'execAttachedSandboxSync',
        async: 'execAttachedSandbox',
        documentation: 'Executes a generated state-aware request on the host terminal.',
      },
      call: { kind: 'execAttached', symbol: 'MxcDiplomat_exec_attached' },
      argument: 'execAttached',
      result: 'waitResult',
    },
  ],
};

const signatures = new Set([
  'DiplomatBufferWriteCreate', 'DiplomatBufferWriteGetBytes', 'DiplomatBufferWriteLen',
  'DiplomatBufferWriteDestroy', 'MxcDiplomatVersionCall', 'MxcDiplomatDiscoverCall',
  'MxcDiplomatRunCall', 'MxcDiplomatVersionValue', 'MxcDiplomatVersionDestroy',
  'MxcDiplomatDiscoveryAvailableBackendsJson', 'MxcDiplomatDiscoveryPlatformSupportJson',
  'MxcDiplomatDiscoveryDestroy', 'MxcDiplomatRunResultExitCode',
  'MxcDiplomatRunResultTimedOut', 'MxcDiplomatRunResultStdout',
  'MxcDiplomatRunResultStderr', 'MxcDiplomatRunResultHasOutputMetadata',
  'MxcDiplomatRunResultOutputMetadataJson', 'MxcDiplomatRunResultWarningsJson',
  'MxcDiplomatRunResultDestroy', 'MxcDiplomatErrorCodeGetter',
  'MxcDiplomatErrorMessage', 'MxcDiplomatErrorHasOperation', 'MxcDiplomatErrorOperation',
  'MxcDiplomatErrorHasNativeCode', 'MxcDiplomatErrorNativeCode',
  'MxcDiplomatErrorHasRemediation', 'MxcDiplomatErrorRemediation',
  'MxcDiplomatErrorDestroy',
  'MxcDiplomatStateAwareEnvelopeResponseJson', 'MxcDiplomatStateAwareEnvelopeDestroy',
  'MxcDiplomatProvisionCall', 'MxcDiplomatStartCall', 'MxcDiplomatStopCall',
  'MxcDiplomatDeprovisionCall', 'MxcDiplomatExecAttachedCall',
]);
const symbols = [...description.ffi.supportSymbols];
for (const operation of description.operations) {
  symbols.push({
    symbol: operation.call.symbol,
    signature: operation.call.kind === 'version'
      ? 'MxcDiplomatVersionCall'
      : operation.call.kind.startsWith('discover')
        ? 'MxcDiplomatDiscoverCall'
        : operation.call.kind === 'run'
          ? 'MxcDiplomatRunCall'
          : `MxcDiplomat${cppName(operation.id)}Call`,
  });
}
const uniqueSymbols = [];
const symbolsByName = new Map();
for (const symbol of symbols) {
  invariant(typeof symbol.symbol === 'string' && signatures.has(symbol.signature),
    `invalid FFI symbol ${symbol.symbol}`);
  const existing = symbolsByName.get(symbol.symbol);
  invariant(
    existing === undefined || existing === symbol.signature,
    `FFI symbol ${symbol.symbol} has conflicting signatures`,
  );
  if (existing === undefined) {
    symbolsByName.set(symbol.symbol, symbol.signature);
    uniqueSymbols.push(symbol);
  }
}

function writeGenerated(relativePath, contents) {
  const destination = join(root, relativePath);
  let current;
  try { current = readFileSync(destination, 'utf8'); } catch { current = undefined; }
  if (current === contents) return;
  if (check) throw new Error(`Generated file is stale: ${relativePath}. Run npm run generate.`);
  mkdirSync(dirname(destination), { recursive: true });
  writeFileSync(destination, contents);
}

function cppName(name) {
  return name[0].toUpperCase() + name.slice(1);
}

const banner = `// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.
//
// Generated by scripts/generate-operations.mjs from Diplomat C headers. DO NOT EDIT.

`;

writeGenerated('native/generated/ffi-symbols.inc',
  `${banner}${uniqueSymbols.map(({ symbol, signature }) => `MXC_FFI_SYMBOL(${symbol}, ${signature})`).join('\n')}\n`);
writeGenerated('native/generated/ffi-library.h',
  `${banner}#pragma once

namespace mxc_node {
constexpr char kMxcFfiLibraryBaseName[] = "${description.ffi.library}";
}  // namespace mxc_node
`);
writeGenerated('native/generated/operations.h',
  `${banner}#pragma once
#include <node_api.h>
namespace mxc_node {
napi_value InitGeneratedOperations(napi_env env, napi_value exports);
}  // namespace mxc_node
`);

const errorCodeCases = description.ffi.errorCodes
  .map(({ native, wire }) => `    case ${native}: return "${wire}";`)
  .join('\n');

function capture(field, expression) {
  return `  NativeOutcome ${field} = api.CaptureWrite(
      [&](DiplomatWrite* write) { return ${expression}write).is_ok; });
  if (!${field}.succeeded) {
    return ${field};
  }`;
}

function nativeCall(operation) {
  const name = cppName(operation.id);
  if (operation.call.kind === 'version') {
    return `NativeOutcome Call${name}(const NativeArguments&) {
  NativeApi& api = NativeApi::Instance();
  NativeOutcome failure{};
  if (!api.EnsureLoaded(&failure)) return failure;
  const MxcDiplomat_version_result response = api.functions().${operation.call.symbol}();
  if (!response.is_ok) return SerializeMxcError(response.err);
  NativeHandle<MxcDiplomatVersion> value(
      response.ok, api.functions().MxcDiplomatVersion_destroy);
${capture('text', 'api.functions().MxcDiplomatVersion_value(value.get(), ')}
  return text;
}`;
  }

  if (operation.call.kind.startsWith('discover')) {
    const getter = operation.call.kind === 'discoverBackends'
      ? 'MxcDiplomatDiscovery_available_backends_json'
      : 'MxcDiplomatDiscovery_platform_support_json';
    return `NativeOutcome Call${name}(const NativeArguments&) {
  NativeApi& api = NativeApi::Instance();
  NativeOutcome failure{};
  if (!api.EnsureLoaded(&failure)) return failure;
  const MxcDiplomat_discover_result response = api.functions().${operation.call.symbol}();
  if (!response.is_ok) return SerializeMxcError(response.err);
  NativeHandle<MxcDiplomatDiscovery> value(
      response.ok, api.functions().MxcDiplomatDiscovery_destroy);
${capture('text', `api.functions().${getter}(value.get(), `)}
  return text;
}`;
  }

  if (operation.call.kind === 'stateAware') {
    return `NativeOutcome Call${name}(const NativeArguments& arguments) {
  NativeApi& api = NativeApi::Instance();
  NativeOutcome failure{};
  if (!api.EnsureLoaded(&failure)) return failure;
  const DiplomatStringView request{arguments.request.data(), arguments.request.size()};
  const MxcDiplomat_${operation.id}_result response = api.functions().${operation.call.symbol}(
      request, arguments.dry_run, arguments.experimental);
  if (!response.is_ok) return SerializeMxcError(response.err);
  NativeHandle<MxcDiplomatStateAwareEnvelope> value(
      response.ok, api.functions().MxcDiplomatStateAwareEnvelope_destroy);
${capture('text', 'api.functions().MxcDiplomatStateAwareEnvelope_response_json(value.get(), ')}
  return text;
}`;
  }

  if (operation.call.kind === 'execAttached') {
    return `NativeOutcome Call${name}(const NativeArguments& arguments) {
  NativeApi& api = NativeApi::Instance();
  NativeOutcome failure{};
  if (!api.EnsureLoaded(&failure)) return failure;
  const DiplomatStringView request{arguments.request.data(), arguments.request.size()};
  const MxcDiplomat_exec_attached_result response = api.functions().${operation.call.symbol}(
      request, arguments.experimental);
  if (!response.is_ok) return SerializeMxcError(response.err);
  return {true, "{\\\"timedOut\\\":" + std::string(response.ok.timed_out ? "true" : "false") +
      ",\\\"exitCode\\\":" + std::to_string(response.ok.exit_code) + "}", {}};
}`;
  }

  return `NativeOutcome Call${name}(const NativeArguments& arguments) {
  NativeApi& api = NativeApi::Instance();
  NativeOutcome failure{};
  if (!api.EnsureLoaded(&failure)) return failure;
  const DiplomatStringView request{arguments.request.data(), arguments.request.size()};
  const MxcDiplomat_run_result response = api.functions().${operation.call.symbol}(request);
  if (!response.is_ok) return SerializeMxcError(response.err);
  NativeHandle<MxcDiplomatRunResult> value(
      response.ok, api.functions().MxcDiplomatRunResult_destroy);
${capture('stdout_text', 'api.functions().MxcDiplomatRunResult_stdout(value.get(), ')}
${capture('stderr_text', 'api.functions().MxcDiplomatRunResult_stderr(value.get(), ')}
${capture('warnings_json', 'api.functions().MxcDiplomatRunResult_warnings_json(value.get(), ')}
  std::string output = "{\\\"exitCode\\\":" +
      std::to_string(api.functions().MxcDiplomatRunResult_exit_code(value.get())) +
      ",\\\"timedOut\\\":" +
      (api.functions().MxcDiplomatRunResult_timed_out(value.get()) ? "true" : "false") +
      ",\\\"stdout\\\":" + JsonString(stdout_text.value) +
      ",\\\"stderr\\\":" + JsonString(stderr_text.value) +
      ",\\\"warnings\\\":" + warnings_json.value;
  if (api.functions().MxcDiplomatRunResult_has_output_metadata(value.get())) {
${capture('output_metadata_json', 'api.functions().MxcDiplomatRunResult_output_metadata_json(value.get(), ')}
    output += ",\\\"outputMetadata\\\":" + output_metadata_json.value;
  }
  output += "}";
  return {true, std::move(output), {}};
}`;
}

function callback(operation, asynchronous) {
  const name = cppName(asynchronous ? operation.js.async : operation.js.sync);
  const input = operation.argument === 'json'
    ? `  NativeArguments arguments;
  if (!SerializeJsonArgument(env, info, &arguments.request)) return nullptr;
`
    : operation.argument === 'stateAware' || operation.argument === 'execAttached'
      ? `  NativeArguments arguments;
  if (!SerializeStateAwareArguments(env, info, ${operation.argument === 'stateAware' ? 'true' : 'false'}, &arguments)) return nullptr;
`
      : '  const NativeArguments arguments;\n';
  return `napi_value ${name}Callback(napi_env env, napi_callback_info info) {
${input}  return ${asynchronous ? 'InvokeAsync' : 'InvokeSync'}(
      env, ${cppName(operation.id)}Operation${asynchronous ? ', std::move(arguments)' : ', arguments'});
}`;
}

const operations = description.operations.flatMap((operation) => [
  nativeCall(operation),
  `const GeneratedOperation ${cppName(operation.id)}Operation{
    "${operation.js.sync}", Call${cppName(operation.id)},
    ${operation.result === 'string' ? 'ConvertString' : 'ConvertJson'}, ConvertMxcError,
};`,
  callback(operation, false),
  ...(operation.js.async ? [callback(operation, true)] : []),
]).join('\n\n');
const properties = description.operations.flatMap((operation) => [
  `    {"${operation.js.sync}", nullptr, ${cppName(operation.js.sync)}Callback, nullptr, nullptr, nullptr, napi_default, nullptr},`,
  ...(operation.js.async ? [`    {"${operation.js.async}", nullptr, ${cppName(operation.js.async)}Callback, nullptr, nullptr, nullptr, napi_default, nullptr},`] : []),
]).join('\n');

writeGenerated('native/generated/operations.cc', `${banner}#include "operations.h"
#include "../runtime.h"

#include <string>
#include <utility>

namespace mxc_node {
namespace {

std::string JsonString(const std::string& value) {
  std::string quoted = "\\\"";
  constexpr char kHex[] = "0123456789abcdef";
  for (const unsigned char ch : value) {
    switch (ch) {
      case '"': quoted += "\\\\\\\""; break;
      case '\\\\': quoted += "\\\\\\\\"; break;
      case '\\b': quoted += "\\\\b"; break;
      case '\\f': quoted += "\\\\f"; break;
      case '\\n': quoted += "\\\\n"; break;
      case '\\r': quoted += "\\\\r"; break;
      case '\\t': quoted += "\\\\t"; break;
      default:
        if (ch < 0x20) {
          quoted += "\\\\u00";
          quoted += kHex[(ch >> 4) & 0x0f];
          quoted += kHex[ch & 0x0f];
        } else {
          quoted += static_cast<char>(ch);
        }
    }
  }
  quoted += '"';
  return quoted;
}

napi_value CreateString(napi_env env, const std::string& value) {
  napi_value result = nullptr;
  return napi_create_string_utf8(env, value.data(), value.size(), &result) == napi_ok ? result : nullptr;
}

bool TryParseJson(napi_env env, const std::string& text, napi_value* result) {
  napi_value global = nullptr, json = nullptr, parse = nullptr, source = nullptr;
  return napi_get_global(env, &global) == napi_ok &&
      napi_get_named_property(env, global, "JSON", &json) == napi_ok &&
      napi_get_named_property(env, json, "parse", &parse) == napi_ok &&
      napi_create_string_utf8(env, text.data(), text.size(), &source) == napi_ok &&
      napi_call_function(env, json, parse, 1, &source, result) == napi_ok;
}

void ClearPendingException(napi_env env) {
  bool pending = false;
  if (napi_is_exception_pending(env, &pending) == napi_ok && pending) {
    napi_value ignored = nullptr;
    napi_get_and_clear_last_exception(env, &ignored);
  }
}

bool InvalidArgument(napi_env env, const char* message) {
  ClearPendingException(env);
  napi_throw_type_error(env, nullptr, message);
  return false;
}

napi_value ConvertString(napi_env env, const std::string& value) { return CreateString(env, value); }

napi_value ConvertJson(napi_env env, const std::string& value) {
  napi_value parsed = nullptr;
  if (TryParseJson(env, value, &parsed)) return parsed;
  ClearPendingException(env);
  napi_throw_type_error(env, nullptr, "mxc_ffi returned malformed JSON");
  return nullptr;
}

const char* ErrorCodeName(MxcDiplomatErrorCode code) {
  switch (code) {
${errorCodeCases}
  }
  return "backend_error";
}

napi_value ConvertMxcError(napi_env env, const std::string& error_json) {
  napi_value parsed = nullptr;
  if (!TryParseJson(env, error_json, &parsed)) {
    ClearPendingException(env);
    napi_value error = nullptr;
    napi_create_error(env, nullptr, CreateString(env, "mxc_ffi returned malformed error JSON"), &error);
    return error;
  }
  napi_value message = nullptr;
  if (napi_get_named_property(env, parsed, "message", &message) != napi_ok) {
    message = CreateString(env, "mxc_ffi returned an error without a message");
  }
  napi_value error = nullptr;
  if (napi_create_error(env, nullptr, message, &error) != napi_ok) return nullptr;
  napi_set_named_property(env, error, "name", CreateString(env, "MxcError"));
  for (const char* field : {"code", "operation", "nativeCode", "remediation"}) {
    bool has = false;
    if (napi_has_named_property(env, parsed, field, &has) == napi_ok && has) {
      napi_value field_value = nullptr;
      if (napi_get_named_property(env, parsed, field, &field_value) == napi_ok) {
        napi_set_named_property(env, error, field, field_value);
      }
    }
  }
  return error;
}

NativeOutcome SerializeMxcError(MxcDiplomatError* raw) {
  NativeApi& api = NativeApi::Instance();
  if (raw == nullptr) return NativeApi::Failure("mxc_ffi returned a null error handle");
  NativeHandle<MxcDiplomatError> error(raw, api.functions().MxcDiplomatError_destroy);
${capture('message', 'api.functions().MxcDiplomatError_message(error.get(), ')}
  std::string output = "{\\\"code\\\":" +
      JsonString(ErrorCodeName(api.functions().MxcDiplomatError_code(error.get()))) +
      ",\\\"message\\\":" + JsonString(message.value);
  if (api.functions().MxcDiplomatError_has_operation(error.get())) {
${capture('operation', 'api.functions().MxcDiplomatError_operation(error.get(), ')}
    output += ",\\\"operation\\\":" + JsonString(operation.value);
  }
  if (api.functions().MxcDiplomatError_has_native_code(error.get())) {
${capture('native_code', 'api.functions().MxcDiplomatError_native_code(error.get(), ')}
    output += ",\\\"nativeCode\\\":" + JsonString(native_code.value);
  }
  if (api.functions().MxcDiplomatError_has_remediation(error.get())) {
${capture('remediation', 'api.functions().MxcDiplomatError_remediation(error.get(), ')}
    output += ",\\\"remediation\\\":" + JsonString(remediation.value);
  }
  output += "}";
  return {false, {}, std::move(output)};
}

bool SerializeJsonArgument(napi_env env, napi_callback_info info, std::string* output) {
  size_t argc = 1;
  napi_value input = nullptr;
  if (napi_get_cb_info(env, info, &argc, &input, nullptr, nullptr) != napi_ok || argc != 1) {
    return InvalidArgument(env, "Expected one JSON request argument");
  }
  napi_valuetype type = napi_undefined;
  if (napi_typeof(env, input, &type) != napi_ok) {
    return InvalidArgument(env, "Could not inspect the JSON request argument");
  }
  napi_value serialized = input;
  if (type != napi_string) {
    napi_value global = nullptr, json = nullptr, stringify = nullptr;
    if (napi_get_global(env, &global) != napi_ok ||
        napi_get_named_property(env, global, "JSON", &json) != napi_ok ||
        napi_get_named_property(env, json, "stringify", &stringify) != napi_ok ||
        napi_call_function(env, json, stringify, 1, &input, &serialized) != napi_ok) {
      return InvalidArgument(env, "Request must be JSON-serializable");
    }
  }
  size_t length = 0;
  if (napi_get_value_string_utf8(env, serialized, nullptr, 0, &length) != napi_ok) {
    return InvalidArgument(env, "Request must serialize to a JSON string");
  }
  output->resize(length + 1);
  if (napi_get_value_string_utf8(env, serialized, &(*output)[0], length + 1, &length) != napi_ok) {
    return InvalidArgument(env, "Request must serialize to a JSON string");
  }
  output->resize(length);
  return true;
}

bool SerializeStateAwareArguments(
    napi_env env, napi_callback_info info, bool has_dry_run, NativeArguments* output) {
  size_t argc = has_dry_run ? 3 : 2;
  napi_value values[3] = {nullptr, nullptr, nullptr};
  if (napi_get_cb_info(env, info, &argc, values, nullptr, nullptr) != napi_ok ||
      argc != (has_dry_run ? 3 : 2)) {
    return InvalidArgument(env, "Expected request JSON and state-aware flags");
  }
  size_t length = 0;
  if (napi_get_value_string_utf8(env, values[0], nullptr, 0, &length) != napi_ok) {
    return InvalidArgument(env, "State-aware request must be a JSON string");
  }
  output->request.resize(length + 1);
  if (napi_get_value_string_utf8(env, values[0], &output->request[0], length + 1, &length) != napi_ok) {
    return InvalidArgument(env, "State-aware request must be a JSON string");
  }
  output->request.resize(length);
  size_t flag = has_dry_run ? 1 : 0;
  if (has_dry_run && napi_get_value_bool(env, values[1], &output->dry_run) != napi_ok) {
    return InvalidArgument(env, "dryRun must be a boolean");
  }
  if (napi_get_value_bool(env, values[flag + 1], &output->experimental) != napi_ok) {
    return InvalidArgument(env, "experimental must be a boolean");
  }
  return true;
}

${operations}

}  // namespace

napi_value InitGeneratedOperations(napi_env env, napi_value exports) {
  const napi_property_descriptor properties[] = {
${properties}
  };
  return napi_define_properties(env, exports, sizeof(properties) / sizeof(properties[0]), properties) == napi_ok
      ? exports : nullptr;
}

}  // namespace mxc_node
`);

const interfaceEntries = description.operations.flatMap((operation) => [
  `  ${operation.js.sync}(${operation.argument === 'json' ? 'requestJson: string' : operation.argument === 'stateAware' ? 'requestJson: string, dryRun: boolean, experimental: boolean' : operation.argument === 'execAttached' ? 'requestJson: string, experimental: boolean' : ''}): unknown;`,
  ...(operation.js.async ? [`  ${operation.js.async}(${operation.argument === 'json' ? 'requestJson: string' : operation.argument === 'stateAware' ? 'requestJson: string, dryRun: boolean, experimental: boolean' : 'requestJson: string, experimental: boolean'}): Promise<unknown>;`] : []),
]).join('\n');
function tsArguments(operation) {
  if (operation.argument === 'json') return { declaration: 'request: RunSandboxRequest', call: 'serializeRequest(request)' };
  if (operation.argument === 'stateAware') return {
    declaration: 'request: StateAwareRequest, options: StateAwareOptions = {}',
    call: 'serializeRequest(request), options.dryRun ?? false, options.experimental ?? false',
  };
  if (operation.argument === 'execAttached') return {
    declaration: 'request: StateAwareRequest, options: ExecAttachedOptions = {}',
    call: 'serializeRequest(request), options.experimental ?? false',
  };
  return { declaration: '', call: '' };
}
const syncFunctions = description.operations.map((operation) => `/**
 * ${operation.js.documentation}
 */
export function ${operation.js.sync}(${tsArguments(operation).declaration}): ${resultTypes[operation.result]} {
  try {
    return ${typeConverters[operation.result]}(native().${operation.js.sync}(${tsArguments(operation).call}));
  } catch (error) {
    throwMxcError(error);
  }
}`);
const asyncFunctions = description.operations.filter((operation) => operation.js.async).map((operation) => `/**
 * ${operation.js.documentation} The C ABI call runs on a Node-API worker.
 */
export async function ${operation.js.async}(${tsArguments(operation).declaration}): Promise<${resultTypes[operation.result]}> {
  try {
    return ${typeConverters[operation.result]}(await native().${operation.js.async}(${tsArguments(operation).call}));
  } catch (error) {
    throwMxcError(error);
  }
}`);

writeGenerated('src/generated/api.ts', `${banner}import { MxcError, type MxcErrorFields } from '../errors.js';
import { loadAddon } from '../runtime.js';
import type { AvailableBackend, ExecAttachedOptions, NativePlatformSupport, RunSandboxRequest, RunSandboxResult,
  StateAwareEnvelope, StateAwareOptions, StateAwareRequest, WaitResult } from '../types.js';

interface NativeAddon {
${interfaceEntries}
}
function native(): NativeAddon { return loadAddon() as NativeAddon; }
function isRecord(value: unknown): value is Record<string, unknown> {
  return value !== null && typeof value === 'object' && !Array.isArray(value);
}
function expectString(value: unknown): string {
  if (typeof value !== 'string') throw new TypeError('mxc_ffi returned a non-string value');
  return value;
}
function expectJson(value: unknown): StateAwareEnvelope {
  return value as StateAwareEnvelope;
}
function expectWaitResult(value: unknown): WaitResult {
  if (!isRecord(value) || typeof value.timedOut !== 'boolean' || typeof value.exitCode !== 'number') {
    throw new TypeError('mxc_ffi returned malformed wait result data');
  }
  return { timedOut: value.timedOut, exitCode: value.exitCode };
}
function expectAvailableBackends(value: unknown): readonly AvailableBackend[] {
  if (!Array.isArray(value) || !value.every((item) => isRecord(item) && typeof item.backend === 'string')) {
    throw new TypeError('mxc_ffi returned malformed available-backends discovery data');
  }
  return value as AvailableBackend[];
}
function expectPlatformSupport(value: unknown): NativePlatformSupport {
  if (!isRecord(value) || typeof value.isSupported !== 'boolean' ||
      (typeof value.reason !== 'string' && value.reason !== null) ||
      !Array.isArray(value.availableMethods) || !value.availableMethods.every((method) => typeof method === 'string')) {
    throw new TypeError('mxc_ffi returned malformed platform-support discovery data');
  }
  return value as NativePlatformSupport;
}
function expectRunSandboxResult(value: unknown): RunSandboxResult {
  if (!isRecord(value) || typeof value.exitCode !== 'number' || typeof value.timedOut !== 'boolean' ||
      typeof value.stdout !== 'string' || typeof value.stderr !== 'string' || !Array.isArray(value.warnings) ||
      !value.warnings.every((warning) => typeof warning === 'string')) {
    throw new TypeError('mxc_ffi returned malformed run result data');
  }
  return { exitCode: value.exitCode, timedOut: value.timedOut, stdout: value.stdout, stderr: value.stderr,
    warnings: value.warnings, ...(value.outputMetadata === undefined ? {} : { outputMetadata: value.outputMetadata }) };
}
function serializeRequest(request: RunSandboxRequest): string {
  return typeof request === 'string' ? request : JSON.stringify(request);
}
function throwMxcError(error: unknown): never {
  if (isRecord(error) && typeof error.code === 'string' && typeof error.message === 'string') {
    const fields: MxcErrorFields = { code: error.code, message: error.message,
      ...(typeof error.operation === 'string' ? { operation: error.operation } : {}),
      ...(typeof error.nativeCode === 'string' ? { nativeCode: error.nativeCode } : {}),
      ...(typeof error.remediation === 'string' ? { remediation: error.remediation } : {}) };
    throw new MxcError(fields);
  }
  throw error;
}

${syncFunctions.join('\n\n')}

${asyncFunctions.join('\n\n')}
`);
