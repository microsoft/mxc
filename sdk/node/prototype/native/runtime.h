// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#pragma once

#include <node_api.h>

#include <string>
#include <utility>

#include <MxcDiplomat.h>
#include <MxcDiplomatDiscovery.h>
#include <MxcDiplomatError.h>
#include <MxcDiplomatRunResult.h>
#include <MxcDiplomatStateAwareEnvelope.h>
#include <MxcDiplomatVersion.h>
#include <MxcDiplomatWaitResult.h>

namespace mxc_node {

using DiplomatBufferWriteCreate = DiplomatWrite* (*)(size_t);
using DiplomatBufferWriteGetBytes = char* (*)(DiplomatWrite*);
using DiplomatBufferWriteLen = size_t (*)(DiplomatWrite*);
using DiplomatBufferWriteDestroy = void (*)(DiplomatWrite*);
using MxcDiplomatVersionCall = MxcDiplomat_version_result (*)();
using MxcDiplomatDiscoverCall = MxcDiplomat_discover_result (*)();
using MxcDiplomatRunCall = MxcDiplomat_run_result (*)(DiplomatStringView);
using MxcDiplomatProvisionCall = MxcDiplomat_provision_result (*)(DiplomatStringView, bool, bool);
using MxcDiplomatStartCall = MxcDiplomat_start_result (*)(DiplomatStringView, bool, bool);
using MxcDiplomatStopCall = MxcDiplomat_stop_result (*)(DiplomatStringView, bool, bool);
using MxcDiplomatDeprovisionCall = MxcDiplomat_deprovision_result (*)(DiplomatStringView, bool, bool);
using MxcDiplomatExecAttachedCall = MxcDiplomat_exec_attached_result (*)(DiplomatStringView, bool);
using MxcDiplomatVersionValue = MxcDiplomatVersion_value_result (*)(
    const MxcDiplomatVersion*, DiplomatWrite*);
using MxcDiplomatVersionDestroy = void (*)(MxcDiplomatVersion*);
using MxcDiplomatDiscoveryAvailableBackendsJson =
    MxcDiplomatDiscovery_available_backends_json_result (*)(
        const MxcDiplomatDiscovery*, DiplomatWrite*);
using MxcDiplomatDiscoveryPlatformSupportJson =
    MxcDiplomatDiscovery_platform_support_json_result (*)(
        const MxcDiplomatDiscovery*, DiplomatWrite*);
using MxcDiplomatDiscoveryDestroy = void (*)(MxcDiplomatDiscovery*);
using MxcDiplomatRunResultExitCode = int32_t (*)(const MxcDiplomatRunResult*);
using MxcDiplomatRunResultTimedOut = bool (*)(const MxcDiplomatRunResult*);
using MxcDiplomatRunResultStdout = MxcDiplomatRunResult_stdout_result (*)(
    const MxcDiplomatRunResult*, DiplomatWrite*);
using MxcDiplomatRunResultStderr = MxcDiplomatRunResult_stderr_result (*)(
    const MxcDiplomatRunResult*, DiplomatWrite*);
using MxcDiplomatRunResultHasOutputMetadata = bool (*)(const MxcDiplomatRunResult*);
using MxcDiplomatRunResultOutputMetadataJson =
    MxcDiplomatRunResult_output_metadata_json_result (*)(
        const MxcDiplomatRunResult*, DiplomatWrite*);
using MxcDiplomatRunResultWarningsJson =
    MxcDiplomatRunResult_warnings_json_result (*)(
        const MxcDiplomatRunResult*, DiplomatWrite*);
using MxcDiplomatRunResultDestroy = void (*)(MxcDiplomatRunResult*);
using MxcDiplomatErrorCodeGetter = MxcDiplomatErrorCode (*)(const MxcDiplomatError*);
using MxcDiplomatErrorMessage = MxcDiplomatError_message_result (*)(
    const MxcDiplomatError*, DiplomatWrite*);
using MxcDiplomatErrorHasOperation = bool (*)(const MxcDiplomatError*);
using MxcDiplomatErrorOperation = MxcDiplomatError_operation_result (*)(
    const MxcDiplomatError*, DiplomatWrite*);
using MxcDiplomatErrorHasNativeCode = bool (*)(const MxcDiplomatError*);
using MxcDiplomatErrorNativeCode = MxcDiplomatError_native_code_result (*)(
    const MxcDiplomatError*, DiplomatWrite*);
using MxcDiplomatErrorHasRemediation = bool (*)(const MxcDiplomatError*);
using MxcDiplomatErrorRemediation = MxcDiplomatError_remediation_result (*)(
    const MxcDiplomatError*, DiplomatWrite*);
using MxcDiplomatErrorDestroy = void (*)(MxcDiplomatError*);
using MxcDiplomatStateAwareEnvelopeResponseJson =
    MxcDiplomatStateAwareEnvelope_response_json_result (*)(
        const MxcDiplomatStateAwareEnvelope*, DiplomatWrite*);
using MxcDiplomatStateAwareEnvelopeDestroy = void (*)(MxcDiplomatStateAwareEnvelope*);

struct NativeOutcome {
  bool succeeded;
  std::string value;
  std::string error_json;
};

struct MxcFfiFunctions {
#define MXC_FFI_SYMBOL(symbol, signature) signature symbol = nullptr;
#include "generated/ffi-symbols.inc"
#undef MXC_FFI_SYMBOL
};

template <typename T>
class NativeHandle {
 public:
  NativeHandle(T* value, void (*destroy)(T*)) : value_(value), destroy_(destroy) {}
  ~NativeHandle() {
    if (value_ != nullptr) {
      destroy_(value_);
    }
  }

  NativeHandle(const NativeHandle&) = delete;
  NativeHandle& operator=(const NativeHandle&) = delete;

  T* get() const { return value_; }

 private:
  T* value_;
  void (*destroy_)(T*);
};

class NativeApi {
 public:
  static NativeApi& Instance();

  bool EnsureLoaded(NativeOutcome* failure);
  const MxcFfiFunctions& functions() const;

  template <typename WriteCall>
  NativeOutcome CaptureWrite(WriteCall call) const {
    DiplomatWrite* writer = functions_.diplomat_buffer_write_create(256);
    if (writer == nullptr) {
      return Failure("mxc_ffi could not allocate a DiplomatWrite buffer");
    }

    const bool wrote = call(writer);
    const size_t length = functions_.diplomat_buffer_write_len(writer);
    char* bytes = functions_.diplomat_buffer_write_get_bytes(writer);
    if (bytes == nullptr && length != 0) {
      functions_.diplomat_buffer_write_destroy(writer);
      return Failure("mxc_ffi returned a DiplomatWrite buffer with null data");
    }

    std::string copied = bytes != nullptr ? std::string(bytes, length) : std::string{};
    functions_.diplomat_buffer_write_destroy(writer);
    if (!wrote) {
      return Failure("mxc_ffi failed while writing an opaque result field");
    }
    return {true, std::move(copied), {}};
  }

  static NativeOutcome Failure(const char* message);

 private:
  NativeApi() = default;
  void Load();

  MxcFfiFunctions functions_;
  void* library_ = nullptr;
  bool loaded_ = false;
  std::string load_error_;
};

struct NativeArguments {
  std::string request;
  bool dry_run = false;
  bool experimental = false;
};

using NativeInvoker = NativeOutcome (*)(const NativeArguments& arguments);
using NativeSuccessConverter = napi_value (*)(napi_env env, const std::string& value);
using NativeErrorConverter = napi_value (*)(napi_env env, const std::string& error_json);

struct GeneratedOperation {
  const char* name;
  NativeInvoker invoke;
  NativeSuccessConverter convert_success;
  NativeErrorConverter convert_error;
};

napi_value InvokeSync(
    napi_env env,
    const GeneratedOperation& operation,
    const NativeArguments& arguments);
napi_value InvokeAsync(
    napi_env env,
    const GeneratedOperation& operation,
    NativeArguments arguments);

}  // namespace mxc_node
