// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#include "handles.h"

#include "runtime.h"

#include <cstring>
#include <functional>
#include <iterator>
#include <memory>
#include <mutex>
#include <string>
#include <utility>
#include <vector>

namespace mxc_node {
namespace {

template <typename T>
struct HandleControl {
  HandleControl(T* value, void (*destroy)(T*)) : value(value), destroy(destroy) {}
  ~HandleControl() {
    if (value != nullptr) {
      destroy(value);
    }
  }

  T* value;
  void (*destroy)(T*);
  std::mutex operation;
};

template <typename T>
using SharedHandle = std::shared_ptr<HandleControl<T>>;

template <typename T>
using WrappedHandle = SharedHandle<T>*;

struct AsyncCall {
  napi_async_work work = nullptr;
  napi_deferred deferred = nullptr;
  bool succeeded = false;
  NativeOutcome outcome{false, {}, {}};
  MxcDiplomatSandbox* sandbox = nullptr;
  std::vector<uint8_t> bytes;
  std::function<void(AsyncCall&)> execute;
  std::function<napi_value(napi_env, AsyncCall&)> convert;
};

const char* ErrorCodeName(MxcDiplomatErrorCode code) {
  switch (code) {
    case MxcDiplomatErrorCode_MalformedRequest: return "malformed_request";
    case MxcDiplomatErrorCode_UnsupportedContainment: return "unsupported_containment";
    case MxcDiplomatErrorCode_UnsupportedPhase: return "unsupported_phase";
    case MxcDiplomatErrorCode_BackendUnavailable: return "backend_unavailable";
    case MxcDiplomatErrorCode_MalformedId: return "malformed_id";
    case MxcDiplomatErrorCode_StaleId: return "stale_id";
    case MxcDiplomatErrorCode_NotProvisioned: return "not_provisioned";
    case MxcDiplomatErrorCode_NotStarted: return "not_started";
    case MxcDiplomatErrorCode_AlreadyStarted: return "already_started";
    case MxcDiplomatErrorCode_AlreadyStopped: return "already_stopped";
    case MxcDiplomatErrorCode_PolicyValidation: return "policy_validation";
    case MxcDiplomatErrorCode_BackendError: return "backend_error";
    case MxcDiplomatErrorCode_Panic: return "panic";
  }
  return "backend_error";
}

std::string EscapeJson(const std::string& value) {
  std::string result;
  result.reserve(value.size() + 2);
  constexpr char kHex[] = "0123456789abcdef";
  for (const unsigned char ch : value) {
    switch (ch) {
      case '"': result += "\\\""; break;
      case '\\': result += "\\\\"; break;
      case '\b': result += "\\b"; break;
      case '\f': result += "\\f"; break;
      case '\n': result += "\\n"; break;
      case '\r': result += "\\r"; break;
      case '\t': result += "\\t"; break;
      default:
        if (ch < 0x20) {
          result += "\\u00";
          result += kHex[(ch >> 4) & 0x0f];
          result += kHex[ch & 0x0f];
        } else {
          result += static_cast<char>(ch);
        }
    }
  }
  return result;
}

NativeOutcome SerializeError(MxcDiplomatError* raw) {
  NativeApi& api = NativeApi::Instance();
  if (raw == nullptr) {
    return NativeApi::Failure("mxc_ffi returned a null error handle");
  }
  NativeHandle<MxcDiplomatError> error(raw, api.functions().MxcDiplomatError_destroy);
  NativeOutcome message = api.CaptureWrite(
      [&](DiplomatWrite* write) {
        return api.functions().MxcDiplomatError_message(error.get(), write).is_ok;
      });
  if (!message.succeeded) {
    return message;
  }
  std::string output = "{\"code\":\"" +
      std::string(ErrorCodeName(api.functions().MxcDiplomatError_code(error.get()))) +
      "\",\"message\":\"" + EscapeJson(message.value) + "\"";
  NativeOutcome field_failure{};
  auto append = [&](bool present, const char* name, auto writer) {
    if (!present) {
      return true;
    }
    NativeOutcome field = api.CaptureWrite(
        [&](DiplomatWrite* write) { return writer(error.get(), write).is_ok; });
    if (!field.succeeded) {
      field_failure = std::move(field);
      return false;
    }
    output += ",\"" + std::string(name) + "\":\"" + EscapeJson(field.value) + "\"";
    return true;
  };
  if (!append(
          api.functions().MxcDiplomatError_has_operation(error.get()), "operation",
          api.functions().MxcDiplomatError_operation) ||
      !append(
          api.functions().MxcDiplomatError_has_native_code(error.get()), "nativeCode",
          api.functions().MxcDiplomatError_native_code) ||
      !append(
          api.functions().MxcDiplomatError_has_remediation(error.get()), "remediation",
          api.functions().MxcDiplomatError_remediation)) {
    return field_failure;
  }
  output += "}";
  return {false, {}, std::move(output)};
}

napi_value String(napi_env env, const std::string& value) {
  napi_value result = nullptr;
  return napi_create_string_utf8(env, value.data(), value.size(), &result) == napi_ok
      ? result
      : nullptr;
}

napi_value Undefined(napi_env env) {
  napi_value result = nullptr;
  napi_get_undefined(env, &result);
  return result;
}

napi_value Null(napi_env env) {
  napi_value result = nullptr;
  napi_get_null(env, &result);
  return result;
}

napi_value ErrorFromOutcome(napi_env env, const NativeOutcome& outcome) {
  napi_value global = nullptr;
  napi_value json = nullptr;
  napi_value parse = nullptr;
  napi_value source = String(env, outcome.error_json);
  napi_value parsed = nullptr;
  if (source == nullptr ||
      napi_get_global(env, &global) != napi_ok ||
      napi_get_named_property(env, global, "JSON", &json) != napi_ok ||
      napi_get_named_property(env, json, "parse", &parse) != napi_ok ||
      napi_call_function(env, json, parse, 1, &source, &parsed) != napi_ok) {
    bool pending = false;
    if (napi_is_exception_pending(env, &pending) == napi_ok && pending) {
      napi_value ignored = nullptr;
      napi_get_and_clear_last_exception(env, &ignored);
    }
    napi_value error = nullptr;
    napi_create_error(env, nullptr, String(env, "mxc_ffi returned malformed error JSON"), &error);
    return error;
  }

  napi_value message = nullptr;
  napi_value error = nullptr;
  napi_get_named_property(env, parsed, "message", &message);
  napi_create_error(env, nullptr, message, &error);
  napi_set_named_property(env, error, "name", String(env, "MxcError"));
  napi_value code = nullptr;
  if (napi_get_named_property(env, parsed, "code", &code) == napi_ok) {
    napi_set_named_property(env, error, "code", code);
  }
  for (const char* field : {"operation", "nativeCode", "remediation"}) {
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

napi_value ThrowOutcome(napi_env env, const NativeOutcome& outcome) {
  napi_throw(env, ErrorFromOutcome(env, outcome));
  return nullptr;
}

template <typename T>
void FinalizeHandle(napi_env, void* data, void*) {
  delete static_cast<WrappedHandle<T>>(data);
}

template <typename T>
bool UnwrapHandle(
    napi_env env,
    napi_callback_info info,
    size_t* argc,
    napi_value* argv,
    napi_value* self,
    SharedHandle<T>* handle) {
  if (napi_get_cb_info(env, info, argc, argv, self, nullptr) != napi_ok) {
    return false;
  }
  WrappedHandle<T> wrapped = nullptr;
  if (napi_unwrap(env, *self, reinterpret_cast<void**>(&wrapped)) != napi_ok ||
      wrapped == nullptr || !*wrapped) {
    napi_throw_error(env, nullptr, "MXC native handle has been disposed");
    return false;
  }
  *handle = *wrapped;
  return true;
}

template <typename T>
napi_value DisposeHandle(napi_env env, napi_callback_info info) {
  size_t argc = 0;
  napi_value self = nullptr;
  if (napi_get_cb_info(env, info, &argc, nullptr, &self, nullptr) != napi_ok) {
    return nullptr;
  }
  WrappedHandle<T> wrapped = nullptr;
  if (napi_unwrap(env, self, reinterpret_cast<void**>(&wrapped)) != napi_ok ||
      wrapped == nullptr) {
    return Undefined(env);
  }
  wrapped->reset();
  return Undefined(env);
}

void ExecuteAsync(napi_env, void* data) {
  auto* call = static_cast<AsyncCall*>(data);
  call->execute(*call);
}

bool TakePendingException(napi_env env, napi_value* exception) {
  bool pending = false;
  return napi_is_exception_pending(env, &pending) == napi_ok && pending &&
      napi_get_and_clear_last_exception(env, exception) == napi_ok;
}

void CompleteAsync(napi_env env, napi_status status, void* data) {
  auto* call = static_cast<AsyncCall*>(data);
  napi_value value = nullptr;
  if (status == napi_ok) {
    value = call->convert(env, *call);
  } else {
    call->succeeded = false;
    call->outcome = NativeApi::Failure("MXC native operation was cancelled");
    value = ErrorFromOutcome(env, call->outcome);
  }

  napi_value exception = nullptr;
  if (TakePendingException(env, &exception)) {
    napi_reject_deferred(env, call->deferred, exception);
  } else if (value == nullptr) {
    napi_reject_deferred(
        env, call->deferred,
        ErrorFromOutcome(
            env, NativeApi::Failure("MXC native operation returned no JavaScript value")));
  } else if (call->succeeded) {
    napi_resolve_deferred(env, call->deferred, value);
  } else {
    napi_reject_deferred(env, call->deferred, value);
  }
  napi_delete_async_work(env, call->work);
  delete call;
}

napi_value Schedule(
    napi_env env,
    const char* name,
    std::function<void(AsyncCall&)> execute,
    std::function<napi_value(napi_env, AsyncCall&)> convert) {
  napi_value promise = nullptr;
  napi_deferred deferred = nullptr;
  if (napi_create_promise(env, &deferred, &promise) != napi_ok) {
    return nullptr;
  }
  auto* call = new AsyncCall{
      nullptr, deferred, false, {false, {}, {}}, nullptr, {},
      std::move(execute), std::move(convert)};
  napi_value resource = String(env, name);
  if (resource == nullptr ||
      napi_create_async_work(
          env, nullptr, resource, ExecuteAsync, CompleteAsync, call, &call->work) != napi_ok ||
      napi_queue_async_work(env, call->work) != napi_ok) {
    if (call->work != nullptr) {
      napi_delete_async_work(env, call->work);
    }
    delete call;
    napi_throw_error(env, nullptr, "Could not schedule MXC native operation");
    return nullptr;
  }
  return promise;
}

napi_value CreateWaitResult(napi_env env, const MxcDiplomatWaitResult& result) {
  napi_value value = nullptr;
  napi_value timed_out = nullptr;
  napi_value exit_code = nullptr;
  if (napi_create_object(env, &value) != napi_ok ||
      napi_get_boolean(env, result.timed_out, &timed_out) != napi_ok ||
      napi_create_int32(env, result.exit_code, &exit_code) != napi_ok ||
      napi_set_named_property(env, value, "timedOut", timed_out) != napi_ok ||
      napi_set_named_property(env, value, "exitCode", exit_code) != napi_ok) {
    napi_throw_error(env, nullptr, "Could not create MXC wait result");
    return nullptr;
  }
  return value;
}

napi_value CreatePollResult(napi_env env, const MxcDiplomatPollResult& result) {
  napi_value value = CreateWaitResult(
      env, MxcDiplomatWaitResult{result.timed_out, result.exit_code});
  napi_value is_running = nullptr;
  if (value == nullptr ||
      napi_get_boolean(env, result.is_running, &is_running) != napi_ok ||
      napi_set_named_property(env, value, "isRunning", is_running) != napi_ok) {
    if (value != nullptr) {
      napi_throw_error(env, nullptr, "Could not create MXC poll result");
    }
    return nullptr;
  }
  return value;
}

napi_value CreateSandbox(napi_env env, MxcDiplomatSandbox* raw);
napi_value CreateInputStream(napi_env env, MxcDiplomatInputStream* raw);
napi_value CreateOutputStream(napi_env env, MxcDiplomatOutputStream* raw);

bool ReadRequest(napi_env env, napi_callback_info info, bool with_flag, NativeArguments* arguments) {
  size_t argc = with_flag ? 2 : 1;
  napi_value argv[2] = {nullptr, nullptr};
  if (napi_get_cb_info(env, info, &argc, argv, nullptr, nullptr) != napi_ok ||
      argc != (with_flag ? 2u : 1u)) {
    napi_throw_type_error(env, nullptr, "Expected serialized request and execution flags");
    return false;
  }
  size_t length = 0;
  if (napi_get_value_string_utf8(env, argv[0], nullptr, 0, &length) != napi_ok) {
    napi_throw_type_error(env, nullptr, "Request must be a JSON string");
    return false;
  }
  arguments->request.resize(length + 1);
  if (napi_get_value_string_utf8(
          env, argv[0], arguments->request.data(), length + 1, &length) != napi_ok) {
    return false;
  }
  arguments->request.resize(length);
  if (with_flag &&
      napi_get_value_bool(env, argv[1], &arguments->experimental) != napi_ok) {
    napi_throw_type_error(env, nullptr, "experimental must be a boolean");
    return false;
  }
  return true;
}

template <bool Exec>
MxcDiplomatSandbox* SpawnNative(const NativeArguments& arguments, NativeOutcome* failure) {
  NativeApi& api = NativeApi::Instance();
  if (!api.EnsureLoaded(failure)) {
    return nullptr;
  }
  const DiplomatStringView request{arguments.request.data(), arguments.request.size()};
  if constexpr (Exec) {
    const auto result = api.functions().MxcDiplomat_exec(request, arguments.experimental);
    if (!result.is_ok) {
      *failure = SerializeError(result.err);
      return nullptr;
    }
    return result.ok;
  } else {
    const auto result = api.functions().MxcDiplomat_spawn(request);
    if (!result.is_ok) {
      *failure = SerializeError(result.err);
      return nullptr;
    }
    return result.ok;
  }
}

template <bool Exec, bool Async>
napi_value SpawnCallback(napi_env env, napi_callback_info info) {
  NativeArguments arguments;
  if (!ReadRequest(env, info, Exec, &arguments)) {
    return nullptr;
  }
  if constexpr (!Async) {
    NativeOutcome failure{};
    MxcDiplomatSandbox* raw = SpawnNative<Exec>(arguments, &failure);
    return raw == nullptr ? ThrowOutcome(env, failure) : CreateSandbox(env, raw);
  }
  return Schedule(
      env,
      Exec ? "execSandbox" : "spawnSandbox",
      [arguments = std::move(arguments)](AsyncCall& call) {
        call.sandbox = SpawnNative<Exec>(arguments, &call.outcome);
        call.succeeded = call.sandbox != nullptr;
      },
      [](napi_env completion_env, AsyncCall& call) {
        return call.succeeded
            ? CreateSandbox(completion_env, std::exchange(call.sandbox, nullptr))
            : ErrorFromOutcome(completion_env, call.outcome);
      });
}

template <typename T>
napi_value Wrap(
    napi_env env,
    T* raw,
    void (*destroy)(T*),
    const napi_property_descriptor* properties,
    size_t property_count) {
  napi_value value = nullptr;
  if (napi_create_object(env, &value) != napi_ok) {
    destroy(raw);
    napi_throw_error(env, nullptr, "Could not create MXC native handle");
    return nullptr;
  }
  auto* wrapped = new SharedHandle<T>(std::make_shared<HandleControl<T>>(raw, destroy));
  if (napi_define_properties(env, value, property_count, properties) != napi_ok ||
      napi_wrap(env, value, wrapped, FinalizeHandle<T>, nullptr, nullptr) != napi_ok) {
    delete wrapped;
    napi_throw_error(env, nullptr, "Could not create MXC native handle");
    return nullptr;
  }
  return value;
}

template <typename Stream, typename Result, typename Call>
napi_value TakeStream(
    napi_env env,
    napi_callback_info info,
    Call call,
    napi_value (*create)(napi_env, Stream*)) {
  size_t argc = 0;
  napi_value self = nullptr;
  SharedHandle<MxcDiplomatSandbox> sandbox;
  if (!UnwrapHandle(env, info, &argc, nullptr, &self, &sandbox)) {
    return nullptr;
  }
  Result result = call(sandbox->value);
  if (!result.is_ok) {
    return ThrowOutcome(env, SerializeError(result.err));
  }
  return result.ok == nullptr ? Null(env) : create(env, result.ok);
}

napi_value TakeStdin(napi_env env, napi_callback_info info) {
  return TakeStream<MxcDiplomatInputStream, MxcDiplomatSandbox_take_stdin_result>(
      env, info, NativeApi::Instance().functions().MxcDiplomatSandbox_take_stdin,
      CreateInputStream);
}

napi_value TakeStdout(napi_env env, napi_callback_info info) {
  return TakeStream<MxcDiplomatOutputStream, MxcDiplomatSandbox_take_stdout_result>(
      env, info, NativeApi::Instance().functions().MxcDiplomatSandbox_take_stdout,
      CreateOutputStream);
}

napi_value TakeStderr(napi_env env, napi_callback_info info) {
  return TakeStream<MxcDiplomatOutputStream, MxcDiplomatSandbox_take_stderr_result>(
      env, info, NativeApi::Instance().functions().MxcDiplomatSandbox_take_stderr,
      CreateOutputStream);
}

napi_value TryWait(napi_env env, napi_callback_info info) {
  size_t argc = 0;
  napi_value self = nullptr;
  SharedHandle<MxcDiplomatSandbox> sandbox;
  if (!UnwrapHandle(env, info, &argc, nullptr, &self, &sandbox)) {
    return nullptr;
  }
  const auto result = NativeApi::Instance().functions().MxcDiplomatSandbox_try_wait(
      sandbox->value);
  return result.is_ok
      ? CreatePollResult(env, result.ok)
      : ThrowOutcome(env, SerializeError(result.err));
}

template <bool Async>
napi_value Wait(napi_env env, napi_callback_info info) {
  size_t argc = 0;
  napi_value self = nullptr;
  SharedHandle<MxcDiplomatSandbox> sandbox;
  if (!UnwrapHandle(env, info, &argc, nullptr, &self, &sandbox)) {
    return nullptr;
  }
  auto invoke = [sandbox](AsyncCall& call) {
    const auto result = NativeApi::Instance().functions().MxcDiplomatSandbox_wait(
        sandbox->value);
    if (result.is_ok) {
      call.succeeded = true;
      call.outcome.value.assign(
          reinterpret_cast<const char*>(&result.ok), sizeof(result.ok));
    } else {
      call.outcome = SerializeError(result.err);
    }
  };
  auto convert = [](napi_env completion_env, AsyncCall& call) {
    if (!call.succeeded) {
      return ErrorFromOutcome(completion_env, call.outcome);
    }
    MxcDiplomatWaitResult result{};
    std::memcpy(&result, call.outcome.value.data(), sizeof(result));
    return CreateWaitResult(completion_env, result);
  };
  if constexpr (Async) {
    return Schedule(env, "sandboxWait", std::move(invoke), std::move(convert));
  }
  AsyncCall call;
  invoke(call);
  return call.succeeded ? convert(env, call) : ThrowOutcome(env, call.outcome);
}

template <bool Async>
napi_value Kill(napi_env env, napi_callback_info info) {
  size_t argc = 0;
  napi_value self = nullptr;
  SharedHandle<MxcDiplomatSandbox> sandbox;
  if (!UnwrapHandle(env, info, &argc, nullptr, &self, &sandbox)) {
    return nullptr;
  }
  auto invoke = [sandbox](AsyncCall& call) {
    const auto result = NativeApi::Instance().functions().MxcDiplomatSandbox_kill(
        sandbox->value);
    call.succeeded = result.is_ok;
    if (!result.is_ok) {
      call.outcome = SerializeError(result.err);
    }
  };
  auto convert = [](napi_env completion_env, AsyncCall& call) {
    return call.succeeded
        ? Undefined(completion_env)
        : ErrorFromOutcome(completion_env, call.outcome);
  };
  if constexpr (Async) {
    return Schedule(env, "sandboxKill", std::move(invoke), std::move(convert));
  }
  AsyncCall call;
  invoke(call);
  return call.succeeded ? Undefined(env) : ThrowOutcome(env, call.outcome);
}

bool ReadBytes(
    napi_env env,
    napi_callback_info info,
    SharedHandle<MxcDiplomatInputStream>* stream,
    std::vector<uint8_t>* bytes) {
  size_t argc = 1;
  napi_value argv[1] = {nullptr};
  napi_value self = nullptr;
  if (!UnwrapHandle(env, info, &argc, argv, &self, stream) || argc != 1) {
    napi_throw_type_error(env, nullptr, "Expected one Uint8Array");
    return false;
  }
  bool is_buffer = false;
  void* data = nullptr;
  size_t length = 0;
  if (napi_is_buffer(env, argv[0], &is_buffer) != napi_ok || !is_buffer ||
      napi_get_buffer_info(env, argv[0], &data, &length) != napi_ok) {
    napi_throw_type_error(env, nullptr, "Expected a Buffer");
    return false;
  }
  const auto* begin = static_cast<const uint8_t*>(data);
  bytes->assign(begin, begin + length);
  return true;
}

template <bool Async>
napi_value Write(napi_env env, napi_callback_info info) {
  SharedHandle<MxcDiplomatInputStream> stream;
  std::vector<uint8_t> bytes;
  if (!ReadBytes(env, info, &stream, &bytes)) {
    return nullptr;
  }
  auto invoke = [stream, bytes = std::move(bytes)](AsyncCall& call) {
    std::lock_guard lock(stream->operation);
    const DiplomatU8View view{bytes.data(), bytes.size()};
    const auto result = NativeApi::Instance().functions().MxcDiplomatInputStream_write(
        stream->value, view);
    if (result.is_ok) {
      call.succeeded = true;
      call.outcome.value = std::to_string(result.ok);
    } else {
      call.outcome = SerializeError(result.err);
    }
  };
  auto convert = [](napi_env completion_env, AsyncCall& call) {
    if (!call.succeeded) {
      return ErrorFromOutcome(completion_env, call.outcome);
    }
    napi_value value = nullptr;
    napi_create_int64(completion_env, std::stoll(call.outcome.value), &value);
    return value;
  };
  if constexpr (Async) {
    return Schedule(env, "sandboxStdinWrite", std::move(invoke), std::move(convert));
  }
  AsyncCall call;
  invoke(call);
  return call.succeeded ? convert(env, call) : ThrowOutcome(env, call.outcome);
}

template <bool Async>
napi_value Flush(napi_env env, napi_callback_info info) {
  size_t argc = 0;
  napi_value self = nullptr;
  SharedHandle<MxcDiplomatInputStream> stream;
  if (!UnwrapHandle(env, info, &argc, nullptr, &self, &stream)) {
    return nullptr;
  }
  auto invoke = [stream](AsyncCall& call) {
    std::lock_guard lock(stream->operation);
    const auto result = NativeApi::Instance().functions().MxcDiplomatInputStream_flush(
        stream->value);
    call.succeeded = result.is_ok;
    if (!result.is_ok) {
      call.outcome = SerializeError(result.err);
    }
  };
  auto convert = [](napi_env completion_env, AsyncCall& call) {
    return call.succeeded
        ? Undefined(completion_env)
        : ErrorFromOutcome(completion_env, call.outcome);
  };
  if constexpr (Async) {
    return Schedule(env, "sandboxStdinFlush", std::move(invoke), std::move(convert));
  }
  AsyncCall call;
  invoke(call);
  return call.succeeded ? Undefined(env) : ThrowOutcome(env, call.outcome);
}

bool ReadSize(
    napi_env env,
    napi_callback_info info,
    SharedHandle<MxcDiplomatOutputStream>* stream,
    size_t* size) {
  size_t argc = 1;
  napi_value argv[1] = {nullptr};
  napi_value self = nullptr;
  if (!UnwrapHandle(env, info, &argc, argv, &self, stream) || argc != 1) {
    napi_throw_type_error(env, nullptr, "Expected one read size");
    return false;
  }
  uint32_t requested = 0;
  if (napi_get_value_uint32(env, argv[0], &requested) != napi_ok || requested == 0) {
    napi_throw_range_error(env, nullptr, "Read size must be a positive uint32");
    return false;
  }
  *size = requested;
  return true;
}

template <bool Async>
napi_value Read(napi_env env, napi_callback_info info) {
  SharedHandle<MxcDiplomatOutputStream> stream;
  size_t size = 0;
  if (!ReadSize(env, info, &stream, &size)) {
    return nullptr;
  }
  auto invoke = [stream, size](AsyncCall& call) {
    std::lock_guard lock(stream->operation);
    call.bytes.resize(size);
    const DiplomatU8ViewMut view{call.bytes.data(), call.bytes.size()};
    const auto result = NativeApi::Instance().functions().MxcDiplomatOutputStream_read(
        stream->value, view);
    if (result.is_ok) {
      call.succeeded = true;
      call.bytes.resize(static_cast<size_t>(result.ok));
    } else {
      call.bytes.clear();
      call.outcome = SerializeError(result.err);
    }
  };
  auto convert = [](napi_env completion_env, AsyncCall& call) {
    if (!call.succeeded) {
      return ErrorFromOutcome(completion_env, call.outcome);
    }
    napi_value value = nullptr;
    void* copied = nullptr;
    if (napi_create_buffer_copy(
            completion_env, call.bytes.size(), call.bytes.data(), &copied, &value) != napi_ok) {
      napi_throw_error(completion_env, nullptr, "Could not create MXC output buffer");
      return static_cast<napi_value>(nullptr);
    }
    return value;
  };
  if constexpr (Async) {
    return Schedule(env, "sandboxOutputRead", std::move(invoke), std::move(convert));
  }
  AsyncCall call;
  invoke(call);
  return call.succeeded ? convert(env, call) : ThrowOutcome(env, call.outcome);
}

napi_value CreateSandbox(napi_env env, MxcDiplomatSandbox* raw) {
  const napi_property_descriptor properties[] = {
      {"takeStdin", nullptr, TakeStdin, nullptr, nullptr, nullptr, napi_default, nullptr},
      {"takeStdout", nullptr, TakeStdout, nullptr, nullptr, nullptr, napi_default, nullptr},
      {"takeStderr", nullptr, TakeStderr, nullptr, nullptr, nullptr, napi_default, nullptr},
      {"tryWait", nullptr, TryWait, nullptr, nullptr, nullptr, napi_default, nullptr},
      {"waitSync", nullptr, Wait<false>, nullptr, nullptr, nullptr, napi_default, nullptr},
      {"wait", nullptr, Wait<true>, nullptr, nullptr, nullptr, napi_default, nullptr},
      {"killSync", nullptr, Kill<false>, nullptr, nullptr, nullptr, napi_default, nullptr},
      {"kill", nullptr, Kill<true>, nullptr, nullptr, nullptr, napi_default, nullptr},
      {"dispose", nullptr, DisposeHandle<MxcDiplomatSandbox>, nullptr, nullptr, nullptr,
       napi_default, nullptr},
  };
  return Wrap(
      env, raw, NativeApi::Instance().functions().MxcDiplomatSandbox_destroy,
      properties, std::size(properties));
}

napi_value CreateInputStream(napi_env env, MxcDiplomatInputStream* raw) {
  const napi_property_descriptor properties[] = {
      {"writeSync", nullptr, Write<false>, nullptr, nullptr, nullptr, napi_default, nullptr},
      {"write", nullptr, Write<true>, nullptr, nullptr, nullptr, napi_default, nullptr},
      {"flushSync", nullptr, Flush<false>, nullptr, nullptr, nullptr, napi_default, nullptr},
      {"flush", nullptr, Flush<true>, nullptr, nullptr, nullptr, napi_default, nullptr},
      {"dispose", nullptr, DisposeHandle<MxcDiplomatInputStream>, nullptr, nullptr, nullptr,
       napi_default, nullptr},
  };
  return Wrap(
      env, raw, NativeApi::Instance().functions().MxcDiplomatInputStream_destroy,
      properties, std::size(properties));
}

napi_value CreateOutputStream(napi_env env, MxcDiplomatOutputStream* raw) {
  const napi_property_descriptor properties[] = {
      {"readSync", nullptr, Read<false>, nullptr, nullptr, nullptr, napi_default, nullptr},
      {"read", nullptr, Read<true>, nullptr, nullptr, nullptr, napi_default, nullptr},
      {"dispose", nullptr, DisposeHandle<MxcDiplomatOutputStream>, nullptr, nullptr, nullptr,
       napi_default, nullptr},
  };
  return Wrap(
      env, raw, NativeApi::Instance().functions().MxcDiplomatOutputStream_destroy,
      properties, std::size(properties));
}

}  // namespace

napi_value InitHandleOperations(napi_env env, napi_value exports) {
  const napi_property_descriptor properties[] = {
      {"spawnSandboxSync", nullptr, SpawnCallback<false, false>, nullptr, nullptr, nullptr,
       napi_default, nullptr},
      {"spawnSandbox", nullptr, SpawnCallback<false, true>, nullptr, nullptr, nullptr,
       napi_default, nullptr},
      {"execSandboxSync", nullptr, SpawnCallback<true, false>, nullptr, nullptr, nullptr,
       napi_default, nullptr},
      {"execSandbox", nullptr, SpawnCallback<true, true>, nullptr, nullptr, nullptr,
       napi_default, nullptr},
  };
  return napi_define_properties(env, exports, std::size(properties), properties) == napi_ok
      ? exports
      : nullptr;
}

}  // namespace mxc_node
