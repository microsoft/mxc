// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#include "runtime.h"
#include "generated/ffi-library.h"

#include <cstdlib>
#include <mutex>
#include <sstream>
#include <utility>

#if defined(_WIN32)
#include <windows.h>
#else
#include <dlfcn.h>
#endif

namespace mxc_node {
namespace {

std::once_flag g_load_once;

std::string JsonEscape(const std::string& value) {
  std::ostringstream escaped;
  for (const unsigned char ch : value) {
    switch (ch) {
      case '"': escaped << "\\\""; break;
      case '\\': escaped << "\\\\"; break;
      case '\b': escaped << "\\b"; break;
      case '\f': escaped << "\\f"; break;
      case '\n': escaped << "\\n"; break;
      case '\r': escaped << "\\r"; break;
      case '\t': escaped << "\\t"; break;
      default:
        if (ch < 0x20) {
          constexpr char kHex[] = "0123456789abcdef";
          escaped << "\\u00" << kHex[(ch >> 4) & 0x0f] << kHex[ch & 0x0f];
        } else {
          escaped << static_cast<char>(ch);
        }
    }
  }
  return escaped.str();
}

napi_value Undefined(napi_env env) {
  napi_value value = nullptr;
  napi_get_undefined(env, &value);
  return value;
}

napi_value CreateError(napi_env env, const char* message) {
  napi_value message_value = nullptr;
  napi_value error = nullptr;
  if (napi_create_string_utf8(env, message, NAPI_AUTO_LENGTH, &message_value) != napi_ok ||
      napi_create_error(env, nullptr, message_value, &error) != napi_ok) {
    return nullptr;
  }
  return error;
}

napi_value InternalError(napi_env env, const char* message) {
  napi_value error = CreateError(env, message);
  if (error != nullptr) {
    napi_throw(env, error);
  }
  return Undefined(env);
}

bool TakePendingException(napi_env env, napi_value* exception) {
  bool pending = false;
  if (napi_is_exception_pending(env, &pending) != napi_ok || !pending) {
    return false;
  }
  return napi_get_and_clear_last_exception(env, exception) == napi_ok;
}

struct AsyncCall {
  napi_async_work work = nullptr;
  napi_deferred deferred = nullptr;
  const GeneratedOperation* operation = nullptr;
  NativeArguments arguments;
  NativeOutcome outcome{false, {}, {}};
};

void ExecuteAsync(napi_env, void* data) {
  auto* call = static_cast<AsyncCall*>(data);
  call->outcome = call->operation->invoke(call->arguments);
}

void CompleteAsync(napi_env env, napi_status status, void* data) {
  auto* call = static_cast<AsyncCall*>(data);
  napi_value completion = nullptr;

  if (status != napi_ok) {
    completion = CreateError(env, "MXC native operation was cancelled");
    napi_reject_deferred(env, call->deferred, completion);
  } else {
    completion = call->outcome.succeeded
        ? call->operation->convert_success(env, call->outcome.value)
        : call->operation->convert_error(env, call->outcome.error_json);

    napi_value exception = nullptr;
    if (TakePendingException(env, &exception)) {
      napi_reject_deferred(env, call->deferred, exception);
    } else if (completion == nullptr) {
      napi_reject_deferred(
          env, call->deferred, CreateError(env, "MXC native operation returned no JavaScript value"));
    } else if (call->outcome.succeeded) {
      napi_resolve_deferred(env, call->deferred, completion);
    } else {
      napi_reject_deferred(env, call->deferred, completion);
    }
  }

  napi_delete_async_work(env, call->work);
  delete call;
}

#if defined(_WIN32)
std::wstring Utf8ToUtf16(const std::string& value) {
  const int length = MultiByteToWideChar(
      CP_UTF8, MB_ERR_INVALID_CHARS, value.data(), static_cast<int>(value.size()), nullptr, 0);
  if (length == 0) {
    return {};
  }
  std::wstring converted(static_cast<size_t>(length), L'\0');
  if (MultiByteToWideChar(
          CP_UTF8, MB_ERR_INVALID_CHARS, value.data(), static_cast<int>(value.size()),
          converted.data(), length) == 0) {
    return {};
  }
  return converted;
}
#endif

}  // namespace

NativeApi& NativeApi::Instance() {
  static NativeApi instance;
  return instance;
}

NativeOutcome NativeApi::Failure(const char* message) {
  return {
      false,
      {},
      "{\"code\":\"backend_error\",\"message\":\"" + JsonEscape(message) + "\"}",
  };
}

bool NativeApi::EnsureLoaded(NativeOutcome* failure) {
  std::call_once(g_load_once, [this] { Load(); });
  if (!loaded_) {
    *failure = Failure(load_error_.c_str());
    return false;
  }
  return true;
}

const MxcFfiFunctions& NativeApi::functions() const {
  return functions_;
}

void NativeApi::Load() {
  const char* configured = std::getenv("MXC_FFI_LIBRARY");
#if defined(_WIN32)
  const std::string library_path = configured != nullptr
      ? configured
      : std::string(kMxcFfiLibraryBaseName) + ".dll";
  const std::wstring wide_path = Utf8ToUtf16(library_path);
  if (wide_path.empty()) {
    load_error_ = "MXC_FFI_LIBRARY is not valid UTF-8";
    return;
  }
  const HMODULE library = LoadLibraryW(wide_path.c_str());
  if (library == nullptr) {
    load_error_ = "Could not load '" + library_path + "'";
    return;
  }
  library_ = library;
#else
#if defined(__APPLE__)
  const std::string default_name = "lib" + std::string(kMxcFfiLibraryBaseName) + ".dylib";
#else
  const std::string default_name = "lib" + std::string(kMxcFfiLibraryBaseName) + ".so";
#endif
  const char* library_path = configured != nullptr ? configured : default_name.c_str();
  library_ = dlopen(library_path, RTLD_NOW | RTLD_LOCAL);
  if (library_ == nullptr) {
    const char* detail = dlerror();
    load_error_ = "Could not load '" + std::string(library_path) + "': " +
        (detail != nullptr ? detail : "unknown loader error");
    return;
  }
#endif

#if defined(_WIN32)
#define MXC_FFI_SYMBOL(symbol, signature) \
  functions_.symbol = reinterpret_cast<signature>(GetProcAddress(static_cast<HMODULE>(library_), #symbol));
#else
#define MXC_FFI_SYMBOL(symbol, signature) \
  functions_.symbol = reinterpret_cast<signature>(dlsym(library_, #symbol));
#endif
#include "generated/ffi-symbols.inc"
#undef MXC_FFI_SYMBOL

#define MXC_FFI_SYMBOL(symbol, signature) \
  if (functions_.symbol == nullptr) { \
    load_error_ = "mxc_ffi is missing required symbol '" #symbol "'"; \
    return; \
  }
#include "generated/ffi-symbols.inc"
#undef MXC_FFI_SYMBOL

  // Keep the library loaded while queued Node-API work may hold its handles.
  loaded_ = true;
}

napi_value InvokeSync(
    napi_env env,
    const GeneratedOperation& operation,
    const NativeArguments& arguments) {
  const NativeOutcome outcome = operation.invoke(arguments);
  napi_value value = outcome.succeeded
      ? operation.convert_success(env, outcome.value)
      : operation.convert_error(env, outcome.error_json);

  bool pending = false;
  if (napi_is_exception_pending(env, &pending) == napi_ok && pending) {
    return nullptr;
  }
  if (value == nullptr) {
    return InternalError(env, "MXC native operation returned no JavaScript value");
  }
  if (!outcome.succeeded) {
    napi_throw(env, value);
    return nullptr;
  }
  return value;
}

napi_value InvokeAsync(
    napi_env env,
    const GeneratedOperation& operation,
    NativeArguments arguments) {
  napi_value promise = nullptr;
  napi_deferred deferred = nullptr;
  if (napi_create_promise(env, &deferred, &promise) != napi_ok) {
    return InternalError(env, "Could not create MXC native promise");
  }

  auto* call = new AsyncCall{nullptr, deferred, &operation, std::move(arguments), {false, {}, {}}};
  napi_value resource_name = nullptr;
  if (napi_create_string_utf8(env, operation.name, NAPI_AUTO_LENGTH, &resource_name) != napi_ok ||
      napi_create_async_work(
          env, nullptr, resource_name, ExecuteAsync, CompleteAsync, call, &call->work) != napi_ok) {
    delete call;
    return InternalError(env, "Could not schedule MXC native operation");
  }

  if (napi_queue_async_work(env, call->work) != napi_ok) {
    napi_delete_async_work(env, call->work);
    delete call;
    return InternalError(env, "Could not queue MXC native operation");
  }
  return promise;
}

}  // namespace mxc_node
