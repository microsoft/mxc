// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#include <node_api.h>

#include "generated/operations.h"
#include "handles.h"

NAPI_MODULE_INIT() {
  napi_value initialized = mxc_node::InitGeneratedOperations(env, exports);
  return initialized == nullptr ? nullptr : mxc_node::InitHandleOperations(env, initialized);
}
