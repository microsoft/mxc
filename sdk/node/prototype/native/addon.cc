// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#include <node_api.h>

#include "generated/operations.h"

NAPI_MODULE_INIT() {
  return mxc_node::InitGeneratedOperations(env, exports);
}
