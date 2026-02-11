#pragma once

#include <string>
#include <string_view>

#include "CodexModels.h"
#include "Logger.h"

// Loads and parses JSON based code execution request from file or base64-encoded string
// If isBase64 is true, requestInput is treated as base64-encoded JSON
// If isBase64 is false, requestInput is treated as a file path
// Returns true on success, false on error (with errorMsg populated)
bool LoadRequest(std::wstring_view requestInput, CodexRequest& codexRequest, WXC::Logger& logger,
                 bool isBase64 = false);
