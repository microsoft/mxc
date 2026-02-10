#pragma once

#include <Windows.h>

#include <wincrypt.h>

#include <oleauto.h>
#include <sddl.h>
#include <wtypes.h>

#include <stdexcept>
#include <string>
#include <vector>

#pragma comment(lib, "crypt32.lib")

// Simple string utility helpers used across the AgentScriptingEnvironment.
class StringUtil
{
public:
    // Convert UTF-8 encoded std::string to wide string.
    static std::wstring Utf8ToWide(std::string_view utf8String);

    // Convert UTF-8 encoded narrow C-string to wide string.
    // The input must be a null-terminated UTF-8 string (if len == -1).
    // If len is specified, exactly that many bytes are converted.
    static std::wstring Utf8ToWide(const char* inputString, int len = -1);

    // Convert wide string to UTF-8 encoded narrow string
    static std::string WideToUtf8(std::wstring_view wideString);

    // Convert a Windows SID to its string representation (e.g., "S-1-5-32-545")
    // Returns the provided defaultValue if conversion fails
    static std::wstring SidToString(PSID sid, std::wstring_view defaultValue = L"");

    // Decode a base64-encoded wide string to UTF-8 narrow string
    // Returns empty string if decoding fails
    static std::string Base64Decode(std::wstring_view base64Input);

    // Encode a UTF-8 narrow string to base64-encoded wide string
    // Returns empty string if encoding fails
    static std::wstring Base64Encode(std::string_view input);

    // Encode a wide-string as a COM BSTR
    static BSTR ToBSTR(std::wstring_view input);
};
