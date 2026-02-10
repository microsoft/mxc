#include "pch.h"

#include "include/StringUtil.h"

std::wstring StringUtil::Utf8ToWide(std::string_view utf8String)
{
    if (utf8String.empty())
    {
        return L"";
    }
    return Utf8ToWide(utf8String.data(), static_cast<int>(utf8String.length()));
}

std::wstring StringUtil::Utf8ToWide(const char* inputString, int len)
{
    // Basic validation
    if (inputString == nullptr || (len == -1 && *inputString == '\0') || len == 0)
    {
        return L"";
    }

    // 1. Calculate the required size for the wide string
    // If len is -1, it expects null-terminated and includes the null in the count.
    // If len > 0, it uses exactly that many bytes and does NOT include a null.
    int wideLen = ::MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, inputString, len, nullptr, 0);

    if (wideLen == 0)
    {
        DWORD err = GetLastError();
        if (err == ERROR_NO_UNICODE_TRANSLATION)
            throw std::runtime_error("Invalid UTF-8 sequence");
        else
            throw std::runtime_error("MultiByteToWideChar failed (length calculation)");
    }

    // 2. Allocate and convert
    std::wstring result(wideLen, L'\0');
    int out = ::MultiByteToWideChar(
        CP_UTF8,
        0, // Flags must be 0 or MB_ERR_INVALID_CHARS; MB_ERR_INVALID_CHARS already validated above
        inputString, len, &result[0], wideLen);

    if (out == 0)
    {
        throw std::runtime_error("MultiByteToWideChar failed (conversion)");
    }

    // 3. Post-processing the null terminator
    // If we used -1, Windows included the null terminator in 'wideLen'.
    // std::wstring manages its own null, so we must trim the character we just wrote.
    if (len == -1)
    {
        result.resize(wideLen - 1);
    }

    return result;
}

std::string StringUtil::WideToUtf8(std::wstring_view wideString)
{
    if (wideString.empty())
    {
        return "";
    }

    // Calculate the required size for the UTF-8 string
    int utf8Len = ::WideCharToMultiByte(CP_UTF8, 0, wideString.data(), static_cast<int>(wideString.length()), nullptr,
                                        0, nullptr, nullptr);

    if (utf8Len == 0)
    {
        throw std::runtime_error("WideCharToMultiByte failed (length calculation)");
    }

    // Allocate and convert
    std::string result(utf8Len, '\0');
    int out = ::WideCharToMultiByte(CP_UTF8, 0, wideString.data(), static_cast<int>(wideString.length()), &result[0],
                                    utf8Len, nullptr, nullptr);

    if (out == 0)
    {
        throw std::runtime_error("WideCharToMultiByte failed (conversion)");
    }

    return result;
}

std::wstring StringUtil::SidToString(PSID sid, std::wstring_view defaultValue)
{
    LPWSTR sidString = nullptr;
    if (::ConvertSidToStringSidW(sid, &sidString))
    {
        std::wstring result(sidString);
        ::LocalFree(sidString);
        return result;
    }
    return std::wstring{defaultValue};
}

std::string StringUtil::Base64Decode(std::wstring_view base64Input)
{
    if (base64Input.empty())
    {
        return "";
    }

    // First, determine the required buffer size
    DWORD binarySize = 0;
    if (!::CryptStringToBinaryW(base64Input.data(), static_cast<DWORD>(base64Input.length()), CRYPT_STRING_BASE64,
                                nullptr, &binarySize, nullptr, nullptr))
    {
        return "";
    }

    // Allocate buffer and decode
    std::vector<BYTE> binaryData(binarySize);
    if (!::CryptStringToBinaryW(base64Input.data(), static_cast<DWORD>(base64Input.length()), CRYPT_STRING_BASE64,
                                binaryData.data(), &binarySize, nullptr, nullptr))
    {
        return "";
    }

    // Convert to narrow string (assuming UTF-8 content)
    return std::string(reinterpret_cast<const char*>(binaryData.data()), binarySize);
}

std::wstring StringUtil::Base64Encode(std::string_view input)
{
    if (input.empty())
    {
        return L"";
    }

    // First, determine the required buffer size
    DWORD base64Size = 0;
    if (!::CryptBinaryToStringW(reinterpret_cast<const BYTE*>(input.data()), static_cast<DWORD>(input.size()),
                                CRYPT_STRING_BASE64 | CRYPT_STRING_NOCRLF, // No newlines in output
                                nullptr, &base64Size))
    {
        return L"";
    }

    // Allocate buffer and encode
    std::vector<wchar_t> base64Buffer(base64Size);
    if (!::CryptBinaryToStringW(reinterpret_cast<const BYTE*>(input.data()), static_cast<DWORD>(input.size()),
                                CRYPT_STRING_BASE64 | CRYPT_STRING_NOCRLF, base64Buffer.data(), &base64Size))
    {
        return L"";
    }

    // Convert to wstring
    // Note: After the call, base64Size contains the actual string length (without null terminator)
    return std::wstring(base64Buffer.data(), base64Size);
}

BSTR StringUtil::ToBSTR(std::wstring_view input)
{
    if (input.length() > static_cast<size_t>((std::numeric_limits<UINT>::max)()))
    {
        std::terminate();
    }

    return ::SysAllocStringLen(input.data(), static_cast<UINT>(input.length()));
}
