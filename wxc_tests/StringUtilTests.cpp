#include "pch.h"

#include <string>
#include <vector>

#include "StringUtil.h"

#include "gtest/gtest.h"

// Test fixture for StringUtil tests
class StringUtilTest : public ::testing::Test
{
protected:
    void SetUp() override
    {
        // Setup code if needed
    }

    void TearDown() override
    {
        // Cleanup code if needed
    }
};

// ============================================================================
// Base64Encode Tests
// ============================================================================

TEST_F(StringUtilTest, Base64Encode_EmptyString_ReturnsEmpty)
{
    std::string input = "";
    std::wstring result = StringUtil::Base64Encode(input);
    EXPECT_TRUE(result.empty());
}

TEST_F(StringUtilTest, Base64Encode_SimpleString_EncodesCorrectly)
{
    std::string input = "Hello World";
    std::wstring result = StringUtil::Base64Encode(input);
    EXPECT_EQ(L"SGVsbG8gV29ybGQ=", result);
}

TEST_F(StringUtilTest, Base64Encode_JsonString_EncodesCorrectly)
{
    std::string input = "{\"script\":{\"code\":\"print('test')\"}}";
    std::wstring result = StringUtil::Base64Encode(input);
    EXPECT_FALSE(result.empty());
    EXPECT_EQ(L"eyJzY3JpcHQiOnsiY29kZSI6InByaW50KCd0ZXN0JykifX0=", result);
}

TEST_F(StringUtilTest, Base64Encode_SpecialCharacters_EncodesCorrectly)
{
    std::string input = "Line1\nLine2\tTabbed";
    std::wstring result = StringUtil::Base64Encode(input);
    EXPECT_FALSE(result.empty());
    // Verify it doesn't contain newlines (NOCRLF flag)
    EXPECT_EQ(std::wstring::npos, result.find(L'\n'));
    EXPECT_EQ(std::wstring::npos, result.find(L'\r'));
}

TEST_F(StringUtilTest, Base64Encode_BinaryData_EncodesCorrectly)
{
    std::string input = std::string("\x00\x01\x02\xFF", 4);
    std::wstring result = StringUtil::Base64Encode(input);
    EXPECT_FALSE(result.empty());
    EXPECT_EQ(L"AAEC/w==", result);
}

// ============================================================================
// Base64Decode Tests
// ============================================================================

TEST_F(StringUtilTest, Base64Decode_EmptyString_ReturnsEmpty)
{
    std::wstring input = L"";
    std::string result = StringUtil::Base64Decode(input);
    EXPECT_TRUE(result.empty());
}

TEST_F(StringUtilTest, Base64Decode_ValidBase64_DecodesCorrectly)
{
    std::wstring input = L"SGVsbG8gV29ybGQ=";
    std::string result = StringUtil::Base64Decode(input);
    EXPECT_EQ("Hello World", result);
}

TEST_F(StringUtilTest, Base64Decode_JsonString_DecodesCorrectly)
{
    std::wstring input = L"eyJzY3JpcHQiOnsiY29kZSI6InByaW50KCd0ZXN0JykifX0=";
    std::string result = StringUtil::Base64Decode(input);
    EXPECT_EQ("{\"script\":{\"code\":\"print('test')\"}}", result);
}

TEST_F(StringUtilTest, Base64Decode_InvalidBase64_ReturnsEmpty)
{
    std::wstring input = L"Invalid!!!Base64";
    std::string result = StringUtil::Base64Decode(input);
    EXPECT_TRUE(result.empty());
}

TEST_F(StringUtilTest, Base64Decode_BinaryData_DecodesCorrectly)
{
    std::wstring input = L"AAEC/w==";
    std::string result = StringUtil::Base64Decode(input);
    EXPECT_EQ(4u, result.size());
    EXPECT_EQ(0x00, static_cast<unsigned char>(result[0]));
    EXPECT_EQ(0x01, static_cast<unsigned char>(result[1]));
    EXPECT_EQ(0x02, static_cast<unsigned char>(result[2]));
    EXPECT_EQ(0xFF, static_cast<unsigned char>(result[3]));
}

// ============================================================================
// Base64 Round-Trip Tests
// ============================================================================

TEST_F(StringUtilTest, Base64RoundTrip_SimpleString_PreservesData)
{
    std::string original = "Hello World";
    std::wstring encoded = StringUtil::Base64Encode(original);
    std::string decoded = StringUtil::Base64Decode(encoded);
    EXPECT_EQ(original, decoded);
}

TEST_F(StringUtilTest, Base64RoundTrip_JsonConfig_PreservesData)
{
    std::string original = "{\"script\":{\"code\":\"print('Hello')\"}}";
    std::wstring encoded = StringUtil::Base64Encode(original);
    std::string decoded = StringUtil::Base64Decode(encoded);
    EXPECT_EQ(original, decoded);
}

TEST_F(StringUtilTest, Base64RoundTrip_SpecialCharacters_PreservesData)
{
    std::string original = "Test\nWith\tSpecial \"Characters\" and 'quotes'";
    std::wstring encoded = StringUtil::Base64Encode(original);
    std::string decoded = StringUtil::Base64Decode(encoded);
    EXPECT_EQ(original, decoded);
}

TEST_F(StringUtilTest, Base64RoundTrip_EmptyString_PreservesData)
{
    std::string original = "";
    std::wstring encoded = StringUtil::Base64Encode(original);
    std::string decoded = StringUtil::Base64Decode(encoded);
    EXPECT_EQ(original, decoded);
}

TEST_F(StringUtilTest, Base64RoundTrip_LargeString_PreservesData)
{
    std::string original(10000, 'A');
    std::wstring encoded = StringUtil::Base64Encode(original);
    std::string decoded = StringUtil::Base64Decode(encoded);
    EXPECT_EQ(original, decoded);
}

// ============================================================================
// Utf8ToWide Tests
// ============================================================================

TEST_F(StringUtilTest, Utf8ToWide_EmptyString_ReturnsEmpty)
{
    const char* input = "";
    std::wstring result = StringUtil::Utf8ToWide(input);
    EXPECT_TRUE(result.empty());
}

TEST_F(StringUtilTest, Utf8ToWide_NullPointer_ReturnsEmpty)
{
    const char* input = nullptr;
    std::wstring result = StringUtil::Utf8ToWide(input);
    EXPECT_TRUE(result.empty());
}

TEST_F(StringUtilTest, Utf8ToWide_SimpleAscii_ConvertsCorrectly)
{
    const char* input = "Hello World";
    std::wstring result = StringUtil::Utf8ToWide(input);
    EXPECT_EQ(L"Hello World", result);
}

TEST_F(StringUtilTest, Utf8ToWide_WithLength_ConvertsCorrectly)
{
    const char* input = "Hello World";
    std::wstring result = StringUtil::Utf8ToWide(input, 5);
    EXPECT_EQ(L"Hello", result);
}

TEST_F(StringUtilTest, Utf8ToWide_ZeroLength_ReturnsEmpty)
{
    const char* input = "Hello World";
    std::wstring result = StringUtil::Utf8ToWide(input, 0);
    EXPECT_TRUE(result.empty());
}

TEST_F(StringUtilTest, Utf8ToWide_InvalidUtf8_ThrowsException)
{
    // Invalid UTF-8 sequence
    const char input[] = {static_cast<char>(0xFF), static_cast<char>(0xFE), 0};
    EXPECT_THROW(StringUtil::Utf8ToWide(input), std::runtime_error);
}

TEST_F(StringUtilTest, Utf8ToWide_ExtendedAscii_ConvertsCorrectly)
{
    // 2-byte UTF-8 sequence: é = C3 A9
    const char* input = "Caf\xC3\xA9"; // "Café"
    std::wstring result = StringUtil::Utf8ToWide(input);
    EXPECT_EQ(L"Caf\u00E9", result);
}

TEST_F(StringUtilTest, Utf8ToWide_ChineseCharacters_ConvertsCorrectly)
{
    // 3-byte UTF-8 sequences: 世 = E4 B8 96, 界 = E7 95 8C
    const char* input = "Hello \xE4\xB8\x96\xE7\x95\x8C"; // "Hello 世界"
    std::wstring result = StringUtil::Utf8ToWide(input);
    EXPECT_EQ(L"Hello \u4E16\u754C", result);
}

TEST_F(StringUtilTest, Utf8ToWide_Emoji_ConvertsCorrectly)
{
    // 4-byte UTF-8 sequence: 😀 = F0 9F 98 80
    const char* input = "Test \xF0\x9F\x98\x80"; // "Test 😀"
    std::wstring result = StringUtil::Utf8ToWide(input);
    EXPECT_EQ(L"Test \U0001F600", result);
}

TEST_F(StringUtilTest, Utf8ToWide_MixedCharacters_ConvertsCorrectly)
{
    // Mix of 1-byte, 2-byte, 3-byte, and 4-byte UTF-8 sequences
    const char* input = "ASCII \xC3\xA9 \xE4\xB8\xAD \xF0\x9F\x98\x80"; // "ASCII é 中 😀"
    std::wstring result = StringUtil::Utf8ToWide(input);
    EXPECT_EQ(L"ASCII \u00E9 \u4E2D \U0001F600", result);
}

TEST_F(StringUtilTest, Utf8ToWide_SpecialCharacters_ConvertsCorrectly)
{
    const char* input = "Line1\nLine2\tTabbed";
    std::wstring result = StringUtil::Utf8ToWide(input);
    EXPECT_EQ(L"Line1\nLine2\tTabbed", result);
}

TEST_F(StringUtilTest, Utf8ToWide_WithLength_MultiByteCharacter_ConvertsCorrectly)
{
    // Test with length parameter that includes complete multi-byte character
    // "Café" where é is 2 bytes (C3 A9), so "Café" = 5 bytes total
    const char* input = "Caf\xC3\xA9!!!";                   // "Café!!!"
    std::wstring result = StringUtil::Utf8ToWide(input, 5); // Only "Café"
    EXPECT_EQ(L"Caf\u00E9", result);
}

TEST_F(StringUtilTest, Utf8ToWide_WithLength_IncompleteMultiByte_ThrowsException)
{
    // Test with length that cuts in the middle of a multi-byte character
    // "Café" where é is 2 bytes (C3 A9)
    // Length of 4 would include "Caf" + first byte of é (C3), which is invalid
    const char* input = "Caf\xC3\xA9"; // "Café"
    EXPECT_THROW(StringUtil::Utf8ToWide(input, 4), std::runtime_error);
}

TEST_F(StringUtilTest, Utf8ToWide_WithLength_Emoji_ConvertsCorrectly)
{
    // Test with length parameter and 4-byte emoji
    // 😀 = F0 9F 98 80 (4 bytes)
    const char* input = "Hi \xF0\x9F\x98\x80 there";        // "Hi 😀 there"
    std::wstring result = StringUtil::Utf8ToWide(input, 7); // "Hi " (3) + emoji (4) = 7 bytes
    EXPECT_EQ(L"Hi \U0001F600", result);
}

TEST_F(StringUtilTest, Utf8ToWide_LargeStringWithUnicode_ConvertsCorrectly)
{
    // Create a large string with repeated Unicode characters
    std::string input;
    for (int i = 0; i < 1000; i++)
    {
        input += "\xE4\xB8\xAD"; // Chinese character 中 (3 bytes each)
    }
    std::wstring result = StringUtil::Utf8ToWide(input.c_str());
    EXPECT_EQ(1000u, result.length());
    // All characters should be the same
    for (wchar_t ch : result)
    {
        EXPECT_EQ(L'\u4E2D', ch);
    }
}

TEST_F(StringUtilTest, Utf8ToWide_InvalidMultiByteSequence_ThrowsException)
{
    // Start of 3-byte sequence but only 2 bytes provided
    const char input[] = {static_cast<char>(0xE4), static_cast<char>(0xB8), 0};
    EXPECT_THROW(StringUtil::Utf8ToWide(input), std::runtime_error);
}

// ============================================================================
// Utf8ToWide (std::string overload) Tests
// ============================================================================

TEST_F(StringUtilTest, Utf8ToWide_StdString_EmptyString_ReturnsEmpty)
{
    std::string input = "";
    std::wstring result = StringUtil::Utf8ToWide(input);
    EXPECT_TRUE(result.empty());
}

TEST_F(StringUtilTest, Utf8ToWide_StdString_SimpleAscii_ConvertsCorrectly)
{
    std::string input = "Hello World";
    std::wstring result = StringUtil::Utf8ToWide(input);
    EXPECT_EQ(L"Hello World", result);
}

TEST_F(StringUtilTest, Utf8ToWide_StdString_ExtendedAscii_ConvertsCorrectly)
{
    std::string input = "Caf\xC3\xA9"; // "Café"
    std::wstring result = StringUtil::Utf8ToWide(input);
    EXPECT_EQ(L"Caf\u00E9", result);
}

TEST_F(StringUtilTest, Utf8ToWide_StdString_ChineseCharacters_ConvertsCorrectly)
{
    std::string input = "Hello \xE4\xB8\x96\xE7\x95\x8C"; // "Hello 世界"
    std::wstring result = StringUtil::Utf8ToWide(input);
    EXPECT_EQ(L"Hello \u4E16\u754C", result);
}

TEST_F(StringUtilTest, Utf8ToWide_StdString_Emoji_ConvertsCorrectly)
{
    std::string input = "Test \xF0\x9F\x98\x80"; // "Test 😀"
    std::wstring result = StringUtil::Utf8ToWide(input);
    EXPECT_EQ(L"Test \U0001F600", result);
}

TEST_F(StringUtilTest, Utf8ToWide_StdString_MixedCharacters_ConvertsCorrectly)
{
    std::string input = "ASCII \xC3\xA9 \xE4\xB8\xAD \xF0\x9F\x98\x80"; // "ASCII é 中 😀"
    std::wstring result = StringUtil::Utf8ToWide(input);
    EXPECT_EQ(L"ASCII \u00E9 \u4E2D \U0001F600", result);
}

TEST_F(StringUtilTest, Utf8ToWide_StdString_InvalidUtf8_ThrowsException)
{
    // Invalid UTF-8 sequence
    std::string input;
    input += static_cast<char>(0xFF);
    input += static_cast<char>(0xFE);
    EXPECT_THROW(StringUtil::Utf8ToWide(input), std::runtime_error);
}

// ============================================================================
// WideToUtf8 Tests
// ============================================================================

TEST_F(StringUtilTest, WideToUtf8_EmptyString_ReturnsEmpty)
{
    std::wstring input = L"";
    std::string result = StringUtil::WideToUtf8(input);
    EXPECT_TRUE(result.empty());
}

TEST_F(StringUtilTest, WideToUtf8_SimpleAscii_ConvertsCorrectly)
{
    std::wstring input = L"Hello World";
    std::string result = StringUtil::WideToUtf8(input);
    EXPECT_EQ("Hello World", result);
}

TEST_F(StringUtilTest, WideToUtf8_UnicodeCharacters_ConvertsCorrectly)
{
    // Test with various Unicode characters: Japanese, emoji, Greek, etc.
    std::wstring input = L"Hello \u4E16\u754C"; // "Hello 世界" (Hello World in Chinese)
    std::string result = StringUtil::WideToUtf8(input);
    EXPECT_FALSE(result.empty());
    // The UTF-8 encoding should be: "Hello " + E4 B8 96 + E7 95 8C
    EXPECT_EQ("Hello \xE4\xB8\x96\xE7\x95\x8C", result);
}

TEST_F(StringUtilTest, WideToUtf8_Emoji_ConvertsCorrectly)
{
    std::wstring input = L"Test \U0001F600"; // "Test 😀" (grinning face emoji)
    std::string result = StringUtil::WideToUtf8(input);
    EXPECT_FALSE(result.empty());
    // The UTF-8 encoding should be: "Test " + F0 9F 98 80
    EXPECT_EQ("Test \xF0\x9F\x98\x80", result);
}

TEST_F(StringUtilTest, WideToUtf8_SpecialCharacters_ConvertsCorrectly)
{
    std::wstring input = L"Line1\nLine2\tTabbed";
    std::string result = StringUtil::WideToUtf8(input);
    EXPECT_EQ("Line1\nLine2\tTabbed", result);
}

TEST_F(StringUtilTest, WideToUtf8_ExtendedAscii_ConvertsCorrectly)
{
    // Test with characters in the extended ASCII range
    std::wstring input = L"Caf\u00E9"; // "Café"
    std::string result = StringUtil::WideToUtf8(input);
    EXPECT_EQ("Caf\xC3\xA9", result); // UTF-8 encoding of é
}

TEST_F(StringUtilTest, WideToUtf8_LargeString_ConvertsCorrectly)
{
    std::wstring input(10000, L'A');
    std::string result = StringUtil::WideToUtf8(input);
    EXPECT_EQ(10000u, result.size());
    EXPECT_EQ(std::string(10000, 'A'), result);
}

TEST_F(StringUtilTest, WideToUtf8_MixedCharacters_ConvertsCorrectly)
{
    // Mix of ASCII, extended ASCII, and multi-byte UTF-8 characters
    std::wstring input = L"ASCII \u00E9 \u4E2D \U0001F600"; // "ASCII é 中 😀"
    std::string result = StringUtil::WideToUtf8(input);
    EXPECT_FALSE(result.empty());
    // Should contain the correct UTF-8 sequences
    EXPECT_EQ("ASCII \xC3\xA9 \xE4\xB8\xAD \xF0\x9F\x98\x80", result);
}

// ============================================================================
// WideToUtf8 and Utf8ToWide Round-Trip Tests
// ============================================================================

TEST_F(StringUtilTest, WideUtf8RoundTrip_SimpleString_PreservesData)
{
    std::wstring original = L"Hello World";
    std::string utf8 = StringUtil::WideToUtf8(original);
    std::wstring result = StringUtil::Utf8ToWide(utf8.c_str());
    EXPECT_EQ(original, result);
}

TEST_F(StringUtilTest, WideUtf8RoundTrip_UnicodeCharacters_PreservesData)
{
    std::wstring original = L"Hello \u4E16\u754C"; // "Hello 世界"
    std::string utf8 = StringUtil::WideToUtf8(original);
    std::wstring result = StringUtil::Utf8ToWide(utf8.c_str());
    EXPECT_EQ(original, result);
}

TEST_F(StringUtilTest, WideUtf8RoundTrip_Emoji_PreservesData)
{
    std::wstring original = L"Test \U0001F600 \U0001F44D"; // "Test 😀 👍"
    std::string utf8 = StringUtil::WideToUtf8(original);
    std::wstring result = StringUtil::Utf8ToWide(utf8.c_str());
    EXPECT_EQ(original, result);
}

TEST_F(StringUtilTest, WideUtf8RoundTrip_SpecialCharacters_PreservesData)
{
    std::wstring original = L"Test\nWith\tSpecial \"Characters\" and 'quotes'";
    std::string utf8 = StringUtil::WideToUtf8(original);
    std::wstring result = StringUtil::Utf8ToWide(utf8.c_str());
    EXPECT_EQ(original, result);
}

TEST_F(StringUtilTest, WideUtf8RoundTrip_EmptyString_PreservesData)
{
    std::wstring original = L"";
    std::string utf8 = StringUtil::WideToUtf8(original);
    std::wstring result = StringUtil::Utf8ToWide(utf8.c_str());
    EXPECT_EQ(original, result);
}

TEST_F(StringUtilTest, WideUtf8RoundTrip_MixedCharacters_PreservesData)
{
    std::wstring original = L"ASCII \u00E9 \u4E2D \U0001F600 test";
    std::string utf8 = StringUtil::WideToUtf8(original);
    std::wstring result = StringUtil::Utf8ToWide(utf8.c_str());
    EXPECT_EQ(original, result);
}

// ============================================================================
// SidToString Tests
// ============================================================================

TEST_F(StringUtilTest, SidToString_NullSid_ReturnsDefault)
{
    PSID nullSid = nullptr;
    std::wstring result = StringUtil::SidToString(nullSid, L"DEFAULT");
    EXPECT_EQ(L"DEFAULT", result);
}

TEST_F(StringUtilTest, SidToString_NullSid_ReturnsEmptyByDefault)
{
    PSID nullSid = nullptr;
    std::wstring result = StringUtil::SidToString(nullSid);
    EXPECT_TRUE(result.empty());
}

// Note: Testing with valid SIDs requires Windows APIs and is platform-specific
// Those tests would need to create valid SID structures using AllocateAndInitializeSid

// ============================================================================
// ToBSTR Tests
// ============================================================================

TEST_F(StringUtilTest, ToBSTR_FromEmpty)
{
    BSTR result = StringUtil::ToBSTR({});
    EXPECT_TRUE(nullptr != result);
    EXPECT_EQ(0u, ::SysStringLen(result));

    ::SysFreeString(result);
}

TEST_F(StringUtilTest, ToBSTR_FromValid)
{
    BSTR result = StringUtil::ToBSTR(L"Valid");
    EXPECT_TRUE(nullptr != result);
    EXPECT_EQ(5u, ::SysStringLen(result));

    ::SysFreeString(result);
}
