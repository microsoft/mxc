#include "pch.h"

#include <filesystem>
#include <fstream>
#include <string_view>

#include "ConfigurationParser.h"
#include "Logger.h"
#include "StringUtil.h"

#include "gtest/gtest.h"

// Test fixture for ConfigurationParser tests
class ConfigurationParserTest : public ::testing::Test
{
protected:
    std::wstring testDir;
    WXC::Logger logger;

    void SetUp() override
    {
        // Create temporary configs directory
        testDir = L"C:\\temp\\WXC\\tests\\temp_configs";
        std::filesystem::create_directories(testDir);

        // Use buffer mode for logger to capture messages
        logger.SetMode(WXC::Logger::Mode::Buffer);
    }

    void TearDown() override
    {
        // Remove test_configs directory and all contents
        if (std::filesystem::exists(testDir))
        {
            std::filesystem::remove_all(testDir);
        }
    }

    // Helper: Create a test file with JSON content
    std::wstring CreateTestFile(std::string_view jsonContent, std::wstring_view filename)
    {
        std::wstring filepath = testDir + L"\\" + std::wstring{filename};
        std::string narrowPath = StringUtil::WideToUtf8(filepath);

        std::ofstream file(narrowPath);
        if (file.is_open())
        {
            file << jsonContent;
            file.close();
        }

        return filepath;
    }

    // Helper: Encode JSON string to base64
    std::wstring EncodeToBase64(std::string_view jsonContent) { return StringUtil::Base64Encode(jsonContent); }
};

// ============================================================================
// File-Based Configuration Tests
// ============================================================================

TEST_F(ConfigurationParserTest, MinimalValidConfig)
{
    std::string json = R"JSON({
    "script": "print('Hello World')"
    }
})JSON";

    std::wstring filepath = CreateTestFile(json, L"minimal.json");

    CodexRequest request;
    bool result = LoadRequest(filepath, request, logger, false);

    std::wcout << logger.GetBuffer();

    EXPECT_TRUE(result);
    EXPECT_EQ(L"print('Hello World')", request.scriptCode);
    EXPECT_EQ(0u, request.scriptTimeout); // Default timeout
}

TEST_F(ConfigurationParserTest, FileNotFound)
{
    std::wstring nonExistentPath = testDir + L"\\nonexistent.json";

    CodexRequest request;
    bool result = LoadRequest(nonExistentPath, request, logger, false);

    EXPECT_FALSE(result);
    EXPECT_FALSE(logger.GetBuffer().empty());
}

TEST_F(ConfigurationParserTest, InvalidJsonSyntax)
{
    std::string json = R"JSON({
    "script": "print('test')",
    INVALID_JSON
})JSON";

    std::wstring filepath = CreateTestFile(json, L"invalid.json");

    CodexRequest request;
    bool result = LoadRequest(filepath, request, logger, false);

    EXPECT_FALSE(result);
    EXPECT_FALSE(logger.GetBuffer().empty());
}

TEST_F(ConfigurationParserTest, MissingScriptCode)
{
    std::string json = R"JSON({
    "timeout": 5000
})JSON";

    std::wstring filepath = CreateTestFile(json, L"missing_code.json");

    CodexRequest request;
    bool result = LoadRequest(filepath, request, logger, false);

    EXPECT_FALSE(result);
    EXPECT_FALSE(logger.GetBuffer().empty());
}

TEST_F(ConfigurationParserTest, EmptyScriptCode)
{
    std::string json = R"JSON({
    "script": "",
})JSON";

    std::wstring filepath = CreateTestFile(json, L"empty_code.json");

    CodexRequest request;
    bool result = LoadRequest(filepath, request, logger, false);

    EXPECT_FALSE(result);
    EXPECT_FALSE(logger.GetBuffer().empty());
}

// ============================================================================
// Base64-Encoded Configuration Tests
// ============================================================================

TEST_F(ConfigurationParserTest, Base64MinimalConfig)
{
    std::string json = R"JSON({
    "script": "print('Base64 Test')"
})JSON";

    std::wstring base64 = EncodeToBase64(json);

    CodexRequest request;
    bool result = LoadRequest(base64, request, logger, true);

    EXPECT_TRUE(result);
    EXPECT_EQ(L"print('Base64 Test')", request.scriptCode);
}

TEST_F(ConfigurationParserTest, InvalidBase64)
{
    std::wstring invalidBase64 = L"This is not valid base64!!!@#$%";

    CodexRequest request;
    bool result = LoadRequest(invalidBase64, request, logger, true);

    EXPECT_FALSE(result);
    EXPECT_FALSE(logger.GetBuffer().empty());
}

TEST_F(ConfigurationParserTest, Base64InvalidJson)
{
    std::string invalidJson = "{ this is not valid JSON }";
    std::wstring base64 = EncodeToBase64(invalidJson);

    CodexRequest request;
    bool result = LoadRequest(base64, request, logger, true);

    EXPECT_FALSE(result);
    EXPECT_FALSE(logger.GetBuffer().empty());
}

TEST_F(ConfigurationParserTest, Base64ComplexConfig)
{
    std::string json = R"JSON({
    "script": "import sys\nprint(sys.version)",
    "timeout": 10000,
    "appContainer": {
        "name": "TestContainer",
        "capabilities": ["internetClient", "privateNetworkClientServer"]
    }
})JSON";

    std::wstring base64 = EncodeToBase64(json);

    CodexRequest request;
    bool result = LoadRequest(base64, request, logger, true);

    EXPECT_TRUE(result);
    EXPECT_EQ(L"import sys\nprint(sys.version)", request.scriptCode);
    EXPECT_EQ(10000u, request.scriptTimeout);
    EXPECT_EQ(L"TestContainer", request.policy.appContainerName);
    EXPECT_EQ(2u, request.policy.capabilities.size());
}

// ============================================================================
// Script Configuration Tests
// ============================================================================

TEST_F(ConfigurationParserTest, ScriptWithTimeout)
{
    std::string json = R"JSON({
    "script": "import sys\nprint(sys.version)",
    "timeout": 60000
    }
})JSON";

    std::wstring filepath = CreateTestFile(json, L"timeout.json");

    CodexRequest request;
    bool result = LoadRequest(filepath, request, logger, false);

    EXPECT_TRUE(result);
    EXPECT_EQ(60000u, request.scriptTimeout);
}

// ============================================================================
// AppContainer Configuration Tests
// ============================================================================

TEST_F(ConfigurationParserTest, AppContainerName)
{
    std::string json = R"JSON({
    "script": "print('test')",
    "appContainer": {
        "name": "CustomAppContainer"
    }
})JSON";

    std::wstring filepath = CreateTestFile(json, L"ac_name.json");

    CodexRequest request;
    bool result = LoadRequest(filepath, request, logger, false);

    EXPECT_TRUE(result);
    EXPECT_EQ(L"CustomAppContainer", request.policy.appContainerName);
}

TEST_F(ConfigurationParserTest, AppContainerCapabilities)
{
    std::string json = R"JSON({
    "script": "print('test')",
    "appContainer": {
        "capabilities": ["internetClient", "privateNetworkClientServer", "documentsLibrary"]
    }
})JSON";

    std::wstring filepath = CreateTestFile(json, L"ac_caps.json");

    CodexRequest request;
    bool result = LoadRequest(filepath, request, logger, false);

    EXPECT_TRUE(result);
    ASSERT_EQ(3u, request.policy.capabilities.size());
    EXPECT_EQ(L"internetClient", request.policy.capabilities[0]);
    EXPECT_EQ(L"privateNetworkClientServer", request.policy.capabilities[1]);
    EXPECT_EQ(L"documentsLibrary", request.policy.capabilities[2]);
}

TEST_F(ConfigurationParserTest, LeastPrivilegeMode)
{
    std::string json = R"JSON({
    "script": "print('test')",
    "appContainer": {
        "leastPrivilege": true
    }
})JSON";

    std::wstring filepath = CreateTestFile(json, L"ac_least.json");

    CodexRequest request;
    bool result = LoadRequest(filepath, request, logger, false);

    EXPECT_TRUE(result);
    EXPECT_TRUE(request.policy.leastPrivilegeMode);
}

// ============================================================================
// Network Configuration Tests
// ============================================================================

TEST_F(ConfigurationParserTest, NetworkDefaultPolicyAllow)
{
    std::string json = R"JSON({
    "script": "print('test')",
    "network": {
        "defaultPolicy": "allow"
    }
})JSON";

    std::wstring filepath = CreateTestFile(json, L"net_allow.json");

    CodexRequest request;
    bool result = LoadRequest(filepath, request, logger, false);

    EXPECT_TRUE(result);
    EXPECT_EQ(ContainerPolicy::NetworkPolicy::Allow, request.policy.defaultNetworkPolicy);
}

TEST_F(ConfigurationParserTest, NetworkDefaultPolicyBlock)
{
    std::string json = R"JSON({
    "script": "print('test')",
    "network": {
        "defaultPolicy": "block"
    }
})JSON";

    std::wstring filepath = CreateTestFile(json, L"net_block.json");

    CodexRequest request;
    bool result = LoadRequest(filepath, request, logger, false);

    EXPECT_TRUE(result);
    EXPECT_EQ(ContainerPolicy::NetworkPolicy::Block, request.policy.defaultNetworkPolicy);
}

TEST_F(ConfigurationParserTest, InvalidNetworkPolicy)
{
    std::string json = R"JSON({
    "script": "print('test')",
    "network": {
        "defaultPolicy": "invalidPolicy"
    }
})JSON";

    std::wstring filepath = CreateTestFile(json, L"net_invalid.json");

    CodexRequest request;
    bool result = LoadRequest(filepath, request, logger, false);

    EXPECT_FALSE(result);
    EXPECT_FALSE(logger.GetBuffer().empty());
}

TEST_F(ConfigurationParserTest, NetworkEnforcementModes)
{
    // Test capabilities mode
    std::string json1 = R"JSON({
    "script": "print('test')",
    "network": {
        "enforcementMode": "capabilities"
    }
})JSON";

    std::wstring filepath1 = CreateTestFile(json1, L"net_mode_caps.json");
    CodexRequest request1;
    bool result1 = LoadRequest(filepath1, request1, logger, false);
    EXPECT_TRUE(result1);
    EXPECT_EQ(ContainerPolicy::NetworkEnforcementMode::Capabilities, request1.policy.networkEnforcementMode);

    // Test firewall mode
    logger.ClearBuffer();
    std::string json2 = R"JSON({
    "script": "print('test')",
    "network": {
        "enforcementMode": "firewall"
    }
})JSON";

    std::wstring filepath2 = CreateTestFile(json2, L"net_mode_fw.json");
    CodexRequest request2;
    bool result2 = LoadRequest(filepath2, request2, logger, false);
    EXPECT_TRUE(result2);
    EXPECT_EQ(ContainerPolicy::NetworkEnforcementMode::Firewall, request2.policy.networkEnforcementMode);

    // Test both mode
    logger.ClearBuffer();
    std::string json3 = R"JSON({
    "script": "print('test')",
    "network": {
        "enforcementMode": "both"
    }
})JSON";

    std::wstring filepath3 = CreateTestFile(json3, L"net_mode_both.json");
    CodexRequest request3;
    bool result3 = LoadRequest(filepath3, request3, logger, false);
    EXPECT_TRUE(result3);
    EXPECT_EQ(ContainerPolicy::NetworkEnforcementMode::Both, request3.policy.networkEnforcementMode);
}

TEST_F(ConfigurationParserTest, InvalidEnforcementMode)
{
    std::string json = R"JSON({
    "script": "print('test')",
    "network": {
        "enforcementMode": "invalidMode"
    }
})JSON";

    std::wstring filepath = CreateTestFile(json, L"net_mode_invalid.json");

    CodexRequest request;
    bool result = LoadRequest(filepath, request, logger, false);

    EXPECT_FALSE(result);
    EXPECT_FALSE(logger.GetBuffer().empty());
}

TEST_F(ConfigurationParserTest, NetworkHosts)
{
    std::string json = R"JSON({
    "script": "print('test')",
    "network": {
        "allowedHosts": ["example.com", "api.trusted.com"],
        "blockedHosts": ["malicious.com", "tracker.net"]
    }
})JSON";

    std::wstring filepath = CreateTestFile(json, L"net_hosts.json");

    CodexRequest request;
    bool result = LoadRequest(filepath, request, logger, false);

    EXPECT_TRUE(result);
    ASSERT_EQ(2u, request.policy.allowedHosts.size());
    EXPECT_EQ(L"example.com", request.policy.allowedHosts[0]);
    EXPECT_EQ(L"api.trusted.com", request.policy.allowedHosts[1]);
    ASSERT_EQ(2u, request.policy.blockedHosts.size());
    EXPECT_EQ(L"malicious.com", request.policy.blockedHosts[0]);
    EXPECT_EQ(L"tracker.net", request.policy.blockedHosts[1]);
}

// ============================================================================
// Filesystem Configuration Tests
// ============================================================================

TEST_F(ConfigurationParserTest, FilesystemPaths)
{
    std::string json = R"JSON({
    "script": "print('test')",
    "filesystem": {
        "readwritePaths": ["C:\\Users\\Public", "C:\\Temp\\Data"],
        "deniedPaths": ["C:\\Windows\\System32", "C:\\Program Files"]
    }
})JSON";

    std::wstring filepath = CreateTestFile(json, L"fs_paths.json");

    CodexRequest request;
    bool result = LoadRequest(filepath, request, logger, false);

    EXPECT_TRUE(result);
    ASSERT_EQ(2u, request.policy.readwritePaths.size());
    EXPECT_EQ(L"C:\\Users\\Public", request.policy.readwritePaths[0]);
    EXPECT_EQ(L"C:\\Temp\\Data", request.policy.readwritePaths[1]);
    ASSERT_EQ(2u, request.policy.deniedPaths.size());
    EXPECT_EQ(L"C:\\Windows\\System32", request.policy.deniedPaths[0]);
    EXPECT_EQ(L"C:\\Program Files", request.policy.deniedPaths[1]);
}

TEST_F(ConfigurationParserTest, FilesystemRestoreFlag)
{
    std::string json = R"JSON({
    "script": "print('test')",
    "filesystem": {
        "clearPolicyOnExit": false
    }
})JSON";

    std::wstring filepath = CreateTestFile(json, L"fs_restore.json");

    CodexRequest request;
    bool result = LoadRequest(filepath, request, logger, false);

    EXPECT_TRUE(result);
    EXPECT_FALSE(request.policy.clearPolicyOnExit);
}

// ============================================================================
// Complex Integration Tests
// ============================================================================

TEST_F(ConfigurationParserTest, FullConfiguration)
{
    std::string json = R"JSON({
    "script": "import os\nimport sys\nprint(f'Python {sys.version}')\nprint(f'CWD: {os.getcwd()}')",
    "timeout": 45000,
    "appContainer": {
        "name": "FullTestContainer",
        "enabled": true,
        "leastPrivilege": true,
        "capabilities": ["internetClient", "privateNetworkClientServer"]
    },
    "filesystem": {
        "readwritePaths": ["C:\\Users\\Public\\Documents"],
        "readonlyPaths": ["C:\\Users\\Public\\Pictures"],
        "deniedPaths": ["C:\\Windows"],
        "restoreAclsOnExit": true
    },
    "network": {
        "defaultPolicy": "block",
        "enforcementMode": "both",
        "allowedHosts": ["api.example.com"],
        "blockedHosts": ["ads.example.com"],
        "removeRulesOnExit": true
    }
})JSON";

    std::wstring filepath = CreateTestFile(json, L"full_config.json");

    CodexRequest request;
    bool result = LoadRequest(filepath, request, logger, false);

    EXPECT_TRUE(result);

    // Verify script configuration
    EXPECT_EQ(L"import os\nimport sys\nprint(f'Python {sys.version}')\nprint(f'CWD: {os.getcwd()}')",
              request.scriptCode);
    EXPECT_EQ(45000u, request.scriptTimeout);

    // Verify AppContainer configuration
    EXPECT_EQ(L"FullTestContainer", request.policy.appContainerName);
    EXPECT_TRUE(request.policy.leastPrivilegeMode);
    ASSERT_EQ(2u, request.policy.capabilities.size());

    // Verify filesystem configuration
    ASSERT_EQ(1u, request.policy.readwritePaths.size());
    EXPECT_EQ(L"C:\\Users\\Public\\Documents", request.policy.readwritePaths[0]);
    ASSERT_EQ(1u, request.policy.readonlyPaths.size());
    EXPECT_EQ(L"C:\\Users\\Public\\Pictures", request.policy.readonlyPaths[0]);
    ASSERT_EQ(1u, request.policy.deniedPaths.size());
    EXPECT_EQ(L"C:\\Windows", request.policy.deniedPaths[0]);
    EXPECT_TRUE(request.policy.clearPolicyOnExit);

    // Verify network configuration
    EXPECT_EQ(ContainerPolicy::NetworkPolicy::Block, request.policy.defaultNetworkPolicy);
    EXPECT_EQ(ContainerPolicy::NetworkEnforcementMode::Both, request.policy.networkEnforcementMode);
    ASSERT_EQ(1u, request.policy.allowedHosts.size());
    EXPECT_EQ(L"api.example.com", request.policy.allowedHosts[0]);
    ASSERT_EQ(1u, request.policy.blockedHosts.size());
    EXPECT_EQ(L"ads.example.com", request.policy.blockedHosts[0]);
    EXPECT_TRUE(request.policy.removeFirewallRulesOnExit);
}
