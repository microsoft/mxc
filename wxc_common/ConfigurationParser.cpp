#include "pch.h"

#include <filesystem>
#include <fstream>

#include "include/ConfigurationParser.h"
#include "include/StringUtil.h"

using json = nlohmann::json;

// Schema
// {
//   "script": "<script code>",                             // string, optional if script is provided via stdin
//   "workingDirectory": "<working directory>",             // string, optional
//   "timeout": <milliseconds>,                             // integer, optional
//   "appContainer": {                                      // object, optional
//     "name": "<container name>",      // string, optional
//     "leastPrivilege": true|false,    // boolean, optional
//     "learningMode": true|false,      // boolean, optional
//     "capabilities": [                // array of strings, optional
//     ]
//   },
//   "filesystem": {                                        // object, optional
//     "readwritePaths": [                // array of strings, optional
//     ],
//     "readonlyPaths": [                // array of strings, optional
//     ],
//     "deniedPaths": [                 // array of strings, optional
//     ],
//     "clearPolicyOnExit": true|false  // boolean, optional
//   },
//   "network": {                                           // object, optional
//     "defaultPolicy": "allow" | "block",                      // string, enum, optional
//     "enforcementMode": "capabilities" | "firewall" | "both", // string, enum, optional
//     "allowedHosts": [                                        // array of strings, optional
//     ],
//     "blockedHosts": [                                        // array of strings, optional
//     ],
//     "removeRulesOnExit": true|false                          // boolean, optional
//   }
// }
//
//
// NOTES:
//
// 1. appContainer/learningMode: true and appContainer/capabilities["permissiveLearningMode"] are equivalent.
//

namespace
{
// Helper: Parse a JSON array of strings into a vector of wide strings
void ParseStringArray(const json& section, std::string_view fieldName, std::vector<std::wstring>& outVector)
{
    if (section.contains(fieldName) && section[fieldName].is_array())
    {
        for (const auto& item : section[fieldName])
        {
            outVector.push_back(StringUtil::Utf8ToWide(item.get<std::string>()));
        }
    }
}
} // namespace

bool ParseRequest(json& config, bool isBase64, std::wstring_view requestInput, WXC::Logger& logger)
{
    namespace fs = std::filesystem;

    if (isBase64)
    {
        // Decode base64 string to JSON
        std::string jsonString = StringUtil::Base64Decode(requestInput);
        if (jsonString.empty())
        {
            logger << L"Failed to decode base64 configuration";
            return false;
        }

        // Parse JSON from decoded string
        try
        {
            config = json::parse(jsonString);
        }
        catch (const json::parse_error&)
        {
            logger << L"Error parsing JSON";
            return false;
        }
        catch (const std::exception&)
        {
            logger << L"Error parsing JSON";
            return false;
        }
    }
    else
    {
        // Load from file
        // Check file exists
        if (!fs::exists(requestInput))
        {
            logger << L"Configuration file not found: " << requestInput;
            logger << std::filesystem::current_path();
            return false;
        }

        // Read file (JSON library expects UTF-8 narrow string path)
        std::string narrowPath = StringUtil::WideToUtf8(requestInput);
        std::ifstream file(narrowPath);
        if (!file.is_open())
        {
            logger << L"Failed to open configuration file: " << requestInput;
            return false;
        }

        // Parse JSON from file
        try
        {
            file >> config;
        }
        catch (const json::parse_error&)
        {
            logger << L"JSON parse error";
            return false;
        }
        catch (const std::exception&)
        {
            logger << L"Error reading JSON";
            return false;
        }
    }

    return true;
}

bool LoadRequest(std::wstring_view requestInput, CodexRequest& codexRequest, WXC::Logger& logger, bool isBase64)
{
    json config;
    if (!ParseRequest(config, isBase64, requestInput, logger))
    {
        return false;
    }

    std::wstring codexScript;
    std::wstring workingDirectory;

    // Validate required fields
    if (!config.contains("script"))
    {
        logger << L"Missing required script execution fields";
        return false;
    }

    // Parse basic script configuration
    codexRequest.scriptCode = StringUtil::Utf8ToWide(config["script"].get<std::string>());
    if (codexRequest.scriptCode.empty())
    {
        logger << L"script cannot be empty";
        return false;
    }
    if (config.contains("workingDirectory"))
    {
        codexRequest.workingDirectory = StringUtil::Utf8ToWide(config["workingDirectory"].get<std::string>());
        if (codexRequest.workingDirectory.empty())
        {
            // TODO: Extract working directory from script if not provided
            // logger << L"workingDirectory cannot be empty";
            // return false;
        }
    }

    if (config.contains("timeout"))
    {
        codexRequest.scriptTimeout = config["timeout"].get<DWORD>();
    }

    // Parse AppContainer configuration
    if (config.contains("appContainer"))
    {
        auto& ac = config["appContainer"];

        if (ac.contains("name"))
            codexRequest.policy.appContainerName = StringUtil::Utf8ToWide(ac["name"].get<std::string>());

        if (ac.contains("leastPrivilege"))
            codexRequest.policy.leastPrivilegeMode = ac["leastPrivilege"].get<bool>();

        // Default capability if appContainer section not specified
        if (ac.contains("learningMode"))
        {
#ifdef _DEBUG
            codexRequest.policy.capabilities.push_back(L"permissiveLearningMode");
            logger << L"WARNING: 'learningMode' enabled - AppContainer restrictions will NOT be enforced (DEBUG BUILD ONLY)\n";
#else
            logger << L"SECURITY: 'learningMode' is disabled in release builds. This capability has been removed.\n";
#endif
        }

        // Add capabilities if defined
        ParseStringArray(ac, "capabilities", codexRequest.policy.capabilities);

        // SECURITY: Remove permissiveLearningMode capability in release builds
#ifndef _DEBUG
        auto& caps = codexRequest.policy.capabilities;
        auto it = std::remove_if(caps.begin(), caps.end(), [&logger](const std::wstring& cap) {
            if (cap == L"permissiveLearningMode")
            {
                logger << L"SECURITY: Removed 'permissiveLearningMode' capability (not allowed in release builds)\n";
                return true;
            }
            return false;
        });
        caps.erase(it, caps.end());
#endif
    }

    // Parse filesystem configuration
    if (config.contains("filesystem"))
    {
        auto& fs = config["filesystem"];

        ParseStringArray(fs, "deniedPaths", codexRequest.policy.deniedPaths);
        ParseStringArray(fs, "readwritePaths", codexRequest.policy.readwritePaths);
        ParseStringArray(fs, "readonlyPaths", codexRequest.policy.readonlyPaths);

        if (fs.contains("clearPolicyOnExit"))
            codexRequest.policy.clearPolicyOnExit = fs["clearPolicyOnExit"].get<bool>();
    }

    // Parse network configuration
    if (config.contains("network"))
    {
        auto& net = config["network"];

        if (net.contains("defaultPolicy"))
        {
            std::string policy = net["defaultPolicy"].get<std::string>();
            if (policy == "allow")
                codexRequest.policy.defaultNetworkPolicy = ContainerPolicy::NetworkPolicy::Allow;
            else if (policy == "block")
                codexRequest.policy.defaultNetworkPolicy = ContainerPolicy::NetworkPolicy::Block;
            else
            {
                logger << L"Invalid network.defaultPolicy value (must be 'allow' or 'block')";
                return false;
            }
        }

        if (net.contains("enforcementMode"))
        {
            std::string mode = net["enforcementMode"].get<std::string>();
            if (mode == "capabilities")
                codexRequest.policy.networkEnforcementMode = ContainerPolicy::NetworkEnforcementMode::Capabilities;
            else if (mode == "firewall")
                codexRequest.policy.networkEnforcementMode = ContainerPolicy::NetworkEnforcementMode::Firewall;
            else if (mode == "both")
                codexRequest.policy.networkEnforcementMode = ContainerPolicy::NetworkEnforcementMode::Both;
            else
            {
                logger << L"Invalid network.enforcementMode value (must be 'capabilities', 'firewall', or 'both')";
                return false;
            }
        }

        ParseStringArray(net, "allowedHosts", codexRequest.policy.allowedHosts);
        ParseStringArray(net, "blockedHosts", codexRequest.policy.blockedHosts);
        if (net.contains("removeRulesOnExit"))
            codexRequest.policy.removeFirewallRulesOnExit = net["removeRulesOnExit"].get<bool>();
    }

    return true;
}
