#include <windows.h>

#include <sddl.h>
#include <userenv.h>

#include <algorithm>
#include <iostream>
#include <memory>
#include <stdexcept>
#include <string>
#include <utility>
#include <vector>

#include "AppContainerScriptRunner.h"
#include "ConfigurationParser.h"
#include "FileSystemBfsManager.h"
#include "Logger.h"
#include "NetworkFirewallManager.h"
#include "ProcessUtilities.h"
#include "ResourceWrappers.h"
#include "StringUtil.h"

namespace
{

void PrintUsage(WXC::Logger& logger)
{
    logger << L"Usage: wxc-exec.exe [--debug] [--config] <config.json>\n";
    logger << L"  or:  wxc-exec.exe [--debug] --config-base64 <base64-encoded-json>\n";
    logger << L"  or:  wxc-exec.exe --delete --containername <containerName>\n";
    logger << L"\nOptions:\n";
    logger << L"  --debug            Enable console output (default: silent)\n";
    logger << L"  --delete           Delete a container profile and its file access policy\n";
    logger << L"  --containername    Specify container name (required with --delete)\n";
}

// Parse command line arguments and return config file path or base64 string
bool ParseCommandLine(int argc, wchar_t* argv[], std::wstring& outConfigData, bool& outIsBase64, bool& outDebugMode,
                      bool& outDeleteMode, std::wstring& outAppId, WXC::Logger& logger)
{
    // Ensure that the minimum number of arguments is provided
    if (argc < 2)
    {
        logger << L"Invalid arguments\n";
        PrintUsage(logger);
        return false;
    }

    // First, scan for --debug, --delete, and --containername flags
    outDebugMode = false;
    outDeleteMode = false;
    outAppId.clear();
    std::vector<std::wstring> remainingArgs;

    for (int i = 1; i < argc; ++i)
    {
        if (std::wstring(argv[i]) == L"--debug")
        {
            outDebugMode = true;
        }
        else if (std::wstring(argv[i]) == L"--delete")
        {
            outDeleteMode = true;
        }
        else if (std::wstring(argv[i]) == L"--containername")
        {
            if (i + 1 < argc)
            {
                outAppId = argv[i + 1];
                ++i; // Skip next argument
            }
            else
            {
                logger << L"Missing value for --containername\n";
                PrintUsage(logger);
                return false;
            }
        }
        else
        {
            remainingArgs.push_back(argv[i]);
        }
    }

    // Handle delete mode
    if (outDeleteMode)
    {
        if (outAppId.empty())
        {
            logger << L"--delete requires --containername to be specified\n";
            PrintUsage(logger);
            return false;
        }
        // Delete mode doesn't need config data
        return true;
    }

    // Parse remaining arguments for config (normal execution mode)
    if (remainingArgs.empty())
    {
        logger << L"Missing configuration file or base64 string\n";
        PrintUsage(logger);
        return false;
    }

    // Support "config.json" (single argument)
    if (remainingArgs.size() == 1)
    {
        outConfigData = remainingArgs[0];
        outIsBase64 = false;
    }
    // Support "--config config.json" or "--config-base64 <base64>"
    else if (remainingArgs.size() == 2)
    {
        if (remainingArgs[0] == L"--config")
        {
            outConfigData = remainingArgs[1];
            outIsBase64 = false;
        }
        else if (remainingArgs[0] == L"--config-base64")
        {
            outConfigData = remainingArgs[1];
            outIsBase64 = true;
        }
        else
        {
            logger << L"Invalid arguments\n";
            PrintUsage(logger);
            return false;
        }
    }
    else
    {
        logger << L"Too many arguments\n";
        PrintUsage(logger);
        return false;
    }

    return true;
}

// Log the loaded configuration information
void LogRequest(const CodexRequest& config, WXC::Logger& logger)
{
    logger << L"Configuration loaded successfully\n";
    logger << L"AppContainer: " << config.policy.appContainerName << L"\n";
    if (config.policy.leastPrivilegeMode)
    {
        logger << L" (Least Privilege Mode)";
    }

    if (std::find(config.policy.capabilities.begin(), config.policy.capabilities.end(), L"permissiveLearningMode") !=
        config.policy.capabilities.end())
    {
        logger << L" (Permissive Learning Mode)";
    }
    logger << L"\n";

    logger << L"Script timeout: " << config.scriptTimeout << L"ms\n";
}

// Display script execution results
void DisplayScriptResults(const ScriptResponse& response, WXC::Logger& logger)
{
    logger << L"\n=== Script Output ===\n";
    logger << response.StandardOut;
    if (!response.StandardErr.empty())
    {
        logger << L"\n=== Errors ===\n";
        logger << response.StandardErr;
    }
    if (!response.ErrorMessage.empty())
    {
        logger << L"\n=== Error Message ===\n";
        logger << response.ErrorMessage;
    }
    logger << L"\n=== Exit Code: " << response.ExitCode << L" ===\n";
}

// Delete an AppContainer profile and its BFS policy
bool DeleteAppContainerProfile(const std::wstring& appContainerName, WXC::Logger& logger)
{
    logger << L"Deleting AppContainer profile: " << appContainerName << L"\n";

    // First, clear the BFS policy
    std::wstring bfsErrorMsg;
    FileSystemBfsManager bfsManager(appContainerName, logger);
    if (!bfsManager.RemoveConfiguration())
    {
        logger << L"Warning: Failed to remove BFS configuration (may not exist)\n";
    }
    else
    {
        logger << L"BFS policy cleared successfully\n";
    }

    // Delete the AppContainer profile
    HRESULT hr = ::DeleteAppContainerProfile(appContainerName.c_str());
    if (FAILED(hr))
    {
        if (hr == HRESULT_FROM_WIN32(ERROR_NOT_FOUND))
        {
            logger << L"AppContainer profile not found: " << appContainerName << L"\n";
            return false;
        }
        else
        {
            wchar_t hexBuffer[32];
            swprintf_s(hexBuffer, L"0x%08X", hr);
            logger << L"Failed to delete AppContainer profile. HRESULT: " << hexBuffer << L"\n";
            return false;
        }
    }

    logger << L"AppContainer profile deleted successfully: " << appContainerName << L"\n";
    return true;
}
} // anonymous namespace

int wmain(int argc, wchar_t* argv[])
{
    // Initialize base configuration
    bool debugMode = false;
    CodexRequest request;
    ScriptResponse result;
    DWORD exitCode = 0;

    // Create temporary logger for command line parsing
    WXC::Logger tempLogger(WXC::Logger::Mode::Buffer);

    // Parse command line arguments
    std::wstring configData;
    std::wstring appId;
    bool isBase64 = false;
    bool deleteMode = false;
    if (!ParseCommandLine(argc, argv, configData, isBase64, debugMode, deleteMode, appId, tempLogger))
    {
        // Create output or flush any buffered messages to console before exiting
        std::wcerr << tempLogger.GetBuffer();
        return -1;
    }

    // Create logger based on debug flag
    // Without --debug: Buffer mode (silent execution)
    // With --debug: Console mode (verbose output)
    WXC::Logger logger(debugMode ? WXC::Logger::Mode::Console : WXC::Logger::Mode::Buffer);

    // Handle delete mode
    if (deleteMode)
    {
        bool success = DeleteAppContainerProfile(appId, logger);

        // Always output in delete mode (even without --debug)
        std::wcout << logger.GetBuffer();

        return success ? 0 : -1;
    }

    // Load request
    if (!LoadRequest(configData, request, logger, isBase64))
    {
        std::wcerr << L"Request error\n" << logger.GetBuffer() << L"\n";
        return -1;
    }

    // Initialize
    ScriptRunner* runner = new AppContainerScriptRunner();
    ScriptResponse response = runner->Run(request, logger);
    DisplayScriptResults(response, logger);
    delete (runner);

    exitCode = static_cast<DWORD>(response.ExitCode);
    std::wcout << response.StandardOut;
    std::wcerr << response.StandardErr;

    return static_cast<int>(exitCode);
}
