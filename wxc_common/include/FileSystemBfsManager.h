#pragma once

#include <span>
#include <string_view>
#include <vector>

#include "CodexModels.h"
#include "Logger.h"

// Manages filesystem BFS configuration for an AppContainer
class FileSystemBfsManager
{
public:
    FileSystemBfsManager(std::wstring appContainerName, WXC::Logger& logger)
        : _appContainerName(std::move(appContainerName))
        , _logger(logger)
    {
    }
    ~FileSystemBfsManager() = default;

    bool Configure(ContainerPolicy policy, std::wstring& errorMsg);

    bool Configured() { return _configured; }

    bool RemoveConfiguration();

private:
    const std::wstring _appContainerName;
    WXC::Logger& _logger;
    bool _configured = false;

    bool AddBfsPath(std::wstring_view path, std::wstring& errorMsg, bool inherit = true);

    bool AddReadOnlyBfsPath(std::wstring_view path, std::wstring& errorMsg, bool inherit = true);

    bool RemoveConfiguration(std::wstring& errorMsg);

    // Helper: Execute bfscfg operation with common error checking and logging
    bool ExecuteBfsCfgOperation(std::span<std::wstring_view> args, std::wstring_view operationDescription,
                                std::wstring& errorMsg);

    // Helper: Run bfscfg.exe with arguments
    std::wstring RunBfsCfg(std::span<std::wstring_view> args, std::wstring& errorMsg);

    // Helper: Test a path to see if it is the root of a drive
    bool TestForRootPath(std::wstring_view path);
};
