#pragma once

#include <Windows.h>

#include <string>
#include <vector>

// Models used by the code execution environment.
struct ContainerPolicy
{
    // AppContainer settings
    std::wstring appContainerName = L"CLI";
    bool leastPrivilegeMode = false;
    std::vector<std::wstring> capabilities;

    // Filesystem policies
    std::vector<std::wstring> readwritePaths;
    std::vector<std::wstring> readonlyPaths;
    std::vector<std::wstring> deniedPaths;
    bool clearPolicyOnExit = true;

    // Network policies
    enum class NetworkPolicy
    {
        Allow,
        Block
    };
    enum class NetworkEnforcementMode
    {
        Capabilities,
        Firewall,
        Both
    };
    NetworkPolicy defaultNetworkPolicy = NetworkPolicy::Allow;
    NetworkEnforcementMode networkEnforcementMode = NetworkEnforcementMode::Capabilities;
    std::vector<std::wstring> allowedHosts;
    std::vector<std::wstring> blockedHosts;
    bool removeFirewallRulesOnExit = true;
};

struct CodexRequest
{
    std::wstring scriptCode;
    std::wstring workingDirectory;
    DWORD scriptTimeout = 0;
    ContainerPolicy policy;
};

struct ScriptResponse
{
    int ExitCode = -1;
    std::wstring StandardOut;
    std::wstring StandardErr;
    std::wstring ErrorMessage;
    bool IsSuccess() const noexcept { return ExitCode == 0; }
};
