#include "pch.h"

#include <stdexcept>

#include "include/FileSystemBfsManager.h"
#include "include/NetworkFirewallManager.h"
#include "include/ResourceWrappers.h"
#include "include/ScriptRunner.h"

ScriptRunner::ScriptRunner(ScriptRequestValidator* validator)
    : _validator(validator)
{
    // Ensure validator dependency is provided
    if (_validator == nullptr)
    {
        throw std::invalid_argument("validator must not be null");
    }
}

ScriptResponse ScriptRunner::Run(const CodexRequest& request, WXC::Logger& logger)
{
    std::wstring errorMessage;

    // First validate the incoming request; on failure, return an error response.
    if (!_validator->Validate(request, errorMessage))
    {
        const std::wstring message = errorMessage.empty() ? std::wstring(L"Script validation failed.") : errorMessage;

        return CreateErrorResponse(message);
    }

    // Next, perform any runner-specific initialization.
    if (!Initialize(request, errorMessage))
    {
        const std::wstring message =
            errorMessage.empty() ? std::wstring(L"Script runner initialization failed.") : errorMessage;
        return CreateErrorResponse(message);
    }

    // Apply filesystem and network policies here if needed

    // ACL logic only works for AppContainer execution mode
    std::wstring principalId = GetPrincipalId();
    FileSystemBfsManager bfsManager(request.policy.appContainerName, logger);
    bfsManager.Configure(request.policy, errorMessage);

    NetworkFirewallManager firewallManager;
    firewallManager.ApplyFirewallRules(principalId, request.policy, logger);

    // Run the script implementation and guard against unexpected exceptions.
    ScriptResponse response;
    try
    {
        response = RunInternal(request, logger);
    }
    catch (const std::exception& ex)
    {
        response = CreateErrorResponse(StringUtil::Utf8ToWide(ex.what()));
    }
    catch (...)
    {
        response = CreateErrorResponse(std::wstring(L"Unknown script execution error."));
    }

    // Unwind filesystem and network policies here if needed
    if (firewallManager.RulesApplied() && request.policy.removeFirewallRulesOnExit)
    {
        firewallManager.RemoveFirewallRules(logger);
    }

    if (bfsManager.Configured() && request.policy.clearPolicyOnExit)
    {
        bfsManager.RemoveConfiguration();
    }

    return response;
}

DWORD ScriptRunner::GetTimeoutMilliseconds(DWORD timeout)
{
    return timeout == 0 ? INFINITE : timeout;
}
