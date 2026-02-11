#pragma once

#include <memory>
#include <string>

#include "Logger.h"
#include "ResourceWrappers.h"
#include "ScriptRequestValidator.h"
#include "ScriptRunner.h"

// Executes scripts using an AppContainer for sandboxing
class AppContainerScriptRunner : public ScriptRunner
{
public:
    AppContainerScriptRunner();
    ~AppContainerScriptRunner() override = default;

protected:
    bool Initialize(const CodexRequest& request, std::wstring& errorMsg) override;

    ScriptResponse RunInternal(const CodexRequest& request, WXC::Logger& logger) override;

    std::wstring GetPrincipalId() override;

private:
    // Create or derive an AppContainer SID from a profile name
    // Creates the profile if it doesn't exist, otherwise derives the SID
    bool CreateAppContainerSid(const std::wstring& appContainerName, WXC::UniqueSid& outSid, std::wstring& errorMsg);

    // Logical name for the AppContainer profile used for execution.
    std::wstring _appContainerName;

    // Reference to the AppContainer SID used for execution.
    WXC::UniqueSid _appContainerSid;

    ScriptRequestValidator _validator;
};
