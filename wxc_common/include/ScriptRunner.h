#pragma once

#include <cstring>
#include <exception>
#include <string>

#include "CodexModels.h"
#include "Logger.h"
#include "ScriptRequestValidator.h"
#include "StringUtil.h"

// Abstract base class that provides common Run implementation for script runners
class ScriptRunner
{
public:
    ScriptRunner(ScriptRequestValidator* validator);

    virtual ~ScriptRunner() = default;
    ScriptResponse Run(const CodexRequest& request, WXC::Logger& logger);

protected:
    virtual bool Initialize(const CodexRequest& request, std::wstring& errorMsg) = 0;

    virtual ScriptResponse RunInternal(const CodexRequest& request, WXC::Logger& logger) = 0;

    virtual std::wstring GetPrincipalId() = 0;

    static ScriptResponse CreateErrorResponse(const std::wstring& errorMessage)
    {
        ScriptResponse result;
        result.StandardOut.clear();
        result.StandardErr = errorMessage;
        result.ExitCode = -1;
        return result;
    }

    DWORD GetTimeoutMilliseconds(DWORD timeout);

private:
    ScriptRequestValidator* _validator;
};
