#include "pch.h"

#include "include/CodexModels.h"
#include "include/ScriptRequestValidator.h"

bool ScriptRequestValidator::Validate(const CodexRequest& request, std::wstring& errorMessage) const
{
    // Basic check: script content must not be empty.
    if (request.scriptCode.empty())
    {
        errorMessage = L"Script content must not be empty.";
        return false;
    }

    // Valid for current implementation.
    return true;
}
