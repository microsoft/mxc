#pragma once

#include <string>

#include "CodexModels.h"

class ScriptRequestValidator
{
public:
    virtual ~ScriptRequestValidator() = default;

    // Returns true if valid, false otherwise; fills errorMessage on failure.
    virtual bool Validate(const CodexRequest& request, std::wstring& errorMessage) const;
};
