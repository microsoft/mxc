#pragma once

#include <string>

#include "CodexModels.h"

// Interface for building executable command lines from a script input
class ICommandBuilder
{
public:
    virtual ~ICommandBuilder() = default;

    // Builds a command line string that can be passed to a process runner.
    // Implementations should not perform any I/O or process execution.
    virtual std::wstring BuildCommand(const CodexRequest& request) = 0;
};
