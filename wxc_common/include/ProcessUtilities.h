#pragma once

#include <Windows.h>

#include <userenv.h>

#include <string>

#include "ResourceWrappers.h"

namespace WXC
{

struct PipeParams
{
    HANDLE hRead;
    HANDLE hWrite;
};

static const DWORD threadBufferSize = 4096;

// Thread function to read from source and write to destination
DWORD WINAPI PipeThread(LPVOID param);

// Read all output from a pipe until EOF, converting UTF-8 to wide string
// Truncates at 1M characters to prevent unbounded memory growth
std::wstring ReadFromPipe(HANDLE hPipe);

// Create pipes with proper inheritance settings
// Read handles are not inherited, write handles are inherited by default
bool CreateStdPipes(UniqueHandle& read, UniqueHandle& write, bool noInheritRead, std::wstring& errorMsg);

// Remove benign Python location error messages from stderr
void SuppressPythonLocationError(std::wstring& stdErr);

// Derive a capability SID from a capability name (e.g., "internetClient")
// Returns the first capability SID in the output parameter
bool GetCapabilitySidFromName(PCWSTR capabilityName, UniqueLocalAlloc& capabilitySid, std::wstring& errorMsg);

// Structure to hold captured process output
struct CapturedOutput
{
    std::wstring stdoutOutput;
    std::wstring stderrOutput;
    int exitCode;
};

// Run a process and capture stdout/stderr to strings
// This is useful for test drivers and scenarios where you need to inspect process output
bool RunProcessWithCapturedOutput(const std::wstring& executablePath, const std::wstring& commandLine, DWORD timeoutMs,
                                  CapturedOutput& output, std::wstring& errorMsg);

} // namespace WXC
