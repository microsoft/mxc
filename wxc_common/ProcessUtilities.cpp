#include "pch.h"

#include "include/ProcessUtilities.h"
#include "include/StringUtil.h"

namespace WXC
{

constexpr DWORD BUFFER_SIZE = 4096;

DWORD WINAPI PipeThread(LPVOID param)
{
    PipeParams* params = static_cast<PipeParams*>(param);
    HANDLE hRead = params->hRead;
    HANDLE hWrite = params->hWrite;

    BYTE buffer[BUFFER_SIZE];
    DWORD bytesRead, bytesWritten;

    while (true)
    {
        if (!ReadFile(hRead, buffer, BUFFER_SIZE, &bytesRead, nullptr) || bytesRead == 0)
        {
            break;
        }

        if (!WriteFile(hWrite, buffer, bytesRead, &bytesWritten, nullptr) || bytesWritten != bytesRead)
        {
            break;
        }

        FlushFileBuffers(hWrite);
    }

    return 0;
}

std::wstring ReadFromPipe(HANDLE hPipe)
{
    constexpr size_t kMaxChars = 1024 * 1024; // 1M UTF-16 chars (~2 MB). Tune as needed.

    std::wstring result;
    result.reserve(BUFFER_SIZE);

    char buffer[BUFFER_SIZE];
    DWORD bytesRead = 0;

    while (::ReadFile(hPipe, buffer, sizeof(buffer), &bytesRead, nullptr) && bytesRead > 0)
    {
        std::wstring wideChunk = StringUtil::Utf8ToWide(std::string_view{buffer, static_cast<size_t>(bytesRead)});

        // Calculate how much space is left in our final 'result'
        size_t remaining = kMaxChars - result.size();
        if (remaining == 0)
            break;

        // Append and handle truncation
        if (wideChunk.length() > remaining)
        {
            result.append(wideChunk, 0, remaining);
            break; // Truncated
        }

        result.append(wideChunk);
    }

    return result;
}

bool CreateStdPipes(UniqueHandle& read, UniqueHandle& write, bool noInheritRead, std::wstring& errorMsg)
{
    SECURITY_ATTRIBUTES saAttr = {};
    saAttr.nLength = sizeof(SECURITY_ATTRIBUTES);
    saAttr.bInheritHandle = TRUE;
    saAttr.lpSecurityDescriptor = nullptr;

    HANDLE hRead = nullptr, hWrite = nullptr;
    if (::CreatePipe(&hRead, &hWrite, &saAttr, 0))
    {
        HANDLE hDup = noInheritRead ? hRead : hWrite;
        if (::SetHandleInformation(hDup, HANDLE_FLAG_INHERIT, 0))
        {
            read.reset(hRead);
            write.reset(hWrite);
            return true;
        }
    }

    errorMsg = L"Failed to create pipe";
    return false;
}

void SuppressPythonLocationError(std::wstring& stdErr)
{
    const std::wstring errorToSuppress = L"Failed to find real location of ";
    size_t pos = stdErr.find(errorToSuppress);
    if (pos != std::wstring::npos)
    {
        size_t endOfLine = stdErr.find(L'\n', pos);
        if (endOfLine != std::wstring::npos)
        {
            stdErr.erase(pos, endOfLine - pos + 1);
        }
        else
        {
            stdErr.erase(pos);
        }
    }
}

bool GetCapabilitySidFromName(PCWSTR capabilityName, UniqueLocalAlloc& capabilitySid, std::wstring& errorMsg)
{
    PSID* capabilitySids = nullptr;
    DWORD capabilitySidCount = 0;
    PSID* groupSids = nullptr;
    DWORD groupSidCount = 0;

    if (!::DeriveCapabilitySidsFromName(capabilityName, &groupSids, &groupSidCount, &capabilitySids,
                                        &capabilitySidCount))
    {
        errorMsg = std::wstring(L"DeriveCapabilitySidsFromName(") + capabilityName + L") failed";
        return false;
    }

    for (DWORD i = 0; i < groupSidCount; ++i)
    {
        ::LocalFree(groupSids[i]);
    }
    ::LocalFree(groupSids);

    if (capabilitySidCount == 0)
    {
        ::LocalFree(capabilitySids);
        errorMsg = std::wstring(L"No capability SID returned for ") + capabilityName;
        return false;
    }

    // Keep the first capability SID alive for the duration of the process creation.
    capabilitySid.reset(capabilitySids[0]);

    // Free the remaining capability SIDs and the array itself.
    for (DWORD i = 1; i < capabilitySidCount; ++i)
    {
        ::LocalFree(capabilitySids[i]);
    }
    ::LocalFree(capabilitySids);

    return true;
}

// Structure to hold pipe reading results (internal use)
struct PipeReadResult
{
    std::wstring output;
    HANDLE hPipe;
};

// Thread function to read from a pipe into a string (internal use)
static DWORD WINAPI ReadPipeThread(LPVOID param)
{
    PipeReadResult* result = static_cast<PipeReadResult*>(param);
    result->output = ReadFromPipe(result->hPipe);
    return 0;
}

bool RunProcessWithCapturedOutput(const std::wstring& executablePath, const std::wstring& commandLine, DWORD timeoutMs,
                                  CapturedOutput& output, std::wstring& errorMsg)
{
    // Create pipes for stdout/stderr
    UniqueHandle hStdInRead, hStdInWrite, hStdOutRead, hStdOutWrite, hStdErrRead, hStdErrWrite;
    if (!CreateStdPipes(hStdInRead, hStdInWrite, false, errorMsg) ||
        !CreateStdPipes(hStdOutRead, hStdOutWrite, true, errorMsg) ||
        !CreateStdPipes(hStdErrRead, hStdErrWrite, true, errorMsg))
    {
        return false;
    }

    // Setup startup info with redirected handles
    STARTUPINFOW si = {};
    si.cb = sizeof(si);
    si.dwFlags = STARTF_USESTDHANDLES;
    si.hStdOutput = hStdOutWrite.get();
    si.hStdError = hStdErrWrite.get();

    PROCESS_INFORMATION pi = {};

    // CreateProcessW requires a non-const command line buffer
    std::vector<wchar_t> cmdLineBuffer(commandLine.begin(), commandLine.end());
    cmdLineBuffer.push_back(L'\0');

    if (!::CreateProcessW(executablePath.empty() ? nullptr : executablePath.c_str(), cmdLineBuffer.data(), nullptr,
                          nullptr, TRUE, 0, nullptr, nullptr, &si, &pi))
    {
        errorMsg = L"CreateProcessW failed. Error code: " + std::to_wstring(::GetLastError());
        return false;
    }

    // Close write handles immediately after CreateProcess
    hStdInRead.reset();
    hStdOutWrite.reset();
    hStdErrWrite.reset();

    UniqueHandle processHandle(pi.hProcess);
    UniqueHandle threadHandle(pi.hThread);

    // Create threads to read stdout and stderr concurrently to avoid deadlock
    PipeReadResult stdOutResult = {L"", hStdOutRead.get()};
    PipeReadResult stdErrResult = {L"", hStdErrRead.get()};

    UniqueHandle hStdOutThread(::CreateThread(nullptr, 0, ReadPipeThread, &stdOutResult, 0, nullptr));
    UniqueHandle hStdErrThread(::CreateThread(nullptr, 0, ReadPipeThread, &stdErrResult, 0, nullptr));

    if (!hStdOutThread || !hStdErrThread)
    {
        errorMsg = L"Failed to create pipe reading threads";
        ::TerminateProcess(processHandle.get(), 1);
        return false;
    }

    // Wait for the process to complete
    DWORD waitResult = ::WaitForSingleObject(processHandle.get(), timeoutMs);

    if (waitResult == WAIT_TIMEOUT)
    {
        errorMsg = L"Process timed out";
        ::TerminateProcess(processHandle.get(), 1);
        return false;
    }

    // Wait for pipe reading threads to complete (give them a bit of extra time)
    HANDLE threads[] = {hStdOutThread.get(), hStdErrThread.get()};
    ::WaitForMultipleObjects(2, threads, TRUE, 2000);

    // Get exit code
    DWORD exitCode = 0;
    if (!::GetExitCodeProcess(processHandle.get(), &exitCode))
    {
        errorMsg = L"GetExitCodeProcess failed";
        return false;
    }

    // Populate output structure
    output.stdoutOutput = stdOutResult.output;
    output.stderrOutput = stdErrResult.output;
    output.exitCode = static_cast<int>(exitCode);

    return true;
}

} // namespace WXC
