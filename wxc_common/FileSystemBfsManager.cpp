#include "pch.h"

#include "include/FileSystemBfsManager.h"

#include "include/Logger.h"
#include "include/ProcessUtilities.h"

bool FileSystemBfsManager::Configure(ContainerPolicy policy, std::wstring& errorMsg)
{
    if (policy.readwritePaths.empty() && policy.readonlyPaths.empty())
    {
        _logger << L"No BFS paths to configure.\n";
        return true; // Nothing to configure
    }

    // Configure BFS for allowed paths
    for (const auto& path : policy.readwritePaths)
    {
        bool inherit = TestForRootPath(path);
        if (!AddBfsPath(path, errorMsg, inherit))
        {
            RemoveConfiguration();
            return false;
        }
        else
        {
            _configured = true;
        }
    }

    // Configure BFS for allowed read-only paths
    for (const auto& path : policy.readonlyPaths)
    {
        bool inherit = TestForRootPath(path);
        if (!AddReadOnlyBfsPath(path, errorMsg, inherit))
        {
            RemoveConfiguration();
            return false;
        }
        else
        {
            _configured = true;
        }
    }

    return true;
}

bool FileSystemBfsManager::RemoveConfiguration()
{
    if (_configured)
    {
        std::wstring errorMsg;
        if (RemoveConfiguration(errorMsg))
        {
            _configured = false;
        }
    }

    return !_configured;
}

// private methods

// Helper to execute bfscfg with given args and handle common error checking/logging
bool FileSystemBfsManager::ExecuteBfsCfgOperation(std::span<std::wstring_view> args,
                                                  std::wstring_view operationDescription, std::wstring& errorMsg)
{
    constexpr static std::wstring_view check = L"Unable to perform policy operation";

    std::wstring output = RunBfsCfg(args, errorMsg);
    if (output.find(check) != std::wstring::npos)
    {
        errorMsg = operationDescription;
        return false;
    }

    if (!output.empty())
    {
        _logger << L"Output from bfscfg.exe:\n" << output << L"\n";
    }

    return true;
}

bool FileSystemBfsManager::AddBfsPath(std::wstring_view path, std::wstring& errorMsg, bool inherit)
{
    std::vector<std::wstring_view> args = {
        L"--addpolicy", L"--policybroker", 
        L"--filename", path, L"--appid", _appContainerName
    };
    if (inherit)
    {
        args.push_back(L"--containerinherit");
    }
    return ExecuteBfsCfgOperation(
        args, L"Failed to add BFS path " + std::wstring{path} + L" for AppContainer " + _appContainerName, errorMsg);
}

bool FileSystemBfsManager::AddReadOnlyBfsPath(std::wstring_view path, std::wstring& errorMsg, bool inherit)
{
    std::vector<std::wstring_view> args = {
        L"--addpolicy", L"--policybrokerreadonly", 
        L"--filename", path, L"--appid",     _appContainerName
    };
    if (inherit)
    {
        args.push_back(L"--containerinherit");
    }
    return ExecuteBfsCfgOperation(
        args, L"Failed to add read-only BFS path " + std::wstring{path} + L" for AppContainer " + _appContainerName,
        errorMsg);
}

bool FileSystemBfsManager::TestForRootPath(std::wstring_view path)
{
    // Test to see if the path is "C:\", if so DO NOT inherit
    return (path == L"C:\\") ? false: true;
}

bool FileSystemBfsManager::RemoveConfiguration(std::wstring& errorMsg)
{
    std::vector<std::wstring_view> args = {L"--clearpolicy", L"--appid", _appContainerName};
    return ExecuteBfsCfgOperation(args, L"Failed to remove BFS configuration for AppContainer " + _appContainerName,
                                  errorMsg);
}

std::wstring FileSystemBfsManager::RunBfsCfg(std::span<std::wstring_view> args, std::wstring& errorMsg)
{
    constexpr static std::wstring_view BfsCfgExe = L"bfscfg.exe";
    constexpr DWORD BfsCfgTimeoutMs = 10000;

    // Create pipes for stdout/stderr
    WXC::UniqueHandle hStdInRead, hStdInWrite, hStdOutRead, hStdOutWrite, hStdErrRead, hStdErrWrite;
    if (!CreateStdPipes(hStdInRead, hStdInWrite, false, errorMsg) ||
        !CreateStdPipes(hStdOutRead, hStdOutWrite, true, errorMsg) ||
        !CreateStdPipes(hStdErrRead, hStdErrWrite, true, errorMsg))
    {
        std::wstring logMsg = L"Failed to create pipes for bfscfg.exe: " + errorMsg;
        _logger << logMsg << L"\n";
        return logMsg;
    }

    STARTUPINFO si = {};
    si.cb = sizeof(STARTUPINFO);
    si.dwFlags = STARTF_USESTDHANDLES;
    si.hStdInput = ::GetStdHandle(STD_INPUT_HANDLE);
    si.hStdOutput = hStdOutWrite.get();
    si.hStdError = hStdErrWrite.get();

    PROCESS_INFORMATION pi = {};

    // Create std::wstring command line from args, quoting any that contain spaces
    std::wstring commandLine{BfsCfgExe};
    for (const auto& arg : args)
    {
        commandLine += L" ";
        if (arg.find(L' ') != std::wstring_view::npos)
        {
            commandLine += L"\"";
            commandLine += arg;
            commandLine += L"\"";
        }
        else
        {
            commandLine += arg;
        }
    }

    std::vector<wchar_t> commandLineBuffer(commandLine.begin(), commandLine.end());
    commandLineBuffer.push_back(L'\0'); // Null-terminate

    BOOL created = ::CreateProcessW(nullptr, commandLineBuffer.data(), nullptr, nullptr, TRUE, CREATE_NO_WINDOW,
                                    nullptr, nullptr, &si, &pi);

    // Close handles that child inherited (we don't need them in parent)
    hStdInRead.reset();
    hStdOutWrite.reset();
    hStdErrWrite.reset();

    if (!created)
    {
        DWORD error = ::GetLastError();
        _logger << L"Failed to create process for bfscfg.exe: " << error << L"\n";
        return L"";
    }

    _logger << L"bfscfg process created successfully (PID: " << pi.dwProcessId << L")\n";

    // Wrap process handles in RAII
    WXC::UniqueHandle hProcess(pi.hProcess);
    WXC::UniqueHandle hThread(pi.hThread);

    // Read output and wait for process completion
    std::wstring stdOut = WXC::ReadFromPipe(hStdOutRead.get());
    std::wstring stdErr = WXC::ReadFromPipe(hStdErrRead.get());

    ::WaitForSingleObject(hProcess.get(), BfsCfgTimeoutMs);

    DWORD exitCode = 0;
    ::GetExitCodeProcess(hProcess.get(), &exitCode);

    if (exitCode != 0)
    {
        _logger << L"bfscfg.exe exited with code " << exitCode << L"\n";
        _logger << L"bfscfg.exe stderr output:\n" << stdErr << L"\n";
        return stdOut + L"\n" + stdErr;
    }

    return stdOut;
}
