#include <windows.h>

#include <chrono>
#include <filesystem>
#include <iostream>
#include <string_view>

#include "ProcessUtilities.h"

namespace
{
static constexpr std::wstring_view redText = L"\x1b[31m";
static constexpr std::wstring_view greenText = L"\x1b[32m";
static constexpr std::wstring_view resetText = L"\x1b[0m";

static constexpr std::wstring_view wxcExecutableName = L"wxc-exec.exe";
constexpr std::chrono::milliseconds wxcTimeout = std::chrono::seconds(10);

int RunWXC(const std::filesystem::path& configPath)
{
    // Get full path to the currently running executable
    wchar_t modulePath[MAX_PATH];
    ::GetModuleFileNameW(nullptr, modulePath, MAX_PATH);

    std::filesystem::path moduleDir = std::filesystem::path(modulePath).parent_path();
    std::filesystem::path wxcPath = moduleDir / wxcExecutableName;

    // Build command line
    std::wstring cmdLine = wxcPath.wstring() + L" " + configPath.wstring();

    // Run process and capture output
    WXC::CapturedOutput output;
    std::wstring errorMsg;
    DWORD timeoutMs = static_cast<DWORD>(wxcTimeout.count());

    if (!WXC::RunProcessWithCapturedOutput(wxcPath.wstring(), cmdLine, timeoutMs, output, errorMsg))
    {
        std::wcout << L"RunProcessWithCapturedOutput failed: " << errorMsg << std::endl;
        return -1;
    }

    // Display captured output
    if (!output.stdoutOutput.empty())
    {
        std::wcout << L"wxc-exec STDOUT:\n" << output.stdoutOutput << std::endl;
    }

    if (!output.stderrOutput.empty())
    {
        std::wcout << L"wxc-exec STDERR:\n" << output.stderrOutput << std::endl;
    }

    return output.exitCode;
}

} // anonymous namespace

int wmain(int argc, wchar_t* argv[])
{
    if (argc < 2)
    {
        std::wcerr << "Usage: WXC_Test_Driver <config_path_dir>" << std::endl;
        return 1;
    }

    const std::filesystem::path configPathDir = argv[1];

    if (!std::filesystem::exists(configPathDir) || !std::filesystem::is_directory(configPathDir))
    {
        std::wcerr << "Provided path is not a valid directory: " << configPathDir << std::endl;
        return 1;
    }

    for (const auto& entry : std::filesystem::directory_iterator(configPathDir))
    {
        if (entry.is_regular_file() && entry.path().extension() == L".json")
        {
            std::wcout << "Running wxc-exec with config: " << entry.path() << std::endl;
            int result = RunWXC(entry.path());
            if (result != 0)
            {
                std::wcout << redText << "wxc-exec failed for config: " << entry.path() << " with exit code: 0x"
                           << std::hex << result << resetText << std::endl;
            }
            else
            {
                std::wcout << greenText << "wxc-exec succeeded for config: " << entry.path() << resetText << std::endl;
            }

            std::wcout << std::endl;
        }
    }

    return 0;
}
