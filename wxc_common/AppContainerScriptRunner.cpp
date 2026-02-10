#include "pch.h"

#include <windows.h>

#include <sddl.h>
#include <userenv.h>

#include <memory>
#include <stdexcept>
#include <string>
#include <utility>
#include <vector>

#include "include/AppContainerScriptRunner.h"
#include "include/ProcessUtilities.h"
#include "include/ResourceWrappers.h"
#include "include/StringUtil.h"

// Bring RAII wrappers and helper functions from WXC namespace into scope
using WXC::AttributeListGuard;
using WXC::CreateStdPipes;
using WXC::GetCapabilitySidFromName;
using WXC::ReadFromPipe;
using WXC::SuppressPythonLocationError;
using WXC::UniqueHandle;
using WXC::UniqueHeapAlloc;
using WXC::UniqueLocalAlloc;
using WXC::UniqueSid;

AppContainerScriptRunner::AppContainerScriptRunner()
    : ScriptRunner(&_validator)
{
}

bool AppContainerScriptRunner::Initialize(const CodexRequest& request, std::wstring& errorMsg)
{
    if (!CreateAppContainerSid(request.policy.appContainerName, _appContainerSid, errorMsg))
    {
        return false;
    }

    _appContainerName = request.policy.appContainerName;
    return true;
}

std::wstring AppContainerScriptRunner::GetPrincipalId()
{
    return StringUtil::SidToString(_appContainerSid.get());
}

ScriptResponse AppContainerScriptRunner::RunInternal(const CodexRequest& request, WXC::Logger& logger)
{
    // Load capabilities from configuration
    std::vector<UniqueLocalAlloc> capabilitySids;
    std::vector<SID_AND_ATTRIBUTES> capabilities;

    // Build list of capabilities to add (from config + auto-added for network enforcement and agentic app container)
    std::vector<std::wstring> capabilitiesToAdd = request.policy.capabilities;
    capabilitiesToAdd.push_back(L"AgenticAppContainer");

    // Automatically add internetClient capability based on enforcement mode and policy
    bool useCapabilitiesForNetwork =
        (request.policy.networkEnforcementMode == ContainerPolicy::NetworkEnforcementMode::Capabilities ||
         request.policy.networkEnforcementMode == ContainerPolicy::NetworkEnforcementMode::Both);

    if (useCapabilitiesForNetwork && request.policy.defaultNetworkPolicy == ContainerPolicy::NetworkPolicy::Allow)
    {
        // Check if internetClient is not already in the list
        bool hasInternetClient = false;
        for (const auto& cap : capabilitiesToAdd)
        {
            if (cap == L"internetClient")
            {
                hasInternetClient = true;
                break;
            }
        }

        if (!hasInternetClient)
        {
            capabilitiesToAdd.push_back(L"internetClient");
            logger << L"Auto-added 'internetClient' capability for network access (defaultPolicy: allow)\n";
        }
    }

    std::wstring errorMsg;
    for (const auto& capName : capabilitiesToAdd)
    {
        UniqueLocalAlloc capSid;
        if (GetCapabilitySidFromName(capName.c_str(), capSid, errorMsg))
        {
            SID_AND_ATTRIBUTES cap = {};
            cap.Sid = capSid.get();
            cap.Attributes = SE_GROUP_ENABLED;
            capabilities.push_back(cap);
            capabilitySids.push_back(std::move(capSid)); // Keep alive until after CreateProcessW
        }
        else
        {
            logger << L"Warning: Could not get capability SID for " << capName << L": " << errorMsg << L"\n";
        }
    }

    SECURITY_CAPABILITIES securityCapabilities = {};
    securityCapabilities.AppContainerSid = _appContainerSid.get();
    securityCapabilities.Capabilities = capabilities.data();
    securityCapabilities.CapabilityCount = static_cast<DWORD>(capabilities.size());
    securityCapabilities.Reserved = 0;

    // Create pipes for stdout/stderr
    UniqueHandle hStdInRead, hStdInWrite, hStdOutRead, hStdOutWrite, hStdErrRead, hStdErrWrite;
    if (!CreateStdPipes(hStdInRead, hStdInWrite, false, errorMsg) ||
        !CreateStdPipes(hStdOutRead, hStdOutWrite, true, errorMsg) ||
        !CreateStdPipes(hStdErrRead, hStdErrWrite, true, errorMsg))
    {
        return CreateErrorResponse(errorMsg);
    }

    // Initialize startup info with extended attributes
    STARTUPINFOEXW siEx = {};
    siEx.StartupInfo.cb = sizeof(STARTUPINFOEXW);
    siEx.StartupInfo.hStdInput = hStdInRead.get();
    siEx.StartupInfo.hStdOutput = hStdOutWrite.get();
    siEx.StartupInfo.hStdError = hStdErrWrite.get();
    siEx.StartupInfo.dwFlags |= STARTF_USESTDHANDLES;
    siEx.StartupInfo.lpDesktop = const_cast<LPWSTR>(L"winsta0\\default");

    // Initialize attribute list (security caps + optional LPAC policy)
    DWORD attrCount = request.policy.leastPrivilegeMode ? 2 : 1;
    SIZE_T attributeListSize = 0;
    ::InitializeProcThreadAttributeList(nullptr, attrCount, 0, &attributeListSize);

    UniqueHeapAlloc attributeListMemory(::HeapAlloc(::GetProcessHeap(), 0, attributeListSize));
    if (!attributeListMemory)
    {
        return CreateErrorResponse(L"Failed to allocate attribute list");
    }

    siEx.lpAttributeList = static_cast<LPPROC_THREAD_ATTRIBUTE_LIST>(attributeListMemory.get());
    if (!::InitializeProcThreadAttributeList(siEx.lpAttributeList, attrCount, 0, &attributeListSize))
    {
        return CreateErrorResponse(L"Failed to initialize attribute list");
    }

    AttributeListGuard attrListGuard(siEx.lpAttributeList);
    attrListGuard.MarkInitialized();

    if (!::UpdateProcThreadAttribute(siEx.lpAttributeList, 0, PROC_THREAD_ATTRIBUTE_SECURITY_CAPABILITIES,
                                     &securityCapabilities, sizeof(securityCapabilities), nullptr, nullptr))
    {
        return CreateErrorResponse(L"Failed to update thread attribute.");
    }

    // Apply LPAC policy if configured
    if (request.policy.leastPrivilegeMode)
    {
        DWORD AllApplicationPackagesPolicy = PROCESS_CREATION_ALL_APPLICATION_PACKAGES_OPT_OUT;

        if (!UpdateProcThreadAttribute(siEx.lpAttributeList, 0, PROC_THREAD_ATTRIBUTE_ALL_APPLICATION_PACKAGES_POLICY,
                                       &AllApplicationPackagesPolicy, sizeof(AllApplicationPackagesPolicy), nullptr,
                                       nullptr))
        {
            return CreateErrorResponse(L"Failed to update ALL_APPLICATION_PACKAGES_POLICY attribute.");
        }
    }

    // Create the process
    std::vector<wchar_t> cmdLineBuffer(request.scriptCode.begin(), request.scriptCode.end());
    cmdLineBuffer.push_back(L'\0');

    PROCESS_INFORMATION pi = {};
    BOOL created = ::CreateProcessW(nullptr, cmdLineBuffer.data(), nullptr, nullptr, TRUE, EXTENDED_STARTUPINFO_PRESENT,
                                    nullptr, nullptr, &siEx.StartupInfo, &pi);

    // Close handles that child inherited (we don't need them in parent)
    hStdInRead.reset();
    hStdOutWrite.reset();
    hStdErrWrite.reset();

    if (!created)
    {
        DWORD error = ::GetLastError();
        return CreateErrorResponse(L"Failed to create process. Error code: " + std::to_wstring(error));
    }

    logger << L"Process created successfully (PID: " << pi.dwProcessId << L")\n";

    // Wrap process handles
    UniqueHandle hProcess(pi.hProcess);
    UniqueHandle hThread(pi.hThread);

    // Get handles to our stdin/stdout/stderr.
    // NOTE: These are NOT stored in UniqueHandles because they belong to the process and will be
    // closed when the process exits.
    HANDLE hParentStdIn = ::GetStdHandle(STD_INPUT_HANDLE);
    HANDLE hParentStdOut = ::GetStdHandle(STD_OUTPUT_HANDLE);
    HANDLE hParentStdErr = ::GetStdHandle(STD_ERROR_HANDLE);

    // Create threads for piping data
    // Thread 1: Parent stdin -> Child stdin
    UniqueHandle hThread1;
    WXC::PipeParams params1;
    params1.hRead = hParentStdIn;
    params1.hWrite = hStdInWrite.get();
    hThread1.reset(::CreateThread(nullptr, 0, WXC::PipeThread, &params1, 0, nullptr));

    // Thread 2: Child stdout -> Parent stdout
    UniqueHandle hThread2;
    WXC::PipeParams params2;
    params2.hRead = hStdOutRead.get();
    params2.hWrite = hParentStdOut;
    hThread2.reset(::CreateThread(nullptr, 0, WXC::PipeThread, &params2, 0, nullptr));

    // Thread 3: Child stderr -> Parent stderr
    UniqueHandle hThread3;
    WXC::PipeParams params3;
    params3.hRead = hStdErrRead.get();
    params3.hWrite = hParentStdErr;
    hThread3.reset(::CreateThread(nullptr, 0, WXC::PipeThread, &params3, 0, nullptr));

    // Wait for child process to exit
    ::WaitForSingleObject(hProcess.get(), GetTimeoutMilliseconds(request.scriptTimeout));

    DWORD exitCode = 0;
    ::GetExitCodeProcess(hProcess.get(), &exitCode);

    // Wait for threads to finish (with 1 second timeout)
    HANDLE threads[] = {hThread1.get(), hThread2.get(), hThread3.get()};
    WaitForMultipleObjects(3, threads, TRUE, 1000);

    // TODO: Decide if we need one shot still and script response, or just error code and logging
    ScriptResponse result;
    result.ExitCode = static_cast<int>(exitCode);

    return result;
}

bool AppContainerScriptRunner::CreateAppContainerSid(const std::wstring& appContainerName, UniqueSid& outSid,
                                                     std::wstring& errorMsg)
{
    PSID rawSid = nullptr;
    HRESULT hr =
        ::CreateAppContainerProfile(appContainerName.c_str(), L"Agent scripting environment profile",
                                    L"Profile for testing Agent scripting environment execution", nullptr, 0, &rawSid);

    if (FAILED(hr) && hr != HRESULT_FROM_WIN32(ERROR_ALREADY_EXISTS))
    {
        errorMsg = L"Failed to create AppContainer profile";
        return false;
    }

    if (hr == HRESULT_FROM_WIN32(ERROR_ALREADY_EXISTS))
    {
        hr = ::DeriveAppContainerSidFromAppContainerName(appContainerName.c_str(), &rawSid);
        if (FAILED(hr))
        {
            errorMsg = L"Failed to derive AppContainer SID";
            return false;
        }
    }

    outSid.reset(rawSid);
    return true;
}
