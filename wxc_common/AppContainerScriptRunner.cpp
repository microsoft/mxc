#include "pch.h"

#include <windows.h>

#include <aclapi.h>
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

namespace
{

// Grant an AppContainer SID read/write access to the Windows NUL device (\\.\NUL).
//
// Many runtimes unconditionally open the NUL device during stdio initialization:
//   - Node.js v19+ (and Electron v29+) in PlatformInit()
//   - Python subprocess with DEVNULL
//   - C/C++ programs redirecting to NUL
//
// AppContainers block device path access by default, causing these runtimes to
// crash before they can use the perfectly valid stdio pipes that WXC provides.
// Since NUL is a data sink (discards writes, returns EOF on reads), granting
// access carries no security risk.
//
// The original DACL is saved so it can be restored after the child process exits.
WXC::UniqueHandle GrantNulDeviceAccess(PSID appContainerSid, PACL& pOriginalDacl,
                                       PSECURITY_DESCRIPTOR& pSD, WXC::Logger& logger)
{
    pOriginalDacl = nullptr;
    pSD = nullptr;

    HANDLE hRaw = ::CreateFileW(L"\\\\.\\NUL", WRITE_DAC | READ_CONTROL,
                                FILE_SHARE_READ | FILE_SHARE_WRITE,
                                nullptr, OPEN_EXISTING, 0, nullptr);
    if (hRaw == INVALID_HANDLE_VALUE)
    {
        logger << L"Warning: Could not open NUL device for DACL modification\n";
        return WXC::UniqueHandle();
    }

    WXC::UniqueHandle hNul(hRaw);

    if (::GetSecurityInfo(hNul.get(), SE_KERNEL_OBJECT, DACL_SECURITY_INFORMATION,
                          nullptr, nullptr, &pOriginalDacl, nullptr, &pSD) != ERROR_SUCCESS)
    {
        logger << L"Warning: Could not read NUL device security descriptor\n";
        return WXC::UniqueHandle();
    }

    EXPLICIT_ACCESS_W ea = {};
    ea.grfAccessPermissions = GENERIC_READ | GENERIC_WRITE;
    ea.grfAccessMode = SET_ACCESS;
    ea.grfInheritance = NO_INHERITANCE;
    ea.Trustee.TrusteeForm = TRUSTEE_IS_SID;
    ea.Trustee.TrusteeType = TRUSTEE_IS_WELL_KNOWN_GROUP;
    ea.Trustee.ptstrName = reinterpret_cast<LPWSTR>(appContainerSid);

    PACL pNewDacl = nullptr;
    if (::SetEntriesInAclW(1, &ea, pOriginalDacl, &pNewDacl) != ERROR_SUCCESS)
    {
        logger << L"Warning: Could not create new ACL for NUL device\n";
        ::LocalFree(pSD);
        pSD = nullptr;
        return WXC::UniqueHandle();
    }

    if (::SetSecurityInfo(hNul.get(), SE_KERNEL_OBJECT, DACL_SECURITY_INFORMATION,
                          nullptr, nullptr, pNewDacl, nullptr) != ERROR_SUCCESS)
    {
        logger << L"Warning: Could not set NUL device DACL\n";
        ::LocalFree(pNewDacl);
        ::LocalFree(pSD);
        pSD = nullptr;
        return WXC::UniqueHandle();
    }

    ::LocalFree(pNewDacl);
    logger << L"Granted AppContainer access to NUL device\n";
    return hNul;
}

// Restore the NUL device's original security descriptor after the child exits.
void RestoreNulDeviceSecurity(WXC::UniqueHandle& hNul, PACL pOriginalDacl,
                              PSECURITY_DESCRIPTOR pSD, WXC::Logger& logger)
{
    if (hNul && pOriginalDacl)
    {
        ::SetSecurityInfo(hNul.get(), SE_KERNEL_OBJECT, DACL_SECURITY_INFORMATION,
                          nullptr, nullptr, pOriginalDacl, nullptr);
        logger << L"Restored NUL device security\n";
    }
    if (pSD)
    {
        ::LocalFree(pSD);
    }
}

} // anonymous namespace

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
    // Validate that permissiveLearningMode is not used in release builds
    for (const auto& cap : request.policy.capabilities)
    {
        if (cap == L"permissiveLearningMode")
        {
#ifdef _DEBUG
            logger << L"*** SECURITY WARNING ***\n";
            logger << L"permissiveLearningMode capability is ENABLED.\n";
            logger << L"AppContainer access restrictions will be LOGGED but NOT ENFORCED.\n";
            logger << L"This is a DEBUG BUILD ONLY feature and provides NO SECURITY.\n";
            logger << L"*** DO NOT USE IN PRODUCTION ***\n\n";
#else
            logger << L"*** SECURITY ERROR ***\n";
            logger << L"permissiveLearningMode capability is NOT ALLOWED in release builds.\n";
            logger << L"This capability completely bypasses AppContainer security.\n";
            logger << L"Refusing to execute. Rebuild in debug mode if learning mode is required.\n";
            return CreateErrorResponse(L"SECURITY: permissiveLearningMode not allowed in release builds");
#endif
        }
    }

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

    // Initialize attribute list (security caps + handle list + optional LPAC policy)
    DWORD attrCount = request.policy.leastPrivilegeMode ? 3 : 2;
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

    // Explicitly list only the pipe handles the child container needs to inherit.
    // This lets us pass bInheritHandles=TRUE to CreateProcessW while still tightly
    // controlling which handles the child can access.
    HANDLE inheritHandles[] = {hStdInRead.get(), hStdOutWrite.get(), hStdErrWrite.get()};
    if (!::UpdateProcThreadAttribute(siEx.lpAttributeList, 0, PROC_THREAD_ATTRIBUTE_HANDLE_LIST, inheritHandles,
                                     sizeof(inheritHandles), nullptr, nullptr))
    {
        return CreateErrorResponse(L"Failed to update HANDLE_LIST attribute.");
    }

    // Grant AppContainer access to the NUL device for runtime stdio initialization.
    // This must happen before CreateProcessW so the child can open \\.\NUL on startup.
    PACL pOriginalNulDacl = nullptr;
    PSECURITY_DESCRIPTOR pNulSD = nullptr;
    auto hNulDevice = GrantNulDeviceAccess(_appContainerSid.get(), pOriginalNulDacl, pNulSD, logger);

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

    // Wait for the child process to exit, or for an output relay thread to finish.
    // Threads 2 and 3 exit when the child closes its stdout/stderr (which happens on exit),
    // so any of these handles signaling indicates the child session is over.
    HANDLE completionHandles[] = {hProcess.get(), hThread2.get(), hThread3.get()};
    DWORD waitResult = ::WaitForMultipleObjects(3, completionHandles, FALSE,
                                                GetTimeoutMilliseconds(request.scriptTimeout));

    if (waitResult == WAIT_TIMEOUT)
    {
        // Timeout elapsed before the child exited: forcibly terminate it.
        ::TerminateProcess(hProcess.get(), static_cast<UINT>(-1));
        // Block until the OS confirms the process is gone so GetExitCodeProcess is valid.
        ::WaitForSingleObject(hProcess.get(), INFINITE);
    }

    // Shut down Thread 1 (stdin relay). CancelSynchronousIo interrupts its blocking
    // ReadFile call, causing PipeThread to break out of its loop. Closing hStdInWrite
    // ensures that any WriteFile already in flight also fails promptly.
    ::CancelSynchronousIo(hThread1.get());
    hStdInWrite.reset();

    // Wait for all relay threads to finish draining and exit cleanly.
    HANDLE allThreads[] = {hThread1.get(), hThread2.get(), hThread3.get()};
    ::WaitForMultipleObjects(3, allThreads, TRUE, 2000);

    DWORD exitCode = 0;
    ::GetExitCodeProcess(hProcess.get(), &exitCode);

    // Restore the NUL device's original security now that the child has exited
    RestoreNulDeviceSecurity(hNulDevice, pOriginalNulDacl, pNulSD, logger);

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
