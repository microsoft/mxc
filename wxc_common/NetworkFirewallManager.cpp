#include "pch.h"

#include <Sddl.h>
#include <WS2tcpip.h>
#include <comdef.h>

#include <iostream>
#include <sstream>

#include "include/CodexModels.h"
#include "include/Logger.h"
#include "include/NetworkFirewallManager.h"
#include "include/StringUtil.h"

#pragma comment(lib, "ole32.lib")
#pragma comment(lib, "oleaut32.lib")
#pragma comment(lib, "ws2_32.lib")

NetworkFirewallManager::NetworkFirewallManager()
{
    // COM will be initialized in ApplyFirewallRules
}

NetworkFirewallManager::~NetworkFirewallManager()
{
    CleanupFirewall();
    CleanupWsa();
}

NetworkFirewallManager::DefaultPolicy NetworkFirewallManager::InitializePolicy(ContainerPolicy policy,
                                                                               bool& useFirewallRules,
                                                                               WXC::Logger& logger)
{
    useFirewallRules = (policy.networkEnforcementMode == ContainerPolicy::NetworkEnforcementMode::Firewall ||
                        policy.networkEnforcementMode == ContainerPolicy::NetworkEnforcementMode::Both);

    if (useFirewallRules && (!policy.allowedHosts.empty() || !policy.blockedHosts.empty() ||
                             policy.defaultNetworkPolicy == ContainerPolicy::NetworkPolicy::Block))
    {
        logger << L"Applying network firewall rules (enforcement mode: ";
        if (policy.networkEnforcementMode == ContainerPolicy::NetworkEnforcementMode::Firewall)
            logger << L"firewall only";
        else
            logger << L"both capabilities and firewall";
        logger << L")...\n";

        return (policy.defaultNetworkPolicy == ContainerPolicy::NetworkPolicy::Block)
                   ? NetworkFirewallManager::DefaultPolicy::Block
                   : NetworkFirewallManager::DefaultPolicy::Allow;
    }

    return NetworkFirewallManager::DefaultPolicy::Allow; // Default to Allow if no rules needed
}

bool NetworkFirewallManager::ApplyFirewallRules(std::wstring_view principalId, ContainerPolicy policy,
                                                WXC::Logger& logger)
{
    bool useFirewallRules = false;
    DefaultPolicy defaultPolicy = InitializePolicy(policy, useFirewallRules, logger);

    // Only apply policies if the firewall has policies to enforce
    if (!useFirewallRules)
    {
        return true;
    }

    if (!InitializeFirewall(logger))
    {
        return false;
    }

    if (!EnsureWsaInitialized(logger))
    {
        return false;
    }

    // Generate unique rule name prefix with timestamp
    SYSTEMTIME st;
    GetSystemTime(&st);
    std::wstringstream ss;
    ss << L"WXC_" << principalId << L"_" << st.wHour << st.wMinute << st.wSecond;
    std::wstring rulePrefix = ss.str();

    if (defaultPolicy == DefaultPolicy::Block)
    {
        // Block all by default, then allow specific hosts

        // Create default block rule
        std::wstring blockAllName = rulePrefix + L"_BlockAll";
        if (!CreateRule(blockAllName, principalId, NET_FW_ACTION_BLOCK, L"", logger))
        {
            return false;
        }
        _createdRuleNames.push_back(blockAllName);

        // Create allow rules for each allowed host
        ProcessHostList(policy.allowedHosts, rulePrefix, principalId, NET_FW_ACTION_ALLOW, L"Allow", logger);
    }
    else // DefaultPolicy::Allow
    {
        // Allow all by default, then block specific hosts

        // Create default allow rule
        std::wstring allowAllName = rulePrefix + L"_AllowAll";
        if (!CreateRule(allowAllName, principalId, NET_FW_ACTION_ALLOW, L"*", logger))
        {
            return false;
        }
        _createdRuleNames.push_back(allowAllName);

        // Create block rules for each blocked host
        ProcessHostList(policy.blockedHosts, rulePrefix, principalId, NET_FW_ACTION_BLOCK, L"Block", logger);
    }

    return true;
}

void NetworkFirewallManager::ProcessHostList(std::span<const std::wstring> hosts, std::wstring_view rulePrefix,
                                             std::wstring_view principalId, NET_FW_ACTION action,
                                             std::wstring_view actionName, WXC::Logger& logger)
{
    int index = 0;
    for (const auto& host : hosts)
    {
        std::wstring ipAddress;

        // Check if it's already an IP/CIDR, otherwise resolve
        if (ValidateIpOrCidr(host))
        {
            ipAddress = host;
        }
        else
        {
            std::wstring errorMsg;
            if (!ResolveHostname(host, ipAddress, errorMsg))
            {
                logger << L"Warning: Could not resolve " << host << L": " << errorMsg << L"\n";
                continue; // Skip this host but continue with others
            }
        }

        std::wstringstream nameSs;
        nameSs << rulePrefix << L"_" << actionName << L"_" << index++;
        std::wstring ruleName = nameSs.str();
        if (!CreateRule(ruleName, principalId, action, ipAddress, logger))
        {
            logger << L"Warning: Could not create " << actionName << L" rule for " << host << L"\n";
            continue;
        }
        _createdRuleNames.push_back(ruleName);
        logger << L"  Created " << actionName << L" rule for: " << host << L" (" << ipAddress << L")\n";
    }
}

bool NetworkFirewallManager::RemoveFirewallRules(WXC::Logger& logger)
{
    logger << L"\nRemoving network firewall rules...\n";
    if (!_fwPolicy)
    {
        logger << L"Firewall policy not initialized";
        return false;
    }

    INetFwRules* rules = nullptr;
    HRESULT hr = _fwPolicy->get_Rules(&rules);
    if (FAILED(hr))
    {
        logger << L"Failed to get firewall rules collection";
        return false;
    }

    bool allSuccess = true;
    std::wstring aggregateErrors;

    for (const auto& ruleName : _createdRuleNames)
    {
        BSTR bstrName = SysAllocString(ruleName.c_str());
        hr = rules->Remove(bstrName);
        SysFreeString(bstrName);

        if (FAILED(hr))
        {
            std::wstringstream ss;
            ss << L"Failed to remove rule " << ruleName << L" (HRESULT: 0x" << std::hex << hr << L"); ";
            aggregateErrors += ss.str();
            allSuccess = false;
        }
    }

    rules->Release();
    _createdRuleNames.clear();

    if (!allSuccess)
    {
        logger << L"Warning: Firewall cleanup failed: " << aggregateErrors << L"\n";
    }

    logger << L"Network firewall rules removed successfully\n";
    return allSuccess;
}

bool NetworkFirewallManager::InitializeFirewall(WXC::Logger& logger)
{
    if (_fwPolicy)
    {
        return true; // Already initialized
    }

    HRESULT hr = CoInitializeEx(nullptr, COINIT_APARTMENTTHREADED);
    if (FAILED(hr) && hr != RPC_E_CHANGED_MODE)
    {
        logger << L"CoInitializeEx failed";
        return false;
    }
    _comInitialized = (hr != RPC_E_CHANGED_MODE);

    hr = CoCreateInstance(__uuidof(NetFwPolicy2), nullptr, CLSCTX_INPROC_SERVER, __uuidof(INetFwPolicy2),
                          reinterpret_cast<void**>(&_fwPolicy));

    if (FAILED(hr))
    {
        std::wostringstream ss;
        ss << std::hex << hr;
        logger << L"Failed to create firewall policy instance (HRESULT: 0x" << ss.str() << L")";
        if (_comInitialized)
        {
            CoUninitialize();
            _comInitialized = false;
        }
        return false;
    }

    return true;
}

void NetworkFirewallManager::CleanupFirewall()
{
    if (_fwPolicy)
    {
        _fwPolicy->Release();
        _fwPolicy = nullptr;
    }

    if (_comInitialized)
    {
        CoUninitialize();
        _comInitialized = false;
    }
}

bool NetworkFirewallManager::EnsureWsaInitialized(WXC::Logger& logger)
{
    if (_wsaInitialized)
    {
        return true; // Already initialized
    }

    WSADATA wsaData;
    int result = WSAStartup(MAKEWORD(2, 2), &wsaData);
    if (result != 0)
    {
        logger << L"WSAStartup failed with error: " << result;
        return false;
    }

    _wsaInitialized = true;
    return true;
}

void NetworkFirewallManager::CleanupWsa()
{
    if (_wsaInitialized)
    {
        WSACleanup();
        _wsaInitialized = false;
    }
}

bool NetworkFirewallManager::CreateRule(std::wstring_view ruleName, std::wstring_view principalId, NET_FW_ACTION action,
                                        std::wstring_view remoteAddresses, WXC::Logger& logger)
{
    INetFwRules* rules = nullptr;
    HRESULT hr = _fwPolicy->get_Rules(&rules);
    if (FAILED(hr))
    {
        logger << L"Failed to get rules collection";
        return false;
    }

    INetFwRule* rule = nullptr;
    hr = CoCreateInstance(__uuidof(NetFwRule), nullptr, CLSCTX_INPROC_SERVER, __uuidof(INetFwRule),
                          reinterpret_cast<void**>(&rule));

    if (FAILED(hr))
    {
        rules->Release();
        logger << L"Failed to create firewall rule instance";
        return false;
    }

    // Query for INetFwRule3 interface (needed for AppContainer binding)
    INetFwRule3* rule3 = nullptr;
    hr = rule->QueryInterface(__uuidof(INetFwRule3), reinterpret_cast<void**>(&rule3));
    if (FAILED(hr))
    {
        rule->Release();
        rules->Release();
        logger << L"Failed to get INetFwRule3 interface (Windows 8+ required for AppContainer binding)";
        return false;
    }

    // Configure the rule
    BSTR bstrName = StringUtil::ToBSTR(ruleName);
    rule->put_Name(bstrName);
    SysFreeString(bstrName);

    BSTR bstrDescription = SysAllocString(L"WXC AppContainer network policy");
    rule->put_Description(bstrDescription);
    SysFreeString(bstrDescription);

    // Bind to AppContainer SID using INetFwRule3
    BSTR bstrAppPkgId = StringUtil::ToBSTR(principalId);
    rule3->put_LocalAppPackageId(bstrAppPkgId);
    SysFreeString(bstrAppPkgId);
    rule3->Release();

    // Outbound traffic rule
    rule->put_Direction(NET_FW_RULE_DIR_OUT);

    // Set action (allow or block)
    rule->put_Action(action);

    // Apply to all interfaces
    VARIANT varInterfaces;
    varInterfaces.vt = VT_EMPTY;
    rule->put_Interfaces(varInterfaces);

    // Set remote addresses
    if (!remoteAddresses.empty())
    {
        BSTR bstrAddresses = StringUtil::ToBSTR(remoteAddresses);
        rule->put_RemoteAddresses(bstrAddresses);
        SysFreeString(bstrAddresses);
    }

    // Enable the rule
    rule->put_Enabled(VARIANT_TRUE);

    // Add the rule
    hr = rules->Add(rule);

    rule->Release();
    rules->Release();

    if (FAILED(hr))
    {
        std::wostringstream ss;
        ss << std::hex << hr;
        logger << L"Failed to add firewall rule (HRESULT: 0x" << ss.str() << L")\n";
        return false;
    }

    return true;
}

bool NetworkFirewallManager::ResolveHostname(std::wstring_view hostname, std::wstring& ipAddress,
                                             std::wstring& errorMsg)
{
    // Convert wide to narrow for getaddrinfo
    std::string narrowHost = StringUtil::WideToUtf8(hostname);

    addrinfo hints = {};
    hints.ai_family = AF_UNSPEC; // Allow IPv4 or IPv6
    hints.ai_socktype = SOCK_STREAM;

    addrinfo* result_info = nullptr;
    int result = getaddrinfo(narrowHost.c_str(), nullptr, &hints, &result_info);

    if (result != 0)
    {
        std::wstringstream ss;
        ss << L"getaddrinfo failed with error: " << result;
        errorMsg = ss.str();
        return false;
    }

    // Get first IP address
    char ipBuffer[INET6_ADDRSTRLEN];
    void* addr = nullptr;

    if (result_info->ai_family == AF_INET)
    {
        sockaddr_in* ipv4 = reinterpret_cast<sockaddr_in*>(result_info->ai_addr);
        addr = &(ipv4->sin_addr);
    }
    else // AF_INET6
    {
        sockaddr_in6* ipv6 = reinterpret_cast<sockaddr_in6*>(result_info->ai_addr);
        addr = &(ipv6->sin6_addr);
    }

    inet_ntop(result_info->ai_family, addr, ipBuffer, sizeof(ipBuffer));

    freeaddrinfo(result_info);

    // Convert narrow IP back to wide
    ipAddress = std::wstring(ipBuffer, ipBuffer + strlen(ipBuffer));
    return true;
}

bool NetworkFirewallManager::ValidateIpOrCidr(std::wstring_view address)
{
    std::string narrow = StringUtil::WideToUtf8(address);

    // Check for CIDR notation
    std::string ipPart = narrow;
    std::string cidrPart;

    size_t slashPos = narrow.find('/');
    if (slashPos != std::string::npos)
    {
        ipPart = narrow.substr(0, slashPos);
        cidrPart = narrow.substr(slashPos + 1);

        // Validate CIDR suffix is a number
        if (cidrPart.empty())
        {
            return false;
        }

        try
        {
            int cidrBits = std::stoi(cidrPart);
            if (cidrBits < 0)
            {
                return false;
            }
        }
        catch (...)
        {
            return false;
        }
    }

    // Try IPv4 validation
    sockaddr_in sa4;
    if (inet_pton(AF_INET, ipPart.c_str(), &(sa4.sin_addr)) == 1)
    {
        // Valid IPv4 - check CIDR range if present
        if (!cidrPart.empty())
        {
            int cidrBits = std::stoi(cidrPart);
            if (cidrBits > 32)
            {
                return false;
            }
        }
        return true;
    }

    // Try IPv6 validation
    sockaddr_in6 sa6;
    if (inet_pton(AF_INET6, ipPart.c_str(), &(sa6.sin6_addr)) == 1)
    {
        // Valid IPv6 - check CIDR range if present
        if (!cidrPart.empty())
        {
            int cidrBits = std::stoi(cidrPart);
            if (cidrBits > 128)
            {
                return false;
            }
        }
        return true;
    }

    return false;
}
