#pragma once

#include <Windows.h>

#include <netfw.h>

#include <span>
#include <string>
#include <string_view>
#include <vector>

#include "CodexModels.h"
#include "Logger.h"

// Manages Windows Firewall rules for AppContainer network isolation
class NetworkFirewallManager
{
public:
    NetworkFirewallManager();
    ~NetworkFirewallManager();

    enum class DefaultPolicy
    {
        Allow,
        Block
    };

    // Creates firewall rules before AppContainer execution
    // - appContainerSid: The AppContainer SID (converted to string for rule binding)
    // - defaultPolicy: Block all except allowedHosts, or Allow all except blockedHosts
    // Returns true on success
    bool ApplyFirewallRules(std::wstring_view principalId, ContainerPolicy policy, WXC::Logger& logger);

    // Removes all created firewall rules after execution
    bool RemoveFirewallRules(WXC::Logger& logger);

    // Check if rules have been applied
    bool RulesApplied() const { return !_createdRuleNames.empty(); }

private:
    INetFwPolicy2* _fwPolicy = nullptr;
    std::vector<std::wstring> _createdRuleNames;
    bool _comInitialized = false;
    bool _wsaInitialized = false;

    DefaultPolicy InitializePolicy(ContainerPolicy policy, bool& useFirewallRules, WXC::Logger& logger);

    // Initialize COM and get firewall policy interface
    bool InitializeFirewall(WXC::Logger& logger);

    // Cleanup COM
    void CleanupFirewall();

    // Initialize Winsock (called once per instance)
    bool EnsureWsaInitialized(WXC::Logger& logger);

    // Cleanup Winsock
    void CleanupWsa();

    // Create a single firewall rule
    bool CreateRule(std::wstring_view ruleName, std::wstring_view principalId, NET_FW_ACTION action,
                    std::wstring_view remoteAddresses, WXC::Logger& logger);

    // Helper: Process a list of hosts and create firewall rules for each
    void ProcessHostList(std::span<const std::wstring> hosts, std::wstring_view rulePrefix,
                         std::wstring_view principalId, NET_FW_ACTION action, std::wstring_view actionName,
                         WXC::Logger& logger);

    // Helper: Resolve hostname to IP address
    bool ResolveHostname(std::wstring_view hostname, std::wstring& ipAddress, std::wstring& errorMsg);

    // Helper: Validate IP address or CIDR notation
    bool ValidateIpOrCidr(std::wstring_view address);
};
