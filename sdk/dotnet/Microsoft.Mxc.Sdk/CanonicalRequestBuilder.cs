// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

using System.Text.Json;
using System.Text.Json.Nodes;

namespace Microsoft.Mxc.Sdk;

internal static class CanonicalRequestBuilder
{
    internal static string Serialize(SandboxRequest request, JsonSerializerOptions options)
    {
        if (string.IsNullOrEmpty(request.Policy.Version))
        {
            throw new MxcException(ErrorCode.MalformedRequest, "Policy version is required.");
        }

        var policy = request.Policy;
        var filesystem = policy.Filesystem ?? new FilesystemPolicy();
        var clearPolicy = filesystem.ClearPolicyOnExit ?? true;
        var root = new JsonObject
        {
            ["version"] = policy.Version,
            ["containerId"] = request.ContainerName ?? Guid.NewGuid().ToString("N"),
            ["lifecycle"] = new JsonObject
            {
                ["destroyOnExit"] = true,
                ["preservePolicy"] = !clearPolicy,
            },
            ["process"] = BuildProcess(request, policy),
            ["filesystem"] = new JsonObject
            {
                ["readwritePaths"] = JsonSerializer.SerializeToNode(
                    filesystem.ReadwritePaths,
                    options),
                ["readonlyPaths"] = JsonSerializer.SerializeToNode(
                    filesystem.ReadonlyPaths,
                    options),
                ["deniedPaths"] = JsonSerializer.SerializeToNode(
                    filesystem.DeniedPaths,
                    options),
            },
        };

        if (policy.Ui is not null)
        {
            root["ui"] = new JsonObject
            {
                ["disable"] = !policy.Ui.AllowWindows,
                ["clipboard"] = Wire(policy.Ui.Clipboard),
                ["injection"] = policy.Ui.AllowInputInjection,
            };
        }

        var directional = HasDirectionalNetwork(policy.Network, request.Containment);
        if (directional && HasLegacyNetwork(policy.Network))
        {
            throw new MxcException(
                ErrorCode.MalformedRequest,
                "Legacy network fields cannot be combined with directional network fields.");
        }
        if (RequiresOutboundForHostRules(request.Containment)
            && policy.Network is { AllowOutbound: false } networkWithRules
            && (networkWithRules.AllowedHosts.Count != 0
                || networkWithRules.BlockedHosts.Count != 0))
        {
            throw new MxcException(
                ErrorCode.MalformedRequest,
                "allowedHosts/blockedHosts require allowOutbound to be true.");
        }
        AddNetwork(root, policy.Network, directional, options);
        AddContainment(root, request.Containment, policy.Network, directional, options);

        if (policy.Telemetry is not null)
        {
            root["telemetry"] = new JsonObject { ["enabled"] = policy.Telemetry.Enabled };
        }

        return root.ToJsonString(options);
    }

    private static JsonObject BuildProcess(SandboxRequest request, SandboxPolicy policy)
    {
        var process = new JsonObject
        {
            ["commandLine"] = request.Command,
            ["timeout"] = policy.TimeoutMs ?? 0,
        };
        if (request.WorkingDirectory is not null)
        {
            process["cwd"] = request.WorkingDirectory;
        }
        if (request.Environment.Count != 0)
        {
            process["env"] = JsonSerializer.SerializeToNode(
                request.Environment.Select(pair => $"{pair.Key}={pair.Value}").ToArray());
        }
        return process;
    }

    private static bool HasDirectionalNetwork(
        NetworkPolicy? network,
        SandboxContainment containment) =>
        containment is ProcessContainerContainment
        {
            Network.AllowedProxyPeer: { } allowedProxyPeer,
        } && !string.IsNullOrWhiteSpace(allowedProxyPeer)
        || network?.Egress is not null
        || network?.Ingress is not null
        || network?.RuntimeConfig?.NetworkProxy is not null;

    private static bool HasLegacyNetwork(NetworkPolicy? network) =>
        network is not null
        && (network.AllowOutbound
            || network.AllowLocalNetwork
            || network.AllowedHosts.Count != 0
            || network.BlockedHosts.Count != 0
            || network.Proxy is not null);

    private static bool RequiresOutboundForHostRules(SandboxContainment containment) =>
        containment is ProcessContainerContainment
        || containment is ProcessContainment && OperatingSystem.IsWindows();

    private static void AddNetwork(
        JsonObject root,
        NetworkPolicy? network,
        bool directional,
        JsonSerializerOptions options)
    {
        if (directional)
        {
            if (network?.Egress is not null || network?.Ingress is not null)
            {
                var wire = new JsonObject();
                if (network.Egress is not null)
                {
                    wire["egress"] = JsonSerializer.SerializeToNode(network.Egress, options);
                }
                if (network.Ingress is not null)
                {
                    wire["ingress"] = JsonSerializer.SerializeToNode(network.Ingress, options);
                }
                root["network"] = wire;
            }
            if (network?.RuntimeConfig is not null)
            {
                root["runtimeConfig"] = JsonSerializer.SerializeToNode(
                    network.RuntimeConfig,
                    options);
            }
            return;
        }

        var legacy = new JsonObject
        {
            ["defaultPolicy"] = network?.AllowOutbound == true ? "allow" : "block",
        };
        if (network is not null)
        {
            legacy["allowLocalNetwork"] = network.AllowLocalNetwork;
            legacy["allowedHosts"] = JsonSerializer.SerializeToNode(network.AllowedHosts, options);
            legacy["blockedHosts"] = JsonSerializer.SerializeToNode(network.BlockedHosts, options);
            if (network.Proxy is not null)
            {
                legacy["proxy"] = JsonSerializer.SerializeToNode(network.Proxy, options);
            }
        }
        root["network"] = legacy;
    }

    private static void AddContainment(
        JsonObject root,
        SandboxContainment containment,
        NetworkPolicy? network,
        bool directional,
        JsonSerializerOptions options)
    {
        switch (containment)
        {
            case ProcessContainment:
                root["containment"] = "process";
                if (OperatingSystem.IsWindows())
                {
                    AddProcessContainer(
                        root,
                        new ProcessContainerContainment(),
                        network,
                        directional,
                        "process",
                        options);
                }
                break;
            case ProcessContainerContainment processContainer:
                AddProcessContainer(
                    root,
                    processContainer,
                    network,
                    directional,
                    "processcontainer",
                    options);
                break;
            case WslcContainment wslc:
                root["containment"] = "wslc";
                root["experimental"] = new JsonObject
                {
                    ["wslc"] = BuildWslc(wslc),
                };
                break;
            default:
                throw new ArgumentException(
                    $"Unsupported containment type {containment.GetType().Name}.",
                    nameof(containment));
        }
    }

    private static JsonObject BuildWslc(WslcContainment wslc)
    {
        var wire = new JsonObject
        {
            ["image"] = wslc.Image,
            ["gpu"] = wslc.Gpu,
        };
        if (wslc.ImageTarPath is not null)
        {
            wire["imageTarPath"] = wslc.ImageTarPath;
        }
        if (wslc.CpuCount is not null)
        {
            wire["cpuCount"] = wslc.CpuCount;
        }
        if (wslc.MemoryMb is not null)
        {
            wire["memoryMb"] = wslc.MemoryMb;
        }
        if (wslc.StoragePath is not null)
        {
            wire["storagePath"] = wslc.StoragePath;
        }
        if (wslc.PortMappings.Count != 0)
        {
            wire["portMappings"] = new JsonArray(
                wslc.PortMappings
                    .Select(mapping => (JsonNode)new JsonObject
                    {
                        ["windowsPort"] = mapping.WindowsPort,
                        ["containerPort"] = mapping.ContainerPort,
                        ["protocol"] = "tcp",
                    })
                    .ToArray());
        }
        return wire;
    }

    private static void AddProcessContainer(
        JsonObject root,
        ProcessContainerContainment containment,
        NetworkPolicy? network,
        bool directional,
        string wireContainment,
        JsonSerializerOptions options)
    {
        root["containment"] = wireContainment;
        var capabilities = new List<string>(containment.Capabilities);
        var allowsInternet = directional
            ? network?.Egress is { } egress
                && (egress.Default == NetworkAction.Allow || egress.Allow?.Count > 0)
            : network?.AllowOutbound == true;
        var allowsLocalNetwork = directional
            ? network?.Ingress?.Default == NetworkAction.Allow
            : network?.AllowLocalNetwork == true;
        AddCapability(capabilities, "internetClient", allowsInternet);
        AddCapability(capabilities, "privateNetworkClientServer", allowsLocalNetwork);

        var section = new JsonObject
        {
            ["leastPrivilege"] = containment.LeastPrivilege,
            ["capabilities"] = JsonSerializer.SerializeToNode(capabilities, options),
        };
        if (containment.LearningMode)
        {
            section["learningMode"] = true;
        }
        if (containment.Ui is not null)
        {
            section["ui"] = JsonSerializer.SerializeToNode(containment.Ui, options);
        }
        if (containment.Network?.AllowedProxyPeer is not null)
        {
            section["network"] = JsonSerializer.SerializeToNode(containment.Network, options);
        }
        if (containment.CaptureDenials is not null)
        {
            section["captureDenials"] = JsonSerializer.SerializeToNode(
                containment.CaptureDenials,
                options);
        }
        root["processContainer"] = section;

        if (!directional && root["network"] is JsonObject legacy)
        {
            legacy["enforcementMode"] =
                network is { AllowedHosts.Count: > 0 } or { BlockedHosts.Count: > 0 }
                    ? "both"
                    : "capabilities";
        }
    }

    private static void AddCapability(List<string> capabilities, string value, bool add)
    {
        if (add && !capabilities.Contains(value, StringComparer.OrdinalIgnoreCase))
        {
            capabilities.Add(value);
        }
    }

    private static string Wire(ClipboardPolicy value) => value switch
    {
        ClipboardPolicy.None => "none",
        ClipboardPolicy.Read => "read",
        ClipboardPolicy.Write => "write",
        ClipboardPolicy.All => "all",
        _ => throw new ArgumentOutOfRangeException(nameof(value)),
    };
}
