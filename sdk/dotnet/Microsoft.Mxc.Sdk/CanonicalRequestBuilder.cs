// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

using System.Text.Json;
using System.Text.Json.Nodes;
using System.Text.Json.Serialization;

namespace Microsoft.Mxc.Sdk;

internal static class CanonicalRequestBuilder
{
    private static readonly JsonSerializerOptions CanonicalReadOptions = new()
    {
        PropertyNameCaseInsensitive = false,
        UnmappedMemberHandling = JsonUnmappedMemberHandling.Disallow,
        Converters =
        {
            new JsonStringEnumConverter(JsonNamingPolicy.CamelCase),
            new NetworkProxyPolicyJsonConverter(),
        },
    };

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

    internal static SandboxRequest Deserialize(ref Utf8JsonReader reader)
    {
        using var document = JsonDocument.ParseValue(ref reader);
        var root = RequireObject(document.RootElement, "request");
        EnsureKnownProperties(
            root,
            "request",
            "version",
            "containerId",
            "lifecycle",
            "process",
            "filesystem",
            "ui",
            "network",
            "runtimeConfig",
            "telemetry",
            "containment",
            "processContainer",
            "experimental");

        var policy = new SandboxPolicy
        {
            Version = RequireString(root, "version", "request"),
        };

        var process = RequireObject(
            RequireProperty(root, "process", "request"),
            "process");
        EnsureKnownProperties(process, "process", "commandLine", "timeout", "cwd", "env");
        var request = new SandboxRequest(
            policy,
            RequireString(process, "commandLine", "process"));

        if (process.TryGetProperty("timeout", out var timeout))
        {
            var timeoutMs = ReadUInt32(timeout, "process.timeout");
            policy.TimeoutMs = timeoutMs == 0 ? null : timeoutMs;
        }
        if (process.TryGetProperty("cwd", out var cwd))
        {
            request.WorkingDirectory = ReadString(cwd, "process.cwd");
        }
        if (process.TryGetProperty("env", out var environment))
        {
            request.Environment = ReadEnvironment(environment);
        }

        if (root.TryGetProperty("containerId", out var containerId))
        {
            request.ContainerName = ReadString(containerId, "containerId");
        }

        ReadFilesystemAndLifecycle(root, policy);
        if (root.TryGetProperty("ui", out var ui))
        {
            policy.Ui = ReadUiPolicy(ui);
        }

        if (root.TryGetProperty("network", out var network))
        {
            policy.Network = ReadNetworkPolicy(
                network,
                root.TryGetProperty("runtimeConfig", out var runtimeConfig)
                    ? runtimeConfig
                    : null);
        }
        else if (root.TryGetProperty("runtimeConfig", out var runtimeConfig))
        {
            policy.Network = new NetworkPolicy
            {
                RuntimeConfig = DeserializeElement<NetworkRuntimeConfig>(
                    runtimeConfig,
                    "runtimeConfig"),
            };
        }

        if (root.TryGetProperty("telemetry", out var telemetry))
        {
            var telemetryObject = RequireObject(telemetry, "telemetry");
            EnsureKnownProperties(telemetryObject, "telemetry", "enabled");
            policy.Telemetry = new TelemetrySettings
            {
                Enabled = telemetryObject.TryGetProperty("enabled", out var enabled)
                    && ReadBoolean(enabled, "telemetry.enabled"),
            };
        }

        var containmentName = root.TryGetProperty("containment", out var containment)
            ? ReadString(containment, "containment")
            : "process";
        request.Containment = containmentName switch
        {
            "process" => ReadProcessContainment(root),
            "processcontainer" => ReadExplicitProcessContainer(root),
            "wslc" => ReadWslcContainment(root),
            _ => throw new JsonException(
                $"Unsupported canonical containment '{containmentName}'."),
        };

        if (containmentName != "wslc" && root.TryGetProperty("experimental", out var experimental))
        {
            var experimentalObject = RequireObject(experimental, "experimental");
            if (experimentalObject.EnumerateObject().Any())
            {
                throw new JsonException(
                    "Only canonical experimental.wslc requests can be deserialized.");
            }
        }

        return request;
    }

    private static void ReadFilesystemAndLifecycle(
        JsonElement root,
        SandboxPolicy policy)
    {
        var filesystem = new FilesystemPolicy();
        if (root.TryGetProperty("filesystem", out var filesystemElement))
        {
            var filesystemObject = RequireObject(filesystemElement, "filesystem");
            EnsureKnownProperties(
                filesystemObject,
                "filesystem",
                "readwritePaths",
                "readonlyPaths",
                "deniedPaths");
            filesystem.ReadwritePaths = ReadStringList(
                filesystemObject,
                "readwritePaths",
                "filesystem.readwritePaths");
            filesystem.ReadonlyPaths = ReadStringList(
                filesystemObject,
                "readonlyPaths",
                "filesystem.readonlyPaths");
            filesystem.DeniedPaths = ReadStringList(
                filesystemObject,
                "deniedPaths",
                "filesystem.deniedPaths");
        }

        var preservePolicy = false;
        if (root.TryGetProperty("lifecycle", out var lifecycleElement))
        {
            var lifecycle = RequireObject(lifecycleElement, "lifecycle");
            EnsureKnownProperties(
                lifecycle,
                "lifecycle",
                "destroyOnExit",
                "preservePolicy");
            if (lifecycle.TryGetProperty("destroyOnExit", out var destroyOnExit)
                && !ReadBoolean(destroyOnExit, "lifecycle.destroyOnExit"))
            {
                throw new JsonException(
                    "SandboxRequest cannot represent lifecycle.destroyOnExit=false.");
            }
            if (lifecycle.TryGetProperty("preservePolicy", out var preserve))
            {
                preservePolicy = ReadBoolean(preserve, "lifecycle.preservePolicy");
            }
        }
        filesystem.ClearPolicyOnExit = !preservePolicy;
        policy.Filesystem = filesystem;
    }

    private static UiPolicy ReadUiPolicy(JsonElement element)
    {
        var ui = RequireObject(element, "ui");
        EnsureKnownProperties(ui, "ui", "disable", "clipboard", "injection");
        return new UiPolicy
        {
            AllowWindows = ui.TryGetProperty("disable", out var disable)
                && !ReadBoolean(disable, "ui.disable"),
            Clipboard = ui.TryGetProperty("clipboard", out var clipboard)
                ? ReadEnum<ClipboardPolicy>(clipboard, "ui.clipboard")
                : ClipboardPolicy.None,
            AllowInputInjection = ui.TryGetProperty("injection", out var injection)
                && ReadBoolean(injection, "ui.injection"),
        };
    }

    private static NetworkPolicy? ReadNetworkPolicy(
        JsonElement element,
        JsonElement? runtimeConfig)
    {
        var network = RequireObject(element, "network");
        var directional = network.TryGetProperty("egress", out _)
            || network.TryGetProperty("ingress", out _);
        if (directional)
        {
            EnsureKnownProperties(network, "network", "egress", "ingress");
            return new NetworkPolicy
            {
                Egress = network.TryGetProperty("egress", out var egress)
                    ? DeserializeElement<NetworkEgressPolicy>(egress, "network.egress")
                    : null,
                Ingress = network.TryGetProperty("ingress", out var ingress)
                    ? DeserializeElement<NetworkIngressPolicy>(ingress, "network.ingress")
                    : null,
                RuntimeConfig = runtimeConfig is { } directionalRuntime
                    ? DeserializeElement<NetworkRuntimeConfig>(
                        directionalRuntime,
                        "runtimeConfig")
                    : null,
            };
        }

        EnsureKnownProperties(
            network,
            "network",
            "defaultPolicy",
            "allowLocalNetwork",
            "allowedHosts",
            "blockedHosts",
            "proxy",
            "enforcementMode");
        if (runtimeConfig is null
            && network.EnumerateObject().All(
                property => property.Name == "defaultPolicy"
                    && property.Value.ValueKind == JsonValueKind.String
                    && property.Value.GetString() == "block"))
        {
            return null;
        }
        var policy = new NetworkPolicy
        {
            AllowOutbound = network.TryGetProperty("defaultPolicy", out var defaultPolicy)
                && ReadString(defaultPolicy, "network.defaultPolicy") switch
                {
                    "allow" => true,
                    "block" => false,
                    var value => throw new JsonException(
                        $"Unsupported network.defaultPolicy '{value}'."),
                },
            AllowLocalNetwork = network.TryGetProperty("allowLocalNetwork", out var local)
                && ReadBoolean(local, "network.allowLocalNetwork"),
            AllowedHosts = ReadStringList(network, "allowedHosts", "network.allowedHosts"),
            BlockedHosts = ReadStringList(network, "blockedHosts", "network.blockedHosts"),
            Proxy = network.TryGetProperty("proxy", out var proxy)
                ? DeserializeElement<NetworkProxyPolicy>(proxy, "network.proxy")
                : null,
            RuntimeConfig = runtimeConfig is { } legacyRuntime
                ? DeserializeElement<NetworkRuntimeConfig>(legacyRuntime, "runtimeConfig")
                : null,
        };
        if (network.TryGetProperty("enforcementMode", out var enforcementMode))
        {
            _ = ReadString(enforcementMode, "network.enforcementMode") switch
            {
                "capabilities" or "firewall" or "both" => true,
                var value => throw new JsonException(
                    $"Unsupported network.enforcementMode '{value}'."),
            };
        }
        return policy;
    }

    private static ProcessContainment ReadProcessContainment(JsonElement root)
    {
        var containment = new ProcessContainment();
        if (root.TryGetProperty("processContainer", out var processContainer))
        {
            if (!OperatingSystem.IsWindows())
            {
                throw new JsonException(
                    "A canonical processContainer section is supported only on Windows.");
            }
            containment.CanonicalProcessContainer = ReadProcessContainer(processContainer);
        }
        return containment;
    }

    private static ProcessContainerContainment ReadExplicitProcessContainer(JsonElement root)
    {
        EnsureProcessContainerPlatform();
        return root.TryGetProperty("processContainer", out var processContainer)
            ? ReadProcessContainer(processContainer)
            : new ProcessContainerContainment { Ui = null };
    }

    private static ProcessContainerContainment ReadProcessContainer(JsonElement element)
    {
        var section = RequireObject(element, "processContainer");
        EnsureKnownProperties(
            section,
            "processContainer",
            "leastPrivilege",
            "learningMode",
            "capabilities",
            "captureDenials",
            "ui",
            "network");
        return new ProcessContainerContainment
        {
            LeastPrivilege = section.TryGetProperty("leastPrivilege", out var leastPrivilege)
                && ReadBoolean(leastPrivilege, "processContainer.leastPrivilege"),
            LearningMode = section.TryGetProperty("learningMode", out var learningMode)
                && ReadBoolean(learningMode, "processContainer.learningMode"),
            Capabilities = ReadStringList(
                section,
                "capabilities",
                "processContainer.capabilities"),
            CaptureDenials = section.TryGetProperty("captureDenials", out var captureDenials)
                ? DeserializeElement<CaptureDenialsPolicy>(
                    captureDenials,
                    "processContainer.captureDenials")
                : null,
            Ui = section.TryGetProperty("ui", out var ui)
                ? DeserializeElement<ProcessContainerUiPolicy>(ui, "processContainer.ui")
                : null,
            Network = section.TryGetProperty("network", out var network)
                ? DeserializeElement<ProcessContainerNetworkPolicy>(
                    network,
                    "processContainer.network")
                : null,
        };
    }

    private static WslcContainment ReadWslcContainment(JsonElement root)
    {
        if (root.TryGetProperty("processContainer", out _))
        {
            throw new JsonException(
                "A canonical WSLC request cannot contain processContainer.");
        }
        var experimental = RequireObject(
            RequireProperty(root, "experimental", "request"),
            "experimental");
        EnsureKnownProperties(experimental, "experimental", "wslc");
        var wslc = RequireObject(
            RequireProperty(experimental, "wslc", "experimental"),
            "experimental.wslc");
        EnsureKnownProperties(
            wslc,
            "experimental.wslc",
            "image",
            "imageTarPath",
            "cpuCount",
            "memoryMb",
            "gpu",
            "storagePath",
            "portMappings");

        var containment = new WslcContainment
        {
            Image = wslc.TryGetProperty("image", out var image)
                ? ReadString(image, "experimental.wslc.image")
                : "alpine:latest",
            ImageTarPath = wslc.TryGetProperty("imageTarPath", out var imageTarPath)
                ? ReadString(imageTarPath, "experimental.wslc.imageTarPath")
                : null,
            CpuCount = wslc.TryGetProperty("cpuCount", out var cpuCount)
                ? ReadUInt32(cpuCount, "experimental.wslc.cpuCount")
                : null,
            MemoryMb = wslc.TryGetProperty("memoryMb", out var memoryMb)
                ? ReadUInt64(memoryMb, "experimental.wslc.memoryMb")
                : null,
            Gpu = wslc.TryGetProperty("gpu", out var gpu)
                && ReadBoolean(gpu, "experimental.wslc.gpu"),
            StoragePath = wslc.TryGetProperty("storagePath", out var storagePath)
                ? ReadString(storagePath, "experimental.wslc.storagePath")
                : null,
        };
        if (wslc.TryGetProperty("portMappings", out var mappings))
        {
            if (mappings.ValueKind != JsonValueKind.Array)
            {
                throw new JsonException("experimental.wslc.portMappings must be an array.");
            }
            foreach (var (mapping, index) in mappings.EnumerateArray().Select((value, index) => (value, index)))
            {
                var mappingObject = RequireObject(
                    mapping,
                    $"experimental.wslc.portMappings[{index}]");
                EnsureKnownProperties(
                    mappingObject,
                    $"experimental.wslc.portMappings[{index}]",
                    "windowsPort",
                    "containerPort",
                    "protocol");
                if (mappingObject.TryGetProperty("protocol", out var protocol)
                    && ReadString(
                        protocol,
                        $"experimental.wslc.portMappings[{index}].protocol") != "tcp")
                {
                    throw new JsonException(
                        "SandboxRequest can represent only TCP WSLC port mappings.");
                }
                containment.PortMappings.Add(new WslcPortMapping(
                    ReadUInt16(
                        RequireProperty(
                            mappingObject,
                            "windowsPort",
                            $"experimental.wslc.portMappings[{index}]"),
                        $"experimental.wslc.portMappings[{index}].windowsPort"),
                    ReadUInt16(
                        RequireProperty(
                            mappingObject,
                            "containerPort",
                            $"experimental.wslc.portMappings[{index}]"),
                        $"experimental.wslc.portMappings[{index}].containerPort")));
            }
        }
        return containment;
    }

    private static Dictionary<string, string> ReadEnvironment(JsonElement element)
    {
        if (element.ValueKind != JsonValueKind.Array)
        {
            throw new JsonException("process.env must be an array.");
        }
        var environment = new Dictionary<string, string>();
        foreach (var (entry, index) in element.EnumerateArray().Select((value, index) => (value, index)))
        {
            var pair = ReadString(entry, $"process.env[{index}]");
            var separator = pair.IndexOf('=');
            if (separator <= 0)
            {
                throw new JsonException(
                    $"process.env[{index}] must have the form NAME=VALUE.");
            }
            if (!environment.TryAdd(pair[..separator], pair[(separator + 1)..]))
            {
                throw new JsonException(
                    $"process.env contains duplicate variable '{pair[..separator]}'.");
            }
        }
        return environment;
    }

    private static List<string> ReadStringList(
        JsonElement parent,
        string propertyName,
        string location) =>
        parent.TryGetProperty(propertyName, out var value)
            ? DeserializeElement<List<string>>(value, location)
            : [];

    private static T DeserializeElement<T>(JsonElement element, string location)
    {
        try
        {
            return element.Deserialize<T>(CanonicalReadOptions)
                ?? throw new JsonException($"{location} cannot be null.");
        }
        catch (JsonException error)
        {
            throw new JsonException($"Invalid {location}: {error.Message}", error);
        }
    }

    private static T ReadEnum<T>(JsonElement element, string location)
        where T : struct, Enum =>
        DeserializeElement<T>(element, location);

    private static JsonElement RequireObject(JsonElement element, string location) =>
        element.ValueKind == JsonValueKind.Object
            ? element
            : throw new JsonException($"{location} must be an object.");

    private static JsonElement RequireProperty(
        JsonElement element,
        string propertyName,
        string location) =>
        element.TryGetProperty(propertyName, out var value)
            ? value
            : throw new JsonException($"{location}.{propertyName} is required.");

    private static string RequireString(
        JsonElement element,
        string propertyName,
        string location) =>
        ReadString(
            RequireProperty(element, propertyName, location),
            $"{location}.{propertyName}");

    private static string ReadString(JsonElement element, string location) =>
        element.ValueKind == JsonValueKind.String
            ? element.GetString()!
            : throw new JsonException($"{location} must be a string.");

    private static bool ReadBoolean(JsonElement element, string location) =>
        element.ValueKind is JsonValueKind.True or JsonValueKind.False
            ? element.GetBoolean()
            : throw new JsonException($"{location} must be a boolean.");

    private static uint ReadUInt32(JsonElement element, string location) =>
        element.ValueKind == JsonValueKind.Number && element.TryGetUInt32(out var value)
            ? value
            : throw new JsonException($"{location} must be an unsigned 32-bit integer.");

    private static ulong ReadUInt64(JsonElement element, string location) =>
        element.ValueKind == JsonValueKind.Number && element.TryGetUInt64(out var value)
            ? value
            : throw new JsonException($"{location} must be an unsigned 64-bit integer.");

    private static ushort ReadUInt16(JsonElement element, string location)
    {
        var value = ReadUInt32(element, location);
        return value is > 0 and <= ushort.MaxValue
            ? (ushort)value
            : throw new JsonException($"{location} must be between 1 and {ushort.MaxValue}.");
    }

    private static void EnsureKnownProperties(
        JsonElement element,
        string location,
        params string[] propertyNames)
    {
        var known = new HashSet<string>(propertyNames, StringComparer.Ordinal);
        var seen = new HashSet<string>(StringComparer.Ordinal);
        foreach (var property in element.EnumerateObject())
        {
            if (!known.Contains(property.Name))
            {
                throw new JsonException(
                    $"Unknown canonical property '{location}.{property.Name}'.");
            }
            if (!seen.Add(property.Name))
            {
                throw new JsonException(
                    $"Duplicate canonical property '{location}.{property.Name}'.");
            }
        }
    }

    private static void EnsureProcessContainerPlatform()
    {
        if (!OperatingSystem.IsWindows())
        {
            throw new PlatformNotSupportedException(
                "ProcessContainer containment is supported only on Windows.");
        }
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
            foreach (var name in request.Environment.Keys)
            {
                if (string.IsNullOrEmpty(name) || name.Contains('='))
                {
                    throw new ArgumentException(
                        "An environment variable name cannot be empty or contain '='.",
                        nameof(request));
                }
            }
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
            case ProcessContainment process:
                root["containment"] = "process";
                if (OperatingSystem.IsWindows())
                {
                    AddProcessContainer(
                        root,
                        process.CanonicalProcessContainer ?? new ProcessContainerContainment(),
                        network,
                        directional,
                        "process",
                        options);
                }
                else if (OperatingSystem.IsLinux())
                {
                    ApplyLinuxNetworkPolicy(root);
                }
                break;
            case ProcessContainerContainment processContainer:
                EnsureProcessContainerPlatform();
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

    /// <summary>
    /// Promotes network enforcement to <c>firewall</c> when host rules are present and no
    /// cooperative proxy is configured — the Linux counterpart of the Rust builder's
    /// <c>apply_linux_network_policy</c>. Without it the parser leaves the mode at
    /// <c>capabilities</c> and the host lists are not applied.
    /// </summary>
    private static void ApplyLinuxNetworkPolicy(JsonObject root)
    {
        if (root["network"] is not JsonObject network || network["proxy"] is not null)
        {
            return;
        }
        if (HasHosts(network, "allowedHosts") || HasHosts(network, "blockedHosts"))
        {
            network["enforcementMode"] = "firewall";
        }
    }

    private static bool HasHosts(JsonObject network, string key) =>
        network[key] is JsonArray hosts && hosts.Count != 0;

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
