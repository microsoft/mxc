// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

using System.Text.Json;
using Wire = Microsoft.Mxc.Sdk.Generated;

namespace Microsoft.Mxc.Sdk.V1;

internal static class ExactOneShotRequestWriter
{
    internal static readonly JsonSerializerOptions JsonOptions = MxcJson.Options;

    internal static string Serialize(SandboxRequest request)
    {
        ArgumentNullException.ThrowIfNull(request);
        return MxcJson.Serialize(ToWire(request), JsonOptions);
    }

    internal static Wire.OneShotRequest ToWire(SandboxRequest request)
    {
        ArgumentNullException.ThrowIfNull(request);
#pragma warning disable MXC0001 // Reject the obsolete option before any normalization or native call.
        if (request.Experimental)
#pragma warning restore MXC0001
        {
            throw new ArgumentException(
                "Stable V1 requests cannot opt in to experimental features; "
                    + "use a raw exact development-contract request with explicit authorization.",
                nameof(request));
        }
        var normalized = NormalizeCompatibilityAliases(request);
        var policy = normalized.Policy;

        var wire = new Wire.OneShotRequest
        {
            Version = Wire.Version._100,
            ContainerId = normalized.ContainerName is null
                ? MintContainerId()
                : normalized.ContainerName,
            Containment = Containment(normalized.Containment),
            Lifecycle = new Wire.Lifecycle
            {
                DestroyOnExit = true,
                PreservePolicy = policy.Filesystem?.ClearPolicyOnExit == false,
            },
            Process = Process(normalized),
            Filesystem = Filesystem(policy.Filesystem),
            Network = Network(policy.Network),
            RuntimeConfig = RuntimeConfig(policy.Network?.RuntimeConfig),
            Ui = Ui(policy.Ui),
            Telemetry = policy.Telemetry is null
                ? null
                : new Wire.Telemetry { Enabled = policy.Telemetry.Enabled },
        };

        switch (normalized.Containment)
        {
            case ProcessContainment:
            case BubblewrapContainment:
            case IsolationSessionContainment:
                break;
            case ProcessContainerContainment processContainer:
                wire.ProcessContainer = ProcessContainer(processContainer);
                break;
            case LxcContainment lxc:
                wire.Lxc = new Wire.Lxc
                {
                    Distribution = lxc.Distribution,
                    Release = lxc.Release,
                };
                break;
            case SeatbeltContainment seatbelt:
                wire.Seatbelt = Seatbelt(seatbelt);
                break;
            case WslcContainment wslc:
                wire.Wslc = Wslc(wslc);
                break;
            default:
                throw new ArgumentException(
                    $"unsupported containment type '{normalized.Containment.GetType().Name}'",
                    nameof(request));
        }

        return wire;
    }

    private static string MintContainerId() => $"dotnet-{Guid.NewGuid():N}";

    private static Wire.Process Process(SandboxRequest request)
    {
        var process = new Wire.Process
        {
            CommandLine = request.Command,
            Cwd = request.WorkingDirectory,
            Env = request.Environment is null
                ? null
                : request.Environment
                    .Select(pair =>
                    {
                        if (string.IsNullOrEmpty(pair.Key)
                            || pair.Key.Contains('=', StringComparison.Ordinal))
                        {
                            throw new ArgumentException(
                                "Environment keys must be nonempty and must not contain '='.",
                                nameof(request));
                        }
                        return $"{pair.Key}={pair.Value}";
                    })
                    .ToList(),
            Timeout = request.Policy.TimeoutMs ?? 0,
        };
        if (request.Environment is not null && request.InheritDefaultEnvironment)
        {
            process.InheritDefaultEnv = true;
        }
        return process;
    }

    private static Wire.Filesystem Filesystem(FilesystemPolicy? policy) => new()
    {
        ReadwritePaths = policy?.ReadwritePaths is null
            ? []
            : new List<string>(policy.ReadwritePaths),
        ReadonlyPaths = policy?.ReadonlyPaths is null
            ? []
            : new List<string>(policy.ReadonlyPaths),
        DeniedPaths = policy?.DeniedPaths is null
            ? []
            : new List<string>(policy.DeniedPaths),
    };

    private static Wire.Network? Network(NetworkPolicy? policy)
    {
        if (policy?.Egress is null && policy?.Ingress is null)
        {
            return null;
        }
        return new Wire.Network
        {
            Egress = NetworkEgress(policy.Egress),
            Ingress = NetworkIngress(policy.Ingress),
        };
    }

    private static Wire.NetworkEgress? NetworkEgress(NetworkEgressPolicy? policy)
    {
        if (policy is null)
        {
            return null;
        }
        return new Wire.NetworkEgress
        {
            Default = policy.Default is { } defaultAction
                ? NetworkAction(defaultAction, "network.egress.default")
                : null,
            Allow = NetworkRules(policy.Allow),
            Deny = NetworkRules(policy.Deny),
        };
    }

    private static Wire.NetworkIngress? NetworkIngress(NetworkIngressPolicy? policy)
    {
        if (policy is null)
        {
            return null;
        }
        return new Wire.NetworkIngress
        {
            Default = policy.Default is { } defaultAction
                ? NetworkAction(defaultAction, "network.ingress.default")
                : null,
            HostLoopback = policy.HostLoopback is { } hostLoopback
                ? NetworkAction(hostLoopback, "network.ingress.hostLoopback")
                : null,
        };
    }

    private static List<Wire.NetworkRule>? NetworkRules(List<NetworkRulePolicy>? rules) =>
        rules is null ? null : rules.Select(NetworkRule).ToList();

    private static Wire.NetworkRule NetworkRule(NetworkRulePolicy rule) => new()
    {
        To = rule.To?.Select(peer => new Wire.NetworkPeer
        {
            Cidr = peer.Cidr,
            Except = peer.Except is null ? null : new List<string>(peer.Except),
        }).ToList(),
        Ports = rule.Ports?.Select(NetworkPort).ToList(),
    };

    private static Wire.NetworkPort NetworkPort(NetworkPortPolicy port) => new()
    {
        Protocol = port.Protocol is { } protocol
            ? NetworkProtocol(protocol, "network.egress.*.ports.protocol")
            : null,
        Port = port.Port,
        EndPort = port.EndPort,
    };

    private static Wire.RuntimeConfig? RuntimeConfig(NetworkRuntimeConfig? runtime) =>
        runtime is null ? null : new Wire.RuntimeConfig { NetworkProxy = runtime.NetworkProxy };

    private static Wire.Ui? Ui(UiPolicy? policy)
    {
        if (policy is null)
        {
            return null;
        }
        return new Wire.Ui
        {
            Disable = !policy.AllowWindows,
            Clipboard = Clipboard(policy.Clipboard, "ui.clipboard"),
            Injection = policy.AllowInputInjection,
        };
    }

    private static Wire.ProcessContainer ProcessContainer(
        ProcessContainerContainment containment)
    {
        var wire = new Wire.ProcessContainer
        {
            LeastPrivilege = containment.LeastPrivilege,
            Capabilities = ValidatedCapabilities(containment.Capabilities),
            CaptureDenials = CaptureDenials(containment.CaptureDenials),
            Filesystem = containment.Filesystem is null
                ? null
                : new Wire.ProcessContainerFilesystem
                {
                    EnumeratePaths = new List<string>(containment.Filesystem.EnumeratePaths),
                },
            Network = containment.Network?.AllowedProxyPeer is null
                ? null
                : new Wire.ProcessContainerNetwork
                {
                    AllowedProxyPeer = containment.Network.AllowedProxyPeer,
                },
            Ui = ProcessContainerUi(containment.Ui),
        };
        if (containment.LearningMode)
        {
            wire.LearningMode = true;
        }
        return wire;
    }

    private static List<string> ValidatedCapabilities(IEnumerable<string> capabilities)
    {
        var result = new List<string>();
        foreach (var capability in capabilities)
        {
            if (capability.Contains(',', StringComparison.Ordinal))
            {
                throw new ArgumentException(
                    "ProcessContainer capability must not contain a comma.",
                    "request");
            }
            result.Add(capability);
        }
        return result;
    }

    private static Wire.CaptureDenials? CaptureDenials(CaptureDenialsPolicy? policy) =>
        policy is null
            ? null
            : new Wire.CaptureDenials
            {
                Mode = CaptureDenialsMode(policy.Mode, "captureDenials.mode"),
                OutputPath = policy.OutputPath,
                RetainEtl = policy.RetainEtl ? true : null,
            };

    private static Wire.ProcessContainerUi? ProcessContainerUi(
        ProcessContainerUiPolicy? policy)
    {
        if (policy is null || IsDefaultProcessContainerUi(policy))
        {
            return null;
        }
        return new Wire.ProcessContainerUi
        {
            Isolation = ProcessContainerUiIsolation(
                policy.Isolation,
                "processContainer.ui.isolation"),
            DesktopSystemControl = policy.DesktopSystemControl ? true : null,
            SystemSettings = ProcessContainerSystemSettings(
                policy.SystemSettings,
                "processContainer.ui.systemSettings"),
            Ime = policy.Ime ? true : null,
        };
    }

    private static bool IsDefaultProcessContainerUi(ProcessContainerUiPolicy policy) =>
        policy.Isolation == global::Microsoft.Mxc.Sdk.V1.ProcessContainerUiIsolation.Container
            && !policy.DesktopSystemControl
            && policy.SystemSettings == global::Microsoft.Mxc.Sdk.V1.ProcessContainerSystemSettings.None
            && !policy.Ime;

    private static Wire.Seatbelt Seatbelt(SeatbeltContainment containment) => new()
    {
        ProfileOverride = containment.ProfileOverride,
        GuiAccess = containment.GuiAccess ? true : null,
        NestedPty = containment.NestedPty ? null : false,
        KeychainAccess = containment.KeychainAccess ? true : null,
        ExtraMachLookups = containment.ExtraMachLookups.Count == 0
            ? null
            : new List<string>(containment.ExtraMachLookups),
    };

    private static Wire.OneShotWslc Wslc(WslcContainment containment) => new()
    {
        Image = containment.Image,
        ImageTarPath = containment.ImageTarPath,
        CpuCount = containment.CpuCount,
        MemoryMb = containment.MemoryMb,
        Gpu = containment.Gpu,
        StoragePath = containment.StoragePath,
        PortMappings = containment.PortMappings.Count == 0
            ? null
            : containment.PortMappings.Select(mapping => new Wire.PortMapping
            {
                WindowsPort = mapping.WindowsPort,
                ContainerPort = mapping.ContainerPort,
                Protocol = Wire.TransportProtocol.Tcp,
            }).ToList(),
    };

    private static string Containment(SandboxContainment containment) => containment switch
    {
        ProcessContainment => Wire.OneShotContainment.Process,
        ProcessContainerContainment => Wire.OneShotContainment.Processcontainer,
        LxcContainment => Wire.OneShotContainment.Lxc,
        BubblewrapContainment => Wire.OneShotContainment.Bubblewrap,
        SeatbeltContainment => Wire.OneShotContainment.Seatbelt,
        IsolationSessionContainment => Wire.OneShotContainment.IsolationSession,
        WslcContainment => Wire.OneShotContainment.Wslc,
        _ => throw new ArgumentException(
            $"unsupported containment type '{containment.GetType().Name}'",
            "request"),
    };

    private static string NetworkAction(
        global::Microsoft.Mxc.Sdk.V1.NetworkAction value,
        string path) =>
        RequireDefined(value, path) switch
        {
            global::Microsoft.Mxc.Sdk.V1.NetworkAction.Allow => Wire.NetworkAction.Allow,
            global::Microsoft.Mxc.Sdk.V1.NetworkAction.Deny => Wire.NetworkAction.Deny,
            _ => throw UnreachableEnum(value, path),
        };

    private static string NetworkProtocol(
        global::Microsoft.Mxc.Sdk.V1.NetworkProtocol value,
        string path) =>
        RequireDefined(value, path) switch
        {
            global::Microsoft.Mxc.Sdk.V1.NetworkProtocol.Tcp => Wire.NetworkProtocol.Tcp,
            global::Microsoft.Mxc.Sdk.V1.NetworkProtocol.Udp => Wire.NetworkProtocol.Udp,
            global::Microsoft.Mxc.Sdk.V1.NetworkProtocol.Icmp => Wire.NetworkProtocol.Icmp,
            global::Microsoft.Mxc.Sdk.V1.NetworkProtocol.Any => Wire.NetworkProtocol.Any,
            _ => throw UnreachableEnum(value, path),
        };

    private static string Clipboard(ClipboardPolicy value, string path) =>
        RequireDefined(value, path) switch
        {
            ClipboardPolicy.None => Wire.UiClipboard.None,
            ClipboardPolicy.Read => Wire.UiClipboard.Read,
            ClipboardPolicy.Write => Wire.UiClipboard.Write,
            ClipboardPolicy.All => Wire.UiClipboard.All,
            _ => throw UnreachableEnum(value, path),
        };

    private static string CaptureDenialsMode(
        global::Microsoft.Mxc.Sdk.V1.CaptureDenialsMode value,
        string path) =>
        RequireDefined(value, path) switch
        {
            global::Microsoft.Mxc.Sdk.V1.CaptureDenialsMode.Block => Wire.CaptureDenialsMode.Block,
            global::Microsoft.Mxc.Sdk.V1.CaptureDenialsMode.Allow => Wire.CaptureDenialsMode.Allow,
            _ => throw UnreachableEnum(value, path),
        };

    private static string ProcessContainerUiIsolation(
        global::Microsoft.Mxc.Sdk.V1.ProcessContainerUiIsolation value,
        string path) =>
        RequireDefined(value, path) switch
        {
            global::Microsoft.Mxc.Sdk.V1.ProcessContainerUiIsolation.Container =>
                Wire.ProcessContainerUiIsolation.Container,
            global::Microsoft.Mxc.Sdk.V1.ProcessContainerUiIsolation.Desktop =>
                Wire.ProcessContainerUiIsolation.Desktop,
            global::Microsoft.Mxc.Sdk.V1.ProcessContainerUiIsolation.Handles =>
                Wire.ProcessContainerUiIsolation.Handles,
            global::Microsoft.Mxc.Sdk.V1.ProcessContainerUiIsolation.Atoms =>
                Wire.ProcessContainerUiIsolation.Atoms,
            _ => throw UnreachableEnum(value, path),
        };

    private static string ProcessContainerSystemSettings(
        global::Microsoft.Mxc.Sdk.V1.ProcessContainerSystemSettings value,
        string path) =>
        RequireDefined(value, path) switch
        {
            global::Microsoft.Mxc.Sdk.V1.ProcessContainerSystemSettings.All => "all",
            global::Microsoft.Mxc.Sdk.V1.ProcessContainerSystemSettings.Parameters => "parameters",
            global::Microsoft.Mxc.Sdk.V1.ProcessContainerSystemSettings.Display => "display",
            global::Microsoft.Mxc.Sdk.V1.ProcessContainerSystemSettings.None => "none",
            _ => throw UnreachableEnum(value, path),
        };

    private static TEnum RequireDefined<TEnum>(TEnum value, string path)
        where TEnum : struct, Enum
    {
        if (!Enum.IsDefined(value))
        {
            throw new ArgumentOutOfRangeException(
                path,
                value,
                $"{typeof(TEnum).Name} value '{Convert.ToInt64(value)}' is not supported.");
        }
        return value;
    }

    private static ArgumentOutOfRangeException UnreachableEnum<TEnum>(
        TEnum value,
        string path)
        where TEnum : struct, Enum =>
        new(path, value, $"{typeof(TEnum).Name} value '{Convert.ToInt64(value)}' is not supported.");

    private static SandboxRequest NormalizeCompatibilityAliases(SandboxRequest request)
    {
#pragma warning disable MXC0001 // Compatibility migration for the obsolete policy field.
        var legacyCaptureDenials = request.Policy.CaptureDenials;
#pragma warning restore MXC0001
        if (legacyCaptureDenials is null)
        {
            return request;
        }

        var containment = request.Containment switch
        {
            ProcessContainment => new ProcessContainerContainment
            {
                CaptureDenials = legacyCaptureDenials,
            },
            ProcessContainerContainment processContainer =>
                CloneProcessContainer(processContainer, legacyCaptureDenials),
            _ => throw new ArgumentException(
                $"{nameof(SandboxPolicy)}.CaptureDenials cannot be used with "
                    + $"{request.Containment.GetType().Name}; set "
                    + $"{nameof(ProcessContainerContainment)}."
                    + $"{nameof(ProcessContainerContainment.CaptureDenials)} instead.",
                nameof(request)),
        };

        return new SandboxRequest(request.Policy.WithoutLegacyCaptureDenials(), request.Command)
        {
            Containment = containment,
            ContainerName = request.ContainerName,
            WorkingDirectory = request.WorkingDirectory,
            Environment = request.Environment is null
                ? null
                : new Dictionary<string, string>(
                    request.Environment, request.Environment.Comparer),
            InheritDefaultEnvironment = request.InheritDefaultEnvironment,
        };
    }

    private static ProcessContainerContainment CloneProcessContainer(
        ProcessContainerContainment containment,
        CaptureDenialsPolicy legacyCaptureDenials)
    {
        if (containment.CaptureDenials is not null
            && !CaptureDenialsEqual(containment.CaptureDenials, legacyCaptureDenials))
        {
            throw new ArgumentException(
                $"{nameof(SandboxPolicy)}.CaptureDenials conflicts with "
                    + $"{nameof(ProcessContainerContainment)}."
                    + $"{nameof(ProcessContainerContainment.CaptureDenials)}.",
                "request");
        }

        return new ProcessContainerContainment
        {
            LeastPrivilege = containment.LeastPrivilege,
            LearningMode = containment.LearningMode,
            Capabilities = new List<string>(containment.Capabilities),
            CaptureDenials = containment.CaptureDenials ?? legacyCaptureDenials,
            Ui = containment.Ui,
            Filesystem = containment.Filesystem,
            Network = containment.Network,
        };
    }

    private static bool CaptureDenialsEqual(
        CaptureDenialsPolicy left,
        CaptureDenialsPolicy right) =>
        left.Mode == right.Mode
            && string.Equals(left.OutputPath, right.OutputPath, StringComparison.Ordinal)
            && left.RetainEtl == right.RetainEtl;
}
