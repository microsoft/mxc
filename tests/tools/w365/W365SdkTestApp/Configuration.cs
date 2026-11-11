// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

using System.Text.Json;
using System.Text.Json.Serialization;

namespace W365SdkTestApp;

[JsonUnmappedMemberHandling(JsonUnmappedMemberHandling.Disallow)]
internal sealed class Configuration
{
    public string TenantId { get; set; } = "";
    public string ClientId { get; set; } = "";
    public string PoolId { get; set; } = "";
    public string ControlPlaneHost { get; set; } = "";
    public string DataPlaneSuffix { get; set; } = "";

    internal static readonly JsonSerializerOptions JsonOptions = new(JsonSerializerDefaults.Web)
    {
        UnmappedMemberHandling = JsonUnmappedMemberHandling.Disallow,
        WriteIndented = true,
    };

    internal static Configuration Read(string path, string operation)
    {
        string text;
        try { text = File.ReadAllText(path); }
        catch (Exception error) when (error is IOException or UnauthorizedAccessException)
        {
            throw new ToolException("config_unreadable", "Cannot read deployment config; supply --config or place w365-test.json beside the executable.");
        }
        var config = JsonSerializer.Deserialize<Configuration>(text, JsonOptions)
            ?? throw new ToolException("invalid_config", "Configuration must be a JSON object.");
        config.TenantId = GuidValue(config.TenantId);
        config.ClientId = GuidValue(config.ClientId);
        config.PoolId = GuidValue(config.PoolId);
        if (operation != "status") config.ControlPlaneHost = Host(config.ControlPlaneHost);
        if (operation != "release")
        {
            config.DataPlaneSuffix = Host(config.DataPlaneSuffix);
            if ($"{config.PoolId}.{config.DataPlaneSuffix}".Length > 253)
                throw new ToolException("invalid_config", "Pool-prefixed hostname is too long.");
        }
        return config;
    }

    internal static string GuidValue(string value) =>
        Guid.TryParseExact(value, "D", out var guid) && guid != Guid.Empty
            ? guid.ToString("D")
            : throw new ToolException("invalid_guid", "Expected a nonempty hyphenated GUID.");

    private static string Host(string value)
    {
        if (string.IsNullOrEmpty(value) || value.Length > 253 ||
            value.Split('.').Any(label => label.Length is < 1 or > 63 ||
                !char.IsAsciiLetterOrDigit(label[0]) || !char.IsAsciiLetterOrDigit(label[^1]) ||
                label.Any(c => !char.IsAsciiLetterOrDigit(c) && c != '-')))
            throw new ToolException("invalid_host", "Endpoints must be bare ASCII DNS hostnames, not URLs.");
        return value;
    }

    internal string Identity(string id)
    {
        var parts = id.Split(':');
        if (parts.Length != 3 || parts[0] != "w365" ||
            !string.Equals(GuidValue(parts[1]), PoolId, StringComparison.OrdinalIgnoreCase))
            throw new ToolException("invalid_session_id", "Supply the full opaque MXC ID for the configured pool.");
        _ = GuidValue(parts[2]);
        return id;
    }
}

internal sealed class Arguments
{
    internal string Operation { get; private set; } = "";
    internal string ConfigPath { get; private set; } = Path.Combine(AppContext.BaseDirectory, "w365-test.json");
    internal string? SessionId { get; private set; }
    internal string? ReceiptPath { get; private set; }
    internal string? Command { get; private set; }
    internal string? WorkingDirectory { get; private set; }
    internal string? LoginHint { get; private set; }
    internal string? ExpectedUserObjectId { get; private set; }
    internal int TimeoutMs { get; private set; } = 30000;
    internal bool ForceSignIn { get; private set; }
    internal bool DryRun { get; private set; }

    internal static Arguments Parse(string[] args)
    {
        var value = new Arguments();
        if (args.Length == 0 || args[0] is not ("run" or "release" or "status"))
            throw new ToolException("invalid_arguments", "Use run, status or release. See --help.");
        value.Operation = args[0];
        var seen = new HashSet<string>(StringComparer.Ordinal);
        for (var index = 1; index < args.Length; index++)
        {
            var name = args[index];
            if (!seen.Add(name))
                throw new ToolException("invalid_arguments", "Duplicate argument.");
            if (name == "--force-sign-in") { value.ForceSignIn = true; continue; }
            if (name == "--dry-run") { value.DryRun = true; continue; }
            if (++index >= args.Length || string.IsNullOrWhiteSpace(args[index]) || args[index].Contains('\0'))
                throw new ToolException("invalid_arguments", "An argument value is missing or invalid.");
            var text = args[index];
            switch (name)
            {
                case "--config": value.ConfigPath = Path.GetFullPath(text); break;
                case "--session-id": value.SessionId = text; break;
                case "--receipt-path": value.ReceiptPath = Path.GetFullPath(text); break;
                case "--command": value.Command = text; break;
                case "--working-directory": value.WorkingDirectory = text; break;
                case "--login-hint": value.LoginHint = text; break;
                case "--expected-user-object-id": value.ExpectedUserObjectId = Configuration.GuidValue(text); break;
                case "--timeout-ms":
                    if (!int.TryParse(text, out var timeout) || timeout is < 0 or > 2147400000)
                        throw new ToolException("invalid_timeout", "Timeout must be an integer from 0 to 2147400000.");
                    value.TimeoutMs = timeout;
                    break;
                default: throw new ToolException("invalid_arguments", "Unknown argument. See --help.");
            }
        }
        if (value.Operation == "run" && value.Command is null ||
            value.Operation is "release" or "status" && (value.SessionId is null || value.Command is not null))
            throw new ToolException("invalid_arguments", "Run requires --command; status/release require --session-id and no command.");
        if (value.Operation == "status" && (seen.Contains("--receipt-path") ||
            seen.Contains("--working-directory") || seen.Contains("--timeout-ms")))
            throw new ToolException("invalid_arguments", "Status does not use receipts or command options.");
        return value;
    }
}

internal sealed class ToolException(string code, string message, JsonElement? details = null) : Exception(message)
{
    internal string Code { get; } = code;
    internal JsonElement? Details { get; } = details?.Clone();
}
