// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

using System.Text.Json.Nodes;
using Dev = Microsoft.Mxc.Sdk.V1.Dev;

namespace W365SdkTestApp;

internal interface ISdk
{
    JsonObject Call(string phase, JsonObject request, bool dryRun);
}

internal sealed class Sdk : ISdk
{
    public JsonObject Call(string phase, JsonObject request, bool dryRun)
    {
        var options = new Dev.JsonOptions { Experimental = true };
        var json = request.ToJsonString();
        if (phase == "exec" && !dryRun)
        {
            var result = Dev.MxcLifecycle.RunInContainerJson(json, options);
            return new JsonObject
            {
                ["exitCode"] = result.ExitCode, ["timedOut"] = result.TimedOut,
                ["stdout"] = result.Stdout, ["stderr"] = result.Stderr,
                ["warnings"] = System.Text.Json.JsonSerializer.SerializeToNode(result.Warnings),
                ["outputMetadata"] = System.Text.Json.JsonSerializer.SerializeToNode(result.OutputMetadata, Configuration.JsonOptions),
            };
        }
        var response = (phase, dryRun) switch
        {
            ("provision", false) => Dev.MxcLifecycle.ProvisionContainerJson(json, options),
            ("start", false) => Dev.MxcLifecycle.StartContainerJson(json, options),
            ("deprovision", false) => Dev.MxcLifecycle.DeprovisionContainerJson(json, options),
            ("provision", true) => Dev.MxcLifecycle.ValidateProvisionJson(json, options),
            ("start", true) => Dev.MxcLifecycle.ValidateStartJson(json, options),
            ("exec", true) => Dev.MxcLifecycle.ValidateProcessJson(json, options),
            ("deprovision", true) => Dev.MxcLifecycle.ValidateDeprovisionJson(json, options),
            _ => throw new InvalidOperationException("Unsupported SDK phase."),
        };
        if (JsonNode.Parse(response) is not JsonObject envelope || envelope.ContainsKey("error") ||
            envelope["result"] is not JsonObject value)
            throw new ToolException("invalid_sdk_response", "SDK returned an invalid success envelope.");
        return value.DeepClone().AsObject();
    }
}
