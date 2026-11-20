// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

// Test-only executable. It has no network or authentication implementation.
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Text;
using System.Threading;
using System.Web.Script.Serialization;

class W365ManualExecutorFixture
{
    static readonly JavaScriptSerializer Json = new JavaScriptSerializer();
    static string Pool;
    const string Session = "44444444-4444-4444-4444-444444444444";
    static string Id { get { return "w365:" + Pool + ":" + Session; } }

    static void Check(bool value) { if (!value) throw new Exception("fixture_contract_assertion"); }
    static void Print(object value) { Console.WriteLine(Json.Serialize(value)); }
    static Dictionary<string, object> Map(object value) { return (Dictionary<string, object>)value; }
    static int Error(string operation, bool withId, string code = null)
    {
        var details = new Dictionary<string, object> {
            { "code", code ?? (operation == "start" ? "attach_timeout" : "auth_denied") },
            { "httpStatus", 403 }, { "possiblySucceeded", true },
            { "poolId", Pool }, { "clientRequestId", Session },
            { "requestId", "safe-correlation-1" }, { "body", "SYNTHETIC_SECRET" },
            { "controlPlaneHost", "recovery.example.invalid" }
        };
        if (withId) details["sandboxId"] = Id;
        Print(new { error = new { code = "backend_error", message = "SYNTHETIC_SECRET", details = details } });
        return 1;
    }

    static int Main(string[] args)
    {
        var scenario = Environment.GetEnvironmentVariable("W365_MANUAL_FIXTURE_SCENARIO");
        if (scenario != null && scenario.StartsWith("reuse_")) scenario = scenario.Substring(6);
        if (scenario != null && scenario.StartsWith("automatic_")) scenario = scenario.Substring(10);
        if (args.Length == 1 && args[0] == "hang") { Thread.Sleep(10000); return 0; }
        if (args.Length == 1 && args[0] == "short") { Thread.Sleep(200); return 0; }
        Pool = Environment.GetEnvironmentVariable("W365_MANUAL_FIXTURE_SELECTED_POOL");
        var values = new Dictionary<string, string>();
        bool dry = false, experimental = false;
        for (int i = 0; i < args.Length; i++)
        {
            if (args[i] == "--experimental") experimental = true;
            else if (args[i] == "--dry-run") dry = true;
            else { string key = args[i]; values[key] = args[++i]; }
        }
        Check(experimental);
        string operation = values["--operation"];
        string json = Encoding.UTF8.GetString(Convert.FromBase64String(values["--config-base64"]));
        Check(!json.Contains("synthetic-private-"));
        var request = Map(Json.DeserializeObject(json));
        Check((string)request["version"] == "1.1.0-alpha");
        Check(!request.ContainsKey("phase") && !request.ContainsKey("sandboxId"));
        bool cp = operation == "provision" || operation == "deprovision";
        bool useDpToken = !cp && Environment.GetEnvironmentVariable("W365_MANUAL_FIXTURE_CP_RESOURCE") !=
            Environment.GetEnvironmentVariable("W365_MANUAL_FIXTURE_DP_RESOURCE");
        string credential = useDpToken ? "W365A_DP_TOKEN" : "W365A_CP_TOKEN";
        string resource = Environment.GetEnvironmentVariable(cp ? "W365_MANUAL_FIXTURE_CP_RESOURCE" : "W365_MANUAL_FIXTURE_DP_RESOURCE");
        string token = resource == "90ecec28-f5a6-42b3-9bde-dae1ca98f8b5" ? "synthetic-private-production-token" : resource ==
            "66666666-6666-6666-6666-666666666666" ? "synthetic-private-dp-token" : "synthetic-private-computer-token";
        string supplied = Environment.GetEnvironmentVariable(credential);
        Check(supplied == token || (dry && supplied == "synthetic-preflight-token"));
        Check(Environment.GetEnvironmentVariable(useDpToken ? "W365A_CP_TOKEN" : "W365A_DP_TOKEN") == null);
        Check(Environment.GetEnvironmentVariable("W365A_DP_SUFFIX") == null);
        if (operation == "provision")
        {
            Check(Environment.GetEnvironmentVariable("W365A_GRAPH_TOKEN") ==
                (dry ? "synthetic-preflight-graph-token" : "synthetic-private-graph-token"));
            Check(Environment.GetEnvironmentVariable("W365A_GRAPH_ENVIRONMENT") ==
                Environment.GetEnvironmentVariable("W365_MANUAL_FIXTURE_GRAPH_ENVIRONMENT"));
        }
        else
        {
            Check(Environment.GetEnvironmentVariable("W365A_GRAPH_TOKEN") == null);
            Check(Environment.GetEnvironmentVariable("W365A_GRAPH_ENVIRONMENT") == null);
        }
        foreach (string key in Environment.GetEnvironmentVariables().Keys)
            Check(!key.StartsWith("MXC_W365_TEST_") && key != "W365A_INHERITED_TEST");
        Check(Console.In.ReadToEnd() == "");
        if (operation == "provision")
        {
            var provision = Map(Map(request["w365Agents"])["provision"]);
            bool optional = Environment.GetEnvironmentVariable("W365_MANUAL_FIXTURE_OPTIONAL_POOL") == "1";
            Check(optional ? !provision.ContainsKey("poolId") : (string)provision["poolId"] ==
                Environment.GetEnvironmentVariable("W365_MANUAL_FIXTURE_REQUESTED_POOL"));
            Check((string)provision["userType"] == "Local");
            if (!dry) Check((string)provision["userObjectId"] == "33333333-3333-3333-3333-333333333333");
            if (!dry)
            {
                var journal = Map(Json.DeserializeObject(File.ReadAllText(
                    Environment.GetEnvironmentVariable("W365_MANUAL_FIXTURE_RECEIPT"))));
                Check((string)journal["state"] == "provisionSubmitted");
                Check((int)journal["provisionInvocationCount"] == 1);
                Check(journal["poolId"] == null);
                Check(!journal.ContainsKey("controlPlaneFallbackHost"));
                Check(!journal.ContainsKey("allocationRequestCount"));
            }
        }
        else
        {
            Check(values["--container-id"] == Id);
            Check(!request.ContainsKey("w365Agents"));
        }
        if (operation == "exec")
        {
            var process = Map(request["process"]);
            Check((string)process["commandLine"] == Environment.GetEnvironmentVariable("W365_MANUAL_FIXTURE_COMMAND"));
            Check(!process.ContainsKey("env"));
            if (process.ContainsKey("cwd")) Check((string)process["cwd"] == @"C:\existing guest path");
        }
        File.AppendAllText(Environment.GetEnvironmentVariable("W365_MANUAL_FIXTURE_LOG"),
            Json.Serialize(new { operation = operation, dry = dry, request = request, pid = Process.GetCurrentProcess().Id,
                id = values.ContainsKey("--container-id") ? values["--container-id"] : null }) + "\n");
        if (dry)
        {
            if (scenario == "preflight_failure") return Error(operation, false);
            Print(new { result = new { } }); return 0;
        }
        if (operation == "provision")
        {
            if (scenario == "routing_write_failure") return Error(operation, true, "routing_state_write");
            if (scenario == "checkout_error_id") return Error(operation, true);
            if (scenario == "checkout_no_id") return Error(operation, false);
            if (scenario == "checkout_invalid")
            {
                Console.WriteLine("SYNTHETIC_SECRET invalid JSON"); return 0;
            }
            if (scenario == "checkout_bad_id")
            {
                Print(new { result = new { sandboxId = "not-a-valid-id" } }); return 0;
            }
            Print(new { result = new { sandboxId = Id,
                metadata = new { poolId = Pool, sessionId = Session, computerId = Session } } });
            return scenario == "checkout_nonzero" ? 9 : 0;
        }
        if (operation == "start")
        {
            if (scenario == "journal_write_failure")
                File.SetAttributes(Environment.GetEnvironmentVariable("W365_MANUAL_FIXTURE_RECEIPT"), FileAttributes.ReadOnly);
            if (scenario == "readiness_failure" || scenario == "primary_and_cleanup_failure") return Error(operation, true);
            if (scenario == "readiness_invalid") { Console.WriteLine("SYNTHETIC_SECRET"); return 0; }
            if (scenario == "long_readiness") Thread.Sleep(46000);
            Print(new { result = new { metadata = new {
                status = scenario == "readiness_live" ? "Live" : "Ready", capability = "microsoft.exec" } } });
            return 0;
        }
        if (operation == "exec")
        {
            Console.WriteLine("guest-output-first");
            if (scenario == "large_output")
            {
                Console.Out.Flush();
                Thread.Sleep(1500);
                Console.Write(new string('O', 524288));
                Console.Error.Write(new string('E', 524288));
                // This must not be interpreted as a lifecycle result.
                Console.WriteLine("{\"error\":{\"code\":\"guest_not_native\"}}");
            }
            if (scenario == "exec_timeout")
            {
                Console.Error.WriteLine("{\"error\":{\"code\":\"backend_error\",\"details\":{\"code\":\"exec_client_timeout\"}}}");
                return 1;
            }
            return scenario == "exec_nonzero" ? 23 : scenario == "exec_negative" ? -1 : 0;
        }
        if (scenario == "release_failure" || scenario == "primary_and_cleanup_failure") return Error(operation, true);
        if (scenario == "release_invalid") { Print(new { result = new { } }); return 0; }
        Print(new { result = new { metadata = new { releaseRequested = true, restartable = false } } });
        return 0;
    }
}
