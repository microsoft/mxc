// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using Dev = Microsoft.Mxc.Sdk.V1.Dev;
using Microsoft.Mxc.Sdk.V1;
using Xunit;

namespace Microsoft.Mxc.Sdk.Tests;

public class DevEntryPointTests
{
    [Fact]
    public async Task DevEntryPointsRejectInvalidDocumentsWithoutLaunching()
    {
        var synchronous = Assert.Throws<MxcException>(
            () => Dev.MxcContainer.SpawnWithPtyJson("{}"));
        Assert.Equal(ErrorCode.MalformedRequest, synchronous.Code);

        var asynchronous = await Assert.ThrowsAsync<MxcException>(
            () => Dev.MxcLifecycle.ProvisionContainerJsonAsync("{}"));
        Assert.Equal(ErrorCode.MalformedRequest, asynchronous.Code);
    }

    [Fact]
    public async Task PhaseSpecificMethodsRejectMismatchesBeforeDispatch()
    {
        const string start = """{"version":"1.0.0","phase":"start","sandboxId":"iso:unused"}""";
        var sync = Assert.Throws<MxcException>(() => Dev.MxcLifecycle.StopContainerJson(start));
        Assert.Equal(ErrorCode.MalformedRequest, sync.Code);
        Assert.Contains("requires phase 'stop'", sync.Message);

        var asynchronous = await Assert.ThrowsAsync<MxcException>(
            () => Dev.MxcLifecycle.ValidateProcessJsonAsync(start));
        Assert.Equal(ErrorCode.MalformedRequest, asynchronous.Code);

        var exec = Assert.Throws<MxcException>(
            () => Dev.MxcLifecycle.SpawnInContainerJson(start));
        Assert.Equal(ErrorCode.MalformedRequest, exec.Code);

        const string duplicate =
            """{"version":"1.0.0","phase":"start","phase":"stop","sandboxId":"iso:unused"}""";
        var repeated = Assert.Throws<MxcException>(
            () => Dev.MxcLifecycle.StartContainerJson(duplicate));
        Assert.Equal(ErrorCode.MalformedRequest, repeated.Code);
    }

    [Fact]
    public async Task CapturedExecValidatesBeforeCanceledSpawn()
    {
        const string start = """{"version":"1.0.0","phase":"start","sandboxId":"iso:unused"}""";
        var error = await Assert.ThrowsAsync<MxcException>(
            () => Dev.MxcLifecycle.RunInContainerJsonAsync(
                start, cancellationToken: new CancellationToken(true)));
        Assert.Equal(ErrorCode.MalformedRequest, error.Code);
        Assert.Contains("RunInContainerJson requires phase 'exec'", error.Message);
    }

    [Theory]
    [InlineData(null)]
    [InlineData("exec")]
    public void PreparationPreservesUnicodeJsonAndExtractsTimeout(string? phase)
    {
        var json =
            " {\"version\":\"1.1.0-alpha\",\"_comment\":\"caf\u00e9 \ud83d\ude00\"," +
            (phase is null ? "" : "\"phase\":\"exec\",\"sandboxId\":\"iso:unused\",") +
            "\"process\":{\"commandLine\":\"echo\",\"timeout\":250}} ";
        var (request, timeout) = Dev.DevJsonRequest.Prepare(
            json, nameof(PreparationPreservesUnicodeJsonAndExtractsTimeout), phase);
        Assert.Equal((uint?)250, timeout);
        Assert.Equal((byte)0, request[^1]);
        Assert.Equal(json, Encoding.UTF8.GetString(request.AsSpan(0, request.Length - 1)));
    }

    [Fact]
    public void ExactContractErrorsReachPublicDevFacade()
    {
        const string unregistered =
            """{"version":"999.0.0","process":{"commandLine":"echo must-not-run"}}""";
        var error = Assert.Throws<MxcException>(() => Dev.MxcContainer.RunJson(unregistered));
        Assert.Equal(ErrorCode.MalformedRequest, error.Code);

        const string unknownField =
            """{"version":"1.0.0","phase":"start","sandboxId":"iso:unused","extra":true}""";
        error = Assert.Throws<MxcException>(
            () => Dev.MxcLifecycle.ValidateStartJson(unknownField));
        Assert.Equal(ErrorCode.MalformedRequest, error.Code);
    }

    [Fact]
    public void ExperimentalAuthorizationIsSeparateFromTheDevelopmentContract()
    {
        const string json =
            """{"version":"1.1.0-alpha","phase":"provision","containment":"windows_sandbox"}""";
        var error = Assert.Throws<MxcException>(
            () => Dev.MxcLifecycle.ValidateProvisionJson(json));
        Assert.Equal(ErrorCode.BackendUnavailable, error.Code);
        Assert.Contains("experimental", error.Message);

        try
        {
            Dev.MxcLifecycle.ValidateProvisionJson(json, new Dev.JsonOptions { Experimental = true });
        }
        catch (MxcException authorized)
        {
            Assert.NotEqual(ErrorCode.BackendUnavailable, authorized.Code);
        }
    }

    [Fact]
    public void EmbeddedNullCannotChangeTheNativeDocument()
    {
        const string json = """{"version":"1.0.0","process":{"commandLine":"echo"}}""" + "\0";
        var error = Assert.Throws<MxcException>(() => Dev.MxcContainer.RunJson(json));
        Assert.Equal(ErrorCode.MalformedRequest, error.Code);
    }

    [Theory]
    [InlineData('\uD800')]
    [InlineData('\uDC00')]
    public async Task LoneSurrogatesAreMalformedRequests(char surrogate)
    {
        var creation = """{"version":"1.0.0","process":{"commandLine":"echo"}}""" + surrogate;
        var start = """{"version":"1.0.0","phase":"start","sandboxId":"iso:unused"}""" + surrogate;
        var sync = Assert.Throws<MxcException>(() => Dev.MxcContainer.RunJson(creation));
        Assert.Equal(ErrorCode.MalformedRequest, sync.Code);
        sync = Assert.Throws<MxcException>(() => Dev.MxcLifecycle.StartContainerJson(start));
        Assert.Equal(ErrorCode.MalformedRequest, sync.Code);

        var asynchronous = await Assert.ThrowsAsync<MxcException>(
            () => Dev.MxcContainer.RunJsonAsync(
                creation, cancellationToken: TestContext.Current.CancellationToken));
        Assert.Equal(ErrorCode.MalformedRequest, asynchronous.Code);
        asynchronous = await Assert.ThrowsAsync<MxcException>(
            () => Dev.MxcLifecycle.StartContainerJsonAsync(start));
        Assert.Equal(ErrorCode.MalformedRequest, asynchronous.Code);
    }

    [Fact]
    public void DeepCommentReachesNativeExactParser()
    {
        static string Request(int depth) =>
            "{\"version\":\"1.0.0\",\"phase\":\"start\",\"sandboxId\":\"nosuchbackend:abc123\",\"_comment\":" +
            new string('[', depth) + "0" + new string(']', depth) + "}";

        var accepted = Assert.Throws<MxcException>(
            () => Dev.MxcLifecycle.ValidateStartJson(Request(70)));
        Assert.Equal(ErrorCode.UnsupportedContainment, accepted.Code);

        var tooDeep = Assert.Throws<MxcException>(
            () => Dev.MxcLifecycle.ValidateStartJson(Request(130)));
        Assert.Equal(ErrorCode.MalformedRequest, tooDeep.Code);
    }

    [Fact]
    public void ExistingContainerExecReachesNativeBackendValidation()
    {
        const string json =
            """{"version":"1.0.0","phase":"exec","sandboxId":"nosuchbackend:abc123","process":{"commandLine":"echo hi"}}""";
        var error = Assert.Throws<MxcException>(
            () => Dev.MxcLifecycle.SpawnInContainerJson(json));
        Assert.Equal(ErrorCode.UnsupportedContainment, error.Code);
    }

    [Fact]
    public void PtyEntryPointsHaveNoAsyncOverloads()
    {
        Assert.Null(typeof(Dev.MxcContainer).GetMethod("SpawnWithPtyJsonAsync"));
        Assert.Null(typeof(Dev.MxcLifecycle).GetMethod("SpawnInContainerWithPtyJsonAsync"));
    }

    [Fact]
    public void DevOptionsAreClosedAndTerminalControlsStayWithPtyOperations()
    {
        Assert.True(typeof(Dev.JsonOptions).IsSealed);
        Assert.True(typeof(Dev.PtyJsonOptions).IsSealed);
        Assert.False(typeof(Dev.JsonOptions).IsAssignableFrom(typeof(Dev.PtyJsonOptions)));
        Assert.Null(typeof(Dev.PtyJsonOptions).GetProperty(nameof(Dev.JsonOptions.PolicyFailures)));
    }

    [Fact]
    public void PolicyFeedbackStoragePreservesUnknownValuesBatchBoundariesAndResourcePresence()
    {
        ushort[] malformedResource = [0xD800, 0, 0xDC00];
        var feedback = new Dev.PolicyFailures
        {
            Results =
            [
                new()
                {
                    Version = 99,
                    MinimumReaderVersion = 98,
                    Outcome = uint.MaxValue,
                    Details =
                    [
                        new()
                        {
                            FailureClass = uint.MaxValue,
                            FailureReason = uint.MaxValue - 1,
                            RequiredAction = uint.MaxValue - 2,
                            ResourceKind = uint.MaxValue - 3,
                            ValueKind = uint.MaxValue - 4,
                            Flags = uint.MaxValue,
                            RequestedValue = ulong.MaxValue,
                            RequiredValue = 9_007_199_254_740_993,
                            Resource = malformedResource,
                        },
                        new() { Resource = [] },
                        new(),
                        new() { Resource = [0xD83D, 0xDE00] },
                    ],
                },
                new()
                {
                    Outcome = Dev.PolicyFailureOutcomes.Blocked,
                    Details =
                    [
                        new()
                        {
                            FailureClass = Dev.PolicyFailureClasses.Filesystem,
                            FailureReason = Dev.PolicyFailureReasons.AccessExceedsCeiling,
                            RequiredAction = Dev.PolicyFailureActions.RestrictFilesystemAccess,
                            ResourceKind = Dev.PolicyFailureResourceKinds.Path,
                            ValueKind = Dev.PolicyFailureValueKinds.Access,
                            Flags = Dev.PolicyFailureFlags.HasActionableDetails | Dev.PolicyFailureFlags.ResourceComplete,
                            RequestedValue = Dev.PolicyFailureAccessValues.ReadWrite,
                            RequiredValue = Dev.PolicyFailureAccessValues.ReadOnly,
                        },
                    ],
                },
            ],
        };

        var stored = feedback.ToJson();
        var restored = Dev.PolicyFailures.FromJson(stored);
        Assert.Equal(stored, restored.ToJson());
        Assert.Equal(2, restored.Results.Length);
        Assert.Equal((uint)99, restored.Results[0].Version);
        Assert.Equal((uint)98, restored.Results[0].MinimumReaderVersion);
        Assert.Equal(uint.MaxValue, restored.Results[0].Outcome);
        var first = restored.Results[0].Details[0];
        Assert.Equal(ulong.MaxValue, first.RequestedValue);
        Assert.Equal(9_007_199_254_740_993UL, first.RequiredValue);
        Assert.Equal(uint.MaxValue, first.Flags);
        Assert.Equal(malformedResource, first.Resource);
        var decoding = Assert.Throws<DecoderFallbackException>(() => first.GetResourceText());
        Assert.Equal("policy resource is not valid UTF-16", decoding.Message);
        Assert.Null(decoding.InnerException);
        Assert.Equal(string.Empty, restored.Results[0].Details[1].GetResourceText());
        Assert.Null(restored.Results[0].Details[2].GetResourceText());
        Assert.Equal("\uD83D\uDE00", restored.Results[0].Details[3].GetResourceText());
        using var document = JsonDocument.Parse(stored);
        var known = document.RootElement.GetProperty("results")[1];
        Assert.Equal(1u, known.GetProperty("outcome").GetUInt32());
        Assert.True(JsonNode.DeepEquals(
            JsonNode.Parse("""
                {"failureClass":2,"failureReason":2,"requiredAction":2,"resourceKind":1,
                 "valueKind":1,"flags":3,"requestedValue":"2","requiredValue":"1"}
                """),
            JsonNode.Parse(known.GetProperty("details")[0].GetRawText())));
        var details = document.RootElement.GetProperty("results")[0].GetProperty("details");
        Assert.Equal("18446744073709551615", details[0].GetProperty("requestedValue").GetString());
        Assert.Equal("9007199254740993", details[0].GetProperty("requiredValue").GetString());
        Assert.Equal(0, details[1].GetProperty("resource").GetArrayLength());
        Assert.False(details[2].TryGetProperty("resource", out _));
        var prepared = Dev.DevJsonRequest.PreparePolicyFailures(restored)!;
        Assert.Equal(stored, Encoding.UTF8.GetString(prepared.AsSpan(0, prepared.Length - 1)));
        Assert.Equal((byte)0, prepared[^1]);
        Assert.Equal(new ushort[] { 0xD800, 0, 0xDC00 }, malformedResource);
        Assert.Equal(stored, feedback.ToJson());
        var nullable = JsonNode.Parse(stored)!;
        nullable["results"]![0]!["details"]![2]!["resource"] = null;
        var normalized = Dev.PolicyFailures.FromJson(nullable.ToJsonString());
        Assert.Null(normalized.Results[0].Details[2].Resource);
        Assert.Equal(stored, normalized.ToJson());
    }

    [Fact]
    public void PolicyFeedbackStorageRejectsInvalidShapeVersionAndLossyValues()
    {
        foreach (var json in new[]
        {
            "null", "[]", "{}",
            """{"formatVersion":2,"results":[]}""",
            """{"formatVersion":1,"results":null}""",
            """{"formatVersion":1,"results":[null]}""",
            """{"formatVersion":1,"results":[],"extra":true}""",
            """{"formatVersion":1,"formatVersion":1,"results":[]}""",
            """{"formatVersion":1,"results":[{"version":1,"minimumReaderVersion":1,"outcome":1,"details":null}]}""",
        })
        {
            Assert.Throws<JsonException>(() => Dev.PolicyFailures.FromJson(json));
        }

        var valid = new Dev.PolicyFailures
        {
            Results = [new() { Details = [new() { RequestedValue = ulong.MaxValue }] }],
        }.ToJson();
        foreach (var invalid in new[] { "2", "\"18446744073709551616\"", "\"-1\"", "\"+1\"", "\"1\\u0000\"" })
        {
            var json = JsonNode.Parse(valid)!;
            json["results"]![0]!["details"]![0]!["requestedValue"] = JsonNode.Parse(invalid);
            Assert.Throws<JsonException>(() => Dev.PolicyFailures.FromJson(json.ToJsonString()));
        }
        foreach (var invalid in new[] { """{"extra":true}""", """{"resource":[65536]}""", """{"flags":-1}""" })
        {
            var json = JsonNode.Parse(valid)!;
            foreach (var property in JsonNode.Parse(invalid)!.AsObject())
            {
                json["results"]![0]!["details"]![0]![property.Key] = property.Value?.DeepClone();
            }
            Assert.Throws<JsonException>(() => Dev.PolicyFailures.FromJson(json.ToJsonString()));
        }
    }

    [Fact]
    public void MalformedPolicyFeedbackDoesNotLeakInputIntoValidationErrors()
    {
        const string marker = "MXC_MALFORMED_POLICY_STRUCTURED_ONLY_9D133E1B";
        var unknown = $$$"""{"formatVersion":1,"results":[],"{{{marker}}}":"private resource"}""";
        var duplicate = $$$"""{"formatVersion":1,"results":[],"{{{marker}}}":true,"{{{marker}}}":false}""";
        foreach (var json in new[] { unknown, duplicate })
        {
            AssertGenericValidationError(Assert.Throws<JsonException>(
                () => Dev.PolicyFailures.FromJson(json)));
            using var document = JsonDocument.Parse(
                $$$"""{"policyFailures":{{{json}}},"backend":"preserved"}""");
            var original = new MxcException(ErrorCode.BackendError, "creation refused",
                "PSEC.Create", "0x80070005", null, document.RootElement);
            AssertGenericValidationError(Assert.Throws<JsonException>(
                () => Dev.PolicyFailures.FromException(original)));
            Assert.Contains(marker, original.Details!.Value.GetRawText());
            Assert.Equal("preserved", original.Details.Value.GetProperty("backend").GetString());
            Assert.Equal("creation refused", original.Message);
            Assert.Equal("PSEC.Create", original.Operation);
            Assert.Equal("0x80070005", original.NativeCode);
        }
        AssertGenericValidationError(Assert.Throws<JsonException>(
            () => Dev.PolicyFailures.FromJson(unknown[..^1])));

        static void AssertGenericValidationError(JsonException error)
        {
            Assert.Equal("invalid stored policy-failure feedback", error.Message);
            Assert.DoesNotContain(marker, error.Message);
            Assert.DoesNotContain(marker, error.ToString());
            Assert.Null(error.InnerException);
        }
    }

    [Fact]
    public async Task StoredTerminalFeedbackReachesNativeCreationLimitsWithoutMutatingInputs()
    {
        var terminal = new Dev.PolicyFailures
        {
            Results = Enumerable.Range(0, 65)
                .Select(index => new Dev.PolicyFailureResult { Outcome = (uint)index }).ToArray(),
        };
        var stored = terminal.ToJson();
        var options = new Dev.JsonOptions { PolicyFailures = Dev.PolicyFailures.FromJson(stored) };
        const string request =
            """{"version":"1.0.0","containment":"process","process":{"commandLine":"must-not-run","timeout":1000}}""";

        var run = Assert.Throws<MxcException>(() => Dev.MxcContainer.RunJson(request, options));
        var spawn = Assert.Throws<MxcException>(() => Dev.MxcContainer.SpawnJson(request, options));
        var runAsync = await Assert.ThrowsAsync<MxcException>(
            () => Dev.MxcContainer.RunJsonAsync(request, options, TestContext.Current.CancellationToken));
        var spawnAsync = await Assert.ThrowsAsync<MxcException>(
            () => Dev.MxcContainer.SpawnJsonAsync(request, options, TestContext.Current.CancellationToken));
        Assert.All(new[] { run, spawn, runAsync, spawnAsync }, error =>
        {
            Assert.Equal(ErrorCode.MalformedRequest, error.Code);
            Assert.Contains("result limit", error.Message);
        });
        Assert.Equal(stored, options.PolicyFailures!.ToJson());
        Assert.Equal(stored, terminal.ToJson());

        var tooMany = new Dev.PolicyFailures
        {
            Results = Enumerable.Repeat(new Dev.PolicyFailureResult(), 66).ToArray(),
        };
        Assert.Throws<JsonException>(() => tooMany.ToJson());
        var tooManyDetails = new Dev.PolicyFailures
        {
            Results = [new() { Details = Enumerable.Repeat(new Dev.PolicyFailureDetail(), 65).ToArray() }],
        };
        Assert.Throws<JsonException>(() => tooManyDetails.ToJson());
    }

    [Fact]
    public void TerminalFeedbackStorageKeepsTheCompleteExtraNativeBatch()
    {
        var results = Enumerable.Range(0, 17)
            .Select(index => new Dev.PolicyFailureResult
            {
                Outcome = (uint)index,
                Details = Enumerable.Range(0, 64)
                    .Select(detail => new Dev.PolicyFailureDetail
                    {
                        Resource = index < 9 && detail == 0 ? new ushort[32_767] : null,
                    }).ToArray(),
            }).ToArray();
        var terminal = new Dev.PolicyFailures { Results = results };
        var restored = Dev.PolicyFailures.FromJson(terminal.ToJson());
        Assert.Equal(1088, restored.Results.Sum(result => result.Details.Length));
        Assert.Equal(294_912, restored.Results.Sum(result =>
            result.Details.Sum(detail => detail.Resource is null ? 0 : detail.Resource.Length + 1)));

        var tooManyDetails = new Dev.PolicyFailures
        {
            Results = [.. results, new() { Details = [new()] }],
        };
        Assert.Throws<JsonException>(() => tooManyDetails.ToJson());
        var tooManyUnits = new Dev.PolicyFailures
        {
            Results = [
                .. Enumerable.Range(0, 9).Select(_ => new Dev.PolicyFailureResult
                {
                    Details = [new() { Resource = new ushort[32_767] }],
                }),
                new() { Details = [new() { Resource = [] }] },
            ],
        };
        Assert.Equal(10, tooManyUnits.Results.Sum(result => result.Details.Length));
        Assert.Throws<JsonException>(() => tooManyUnits.ToJson());
        Assert.Throws<JsonException>(() => new Dev.PolicyFailures
        {
            Results = [new() { Details = [new() { Resource = new ushort[32_768] }] }],
        }.ToJson());
        Assert.Throws<JsonException>(() => Dev.PolicyFailures.FromJson(
            new string(' ', 4 * 1024 * 1024 + 512 * 1024) + "{}"));
        Assert.Equal(1088, terminal.Results.Sum(result => result.Details.Length));
    }

    [Fact]
    public async Task SharedJsonOptionsRejectFeedbackOnEveryLifecycleAndValidationOperation()
    {
        var options = new Dev.JsonOptions { PolicyFailures = new Dev.PolicyFailures() };
        Action[] synchronous =
        [
            () => Dev.MxcLifecycle.RunInContainerJson("{}", options),
            () => Dev.MxcLifecycle.SpawnInContainerJson("{}", options),
            () => Dev.MxcLifecycle.ProvisionContainerJson("{}", options),
            () => Dev.MxcLifecycle.StartContainerJson("{}", options),
            () => Dev.MxcLifecycle.StopContainerJson("{}", options),
            () => Dev.MxcLifecycle.DeprovisionContainerJson("{}", options),
            () => Dev.MxcLifecycle.ValidateProvisionJson("{}", options),
            () => Dev.MxcLifecycle.ValidateStartJson("{}", options),
            () => Dev.MxcLifecycle.ValidateStopJson("{}", options),
            () => Dev.MxcLifecycle.ValidateDeprovisionJson("{}", options),
            () => Dev.MxcLifecycle.ValidateProcessJson("{}", options),
        ];
        Func<Task>[] asynchronous =
        [
            () => Dev.MxcLifecycle.RunInContainerJsonAsync("{}", options, TestContext.Current.CancellationToken),
            () => Dev.MxcLifecycle.SpawnInContainerJsonAsync("{}", options, TestContext.Current.CancellationToken),
            () => Dev.MxcLifecycle.ProvisionContainerJsonAsync("{}", options),
            () => Dev.MxcLifecycle.StartContainerJsonAsync("{}", options),
            () => Dev.MxcLifecycle.StopContainerJsonAsync("{}", options),
            () => Dev.MxcLifecycle.DeprovisionContainerJsonAsync("{}", options),
            () => Dev.MxcLifecycle.ValidateProvisionJsonAsync("{}", options),
            () => Dev.MxcLifecycle.ValidateStartJsonAsync("{}", options),
            () => Dev.MxcLifecycle.ValidateStopJsonAsync("{}", options),
            () => Dev.MxcLifecycle.ValidateDeprovisionJsonAsync("{}", options),
            () => Dev.MxcLifecycle.ValidateProcessJsonAsync("{}", options),
        ];
        foreach (var call in synchronous)
        {
            AssertUnsupportedFeedback(Assert.Throws<MxcException>(call));
        }
        foreach (var call in asynchronous)
        {
            AssertUnsupportedFeedback(await Assert.ThrowsAsync<MxcException>(call));
        }
        Assert.Empty(options.PolicyFailures.Results);
    }

    private static void AssertUnsupportedFeedback(MxcException error)
    {
        Assert.Equal(ErrorCode.MalformedRequest, error.Code);
        Assert.Contains("does not accept PolicyFailures", error.Message);
    }
}
