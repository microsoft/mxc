# Hyperlight .NET Discovery Parity Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Restore C# SDK discovery parity after native discovery began reporting the Hyperlight backend.

**Architecture:** Keep the existing native-to-managed discovery flow unchanged and extend only its closed managed representation. Add one enum member, map the canonical `"hyperlight"` wire name through the shared parser used by both discovery APIs, and extend the existing table-driven unit test; retain `Unknown` for future unrecognized values.

**Tech Stack:** C#/.NET 10, xUnit, Rust-to-C# static parity gate in Node.js, Git, GitHub CLI

---

## File Map

- Modify `sdk/dotnet/Microsoft.Mxc.Sdk/PlatformDiscovery.cs`: add the public
  `ContainmentBackend.Hyperlight` discovery value.
- Modify `sdk/dotnet/Microsoft.Mxc.Sdk/MxcSandbox.cs`: map native wire value
  `"hyperlight"` to the new managed enum member.
- Modify `sdk/dotnet/Microsoft.Mxc.Sdk.Tests/MxcSandboxTests.cs`: add Hyperlight
  to the existing table-driven discovery parser test.
- Do not modify native probing, PR #1070 behavior, workflows, package sources,
  dependencies, `Cargo.lock`, or Copilot instructions.

### Task 1: Capture the regression and add the failing managed test

**Files:**
- Test: `sdk/dotnet/Microsoft.Mxc.Sdk.Tests/MxcSandboxTests.cs:182-195`
- Reference: `scripts/check-dotnet-api-parity.js:357-403`

- [ ] **Step 1: Reproduce the current-main parity failure before production edits**

Run from the repository root:

```powershell
node scripts/check-dotnet-api-parity.js
```

Expected: exit code `1` with both failures:

```text
C# API parity FAILED:
  - discovery backend enum: managed [Bubblewrap, IsolationSession, Lxc, ProcessContainer, Seatbelt, WindowsSandbox, Wslc], Rust [Bubblewrap, Hyperlight, IsolationSession, Lxc, ProcessContainer, Seatbelt, WindowsSandbox, Wslc]
  - discovery backend Hyperlight: managed wire "undefined", Rust wire "hyperlight"
```

- [ ] **Step 2: Add the Hyperlight row to the existing parser theory**

In `sdk/dotnet/Microsoft.Mxc.Sdk.Tests/MxcSandboxTests.cs`, replace the current
`Discovery_MapsEveryNativeBackend` theory declaration with:

```csharp
[Theory]
[InlineData("processcontainer", ContainmentBackend.ProcessContainer)]
[InlineData("windows_sandbox", ContainmentBackend.WindowsSandbox)]
[InlineData("lxc", ContainmentBackend.Lxc)]
[InlineData("wslc", ContainmentBackend.Wslc)]
[InlineData("seatbelt", ContainmentBackend.Seatbelt)]
[InlineData("isolation_session", ContainmentBackend.IsolationSession)]
[InlineData("bubblewrap", ContainmentBackend.Bubblewrap)]
[InlineData("hyperlight", ContainmentBackend.Hyperlight)]
public void Discovery_MapsEveryNativeBackend(
    string wireName,
    ContainmentBackend expected)
{
    Assert.Equal(expected, MxcSandbox.ParseBackend(wireName));
}
```

- [ ] **Step 3: Run the focused test to verify the new case is red**

Run from `sdk/dotnet`:

```powershell
dotnet test Microsoft.Mxc.Sdk.Tests\Microsoft.Mxc.Sdk.Tests.csproj --filter FullyQualifiedName~Discovery_MapsEveryNativeBackend
```

Expected: nonzero exit code with compiler error `CS0117` because
`ContainmentBackend` does not yet define `Hyperlight`.

If restore instead fails with Azure Artifacts HTTP 403, record it as an
external `ReadPackages` authorization block. Do not alter package sources,
credentials, dependencies, or CI to bypass it.

### Task 2: Add the minimal managed discovery implementation

**Files:**
- Modify: `sdk/dotnet/Microsoft.Mxc.Sdk/PlatformDiscovery.cs:9-34`
- Modify: `sdk/dotnet/Microsoft.Mxc.Sdk/MxcSandbox.cs:340-351`
- Test: `sdk/dotnet/Microsoft.Mxc.Sdk.Tests/MxcSandboxTests.cs:182-196`

- [ ] **Step 1: Add Hyperlight to the managed discovery enum**

In `sdk/dotnet/Microsoft.Mxc.Sdk/PlatformDiscovery.cs`, make the enum:

```csharp
/// <summary>A containment backend reported by native host discovery.</summary>
public enum ContainmentBackend
{
    /// <summary>A backend introduced by a newer native library.</summary>
    Unknown,

    /// <summary>Windows ProcessContainer (BaseContainer or AppContainer).</summary>
    ProcessContainer,

    /// <summary>Windows Sandbox.</summary>
    WindowsSandbox,

    /// <summary>Linux LXC.</summary>
    Lxc,

    /// <summary>Windows WSL Container.</summary>
    Wslc,

    /// <summary>macOS Seatbelt.</summary>
    Seatbelt,

    /// <summary>Windows IsolationSession.</summary>
    IsolationSession,

    /// <summary>Linux Bubblewrap.</summary>
    Bubblewrap,

    /// <summary>Hyperlight micro-VM.</summary>
    Hyperlight,
}
```

- [ ] **Step 2: Map the canonical native wire name**

In `sdk/dotnet/Microsoft.Mxc.Sdk/MxcSandbox.cs`, make `ParseBackend`:

```csharp
internal static ContainmentBackend ParseBackend(string value) =>
    value switch
    {
        "processcontainer" => ContainmentBackend.ProcessContainer,
        "windows_sandbox" => ContainmentBackend.WindowsSandbox,
        "lxc" => ContainmentBackend.Lxc,
        "wslc" => ContainmentBackend.Wslc,
        "seatbelt" => ContainmentBackend.Seatbelt,
        "isolation_session" => ContainmentBackend.IsolationSession,
        "bubblewrap" => ContainmentBackend.Bubblewrap,
        "hyperlight" => ContainmentBackend.Hyperlight,
        _ => ContainmentBackend.Unknown,
    };
```

- [ ] **Step 3: Run the focused discovery mapping test**

Run from `sdk/dotnet`:

```powershell
dotnet test Microsoft.Mxc.Sdk.Tests\Microsoft.Mxc.Sdk.Tests.csproj --filter FullyQualifiedName~Discovery_MapsEveryNativeBackend
```

Expected: exit code `0`; all eight `InlineData` cases pass with zero failures.

If the command is blocked by the external Azure Artifacts HTTP 403, do not
change code or feeds to work around it. Preserve the successful static parity
result from the next step and report the test as authorization-blocked.

- [ ] **Step 4: Run the Rust-to-C# API parity gate**

Run from the repository root:

```powershell
node scripts/check-dotnet-api-parity.js
```

Expected: exit code `0` and:

```text
C# API parity OK: request/policy fields, sandbox-id prefixes, 3 one-shot backends, 8 discovery backends, 1 capabilities
```

- [ ] **Step 5: Confirm unknown values remain forward-compatible**

Run from `sdk/dotnet`:

```powershell
dotnet test Microsoft.Mxc.Sdk.Tests\Microsoft.Mxc.Sdk.Tests.csproj --filter FullyQualifiedName~Discovery_PreservesUnknownNativeBackend
```

Expected: exit code `0`; both `"unknown"` and `"processContainer"` cases still
map to `ContainmentBackend.Unknown`, with zero failures.

### Task 3: Review and commit the production change

**Files:**
- Review: `sdk/dotnet/Microsoft.Mxc.Sdk/PlatformDiscovery.cs`
- Review: `sdk/dotnet/Microsoft.Mxc.Sdk/MxcSandbox.cs`
- Review: `sdk/dotnet/Microsoft.Mxc.Sdk.Tests/MxcSandboxTests.cs`

- [ ] **Step 1: Verify the diff is limited to the approved implementation**

Run from the repository root:

```powershell
git diff --check
git status --short
git --no-pager diff -- sdk/dotnet/Microsoft.Mxc.Sdk/PlatformDiscovery.cs sdk/dotnet/Microsoft.Mxc.Sdk/MxcSandbox.cs sdk/dotnet/Microsoft.Mxc.Sdk.Tests/MxcSandboxTests.cs
```

Expected: `git diff --check` emits no output; `git status --short` lists exactly
the three modified C# files; the diff contains one enum member, one parser case,
and one `InlineData` row.

- [ ] **Step 2: Run the code review gate**

Invoke the `council-code-review` skill on the current uncommitted diff, scoped
to the three C# files above. Require review of correctness, public API
compatibility, exact native wire-name parity, fallback preservation, and test
coverage.

Expected: no blocking or high-confidence findings. If the review identifies a
correctness issue, make only the directly required correction, then repeat
Task 2 Steps 3-5 and this review step before continuing.

- [ ] **Step 3: Commit only the implementation files**

Run from the repository root:

```powershell
git add -- sdk/dotnet/Microsoft.Mxc.Sdk/PlatformDiscovery.cs sdk/dotnet/Microsoft.Mxc.Sdk/MxcSandbox.cs sdk/dotnet/Microsoft.Mxc.Sdk.Tests/MxcSandboxTests.cs
git diff --cached --check
git commit -m "fix(dotnet): add Hyperlight discovery parity" -m "Co-authored-by: Copilot App <223556219+Copilot@users.noreply.github.com>"
```

Expected: one new commit containing exactly the three C# files.

- [ ] **Step 4: Verify the committed change**

Run:

```powershell
git status --short
git --no-pager show --stat --oneline --name-only HEAD
```

Expected: clean worktree and a commit listing only:

```text
sdk/dotnet/Microsoft.Mxc.Sdk/PlatformDiscovery.cs
sdk/dotnet/Microsoft.Mxc.Sdk/MxcSandbox.cs
sdk/dotnet/Microsoft.Mxc.Sdk.Tests/MxcSandboxTests.cs
```

### Task 4: Push and open the draft pull request

**Files:**
- Reference: `.github/PULL_REQUEST_TEMPLATE.md`
- No repository file modifications

- [ ] **Step 1: Push the implementation branch**

Run:

```powershell
git push --set-upstream origin HEAD
```

Expected: branch `user/modanish/hyperlight-dotnet-discovery-parity` is created
or updated on `origin` and configured as the local upstream.

- [ ] **Step 2: Create the draft PR with the repository template**

Run in PowerShell:

```powershell
$env:GH_TOKEN = ''
$env:GITHUB_TOKEN = ''
$body = @'
## 📖 Description

Adds the missing C# SDK discovery representation for Hyperlight after native discovery began reporting the backend. The change adds the managed enum member, maps the canonical `hyperlight` wire value, and covers it in the existing parser theory without changing runtime probing or launch behavior.

## 🔗 References

Related regression: #1059

## 🔍 Validation

- `node scripts/check-dotnet-api-parity.js`
- `dotnet test Microsoft.Mxc.Sdk.Tests\Microsoft.Mxc.Sdk.Tests.csproj --filter FullyQualifiedName~Discovery_MapsEveryNativeBackend`
- `dotnet test Microsoft.Mxc.Sdk.Tests\Microsoft.Mxc.Sdk.Tests.csproj --filter FullyQualifiedName~Discovery_PreservesUnknownNativeBackend`

## ✅ Checklist

- [x] Signed the [Contributor License Agreement](https://cla.opensource.microsoft.com)
- [ ] Linked to an issue
- [x] Updated documentation (if applicable)
- [ ] Updated [Copilot instructions](.github/copilot-instructions.md) (if build, architecture, or conventions changed)
- [x] If this PR changes `Cargo.lock`, the `dependency-feed-check` check passes (see [docs/pull-requests.md](https://github.com/microsoft/mxc/blob/main/docs/pull-requests.md))

## 📋 Issue Type

- [x] Bug fix
- [ ] Feature
- [ ] Task
'@
gh pr create --repo microsoft/mxc --base main --head user/modanish/hyperlight-dotnet-discovery-parity --draft --title "fix(dotnet): map Hyperlight discovery backend" --body $body
```

Expected: exit code `0` and the URL of a new draft pull request.

If `gh` reports SAML enforcement while an injected token is active, confirm
that both environment tokens are cleared exactly as shown and retry once using
the SSO-authorized keyring login. Do not change repository authentication or
embed credentials.

- [ ] **Step 3: Verify draft PR metadata**

Run:

```powershell
$env:GH_TOKEN = ''
$env:GITHUB_TOKEN = ''
gh pr view --repo microsoft/mxc user/modanish/hyperlight-dotnet-discovery-parity --json isDraft,title,baseRefName,headRefName --jq '{isDraft,title,baseRefName,headRefName}'
```

Expected:

```json
{
  "baseRefName": "main",
  "headRefName": "user/modanish/hyperlight-dotnet-discovery-parity",
  "isDraft": true,
  "title": "fix(dotnet): map Hyperlight discovery backend"
}
```

- [ ] **Step 4: Report delivery and any external validation block**

Report the implementation commit SHA and draft PR URL. State whether both
focused .NET tests passed; if Azure Artifacts returned HTTP 403, identify it
only as the external `ReadPackages` authorization block and do not describe the
implementation as the cause.
