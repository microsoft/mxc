# CLI + MXC Direct Dispatch Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make the Copilot CLI + MXC validation workflow directly dispatchable so its `copilot` environment secret is available to the private CLI checkout.

**Architecture:** The dedicated workflow becomes the only manual entry point and continues to own the T1 ScaleSet job. The scheduled backend workflow no longer exposes or calls the private-source lane, eliminating the reusable-workflow secret boundary that produced an empty checkout token.

**Tech Stack:** GitHub Actions, 1ES ScaleSet runners, GitHub environments and secrets, PowerShell 7.

---

## File map

| File | Responsibility |
|---|---|
| `.github/workflows/Validation.CopilotCli.Mxc.Job.yml` | Direct manual entry point and T1 build job. |
| `.github/workflows/Validation.Tests.Scheduled.yml` | Scheduled backend validation only. |
| `docs/ci-validation-infrastructure.md` | Operator instructions and credential flow. |
| `.github/copilot-instructions.md` | Repository-level workflow convention summary. |

### Task 1: Convert the dedicated workflow to direct dispatch

**Files:**
- Modify: `.github/workflows/Validation.CopilotCli.Mxc.Job.yml:1-5`
- Modify: `.github/workflows/Validation.Tests.Scheduled.yml:7-65`

- [ ] **Step 1: Change the dedicated workflow trigger**

Replace:

```yaml
on:
  workflow_call:
```

with:

```yaml
on:
  workflow_dispatch:
```

Keep:

```yaml
environment: copilot
runs-on: 1es-mxc-windows-prerelease-t1-x64
```

on the build job so the job receives the environment secret directly and uses
Elliot's ScaleSet runner syntax.

- [ ] **Step 2: Remove the broken scheduled-workflow option**

Remove `copilot-cli-build` from the `workflow_dispatch.inputs.plan.options`
list and remove this job:

```yaml
copilot-cli-build:
  if: github.event_name == 'workflow_dispatch' && inputs.plan == 'copilot-cli-build'
  uses: ./.github/workflows/Validation.CopilotCli.Mxc.Job.yml
```

Remove the `inputs.plan != 'copilot-cli-build'` guards from the dependency and
platform build jobs, restoring their prior behavior.

- [ ] **Step 3: Parse both workflow files**

Run:

```powershell
python -c "import yaml; [yaml.safe_load(open(p, encoding='utf-8')) for p in [r'.github\workflows\Validation.Tests.Scheduled.yml', r'.github\workflows\Validation.CopilotCli.Mxc.Job.yml']]; print('YAML parse OK')"
```

Expected: `YAML parse OK`.

- [ ] **Step 4: Commit the workflow change**

```powershell
git add -- .github/workflows/Validation.CopilotCli.Mxc.Job.yml .github/workflows/Validation.Tests.Scheduled.yml
git commit -m "Dispatch CLI MXC validation directly" -m "Co-authored-by: Copilot App <223556219+Copilot@users.noreply.github.com>"
```

### Task 2: Update operator documentation

**Files:**
- Modify: `docs/ci-validation-infrastructure.md`
- Modify: `.github/copilot-instructions.md`

- [ ] **Step 1: Update dispatch instructions**

State that operators run `Validation.CopilotCli.Mxc.Job.yml` directly with
`workflow_dispatch`. Remove claims that `Validation.Tests.Scheduled.yml` offers
a `copilot-cli-build` plan or calls the dedicated workflow.

- [ ] **Step 2: Document why the workflow is direct**

Add that the build job references `environment: copilot` directly so
`GHCP_CLI_SOURCE_READ` is available only to that job. Preserve the statement
that the secret is used only by the private checkout with
`persist-credentials: false`.

- [ ] **Step 3: Check the diff**

Run:

```powershell
git --no-pager diff --check
```

Expected: no output and exit code 0.

- [ ] **Step 4: Commit the documentation change**

```powershell
git add -- docs/ci-validation-infrastructure.md .github/copilot-instructions.md
git commit -m "Document direct CLI MXC validation dispatch" -m "Co-authored-by: Copilot App <223556219+Copilot@users.noreply.github.com>"
```

### Task 3: Push and prove the direct workflow

**Files:**
- Test: `.github/workflows/Validation.CopilotCli.Mxc.Job.yml`
- Test: `scripts/ci/test-copilot-cli-mxc-build.ps1`

- [ ] **Step 1: Run local contract tests**

Run:

```powershell
pwsh -NoProfile -File scripts/ci/test-copilot-cli-mxc-build.ps1
```

Expected: 14 passed, 0 failed.

- [ ] **Step 2: Push the feature branch**

Push `user/modanish/cli-mxc-1es-workflow` using the SSO-authorized GitHub
keyring credential. Do not commit or upload `.playwright-cli/`.

- [ ] **Step 3: Dispatch the dedicated workflow**

Run:

```powershell
$env:GH_TOKEN=''
$env:GITHUB_TOKEN=''
gh workflow run Validation.CopilotCli.Mxc.Job.yml `
  --repo microsoft/mxc `
  --ref user/modanish/cli-mxc-1es-workflow
```

Expected: GitHub returns a new Actions run URL.

- [ ] **Step 4: Verify runner and secret resolution**

Inspect the run and require:

- the job label is exactly `1es-mxc-windows-prerelease-t1-x64`;
- the runner is assigned;
- the log reports `Secret source: Environment`;
- `Check out Copilot CLI main` succeeds.

- [ ] **Step 5: Follow the build to completion**

Run:

```powershell
$runId = gh run list `
  --repo microsoft/mxc `
  --workflow Validation.CopilotCli.Mxc.Job.yml `
  --branch user/modanish/cli-mxc-1es-workflow `
  --event workflow_dispatch `
  --limit 1 `
  --json databaseId `
  --jq '.[0].databaseId'
gh run watch $runId --repo microsoft/mxc --exit-status
```

If the build fails after checkout, inspect
`gh run view $runId --repo microsoft/mxc --log-failed`,
apply the smallest compatibility correction, rerun local checks, push, and
dispatch again.

- [ ] **Step 6: Update the draft PR description**

Replace the cancelled/queued run reference with the terminal direct-dispatch
run and accurately state whether combined compilation and provenance passed.
