# CLI + MXC Inline Dispatch Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Inline the Copilot CLI + MXC validation job into the existing dispatchable workflow so its `copilot` environment secret is available to the private CLI checkout before merge.

**Architecture:** `Validation.Tests.Scheduled.yml` remains the manual entry point because it already exists on the default branch. Its `copilot-cli-build` selection runs an inline T1 ScaleSet job with `environment: copilot`, eliminating the reusable-workflow secret boundary; the now-unusable dedicated workflow file is removed.

**Tech Stack:** GitHub Actions, 1ES ScaleSet runners, GitHub environments and secrets, PowerShell 7.

---

## File map

| File | Responsibility |
|---|---|
| `.github/workflows/Validation.CopilotCli.Mxc.Job.yml` | Remove the unusable direct/reusable entry point. |
| `.github/workflows/Validation.Tests.Scheduled.yml` | Existing manual entry point and inline T1 build job. |
| `docs/ci-validation-infrastructure.md` | Operator instructions and credential flow. |
| `.github/copilot-instructions.md` | Repository-level workflow convention summary. |

### Task 1: Inline the T1 job in the existing entry point

**Files:**
- Delete: `.github/workflows/Validation.CopilotCli.Mxc.Job.yml`
- Modify: `.github/workflows/Validation.Tests.Scheduled.yml`

- [ ] **Step 1: Restore the manual plan**

```yaml
options:
  - nightly
  - weekly
  - copilot-cli-build
```

- [ ] **Step 2: Skip backend builds only for the CLI plan**

```yaml
if: inputs.plan != 'copilot-cli-build'
```

Apply this guard to `dependency-feed-check`, `windows`, `linux`, and `macos`.

- [ ] **Step 3: Inline the T1 build job**

copilot-cli-build:
  if: github.event_name == 'workflow_dispatch' && inputs.plan == 'copilot-cli-build'
  environment: copilot
  runs-on: 1es-mxc-windows-prerelease-t1-x64
```

Move the checkout, inventory, build, evidence upload, and cleanup steps from the
dedicated workflow into this job, then delete the dedicated workflow file.

- [ ] **Step 4: Parse the scheduled workflow**

Run:

```powershell
python -c "import yaml; yaml.safe_load(open(r'.github\workflows\Validation.Tests.Scheduled.yml', encoding='utf-8')); print('YAML parse OK')"
```

Expected: `YAML parse OK`.

- [ ] **Step 5: Commit the workflow change**

```powershell
git add -- .github/workflows/Validation.CopilotCli.Mxc.Job.yml .github/workflows/Validation.Tests.Scheduled.yml
git commit -m "Inline CLI MXC validation job" -m "Co-authored-by: Copilot App <223556219+Copilot@users.noreply.github.com>"
```

### Task 2: Update operator documentation

**Files:**
- Modify: `docs/ci-validation-infrastructure.md`
- Modify: `.github/copilot-instructions.md`

- [ ] **Step 1: Update dispatch instructions**

State that operators dispatch `Validation.Tests.Scheduled.yml` with
`plan: copilot-cli-build`, which runs the T1 job directly rather than through a
reusable workflow.

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

### Task 3: Push and prove the inline workflow

**Files:**
- Test: `.github/workflows/Validation.Tests.Scheduled.yml`
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

- [ ] **Step 3: Dispatch the established workflow with the CLI plan**

Run:

```powershell
$env:GH_TOKEN=''
$env:GITHUB_TOKEN=''
gh workflow run Validation.Tests.Scheduled.yml `
  --repo microsoft/mxc `
  --ref user/modanish/cli-mxc-1es-workflow `
  -f plan=copilot-cli-build
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
  --workflow Validation.Tests.Scheduled.yml `
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
