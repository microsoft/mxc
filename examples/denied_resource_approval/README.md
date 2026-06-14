# Denied Resource Approval — End-to-End Demo

This example demonstrates the **denied resource approval workflow** using the
MXC SDK. It shows how to:

1. **Spawn** a sandboxed process with a restrictive policy
2. **Detect failure** — the process exits non-zero due to access denials
3. **Parse denials** — extract denied filesystem paths from the output
4. **Prompt the user** — ask which paths should be granted access
5. **Regenerate the policy** — produce an updated `SandboxPolicy` with approved paths
6. **Re-run successfully** — execute the same script with the relaxed policy

## Prerequisites

- Windows 10/11 with MXC (`wxc-exec.exe`) built and available
- Python installed and on PATH
- Node.js ≥ 18

## Quick Start

```bash
# From the repo root, build the SDK first
cd sdk && npm install && npm run build && cd ..

# Then build and run this example
cd examples/denied_resource_approval
npm install
npm run build
npm start
```

## What Happens

The demo runs `test_script.py` inside a sandboxed AppContainer. The script
tries to write a file to a temporary directory that is **not** in the initial
policy's `readwritePaths`.

On the first run the script fails with a `PermissionError`. The example then:

- Calls `parseDeniedResources()` to extract the denied path from the error output
- Prompts you (interactively) to approve the path
- Calls `generateUpdatedPolicy()` to create a new policy with the path added
- Re-runs the sandbox with the updated policy — this time it succeeds

## Key SDK APIs Used

| Function | Module | Purpose |
|----------|--------|---------|
| `spawnSandboxAsync` | `sandbox.ts` | Run a sandboxed command and await output |
| `parseDeniedResources` | `denied-resources.ts` | Extract denied paths from process output |
| `generateUpdatedPolicy` | `policy-regen.ts` | Merge approved paths into a policy |

## File Layout

```
denied_resource_approval/
├── src/
│   └── index.ts          # Main demo orchestration
├── test_script.py        # Script executed inside the sandbox
├── package.json
├── tsconfig.json
└── README.md             # This file
```

## Non-Interactive Mode

To run without prompts (auto-approve all denials), set the environment variable:

```bash
set MXC_AUTO_APPROVE=1
npm start
```

(Not implemented in the base demo — left as an exercise or future enhancement.)
