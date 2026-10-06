# MXC administrative WSLC registry allowlist

> **Audience:** MXC consumers

MXC pulls a WSL Container image from its registry when a run names an image the
machine has not cached. An administrator can restrict which registries that pull
may contact.

## The setting

| | |
|---|---|
| Key | `HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Mxc` |
| Value | `WslcAllowedImageRegistries` |
| Type | `REG_MULTI_SZ` |

Each string is a registry host, matched case-insensitively against the host in
the image reference. A reference with no registry — `alpine:latest`,
`library/alpine` — resolves against `docker.io`, so permit `docker.io`
explicitly to allow short names.

The key sits under `SOFTWARE\Policies`, which only administrators can write, so
a standard user cannot widen the list. It is the same key the telemetry policy
uses; see
[`telemetry-administrative-policy.md`](../telemetry/telemetry-administrative-policy.md).

### Values

| State | Meaning |
|---|---|
| Value absent | Unmanaged. Any registry may be contacted. |
| One or more hosts | Only those hosts may be contacted. |
| Present but empty | No registry may be contacted. |
| Present but unreadable | No registry may be contacted. |

An unreadable value — the wrong type, or an ACL that hides the key — denies
rather than falling back to unmanaged, so a misconfigured policy produces the
restriction the administrator was reaching for instead of the open default they
were not.

## What it governs

The allowlist governs **runtime pulls only**: the fetch MXC performs on a cache
miss during a run.

It does not govern `wxc-exec.exe --setup-wslc`, which an operator runs
deliberately to warm a cache, nor `wslc.imageTarPath`, which reaches no
registry. Restricting registries does not prevent an operator from preparing a
machine, and it does not block a run whose image is already cached.

## Deploying it

```powershell
# Permit only these two registries, machine-wide. Run elevated.
New-Item -Path 'HKLM:\SOFTWARE\Policies\Mxc' -Force | Out-Null
New-ItemProperty -Path 'HKLM:\SOFTWARE\Policies\Mxc' `
    -Name 'WslcAllowedImageRegistries' `
    -PropertyType MultiString `
    -Value @('mcr.microsoft.com', 'ghcr.io') `
    -Force | Out-Null
```

To return the machine to unmanaged, remove the value:

```powershell
Remove-ItemProperty -Path 'HKLM:\SOFTWARE\Policies\Mxc' `
    -Name 'WslcAllowedImageRegistries' -ErrorAction SilentlyContinue
```

### Verifying

Run a config naming an image from a registry the policy does not list, against
a machine that has not cached it. The run fails without contacting the
registry, and the error names the offending host and the policy value:

```text
WSLC image 'docker.io/library/alpine:3' cannot be pulled: 'docker.io' is not in
the administrative registry allowlist (SOFTWARE\Policies\Mxc\
WslcAllowedImageRegistries). Use a permitted registry, or supply the image with
wslc.imageTarPath.
```

## Relationship to the WSLC SDK's own policy

The WSLC SDK can independently refuse a registry, reporting
`WSLC_E_REGISTRY_BLOCKED_BY_POLICY`. That decision is made below MXC and is not
configurable through this value; MXC surfaces the refusal but cannot relax it.
This allowlist is the control an MXC administrator owns, and it applies before
the SDK is asked to pull at all.

## See also

- [`wsl-container-getting-started.md`](wsl-container-getting-started.md) — running WSLC workloads
- [`telemetry-administrative-policy.md`](../telemetry/telemetry-administrative-policy.md) — the other policy under the same key
