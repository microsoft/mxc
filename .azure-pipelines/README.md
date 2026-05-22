# Configuration Strategy

## For Developers

Developers should use public registries like `crates.io`
and `npmjs` directly so they can iterate quickly.

## For CI/Pipelines

### Central Feed Services
Production CI pipelines use an Azure Artifacts feed (CFS) to source dependencies
from crates.io and npmjs, helping ensure secure and vetted consumption of third‑party packages.
(Microsoft engineers can consult the internal "Central Feed Services" documentation for setup details; external readers can treat the centralized feed as a Microsoft-internal Azure Artifacts mirror of the public registries.)

### Production Build and Release pipelines
- We use Azure pipelines for official builds with signing and public releases.

### PR Pipelines
- We use github actions but will be consolidated to use the azure pipelines which
  contain governance tasks, like binary scanning etc in the future.