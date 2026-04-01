# Configuration Strategy

## For Developers

Developers should to use public registries like `crates.io`
and `npmjs` directly so they can iterate quickly.

## For CI/Pipelines

### Central Feed Services
Production CI pipelines use an Azure Artifacts feed (CFS) to source dependencies
from crates.io and npmjs, helping ensure secure and vetted consumption of third‑party packages.
For Microsoft folks see: [Central Feed Services](https://eng.ms/docs/coreai/devdiv/one-engineering-system-1es/1es-docs/secure-supply-chain/central-feed-services-cfs/central-feed-services-cfs).

### Production Build and Release pipelines
- We use Azure pipelines for official builds with signing and public releases.

### PR Pipelines
- We use github actions but will be consolidated to use the azure pipelines which
  contain governance tasks, like binary scanning etc in the future.