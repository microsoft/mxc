// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

// Phase 3 introduces and tests the adapter before Phase 6 wires it into
// shadow exact-contract dispatch. The adapter is reachable as a `From`
// conversion on the wire model, so it needs no dead-code exemption while it
// is still unwired.
pub(crate) mod v0_6;
