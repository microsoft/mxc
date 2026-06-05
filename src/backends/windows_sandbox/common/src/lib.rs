// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Windows Sandbox backend — shared code between `wxc-exec`, the
//! `wxc-windows-sandbox-daemon` host process, and the
//! `wxc-windows-sandbox-guest` agent inside the VM.

pub mod sandbox_protocol;
