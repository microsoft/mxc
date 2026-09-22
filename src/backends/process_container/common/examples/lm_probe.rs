// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Manual validation probe for the Learning Mode trace + security-environment API.
//!
//! Prints whether `processmodel.dll` on this machine exposes the Learning Mode trace
//! exports (`StartLearningModeTrace` / `StopLearningModeTrace` /
//! `CloseLearningModeTrace`) and the 2-phase security-environment exports
//! (`CreateProcessSecurityEnvironment` /
//! `QueryProcessSecurityEnvironmentSupport` /
//! `CloseProcessSecurityEnvironment`),
//! reporting each official export that resolves. Intended to be run on a
//! feature-enabled Windows build to confirm the runtime FFI resolves against the real API.
//!
//! ```text
//! cargo run -p process_container_common --example lm_probe
//! ```

fn main() {
    std::process::exit(run_probe());
}

#[cfg(target_os = "windows")]
fn run_probe() -> i32 {
    let learning_mode_available = learning_mode_windows::is_learning_mode_api_available();
    println!("is_learning_mode_api_available = {learning_mode_available}");

    match learning_mode_windows::LearningModeApi::load() {
        Ok(api) => println!("LearningModeApi::load = OK  ({api:?})"),
        Err(e) => println!("LearningModeApi::load = ERR ({e})"),
    }

    let secenv_available = process_container_common::is_security_environment_api_available();
    println!("is_security_environment_api_available = {secenv_available}");

    let report = process_container_common::probe_security_environment_exports();
    println!("  create export = {:?}", report.create);
    println!("  query support = {:?}", report.query_support);
    println!("  close  export = {:?}", report.close);

    match process_container_common::ProcessSecurityEnvironmentApi::load() {
        Ok(api) => println!("ProcessSecurityEnvironmentApi::load = OK  ({api:?})"),
        Err(e) => println!("ProcessSecurityEnvironmentApi::load = ERR ({e})"),
    }

    if learning_mode_available && secenv_available {
        0
    } else {
        2
    }
}

#[cfg(not(target_os = "windows"))]
fn run_probe() -> i32 {
    println!("is_learning_mode_api_available = false");
    2
}
