// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Manual validation probe for the Learning Mode trace + security-environment API.
//!
//! Prints whether `processmodel.dll` on this machine exposes the Learning Mode trace
//! exports (`StartLearningModeTrace` / `StopLearningModeTrace`) and the 2-phase
//! security-environment exports (`CreateProcessSecurityEnvironment` /
//! `CreateProcessAsUserInsideSecurityEnvironment` / `CloseProcessSecurityEnvironment`),
//! reporting the exact resolved name for each (plain vs `Experimental_`). Intended to
//! be run on a feature-enabled Windows build to confirm the runtime FFI resolves
//! against the real API.
//!
//! ```text
//! cargo run -p learning_mode_windows --example lm_probe
//! ```

fn main() {
    let learning_mode_available = learning_mode_windows::is_learning_mode_api_available();
    println!("is_learning_mode_api_available = {learning_mode_available}");

    #[cfg(target_os = "windows")]
    let available = {
        match learning_mode_windows::LearningModeApi::load() {
            Ok(api) => println!("LearningModeApi::load = OK  ({api:?})"),
            Err(e) => println!("LearningModeApi::load = ERR ({e})"),
        }

        let secenv_available = learning_mode_windows::is_security_environment_api_available();
        println!("is_security_environment_api_available = {secenv_available}");

        let report = learning_mode_windows::probe_security_environment_exports();
        println!("  create export = {:?}", report.create);
        println!("  launch export = {:?}", report.launch);
        println!("  close  export = {:?}", report.close);

        match learning_mode_windows::SecurityEnvironmentApi::load() {
            Ok(api) => println!("SecurityEnvironmentApi::load = OK  ({api:?})"),
            Err(e) => println!("SecurityEnvironmentApi::load = ERR ({e})"),
        }

        learning_mode_available && secenv_available
    };

    #[cfg(not(target_os = "windows"))]
    let available = false;

    std::process::exit(if available { 0 } else { 2 });
}
