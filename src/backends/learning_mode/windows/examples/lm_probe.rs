// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Manual validation probe for the Learning Mode trace API.
//!
//! Prints whether `processmodel.dll` on this machine exposes the
//! `StartLearningModeTrace` / `StopLearningModeTrace` exports. Intended to be run
//! on a feature-enabled OS build (e.g. a GE_CURRENT DirectWinPD image) to confirm
//! the runtime FFI resolves against the real API.
//!
//! ```text
//! cargo run -p learning_mode_windows --example lm_probe
//! ```

fn main() {
    let available = learning_mode_windows::is_learning_mode_api_available();
    println!("is_learning_mode_api_available = {available}");

    #[cfg(target_os = "windows")]
    {
        match learning_mode_windows::LearningModeApi::load() {
            Ok(api) => println!("LearningModeApi::load = OK  ({api:?})"),
            Err(e) => println!("LearningModeApi::load = ERR ({e})"),
        }
    }

    std::process::exit(if available { 0 } else { 2 });
}
