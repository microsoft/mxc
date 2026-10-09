use std::time::{SystemTime, UNIX_EPOCH};

use mxc_sdk::v1::WaitResult;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let nonce = format!(
        "mxc-nvx-{}-{}",
        std::process::id(),
        SystemTime::now().duration_since(UNIX_EPOCH)?.as_nanos()
    );
    let command = format!("printf '%s\\n' '{nonce}'; cat /etc/os-release");
    let request = serde_json::json!({
        "version": "1.1.0-alpha",
        "containment": "microvm",
        "process": {
            "commandLine": command,
            "timeout": 30_000
        }
    });

    let result = mxc_sdk::__ffi::run_json(&request.to_string(), true)?;
    print!("{}", String::from_utf8_lossy(&result.stdout));
    eprint!("{}", String::from_utf8_lossy(&result.stderr));
    match result.outcome {
        WaitResult::Exited(code) => println!("exit={code}"),
        WaitResult::TimedOut => println!("timed out"),
    }
    if !result
        .stdout
        .windows(nonce.len())
        .any(|bytes| bytes == nonce.as_bytes())
    {
        return Err("NVX output did not contain the nonce".into());
    }
    Ok(())
}
