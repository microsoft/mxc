// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

fn main() {
    println!("cargo:rerun-if-changed=build.rs");
    println!("cargo:rerun-if-changed=Cargo.toml");

    if std::env::var("CARGO_CFG_TARGET_OS").as_deref() != Ok("windows") {
        return;
    }

    let mut resource = winresource::WindowsResource::new();
    resource
        .set("ProductName", "Microsoft Experimental Containers")
        .set(
            "FileDescription",
            "Elevated WinHTTP proxy policy shim for AppContainer sandboxing",
        )
        .set("OriginalFilename", "winhttp-proxy-shim.exe")
        .compile()
        .expect("failed to embed Windows version info");
}
