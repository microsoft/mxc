// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use std::env;
use std::path::PathBuf;
use std::process::Command;

pub(crate) fn run() -> Result<(), Box<dyn std::error::Error>> {
    if env::var("CARGO_CFG_TARGET_OS").as_deref() != Ok("linux") {
        return Ok(());
    }

    let target = env::var("TARGET")?;
    let architecture = env::var("CARGO_CFG_TARGET_ARCH")?;
    let (machine, cross_compiler) = match architecture.as_str() {
        "x86_64" => (62, "x86_64-linux-gnu-gcc"),
        "aarch64" => (183, "aarch64-linux-gnu-gcc"),
        _ => {
            return Err(
                format!("unsupported LXC capability helper architecture: {architecture}").into(),
            );
        }
    };
    let normalized_target = target.replace('-', "_");
    let compiler_variables = [
        format!("CC_{target}"),
        format!("CC_{normalized_target}"),
        "TARGET_CC".to_string(),
        "CC".to_string(),
        format!(
            "CARGO_TARGET_{}_LINKER",
            normalized_target.to_ascii_uppercase()
        ),
    ];
    for variable in &compiler_variables {
        println!("cargo:rerun-if-env-changed={variable}");
    }
    let compiler = compiler_variables
        .iter()
        .find_map(|variable| env::var_os(variable).filter(|value| !value.is_empty()))
        .unwrap_or_else(|| {
            if env::var("HOST").as_deref() == Ok(target.as_str()) {
                "cc".into()
            } else {
                cross_compiler.into()
            }
        });

    let source =
        PathBuf::from(env::var_os("CARGO_MANIFEST_DIR").ok_or("missing CARGO_MANIFEST_DIR")?)
            .join("src/backends/lxc/common/lxc_capability_helper.c");
    println!("cargo:rerun-if-changed={}", source.display());
    let out_dir = PathBuf::from(env::var_os("OUT_DIR").ok_or("missing OUT_DIR")?);
    let helper = out_dir.join("lxc-capability-helper");
    let output = Command::new(&compiler)
        .args([
            "-std=c11",
            "-O2",
            "-Wall",
            "-Wextra",
            "-Werror",
            "-ffreestanding",
            "-fno-builtin",
            "-fno-stack-protector",
            "-fno-pie",
            "-fno-unwind-tables",
            "-fno-asynchronous-unwind-tables",
            "-nostdlib",
            "-static",
            "-no-pie",
            "-Wl,--build-id=none",
            "-Wl,-z,noexecstack",
            "-Wl,-e,_start",
        ])
        .arg(&source)
        .arg("-o")
        .arg(&helper)
        .env("TMPDIR", &out_dir)
        .env("TMP", &out_dir)
        .env("TEMP", &out_dir)
        .output()
        .map_err(|error| {
            format!("cannot run LXC capability helper compiler {compiler:?}: {error}")
        })?;
    if !output.status.success() {
        return Err(format!(
            "LXC capability helper compiler {compiler:?} failed ({}): {}",
            output.status,
            String::from_utf8_lossy(&output.stderr).trim()
        )
        .into());
    }
    verify_static_elf(&std::fs::read(&helper)?, machine)?;
    Ok(())
}

fn verify_static_elf(
    image: &[u8],
    expected_machine: u16,
) -> Result<(), Box<dyn std::error::Error>> {
    let invalid = "LXC capability helper must be a static ELF64 executable for its target architecture with a nonexecutable stack";
    if image.len() < 64 || &image[..6] != b"\x7fELF\x02\x01" {
        return Err(invalid.into());
    }
    let read_u16 = |offset: usize| -> Result<u16, Box<dyn std::error::Error>> {
        Ok(u16::from_le_bytes(
            image.get(offset..offset + 2).ok_or(invalid)?.try_into()?,
        ))
    };
    let read_u32 = |offset: usize| -> Result<u32, Box<dyn std::error::Error>> {
        Ok(u32::from_le_bytes(
            image.get(offset..offset + 4).ok_or(invalid)?.try_into()?,
        ))
    };
    let read_u64 = |offset: usize| -> Result<u64, Box<dyn std::error::Error>> {
        Ok(u64::from_le_bytes(
            image.get(offset..offset + 8).ok_or(invalid)?.try_into()?,
        ))
    };

    if read_u16(16)? != 2 || read_u16(18)? != expected_machine {
        return Err(invalid.into());
    }
    let entry = read_u64(24)?;
    let program_headers = usize::try_from(read_u64(32)?)?;
    let header_size = usize::from(read_u16(54)?);
    let header_count = usize::from(read_u16(56)?);
    if header_size < 56
        || program_headers > image.len()
        || header_count > (image.len() - program_headers) / header_size
    {
        return Err(invalid.into());
    }
    let mut executable_entry = false;
    let mut nonexecutable_stack = false;
    for index in 0..header_count {
        let header = program_headers + index * header_size;
        let kind = read_u32(header)?;
        let flags = read_u32(header + 4)?;
        match kind {
            2 | 3 => return Err(invalid.into()),
            1 if flags & 1 != 0 => {
                let address = read_u64(header + 16)?;
                let length = read_u64(header + 40)?;
                executable_entry |= entry >= address && entry - address < length;
            }
            0x6474_e551 => {
                if flags & 1 != 0 {
                    return Err(invalid.into());
                }
                nonexecutable_stack = true;
            }
            _ => {}
        }
    }
    if !executable_entry || !nonexecutable_stack {
        return Err(invalid.into());
    }
    Ok(())
}
