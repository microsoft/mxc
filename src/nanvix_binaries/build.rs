// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Build script that downloads NanVix binaries from GitHub releases.
//!
//! Uses system tools (`curl.exe`, `tar.exe`, `certutil`) instead of Rust
//! crates. Zero build-dependencies.
//!
//! ## Configuration files
//!
//! - `versions.json` — pinned release tags and exact asset names
//! - `checksums.json` — SHA256 hashes for integrity verification
//!
//! ## Environment variables
//!
//! - `GITHUB_TOKEN` / `GH_TOKEN` — optional; increases API rate limit
//!
//! ## Caching
//!
//! Binaries are cached in OUT_DIR. Checksums are re-verified on every build
//! to catch corrupted or truncated files.
//!
//! # TODO(security): NanVix binaries are not ESRP-signed. Before shipping in
//! # official MXC releases, either extend ESRP to cover these binaries or
//! # establish an internal mirror with supply-chain controls.

use std::collections::HashMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

// -- Config structs (parsed manually — no serde needed) ----------------------

struct ReleaseConfig {
    nanvix: RepoConfig,
    cpython: RepoConfig,
}

struct RepoConfig {
    tag: String,
    asset: String,
    binaries: Vec<String>,
}

fn main() {
    let target = std::env::var("CARGO_CFG_TARGET_OS").unwrap_or_default();
    if target != "windows" {
        let out_dir = std::env::var("OUT_DIR").unwrap();
        println!("cargo:rustc-env=NANVIX_BIN_DIR={}", out_dir);
        println!("cargo:rerun-if-changed=build.rs");
        return;
    }

    let out_dir = PathBuf::from(std::env::var("OUT_DIR").unwrap());
    let bin_dir = out_dir.join("nanvix-binaries");
    fs::create_dir_all(&bin_dir).expect("failed to create nanvix-binaries dir");

    let versions = load_versions("versions.json");
    let checksums = load_checksums("checksums.json");

    let all_binaries: Vec<&str> = versions
        .nanvix
        .binaries
        .iter()
        .chain(versions.cpython.binaries.iter())
        .map(|s| s.as_str())
        .collect();

    let needs_nanvix = needs_download(&versions.nanvix, &bin_dir, &checksums);
    let needs_cpython = needs_download(&versions.cpython, &bin_dir, &checksums);

    if needs_nanvix {
        eprintln!("nanvix_binaries: downloading nanvix/nanvix {}...", versions.nanvix.tag);
        download_and_extract(&versions.nanvix, "nanvix/nanvix", &bin_dir);
    }

    if needs_cpython {
        eprintln!("nanvix_binaries: downloading nanvix/cpython {}...", versions.cpython.tag);
        download_and_extract(&versions.cpython, "nanvix/cpython", &bin_dir);
    }

    if !needs_nanvix && !needs_cpython {
        eprintln!("nanvix_binaries: all binaries cached and verified");
    }

    verify_checksums(&all_binaries, &bin_dir, &checksums);

    println!("cargo:rustc-env=NANVIX_BIN_DIR={}", bin_dir.display());
    println!("cargo:BIN_DIR={}", bin_dir.display());
    println!("cargo:rerun-if-changed=build.rs");
    println!("cargo:rerun-if-changed=versions.json");
    println!("cargo:rerun-if-changed=checksums.json");
    println!("cargo:rerun-if-env-changed=GITHUB_TOKEN");
    println!("cargo:rerun-if-env-changed=GH_TOKEN");
}

// -- Manual JSON parsing (versions.json + checksums.json) --------------------
// STABILITY: versions.json and checksums.json are deliberately minimal schemas
// owned by this project. If schema complexity grows, re-evaluate adding serde.

fn load_versions(path: &str) -> ReleaseConfig {
    let content = fs::read_to_string(path)
        .unwrap_or_else(|e| panic!("nanvix_binaries: failed to read {}: {}", path, e));
    let top = parse_json_object(&content);

    let nanvix_str = top.get("nanvix")
        .unwrap_or_else(|| panic!("nanvix_binaries: versions.json missing 'nanvix' key"));
    let cpython_str = top.get("cpython")
        .unwrap_or_else(|| panic!("nanvix_binaries: versions.json missing 'cpython' key"));

    ReleaseConfig {
        nanvix: parse_repo_config(nanvix_str),
        cpython: parse_repo_config(cpython_str),
    }
}

fn parse_repo_config(json: &str) -> RepoConfig {
    let obj = parse_json_object(json);
    let tag = obj.get("tag")
        .map(|s| unquote(s))
        .unwrap_or_else(|| panic!("nanvix_binaries: missing 'tag' in repo config"));
    let asset = obj.get("asset")
        .map(|s| unquote(s))
        .unwrap_or_else(|| panic!("nanvix_binaries: missing 'asset' in repo config"));
    let binaries_str = obj.get("binaries")
        .unwrap_or_else(|| panic!("nanvix_binaries: missing 'binaries' in repo config"));
    let binaries = parse_json_string_array(binaries_str);
    RepoConfig { tag, asset, binaries }
}

fn load_checksums(path: &str) -> HashMap<String, String> {
    let content = fs::read_to_string(path)
        .unwrap_or_else(|e| panic!("nanvix_binaries: failed to read {}: {}", path, e));
    let obj = parse_json_object(&content);
    obj.into_iter()
        .map(|(k, v)| (unquote(&k), unquote(&v)))
        .collect()
}

/// Minimal JSON object parser — extracts top-level key-value pairs.
/// Values are returned as raw JSON strings (may be quoted strings, arrays, or objects).
fn parse_json_object(json: &str) -> HashMap<String, String> {
    let trimmed = json.trim();
    let inner = trimmed
        .strip_prefix('{')
        .and_then(|s| s.strip_suffix('}'))
        .unwrap_or_else(|| panic!("nanvix_binaries: expected JSON object, got: {}", &trimmed[..trimmed.len().min(50)]));

    let mut result = HashMap::new();
    let mut chars = inner.chars().peekable();

    loop {
        skip_whitespace(&mut chars);
        if chars.peek().is_none() {
            break;
        }

        // Parse key
        let key = parse_quoted_string(&mut chars);
        skip_whitespace(&mut chars);
        expect_char(&mut chars, ':');
        skip_whitespace(&mut chars);

        // Parse value (collect until matching delimiter)
        let value = collect_value(&mut chars);
        result.insert(key, value);

        skip_whitespace(&mut chars);
        if chars.peek() == Some(&',') {
            chars.next();
        }
    }

    result
}

fn parse_json_string_array(json: &str) -> Vec<String> {
    let trimmed = json.trim();
    let inner = trimmed
        .strip_prefix('[')
        .and_then(|s| s.strip_suffix(']'))
        .unwrap_or_else(|| panic!("nanvix_binaries: expected JSON array"));

    let mut result = Vec::new();
    let mut chars = inner.chars().peekable();

    loop {
        skip_whitespace(&mut chars);
        if chars.peek().is_none() {
            break;
        }
        let s = parse_quoted_string(&mut chars);
        result.push(s);
        skip_whitespace(&mut chars);
        if chars.peek() == Some(&',') {
            chars.next();
        }
    }
    result
}

fn parse_quoted_string(chars: &mut std::iter::Peekable<std::str::Chars>) -> String {
    expect_char(chars, '"');
    let mut s = String::new();
    loop {
        match chars.next() {
            Some('"') => break,
            Some('\\') => {
                if let Some(c) = chars.next() {
                    s.push(c);
                }
            }
            Some(c) => s.push(c),
            None => panic!("nanvix_binaries: unterminated string in JSON"),
        }
    }
    s
}

fn collect_value(chars: &mut std::iter::Peekable<std::str::Chars>) -> String {
    let mut val = String::new();
    let mut depth = 0i32;
    let mut in_string = false;

    loop {
        match chars.peek() {
            None => break,
            Some(&c) if !in_string && depth == 0 && (c == ',' || c == '}' || c == ']') => break,
            _ => {}
        }
        let c = chars.next().unwrap();
        val.push(c);
        if in_string {
            if c == '\\' {
                // Escape sequence — push next char verbatim
                if let Some(&next) = chars.peek() {
                    val.push(next);
                    chars.next();
                }
            } else if c == '"' {
                in_string = false;
            }
        } else {
            match c {
                '"' => in_string = true,
                '{' | '[' => depth += 1,
                '}' | ']' => depth -= 1,
                _ => {}
            }
        }
    }
    val.trim().to_string()
}

fn skip_whitespace(chars: &mut std::iter::Peekable<std::str::Chars>) {
    while let Some(&c) = chars.peek() {
        if c.is_whitespace() {
            chars.next();
        } else {
            break;
        }
    }
}

fn expect_char(chars: &mut std::iter::Peekable<std::str::Chars>, expected: char) {
    match chars.next() {
        Some(c) if c == expected => {}
        other => panic!(
            "nanvix_binaries: expected '{}', got {:?} in JSON",
            expected, other
        ),
    }
}

fn unquote(s: &str) -> String {
    let trimmed = s.trim();
    trimmed
        .strip_prefix('"')
        .and_then(|s| s.strip_suffix('"'))
        .unwrap_or(trimmed)
        .to_string()
}

// -- Download via curl.exe ---------------------------------------------------

/// Construct deterministic GitHub release download URL.
/// Format: https://github.com/{repo}/releases/download/{tag}/{asset}
fn github_download_url(repo: &str, tag: &str, asset: &str) -> String {
    format!(
        "https://github.com/{}/releases/download/{}/{}",
        repo, tag, asset
    )
}

fn needs_download(config: &RepoConfig, bin_dir: &Path, checksums: &HashMap<String, String>) -> bool {
    config.binaries.iter().any(|name| {
        let path = bin_dir.join(name);
        if !path.exists() {
            return true;
        }
        if let Some(expected) = checksums.get(name.as_str()) {
            certutil_sha256(&path) != *expected
        } else {
            false
        }
    })
}

fn download_and_extract(config: &RepoConfig, repo: &str, bin_dir: &Path) {
    let url = github_download_url(repo, &config.tag, &config.asset);

    // Download zip to a temp file (tar.exe needs a file, not stdin for zip format)
    let zip_path = bin_dir.join(&config.asset);
    eprintln!("  downloading {}...", config.asset);
    curl_download_to_file(&url, &zip_path);

    let size = zip_path.metadata().map(|m| m.len()).unwrap_or(0);
    eprintln!("  downloaded {} bytes, extracting...", size);

    // Extract only the files we need using tar.exe (supports zip since Windows 10 1803)
    let binaries: Vec<&str> = config.binaries.iter().map(|s| s.as_str()).collect();
    tar_extract_from_zip(&zip_path, bin_dir, &binaries);

    // Clean up the zip
    let _ = fs::remove_file(&zip_path);
}

/// Download a file via curl.exe with retry, writing directly to disk.
fn curl_download_to_file(url: &str, dest: &Path) {
    let mut cmd = Command::new("curl");
    cmd.args([
        "--silent", "--show-error", "--fail", "--location",
        "--retry", "2", "--retry-delay", "2",
        "--output",
    ]);
    cmd.arg(dest);
    cmd.args(["--header", "User-Agent: mxc-nanvix-build/0.1"]);

    if let Some(token) = github_token() {
        cmd.arg("--header");
        cmd.arg(format!("Authorization: Bearer {}", token));
    }

    cmd.arg(url);

    let output = cmd.output().unwrap_or_else(|e| {
        panic!(
            "nanvix_binaries: curl.exe not found: {}\n\
             curl.exe ships with Windows 10 1803+. Ensure it's in PATH.",
            e
        );
    });

    if !output.status.success() {
        panic!(
            "nanvix_binaries: curl failed for {}\n  exit code: {}\n  stderr: {}",
            url,
            output.status,
            String::from_utf8_lossy(&output.stderr)
        );
    }
}

/// Extract specific files from a zip using tar.exe (ships with Windows 10 1803+).
fn tar_extract_from_zip(zip_path: &Path, dest_dir: &Path, files: &[&str]) {
    let mut cmd = Command::new("tar");
    cmd.arg("-xf");
    cmd.arg(zip_path);
    cmd.arg("-C");
    cmd.arg(dest_dir);
    for f in files {
        cmd.arg(f);
    }

    let output = cmd.output().unwrap_or_else(|e| {
        panic!(
            "nanvix_binaries: tar.exe not found: {}\n\
             tar.exe ships with Windows 10 1803+. Ensure it's in PATH.",
            e
        );
    });

    if !output.status.success() {
        panic!(
            "nanvix_binaries: tar extraction failed\n  exit code: {}\n  stderr: {}",
            output.status,
            String::from_utf8_lossy(&output.stderr)
        );
    }

    for f in files {
        let path = dest_dir.join(f);
        if path.exists() {
            let size = path.metadata().map(|m| m.len()).unwrap_or(0);
            eprintln!("  {} -- extracted ({} bytes)", f, size);
        } else {
            panic!(
                "nanvix_binaries: '{}' not found in zip after extraction",
                f
            );
        }
    }
}

fn github_token() -> Option<String> {
    std::env::var("GITHUB_TOKEN")
        .or_else(|_| std::env::var("GH_TOKEN"))
        .ok()
}

// -- SHA256 via certutil -----------------------------------------------------

fn certutil_sha256(path: &Path) -> String {
    let output = Command::new("certutil")
        .args(["-hashfile"])
        .arg(path)
        .arg("SHA256")
        .output()
        .unwrap_or_else(|e| {
            panic!("nanvix_binaries: failed to run certutil: {}", e);
        });

    if !output.status.success() {
        panic!(
            "nanvix_binaries: certutil -hashfile failed for {}: {}",
            path.display(),
            String::from_utf8_lossy(&output.stderr)
        );
    }

    // certutil output format:
    //   SHA256 hash of <file>:
    //   <hex hash>
    //   CertUtil: -hashfile command completed successfully.
    let stdout = String::from_utf8(output.stdout)
        .expect("certutil output not UTF-8");
    stdout
        .lines()
        .nth(1) // second line is the hash
        .unwrap_or_else(|| panic!("nanvix_binaries: unexpected certutil output: {}", stdout))
        .trim()
        .replace(' ', "") // certutil may space-separate hex groups
        .to_lowercase()
}

fn verify_checksums(
    binaries: &[&str],
    bin_dir: &Path,
    checksums: &HashMap<String, String>,
) {
    for name in binaries {
        let path = bin_dir.join(name);
        if !path.exists() {
            panic!("nanvix_binaries: {} not found after download/extract", name);
        }

        if let Some(expected) = checksums.get(*name) {
            let actual = certutil_sha256(&path);
            if actual != *expected {
                panic!(
                    "nanvix_binaries: SHA256 mismatch for '{}'!\n\
                     \x20 expected: {}\n\
                     \x20 actual:   {}\n\
                     This may indicate a corrupted download or a NanVix version update.\n\
                     Update checksums.json with the new hashes.",
                    name, expected, actual
                );
            }
            eprintln!("  {} -- checksum OK", name);
        } else {
            eprintln!(
                "  {} -- WARNING: no checksum entry in checksums.json",
                name
            );
        }
    }
}
