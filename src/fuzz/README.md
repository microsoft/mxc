# mxc_fuzz

cargo-fuzz harnesses for the MXC config-parsing surface. Continuous fuzzing
runs daily under [OneFuzz](https://aka.ms/onefuzz) on Windows x64 with
AddressSanitizer. See [`docs/fuzzing.md`](../../docs/fuzzing.md) for the
full reference.

## Targets

| Target           | What it fuzzes                                                    |
| ---------------- | ----------------------------------------------------------------- |
| `config_parser`  | `wxc_common::config_parser::load_mxc_request`, `is_base64 = false` |
| `base64_decode`  | Same entry point with `is_base64 = true` (covers base64 + JSON + conversion) |
| `validator`      | Parse + `wxc_common::validator::validate_common` on one-shot requests |

## Running locally (Windows)

```pwsh
# One-time setup
rustup toolchain install nightly --profile minimal
cargo +nightly install cargo-fuzz

# Put the MSVC ASAN runtime DLL on PATH for the test run
$asanDir = 'C:\Program Files\Microsoft Visual Studio\18\Enterprise\VC\Tools\MSVC\<ver>\bin\HostX64\x64'
$env:PATH = "$asanDir;$env:PATH"

# Run a target for 30 seconds (uses test_configs/ as the seed corpus)
cd src\fuzz
cargo +nightly fuzz run config_parser ..\..\test_configs -- -max_total_time=30
```

Findings are written to `artifacts/<target>/`. Reproduce a finding with:

```pwsh
cargo +nightly fuzz run config_parser artifacts\config_parser\crash-<hash>
```

## Minimizing the corpus

OneFuzz dedups by coverage server-side, but for the in-repo seed corpus run:

```pwsh
cargo +nightly fuzz cmin config_parser
```

Only the resulting set should be committed.

## OneFuzzConfig.json

`OneFuzzConfig.json` ships in the OneFuzz drop directory alongside the fuzzer
binaries. Validate locally with the OIP tool:

```pwsh
oip.exe validate OneFuzzConfig.json
```
