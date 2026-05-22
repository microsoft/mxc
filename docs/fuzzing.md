# Fuzzing

MXC uses [cargo-fuzz](https://rust-fuzz.github.io/book/cargo-fuzz.html) for
local fuzzing harnesses and [OneFuzz](https://aka.ms/onefuzz) for continuous
fuzzing in CI.

## What we fuzz

The `mxc_fuzz` crate at `src/fuzz/` defines three libFuzzer targets, all
exercising the attacker-influenced config surface consumed by `wxc-exec` and
`lxc-exec`:

| Target           | Entry point                                              |
| ---------------- | -------------------------------------------------------- |
| `config_parser`  | `load_mxc_request(s, .., is_base64 = false)`             |
| `base64_decode`  | `load_mxc_request(s, .., is_base64 = true)` (SDK wire format) |
| `validator`      | parse + `validate_common` on a one-shot request          |

Seed corpora for `config_parser` and `validator` targets come directly from
`test_configs/*.json`. The `base64_decode` target uses pre-encoded seeds in
`src/fuzz/corpus/base64_decode/`. OneFuzz dedups by coverage server-side and
grows the corpus across daily runs, so we keep the in-repo seeds small.

## Platform coverage

Targets are pure-Rust code in `wxc_common`, so they compile and run
identically on Windows, Linux, and macOS. We fuzz on **Windows only**
because:

- OneFuzz supports Windows, Ubuntu, AzureLinux3, and TKO — not macOS.
- For these parser targets the bugs are platform-independent; one OS gives
  full coverage of the relevant code paths.

## Running locally (Windows)

```pwsh
# One-time setup
rustup toolchain install nightly --profile minimal
cargo +nightly install cargo-fuzz

# Put the MSVC ASAN runtime DLL on PATH for this shell
$asanDir = (Get-ChildItem 'C:\Program Files\Microsoft Visual Studio' -Recurse `
    -Filter 'clang_rt.asan_dynamic-x86_64.dll' -ErrorAction SilentlyContinue `
    | Where-Object FullName -Match 'HostX64\\x64\\clang_rt' | Select-Object -First 1).Directory.FullName
$env:PATH = "$asanDir;$env:PATH"

# Run a target for 30 seconds (uses test_configs/ as the seed corpus)
cd src\fuzz
cargo +nightly fuzz run config_parser ..\..\test_configs -- -max_total_time=30
```

Discovered crashes are written to `artifacts/<target>/` (relative to `src/fuzz/`)
and printed to the console. Re-run a single input with:

```pwsh
cargo +nightly fuzz run config_parser artifacts\config_parser\crash-<hash>
```

## Minimizing the seed corpus

libFuzzer auto-saves any new-coverage input into the corpus dir during a
run, which can bloat the commit. Before committing seed-corpus updates:

```pwsh
cargo +nightly fuzz cmin <target>
```

`cmin` keeps the smallest set that retains all coverage.

## Continuous fuzzing pipeline

`.azure-pipelines/Fuzz.Build.yml` runs daily at 00:00 UTC on `main`. The job
template (`.azure-pipelines/templates/Fuzz.Build.Job.yml`):

1. Installs nightly Rust on the agent (cargo registry stays pointed at
   `Mxc-Azure-Feed`, so all crate sources still come from the internal feed).
2. Installs `cargo-fuzz`.
3. Builds the three fuzz targets with `-Z sanitizer=address`.
4. Stages an OneFuzz drop directory: one subdir per fuzzer with the `.exe`,
   the ASAN runtime DLL, and the seed corpus.
5. Publishes the drop dir as a pipeline artifact (for debugging).
6. Submits via `onefuzz-task@0` (skipped on PR builds).

## Bug triage

When OneFuzz files a bug via the routing configured in `OneFuzzConfig.json`,
triage steps:

1. **Reproduce locally.** Download the offending input from the fuzz job
   page and run `cargo +nightly fuzz run <target> <crash-file>` (see
   "Running locally"). If it reproduces against `main`, the bug is real.
2. **Classify.** AddressSanitizer findings (heap overflow, use-after-free,
   etc.) are security-relevant and should be handled through the project's
   security response process. Plain panics in parsers are correctness bugs
   and can be fixed in-band.
3. **Add a regression test.** Drop the minimized crash input into the
   appropriate corpus subdir so `cmin` keeps it. If the bug fits the unit
   test pattern, add a dedicated `#[test]` in `wxc_common` too.
4. **Fix + verify.** After the fix lands, re-run the fuzz target locally
   against the original crash to confirm. Once the daily pipeline runs
   again with the fix, the fuzz job should mark the bug as resolved.
