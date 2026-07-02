@echo off
setlocal enabledelayedexpansion

:: Defaults
set "BUILD_CONFIG=release"
set "BUILD_ARCH="
set "BUILD_ALL=0"
set "WITH_NANVIX=0"
set "WITH_WSLC=0"
set "WITH_ISOLATION_SESSION=0"
set "WITH_HYPERLIGHT=0"

:: Parse arguments
:parse_args
if "%~1"=="" goto :args_done
if /i "%~1"=="--debug"   ( set "BUILD_CONFIG=debug"   & shift & goto :parse_args )
if /i "%~1"=="--release" ( set "BUILD_CONFIG=release"  & shift & goto :parse_args )
if /i "%~1"=="--x64"     ( set "BUILD_ARCH=x86_64-pc-windows-msvc"   & shift & goto :parse_args )
if /i "%~1"=="--arm64"   ( set "BUILD_ARCH=aarch64-pc-windows-msvc"  & shift & goto :parse_args )
if /i "%~1"=="--all"     ( set "BUILD_ALL=1"           & shift & goto :parse_args )
if /i "%~1"=="--with-microvm" ( set "WITH_NANVIX=1"    & shift & goto :parse_args )
if /i "%~1"=="--with-wslc"    ( set "WITH_WSLC=1"      & shift & goto :parse_args )
if /i "%~1"=="--with-isolation-session" ( set "WITH_ISOLATION_SESSION=1" & shift & goto :parse_args )
if /i "%~1"=="--with-hyperlight" ( set "WITH_HYPERLIGHT=1" & shift & goto :parse_args )
if /i "%~1"=="--help"    ( goto :usage )
if /i "%~1"=="-h"        ( goto :usage )
echo Unknown argument: %~1
goto :usage
:args_done

:: Detect native architecture if not specified and not --all
if "%BUILD_ALL%"=="0" if "%BUILD_ARCH%"=="" (
    if /i "%PROCESSOR_ARCHITECTURE%"=="ARM64" (
        set "BUILD_ARCH=aarch64-pc-windows-msvc"
    ) else (
        set "BUILD_ARCH=x86_64-pc-windows-msvc"
    )
)

:: Build flags
set "CARGO_FLAGS=--target"
if "%BUILD_CONFIG%"=="release" set "CARGO_FLAGS=--release --target"
:: plm is a standalone Windows-only binary that does not consume any of the
:: workspace feature flags above, so it uses its own profile/target-only flags.
set "PLM_FLAGS=--target"
if "%BUILD_CONFIG%"=="release" set "PLM_FLAGS=--release --target"
if "%WITH_NANVIX%"=="1" set "CARGO_FLAGS=--features microvm %CARGO_FLAGS%"
if "%WITH_WSLC%"=="1" set "CARGO_FLAGS=--features wslc %CARGO_FLAGS%"
if "%WITH_ISOLATION_SESSION%"=="1" set "CARGO_FLAGS=--features isolation_session %CARGO_FLAGS%"
if "%WITH_HYPERLIGHT%"=="1" set "CARGO_FLAGS=--features hyperlight %CARGO_FLAGS%"

:: Build Rust
echo.
echo Building WXC (Rust) [%BUILD_CONFIG%]...
pushd src

:: Ensure the rustup targets are installed for the pinned toolchain
:: (src\rust-toolchain.toml). No-op if rustup is missing or the target
:: is already present.
where rustup >nul 2>&1
if not errorlevel 1 (
    if "%BUILD_ALL%"=="1" (
        rustup target add x86_64-pc-windows-msvc >nul 2>&1
        rustup target add aarch64-pc-windows-msvc >nul 2>&1
    ) else (
        rustup target add %BUILD_ARCH% >nul 2>&1
    )
)

if "%BUILD_ALL%"=="1" (
    echo   Target: x86_64-pc-windows-msvc
    cargo build %CARGO_FLAGS% x86_64-pc-windows-msvc || goto :error
    cargo build -p plm %PLM_FLAGS% x86_64-pc-windows-msvc || goto :error
    echo   Target: aarch64-pc-windows-msvc
    cargo build %CARGO_FLAGS% aarch64-pc-windows-msvc || goto :error
    cargo build -p plm %PLM_FLAGS% aarch64-pc-windows-msvc || goto :error
) else (
    echo   Target: %BUILD_ARCH%
    cargo build %CARGO_FLAGS% %BUILD_ARCH% || goto :error
    cargo build -p plm %PLM_FLAGS% %BUILD_ARCH% || goto :error
)
echo   Check formatting
cargo fmt --all -- --check || goto :error
echo   Check linting
cargo clippy --workspace --all-targets -- -D warnings || goto :error
popd

:: Copy binaries into SDK package
echo.
echo Copying binaries into SDK package...
for %%T in (x86_64-pc-windows-msvc aarch64-pc-windows-msvc) do (
    set "BIN_DIR=src\target\%%T\%BUILD_CONFIG%"
    if "%%T"=="x86_64-pc-windows-msvc" (set "SDK_ARCH=x64") else (set "SDK_ARCH=arm64")
    if exist "!BIN_DIR!\wxc-exec.exe" (
        if not exist "sdk\bin\!SDK_ARCH!" mkdir "sdk\bin\!SDK_ARCH!"
        copy /Y "!BIN_DIR!\wxc-exec.exe" "sdk\bin\!SDK_ARCH!\" >nul
        echo   Copied !SDK_ARCH!\wxc-exec.exe
        if exist "!BIN_DIR!\wxc-windows-sandbox-guest.exe" (
            copy /Y "!BIN_DIR!\wxc-windows-sandbox-guest.exe" "sdk\bin\!SDK_ARCH!\" >nul
            echo   Copied !SDK_ARCH!\wxc-windows-sandbox-guest.exe
        )
        if exist "!BIN_DIR!\wxc-windows-sandbox-daemon.exe" (
            copy /Y "!BIN_DIR!\wxc-windows-sandbox-daemon.exe" "sdk\bin\!SDK_ARCH!\" >nul
            echo   Copied !SDK_ARCH!\wxc-windows-sandbox-daemon.exe
        )
        if exist "!BIN_DIR!\winhttp-proxy-shim.exe" (
            copy /Y "!BIN_DIR!\winhttp-proxy-shim.exe" "sdk\bin\!SDK_ARCH!\" >nul
            echo   Copied !SDK_ARCH!\winhttp-proxy-shim.exe
        )
        if exist "!BIN_DIR!\wxc-test-proxy.exe" (
            copy /Y "!BIN_DIR!\wxc-test-proxy.exe" "sdk\bin\!SDK_ARCH!\" >nul
            echo   Copied !SDK_ARCH!\wxc-test-proxy.exe
        )
        if exist "!BIN_DIR!\wxc-host-prep.exe" (
            copy /Y "!BIN_DIR!\wxc-host-prep.exe" "sdk\bin\!SDK_ARCH!\" >nul
            echo   Copied !SDK_ARCH!\wxc-host-prep.exe
        )
        if exist "!BIN_DIR!\plm.exe" (
            copy /Y "!BIN_DIR!\plm.exe" "sdk\bin\!SDK_ARCH!\" >nul
            echo   Copied !SDK_ARCH!\plm.exe
        )
        if "%WITH_NANVIX%"=="1" (
            for %%B in (nanvixd.exe nanvix_rootfs.img python3.initrd) do (
                if exist "!BIN_DIR!\%%B" (
                    copy /Y "!BIN_DIR!\%%B" "sdk\bin\!SDK_ARCH!\" >nul
                    echo   Copied !SDK_ARCH!\%%B
                )
            )
            if exist "!BIN_DIR!\bin\kernel.elf" (
                if not exist "sdk\bin\!SDK_ARCH!\bin" mkdir "sdk\bin\!SDK_ARCH!\bin"
                copy /Y "!BIN_DIR!\bin\kernel.elf" "sdk\bin\!SDK_ARCH!\bin\" >nul
                echo   Copied !SDK_ARCH!\bin\kernel.elf
            )
            for %%S in (kernel.vmem kernel.whp.cbor) do (
                if exist "!BIN_DIR!\snapshots\%%S" (
                    if not exist "sdk\bin\!SDK_ARCH!\snapshots" mkdir "sdk\bin\!SDK_ARCH!\snapshots"
                    copy /Y "!BIN_DIR!\snapshots\%%S" "sdk\bin\!SDK_ARCH!\snapshots\" >nul
                    echo   Copied !SDK_ARCH!\snapshots\%%S
                )
            )
        )
        if "%WITH_WSLC%"=="1" (
            if exist "!BIN_DIR!\wslcsdk.dll" (
                copy /Y "!BIN_DIR!\wslcsdk.dll" "sdk\bin\!SDK_ARCH!\" >nul
                echo   Copied !SDK_ARCH!\wslcsdk.dll
            )
        )
    )
)

:: Build npm packages
echo.
echo Building npm SDK package...
pushd sdk
call npm install & call npm run build
popd

echo.
echo Building SDK integration tests...
pushd sdk\tests\integration
:: npm caches `file:` deps by package.json version. The local SDK version
:: rarely bumps between builds, so a plain `npm install` keeps reusing the
:: stale packed copy. Force a refresh of the @microsoft/mxc-sdk link so
:: type-checking sees the dist we just rebuilt above.
if exist node_modules\@microsoft\mxc-sdk rmdir /s /q node_modules\@microsoft\mxc-sdk
call npm install & call npm run build
popd

echo.
echo Build complete.

:: Non-blocking prerequisite check for E2E tests.
:: We check whether the *first* python.exe in PATH is the user's App Execution
:: Alias reparse point at %LOCALAPPDATA%\Microsoft\WindowsApps\python.exe.
:: When that alias resolves first, sandbox containers cannot launch python.exe
:: (CreateProcessW returns 0x80070057).
echo.
echo === Checking E2E test prerequisites ===
set "PREREQ_WARN=0"

:: Check Python is available and first match is not the App Execution Alias
where python.exe >nul 2>&1
if errorlevel 1 (
    echo   WARNING: python.exe not found. E2E tests require a system-wide Python install.
    set "PREREQ_WARN=1"
) else (
    for /f "tokens=*" %%P in ('where python.exe') do (
        if /i "%%P"=="%LOCALAPPDATA%\Microsoft\WindowsApps\python.exe" (
            echo   WARNING: python.exe first resolves to an App Execution Alias.
            echo            The alias reparse point cannot be launched inside sandbox containers.
            set "PREREQ_WARN=1"
        )
        goto :python_check_done
    )
)
:python_check_done

:: Check pwsh.exe exists at the expected path used by test configs
if not exist "C:\Program Files\PowerShell\7\pwsh.exe" (
    echo   WARNING: PowerShell 7 not found at C:\Program Files\PowerShell\7\pwsh.exe.
    echo            pwsh sandbox tests will fail.
    set "PREREQ_WARN=1"
)

if "%PREREQ_WARN%"=="0" (
    echo   All E2E test prerequisites met.
) else (
    echo.
    echo   To install Python and disable the alias, run from an elevated PowerShell prompt:
    echo     .\scripts\setup-test-prereqs.ps1
)

:done

exit /b 0

:error
popd
echo.
echo Build failed.
exit /b 1

:usage
echo.
echo Usage: build.bat [options]
echo.
echo Options:
echo   --debug     Build debug configuration (default: release)
echo   --release   Build release configuration
echo   --x64       Build for x64 only
echo   --arm64     Build for ARM64 only
echo   --all             Build for both x64 and ARM64
echo   --with-microvm    Download and include NanVix micro-VM binaries
echo   --with-wslc       Build with WSL Container (WSLC SDK) support
echo   --with-isolation-session   Build with IsolationSession backend (IsoEnvBroker)
echo   --with-hyperlight         Build with Hyperlight (micro-VM) backend (x86_64 only)
echo   -h, --help        Show this help
echo.
echo Default: builds release for the current machine architecture.
exit /b 0
