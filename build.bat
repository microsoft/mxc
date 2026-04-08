@echo off
setlocal enabledelayedexpansion

:: Defaults
set "BUILD_CONFIG=release"
set "BUILD_ARCH="
set "BUILD_ALL=0"
set "WITH_NANVIX=0"

:: Parse arguments
:parse_args
if "%~1"=="" goto :args_done
if /i "%~1"=="--debug"   ( set "BUILD_CONFIG=debug"   & shift & goto :parse_args )
if /i "%~1"=="--release" ( set "BUILD_CONFIG=release"  & shift & goto :parse_args )
if /i "%~1"=="--x64"     ( set "BUILD_ARCH=x86_64-pc-windows-msvc"   & shift & goto :parse_args )
if /i "%~1"=="--arm64"   ( set "BUILD_ARCH=aarch64-pc-windows-msvc"  & shift & goto :parse_args )
if /i "%~1"=="--all"     ( set "BUILD_ALL=1"           & shift & goto :parse_args )
if /i "%~1"=="--with-microvm" ( set "WITH_NANVIX=1"    & shift & goto :parse_args )
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
if "%WITH_NANVIX%"=="1" set "CARGO_FLAGS=--features microvm %CARGO_FLAGS%"

:: Build Rust
echo.
echo Building WXC (Rust) [%BUILD_CONFIG%]...
pushd src
if "%BUILD_ALL%"=="1" (
    echo   Target: x86_64-pc-windows-msvc
    cargo build %CARGO_FLAGS% x86_64-pc-windows-msvc || goto :error
    echo   Target: aarch64-pc-windows-msvc
    cargo build %CARGO_FLAGS% aarch64-pc-windows-msvc || goto :error 
) else (
    echo   Target: %BUILD_ARCH%
    cargo build %CARGO_FLAGS% %BUILD_ARCH% || goto :error
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
    if exist "!BIN_DIR!\wxc-exec.exe" (
        if not exist "sdk\bin\%%T" mkdir "sdk\bin\%%T"
        copy /Y "!BIN_DIR!\wxc-exec.exe" "sdk\bin\%%T\" >nul
        echo   Copied %%T\wxc-exec.exe
        if exist "!BIN_DIR!\wxc-sandbox-guest.exe" (
            copy /Y "!BIN_DIR!\wxc-sandbox-guest.exe" "sdk\bin\%%T\" >nul
            echo   Copied %%T\wxc-sandbox-guest.exe
        )
        if exist "!BIN_DIR!\wxc-sandbox-daemon.exe" (
            copy /Y "!BIN_DIR!\wxc-sandbox-daemon.exe" "sdk\bin\%%T\" >nul
            echo   Copied %%T\wxc-sandbox-daemon.exe
        )
        if exist "!BIN_DIR!\winhttp-proxy-shim.exe" (
            copy /Y "!BIN_DIR!\winhttp-proxy-shim.exe" "sdk\bin\%%T\" >nul
            echo   Copied %%T\winhttp-proxy-shim.exe
        )
        if exist "!BIN_DIR!\wxc-test-proxy.exe" (
            copy /Y "!BIN_DIR!\wxc-test-proxy.exe" "sdk\bin\%%T\" >nul
            echo   Copied %%T\wxc-test-proxy.exe
        )
        if "%WITH_NANVIX%"=="1" (
            for %%B in (nanvixd.exe kernel.elf python.elf cpython-ramfs.img) do (
                if exist "!BIN_DIR!\%%B" (
                    copy /Y "!BIN_DIR!\%%B" "sdk\bin\%%T\" >nul
                    echo   Copied %%T\%%B
                )
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
echo Build complete.
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
echo   -h, --help        Show this help
echo.
echo Default: builds release for the current machine architecture.
exit /b 0
