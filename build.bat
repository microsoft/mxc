@echo off

echo.
echo Building WXC (Rust)...
pushd src
cargo build --release
popd

echo.
echo Building npm SDK package...
pushd sdk
call npm install & call npm run build
popd
