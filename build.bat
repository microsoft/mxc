@echo off
echo.
echo Building WXC...
msbuild wxc.sln /p:Configuration=Release /p:Platform=x64 /t:Rebuild /m /verbosity:minimal

echo.
echo Build npm SDK package...
pushd sdk
call npm install & call npm run build
popd
