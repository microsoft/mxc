@echo off
echo.
echo Building test project...
msbuild wxc_tests\wxc_tests.vcxproj /p:Configuration=Debug /p:Platform=x64 /m /verbosity:minimal

if %ERRORLEVEL% EQU 0 (
    echo.
    echo Running tests...
    outputs\wxc_tests\x64\Debug\wxc_tests.exe
)

echo.
echo Testing SDK package...
pushd cli
call npm install && call npm run build
call npm run start platform
popd