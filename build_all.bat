@echo off
echo Building Debug configuration...
msbuild wxc.sln /p:Configuration=Debug /p:Platform=x64 /t:Rebuild /nologo /verbosity:minimal

echo.
echo Building Release configuration...
msbuild wxc.sln /p:Configuration=Release /p:Platform=x64 /t:Rebuild /nologo /verbosity:minimal
