@echo off
rem ---------------------------------------------------------------------------
rem build.bat -- compile payload.dll, target.exe and injector.exe with MSVC
rem              (Visual Studio 2022, x64).
rem
rem Just run it from a normal cmd prompt; it locates VS2022 itself via vswhere
rem and calls vcvars64.bat for you.
rem ---------------------------------------------------------------------------
setlocal enabledelayedexpansion

set "ROOT=%~dp0"
set "BUILD=%ROOT%build"
if not exist "%BUILD%" mkdir "%BUILD%"

rem --- locate Visual Studio 2022 with the C++ toolset ------------------------
set "VSWHERE=%ProgramFiles(x86)%\Microsoft Visual Studio\Installer\vswhere.exe"
if not exist "%VSWHERE%" (
    echo [-] vswhere.exe not found - is Visual Studio 2022 installed?
    exit /b 1
)

set "VSPATH="
for /f "usebackq tokens=*" %%i in (`"%VSWHERE%" -latest -products * ^
        -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 ^
        -property installationPath`) do set "VSPATH=%%i"

if not defined VSPATH (
    echo [-] Visual Studio 2022 with the "Desktop development with C++"
    echo     workload was not found.
    exit /b 1
)

echo [*] using Visual Studio at: %VSPATH%
call "%VSPATH%\VC\Auxiliary\Build\vcvars64.bat" >nul
if errorlevel 1 (
    echo [-] failed to initialise the MSVC environment
    exit /b 1
)

pushd "%BUILD%"

echo [*] building payload.dll ...
cl /nologo /LD /O2 /W4 /Fe:payload.dll "%ROOT%payload\payload.c"
if errorlevel 1 goto :fail

echo [*] building target.exe ...
cl /nologo /O2 /W4 /Fe:target.exe "%ROOT%target\target.c"
if errorlevel 1 goto :fail

echo [*] building target_hardened.exe ...
cl /nologo /O2 /W4 /Fe:target_hardened.exe "%ROOT%target_hardened\target_hardened.c"
if errorlevel 1 goto :fail

echo [*] building injector.exe ...
cl /nologo /O2 /W4 /Fe:injector.exe "%ROOT%injector\injector.c"
if errorlevel 1 goto :fail

popd
echo.
echo [+] build ok - artefacts in "%BUILD%"
exit /b 0

:fail
popd
echo.
echo [-] build failed
exit /b 1
