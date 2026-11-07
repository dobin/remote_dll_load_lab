@echo off
rem ---------------------------------------------------------------------------
rem run_test_hardened.bat -- prove that a DLL-load mitigation blocks injection.
rem
rem   1. build everything
rem   2. start target_hardened.exe with MicrosoftSignedOnly enabled
rem   3. inject payload.dll with injector.exe  -> should FAIL
rem   4. show that no marker file was written
rem   5. kill the target
rem ---------------------------------------------------------------------------
setlocal

set "ROOT=%~dp0"
set "BUILD=%ROOT%build"

call "%ROOT%build.bat"
if errorlevel 1 exit /b 1

echo.
echo [*] starting target_hardened.exe (MicrosoftSignedOnly) ...
set "PID="
for /f "usebackq delims=" %%p in (`powershell -NoProfile -Command "$p = Start-Process -FilePath '%BUILD%\target_hardened.exe' -ArgumentList '--signature' -PassThru; $p.Id"`) do set "PID=%%p"

if not defined PID (
    echo [-] could not determine the target pid
    exit /b 1
)
echo [*] target pid = %PID%

timeout /t 1 /nobreak >nul

echo.
echo [*] injecting payload.dll into the hardened target ...
"%BUILD%\injector.exe" %PID% "%BUILD%\payload.dll"
set "RC=%ERRORLEVEL%"
echo [*] injector exit code = %RC%   (non-zero = blocked, as expected)

timeout /t 1 /nobreak >nul

echo.
echo [*] marker file C:\data\dll_load_%PID%.txt :
echo ---------------------------------------------------------------
if exist "C:\data\dll_load_%PID%.txt" (
    echo [!] marker file EXISTS - the DLL loaded despite the mitigation
    type "C:\data\dll_load_%PID%.txt"
) else (
    echo [+] no marker file - the DLL was NOT loaded. mitigation works.
)
echo ---------------------------------------------------------------

echo.
echo [*] cleaning up target process ...
taskkill /PID %PID% /F >nul 2>&1

exit /b 0
