@echo off
rem ---------------------------------------------------------------------------
rem run_test.bat -- end-to-end smoke test:
rem   1. build everything
rem   2. start target.exe and grab its pid
rem   3. inject payload.dll into it
rem   4. show the marker file the payload wrote to C:\data
rem   5. kill the target
rem ---------------------------------------------------------------------------
setlocal

set "ROOT=%~dp0"
set "BUILD=%ROOT%build"

call "%ROOT%build.bat"
if errorlevel 1 exit /b 1

echo.
echo [*] starting target.exe ...
set "PID="
for /f "usebackq delims=" %%p in (`powershell -NoProfile -Command "$p = Start-Process -FilePath '%BUILD%\target.exe' -PassThru; $p.Id"`) do set "PID=%%p"

if not defined PID (
    echo [-] could not determine the target pid
    exit /b 1
)
echo [*] target pid = %PID%

rem give the target a moment to finish starting up
timeout /t 1 /nobreak >nul

echo.
echo [*] injecting ...
"%BUILD%\injector.exe" %PID% "%BUILD%\payload.dll"
set "RC=%ERRORLEVEL%"
echo [*] injector exit code = %RC%

timeout /t 1 /nobreak >nul

echo.
echo [*] marker file C:\data\dll_load_%PID%.txt :
echo ---------------------------------------------------------------
if exist "C:\data\dll_load_%PID%.txt" (
    type "C:\data\dll_load_%PID%.txt"
) else (
    echo [!] marker file not found - injection did not work
)
echo ---------------------------------------------------------------

echo.
echo [*] cleaning up target process ...
taskkill /PID %PID% /F >nul 2>&1

exit /b %RC%
