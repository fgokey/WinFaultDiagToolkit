@echo off
setlocal enabledelayedexpansion
set SCRIPT_DIR=%~dp0
set PS1=%SCRIPT_DIR%WinFaultDiag.ps1
set OUTPUT_ROOT=%SCRIPT_DIR%WinFaultDiagOutput
set DUMP_FOLDER=%SCRIPT_DIR%CrashDumps

echo.
echo WinFaultDiag - one-click Windows fault diagnostics
echo ==================================================
echo.
echo Default collection is read-only. It does not repair/delete anything.
echo.
set /p TARGET_PROCESS=Target process name, e.g. DingTalkReal, msedge, YourApp: 
set /p TARGET_EXE=Target exe full path, optional. Drag exe here or press Enter: 
set TARGET_EXE=%TARGET_EXE:"=%
set /p EXTRA_KEYWORDS=Extra keywords, comma-separated, optional: 
set /p HOURS=Lookback hours [24]: 
if "%HOURS%"=="" set HOURS=24
set /p RUN_PROBE=Launch target and observe? Requires valid exe path. [y/N]: 
set /p KILL_EXISTING=Kill existing target/Edge/WebView2/WerFault before probe? [y/N]: 
set /p ENABLE_DUMPS=Enable WER LocalDumps? Requires Administrator. [y/N]: 
set /p INCLUDE_MODULES=Capture loaded modules? May require Administrator. [y/N]: 

set ARGS=-TargetProcessName "%TARGET_PROCESS%" -Hours %HOURS% -DeepSearchWer -OutputRoot "%OUTPUT_ROOT%" -DumpFolder "%DUMP_FOLDER%"
if not "%TARGET_EXE%"=="" set ARGS=%ARGS% -TargetExePath "%TARGET_EXE%"
if not "%EXTRA_KEYWORDS%"=="" set ARGS=%ARGS% -Keywords "%EXTRA_KEYWORDS%"
if /I "%RUN_PROBE%"=="Y" set ARGS=%ARGS% -RunProbe
if /I "%KILL_EXISTING%"=="Y" set ARGS=%ARGS% -KillExisting
if /I "%ENABLE_DUMPS%"=="Y" set ARGS=%ARGS% -EnableLocalDumps
if /I "%INCLUDE_MODULES%"=="Y" set ARGS=%ARGS% -IncludeModuleList

echo.
echo Running:
echo OutputRoot: "%OUTPUT_ROOT%"
echo DumpFolder : "%DUMP_FOLDER%"
echo powershell -NoProfile -ExecutionPolicy Bypass -File "%PS1%" %ARGS%
echo.
powershell -NoProfile -ExecutionPolicy Bypass -File "%PS1%" %ARGS%
echo.
echo Finished. Open the output directory printed above, then read SUMMARY.md.
pause
