@echo off
setlocal
set SCRIPT_DIR=%~dp0
echo Starting Click2Fix Appliance Setup...
powershell -NoProfile -ExecutionPolicy Bypass -File "%SCRIPT_DIR%install.ps1"
if errorlevel 1 (
  echo.
  echo Setup failed. Review the error output above.
  pause
  exit /b 1
)
echo.
echo Setup completed.
pause
endlocal
