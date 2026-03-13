@echo off
setlocal
set SCRIPT_DIR=%~dp0
powershell -NoProfile -ExecutionPolicy Bypass -File "%SCRIPT_DIR%preflight.ps1" -Root "%SCRIPT_DIR%" >nul 2>&1
if not exist "%SCRIPT_DIR%.env.appliance" (
  echo Starting Click2Fix Appliance first-time setup...
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
  exit /b 0
)

echo Opening Click2Fix Appliance Control Center...
powershell -NoProfile -ExecutionPolicy Bypass -File "%SCRIPT_DIR%manage.ps1"
endlocal
