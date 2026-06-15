@echo off
setlocal

set "ROOT=%~dp0"
set "LAB_URL=http://127.0.0.1:5001/"

powershell -NoProfile -ExecutionPolicy Bypass -Command "try { Invoke-WebRequest -Uri 'http://127.0.0.1:5001/health' -UseBasicParsing -TimeoutSec 1 | Out-Null; exit 0 } catch { exit 1 }"

if errorlevel 1 (
  echo Starting vulnerable app on %LAB_URL% ...
  start "Vulnerable App - 127.0.0.1:5001" /D "%ROOT%" cmd /k python .\vulnerable_app\app.py
  timeout /t 3 /nobreak >nul
)

start "" "%LAB_URL%"

endlocal
