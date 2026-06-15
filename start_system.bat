@echo off
setlocal

set "ROOT=%~dp0"

echo Starting vulnerable app on http://127.0.0.1:5001 ...
start "Vulnerable App - 127.0.0.1:5001" /D "%ROOT%" cmd /k python .\vulnerable_app\app.py

echo Starting scanner console on http://127.0.0.1:8000 ...
start "Scanner Console - 127.0.0.1:8000" /D "%ROOT%" cmd /k python serve_app.py

echo Waiting for services to initialize...
timeout /t 3 /nobreak >nul

start "" "http://127.0.0.1:8000/"

echo.
echo Opened scanner console: http://127.0.0.1:8000/
echo Keep the two server windows open while using the system.
echo Close those two windows to stop the system.
pause
