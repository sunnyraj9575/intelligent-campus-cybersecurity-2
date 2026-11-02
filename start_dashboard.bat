@echo off
title Campus Cyber Threat Detection - SOC Dashboard
cd /d "%~dp0"
set PYTHONPATH=%~dp0
echo ======================================================================
echo Starting Intelligent Campus Cyber Threat Detection SOC Dashboard...
echo ======================================================================
echo Dashboard URL: http://127.0.0.1:8000
echo Press Ctrl+C to terminate.
echo.
python dashboard\app.py
pause
