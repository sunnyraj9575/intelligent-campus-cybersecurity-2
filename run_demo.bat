@echo off
title Campus Threat Detection - Live CLI Demo
cd /d "%~dp0"
set PYTHONPATH=%~dp0
echo ======================================================================
echo Running Campus Threat Detection Live Simulation...
echo ======================================================================
echo.
python run_demo.py
echo.
pause
