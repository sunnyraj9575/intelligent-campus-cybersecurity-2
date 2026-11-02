@echo off
title Campus Threat Detection - Train Models Pipeline
cd /d "%~dp0"
set PYTHONPATH=%~dp0
echo ======================================================================
echo Training Supervised ML Threat Detection Models...
echo ======================================================================
echo.
python models\train.py
echo.
pause
