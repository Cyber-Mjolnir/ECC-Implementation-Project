@echo off
title MITM Traffic Proxy - Port 3001
:: Get the project root directory
set "PROJECT_ROOT=%~dp0"
cd /d "%PROJECT_ROOT%"
:: Run the script using the local virtual environment's python directly
"%PROJECT_ROOT%venv\Scripts\python.exe" traffic_monitor/mitm_proxy.py
pause
