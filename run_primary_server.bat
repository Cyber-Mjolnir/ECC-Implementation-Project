@echo off
title Primary Server - Port 3000
:: Get the project root directory
set "PROJECT_ROOT=%~dp0"
cd /d "%PROJECT_ROOT%"
:: Run the script using the local virtual environment's python directly
"%PROJECT_ROOT%venv\Scripts\python.exe" server_app/primary_server.py
pause