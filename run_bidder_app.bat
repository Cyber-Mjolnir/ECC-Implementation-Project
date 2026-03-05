@echo off
title Bidder Application
:: Get the project root directory
set "PROJECT_ROOT=%~dp0"
cd /d "%PROJECT_ROOT%"
:: Run the script using the local virtual environment's python directly
"%PROJECT_ROOT%venv\Scripts\python.exe" bidder_app/main_bidder.py
pause