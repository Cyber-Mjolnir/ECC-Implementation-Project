@echo off
title Primary Server - Port 3000
:: Activate the virtual environment
call venv\Scripts\activate
:: Run the script
python server_app/primary_server.py
pause