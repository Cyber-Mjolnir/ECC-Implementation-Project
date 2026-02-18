@echo off
title Backup Server - Standby Mode
:: Activate the virtual environment
call venv\Scripts\activate
:: Run the script
python server_app/backup_server.py
pause