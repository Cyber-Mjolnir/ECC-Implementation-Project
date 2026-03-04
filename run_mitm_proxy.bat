@echo off
title MITM Traffic Proxy - Port 3001
:: Activate the virtual environment
call venv\Scripts\activate
:: Run the script
python traffic_monitor/mitm_proxy.py
pause
