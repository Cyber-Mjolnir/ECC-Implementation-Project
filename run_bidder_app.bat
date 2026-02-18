@echo off
title Bidder Application
:: Activate the virtual environment
call venv\Scripts\activate
:: Run the script
python bidder_app/main_bidder.py
pause