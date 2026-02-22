@echo off
:: Wrapper for skillscan.py - works from cmd.exe and PowerShell
python "%~dp0skillscan.py" %*
exit /b %ERRORLEVEL%
