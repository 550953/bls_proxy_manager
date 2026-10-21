@echo off
rem Double-click to run the VisaGlobal smoke test. Result is saved next to this file as smoke_result.txt
powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0smoke_test.ps1"
echo.
echo Done. Result saved to: %~dp0smoke_result.txt
pause
