@echo off
rem Double-click launcher: runs the network check without changing the
rem machine's execution policy, writes the report to the reports folder
rem (and the log to the logs folder) next to this file, and opens it.
rem The script asks its own questions (venue, VLAN, firewall rules).
cd /d "%~dp0"
powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0Test-PulseVerify.ps1"
for /f "delims=" %%F in ('dir /b /o-d "%~dp0reports\vpu-network-check-*.html" 2^>nul') do (start "" "%~dp0reports\%%F" & goto :done)
:done
pause
