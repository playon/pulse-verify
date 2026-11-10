@echo off
rem Double-click launcher: runs the network check without changing the
rem machine's execution policy, writes the report to the reports folder
rem (and the log to the logs folder) next to this file, and opens it.
rem The script asks its own questions (VLAN, firewall rules, speed test).
cd /d "%~dp0"
powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0Test-PulseVerify.ps1"
rem Exit 0 (ready) or 1 (not ready) means this run wrote a report. 2 and up
rem (stopped at a question, missing file, error) wrote none, so don't reopen
rem an older report from the folder. "if errorlevel 2" means 2 or higher.
if errorlevel 2 goto :done
for /f "delims=" %%F in ('dir /b /o-d "%~dp0reports\vpu-network-check-*.html" 2^>nul') do (start "" "%~dp0reports\%%F" & goto :done)
:done
pause
