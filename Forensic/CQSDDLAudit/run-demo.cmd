@echo off
REM CQSDDLAudit demo. Analyses the bundled sample collection, no admin needed.
REM Author: Paula Januszkiewicz ^| CQURE   License: Apache License 2.0
setlocal
cd /d "%~dp0"

echo.
echo === 1. the service report, every finding =========================
py -3 CQSDDLAudit.py services --input samples\demo_sddl.csv
if errorlevel 1 goto :failed

echo.
echo === 2. only the hidden ones ======================================
py -3 CQSDDLAudit.py services --input samples\demo_sddl.csv --only-hidden
if errorlevel 1 goto :failed

echo.
echo === 3. findings with severity ====================================
py -3 CQSDDLAudit.py risk --input samples\demo_sddl.csv --min-severity medium
if errorlevel 1 goto :failed

echo.
echo === 4. the hiding ACE, decoded ====================================
py -3 CQSDDLAudit.py decode --object-type service --source CQHiddenService ^
    --sddl "O:SYG:SYD:(D;;DCLCWPDTSD;;;IU)(D;;DCLCWPDTSD;;;SU)(D;;DCLCWPDTSD;;;BA)(A;;CCLCSWRPWPDTLOCRRC;;;SY)"
if errorlevel 1 goto :failed

echo.
echo === 5. can an administrator stop it? ==============================
py -3 CQSDDLAudit.py access --object-type service --token BA --want WP --explain ^
    --sddl "O:SYG:SYD:(D;;DCLCWPDTSD;;;BA)(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;BA)"
if errorlevel 1 goto :failed

echo.
echo === 6. the HTML report ===========================================
py -3 CQSDDLAudit.py services --input samples\demo_sddl.csv --all --html demo-report.html --host DEMO
if errorlevel 1 goto :failed

echo.
echo Done. Open demo-report.html.
echo To audit this machine, run elevated:
echo     powershell -ExecutionPolicy Bypass -File Collect-Sddl.ps1 -OutFile services.csv
echo     py -3 CQSDDLAudit.py services --input services.csv --html report.html
goto :eof

:failed
echo.
echo A step failed. Check that Python 3 is installed and reachable as "py -3".
exit /b 1
