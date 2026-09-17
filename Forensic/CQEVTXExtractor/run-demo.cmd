@echo off
setlocal
cd /d "%~dp0"

echo.
echo ===========================================================================
echo  CQEVTXExtractor demo   -   Operation Amber, host WKS-041, 17 March 2026
echo ===========================================================================

if not exist "samples\demo_Security.evtx" (
    echo Sample missing, generating it...
    py -3 make_demo_data.py samples || goto :fail
)

echo.
echo --- 1/6  info: header, chunk map and CRC32 validation ---------------------
py -3 CQEVTXExtractor.py info -i samples\demo_Security.evtx || goto :fail

echo.
echo --- 2/6  stats: what is in this log, by volume ----------------------------
py -3 CQEVTXExtractor.py stats -i samples\demo_Security.evtx || goto :fail

echo.
echo --- 3/6  dump: the whole timeline -----------------------------------------
py -3 CQEVTXExtractor.py dump -i samples\demo_Security.evtx --limit 0 || goto :fail

echo.
echo --- 4/6  dump: just the logons, and just the failures ---------------------
py -3 CQEVTXExtractor.py dump -i samples\demo_Security.evtx --event-id 4624 4625 || goto :fail

echo.
echo --- 5/6  dump: full XML for the credential theft --------------------------
py -3 CQEVTXExtractor.py dump -i samples\demo_Security.evtx --contains mimi.exe --print-xml || goto :fail

echo.
echo --- 6/6  evtxecmd: hand the logons to CQUSNCorrelate ----------------------
py -3 CQEVTXExtractor.py evtxecmd -i samples\demo_Security.evtx --sessions-only -o amber.csv || goto :fail

echo.
echo ===========================================================================
echo  Done. amber.csv is ready for:
echo    py -3 CQUSNCorrelate.py sessions --input samples\demo_J.bin --evtx amber.csv
echo ===========================================================================
goto :eof

:fail
echo.
echo FAILED. If "py" is not recognised, install Python 3.8 or later.
exit /b 1
