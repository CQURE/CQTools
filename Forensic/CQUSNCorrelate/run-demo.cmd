@echo off
REM CQUSNCorrelate demo runner
REM Author: Paula Januszkiewicz ^| CQURE
REM
REM Walks all five correlations against the bundled sample data. The planted
REM scenario is written out in samples\demo_README.md, so every answer below
REM can be checked against what was actually put there.

setlocal
cd /d "%~dp0"

where py >nul 2>&1
if errorlevel 1 (
  echo.
  echo   The Python launcher 'py' was not found on PATH.
  echo   Install Python 3.8 or later, or call your interpreter directly:
  echo       ^<python3^> CQUSNCorrelate.py exec-evidence --input samples\demo_J.bin
  echo.
  exit /b 1
)

set J=samples\demo_J.bin
set MFT=samples\demo_MFT.raw
set EVTX=samples\demo_evtx.csv

if not exist "%J%" (
  echo   Sample data missing, generating it now...
  py -3 make_demo_data.py samples\ || exit /b 1
)

echo.
echo ############################################################
echo #  1 / 5   EXEC EVIDENCE, dropped and then executed
echo ############################################################
py -3 CQUSNCorrelate.py exec-evidence --input "%J%" --unpaired --quiet

echo.
echo ############################################################
echo #  2 / 5   LIFECYCLE, created and then deleted
echo ############################################################
py -3 CQUSNCorrelate.py lifecycle --input "%J%" --limit 12 --quiet

echo.
echo ############################################################
echo #  3 / 5   SESSIONS, who was logged on at the time
echo ############################################################
py -3 CQUSNCorrelate.py sessions --input "%J%" --evtx "%EVTX%" --skip-directories --quiet

echo.
echo ############################################################
echo #  4 / 5   METADATA CHANGED, timestamps touched, content not
echo ############################################################
py -3 CQUSNCorrelate.py metadata-changed --input "%J%" --skip-directories --quiet

echo.
echo ############################################################
echo #  5 / 5   SI vs FN, the timestomp check against the $MFT
echo ############################################################
py -3 CQUSNCorrelate.py si-vs-fn --mft "%MFT%" --quiet

echo.
echo ############################################################
echo   Done. The planted scenario is in samples\demo_README.md
echo   so you can check these answers against what was put there.
echo ############################################################
echo.
endlocal
