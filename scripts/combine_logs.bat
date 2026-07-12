@echo off
REM Double-click this. It picks an interpreter that actually HAS pandas,
REM rather than trusting the default .py file association - Dean has more
REM than one Python installed and only 3.13 has the deps.
setlocal enabledelayedexpansion

set "PYCMD="
for %%P in ("py -3.13" "py -3.12" "py -3" "python") do (
    if not defined PYCMD (
        %%~P -c "import pandas, numpy" >nul 2>&1
        if !errorlevel! equ 0 set "PYCMD=%%~P"
    )
)

if not defined PYCMD (
    echo.
    echo No Python on this machine has both pandas and numpy.
    echo Tried: py -3.13, py -3.12, py -3, python
    echo.
    echo Install into the one you want, e.g.:
    echo     py -3.13 -m pip install pandas
    echo.
    pause
    exit /b 9
)

echo Using: !PYCMD!
!PYCMD! "%~dp0combine_logs.py" %*
set RC=!errorlevel!

if not "!RC!"=="0" (
    echo.
    echo ==== combine_logs.py exited with code !RC! ====
    echo.
    pause
)
endlocal
