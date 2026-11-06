@echo off
setlocal
set "DIR=%~dp0"

set "LOG_DIR=%LOCALAPPDATA%\CertFilterHost"
if not defined LOCALAPPDATA set "LOG_DIR=%TEMP%\CertFilterHost"
if not exist "%LOG_DIR%" mkdir "%LOG_DIR%" 2>nul

if exist "%DIR%python.exe" (
  "%DIR%python.exe" "%DIR%cert_filter_host.py" %* 2>>"%LOG_DIR%\host.log"
  exit /b %errorlevel%
)

where py >nul 2>nul
if %errorlevel%==0 (
  py -3 "%DIR%cert_filter_host.py" %* 2>>"%LOG_DIR%\host.log"
  exit /b %errorlevel%
)

python "%DIR%cert_filter_host.py" %* 2>>"%LOG_DIR%\host.log"
exit /b %errorlevel%
