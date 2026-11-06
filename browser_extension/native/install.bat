@echo off
setlocal EnableExtensions

set "HOST_NAME=com.certfilter.host"
set "EXT_ID=pmgabkmokgnookclibdbmkkfchobocek"
set "FIREFOX_ID=cert-filter@local"

set "SCRIPT_DIR=%~dp0"
for %%I in ("%SCRIPT_DIR%..\..") do set "PROJECT_ROOT=%%~fI"

if not defined LOCALAPPDATA (
  echo Ошибка: LOCALAPPDATA не задан.
  exit /b 1
)

set "INSTALL_DIR=%LOCALAPPDATA%\CertFilterHost"

where py >nul 2>nul
if %errorlevel%==0 (
  set "PYTHON_CMD=py -3"
) else (
  where python >nul 2>nul
  if errorlevel 1 (
    echo Ошибка: Python не найден в PATH.
    exit /b 1
  )
  set "PYTHON_CMD=python"
)

echo Каталог установки: %INSTALL_DIR%
if not exist "%INSTALL_DIR%\configs" mkdir "%INSTALL_DIR%\configs"

copy /Y "%SCRIPT_DIR%cert_filter_host.py" "%INSTALL_DIR%\" >nul
if errorlevel 1 exit /b 1
copy /Y "%SCRIPT_DIR%run_host.bat" "%INSTALL_DIR%\" >nul
if errorlevel 1 exit /b 1
copy /Y "%PROJECT_ROOT%\config_*.json" "%INSTALL_DIR%\configs\" >nul

set "HOST_JSON=%INSTALL_DIR%\%HOST_NAME%.json"
set "FF_JSON=%INSTALL_DIR%\%HOST_NAME%.firefox.json"

powershell -NoProfile -ExecutionPolicy Bypass -Command ^
  "$m = @{ name='%HOST_NAME%'; description='Cert Filter native host'; path='%INSTALL_DIR%\run_host.bat'; type='stdio'; allowed_origins=@('chrome-extension://%EXT_ID%/') }; $m | ConvertTo-Json -Depth 5 | Set-Content -Encoding UTF8 -Path '%HOST_JSON%'"
if errorlevel 1 exit /b 1

powershell -NoProfile -ExecutionPolicy Bypass -Command ^
  "$m = @{ name='%HOST_NAME%'; description='Cert Filter native host'; path='%INSTALL_DIR%\run_host.bat'; type='stdio'; allowed_extensions=@('%FIREFOX_ID%') }; $m | ConvertTo-Json -Depth 5 | Set-Content -Encoding UTF8 -Path '%FF_JSON%'"
if errorlevel 1 exit /b 1

for %%K in (
  "HKCU\Software\Google\Chrome\NativeMessagingHosts\%HOST_NAME%"
  "HKCU\Software\Chromium\NativeMessagingHosts\%HOST_NAME%"
  "HKCU\Software\Chromium-GOST\NativeMessagingHosts\%HOST_NAME%"
  "HKCU\Software\Microsoft\Edge\NativeMessagingHosts\%HOST_NAME%"
  "HKCU\Software\BraveSoftware\Brave-Browser\NativeMessagingHosts\%HOST_NAME%"
  "HKCU\Software\Vivaldi\NativeMessagingHosts\%HOST_NAME%"
  "HKCU\Software\Yandex\YandexBrowser\NativeMessagingHosts\%HOST_NAME%"
  "HKCU\Software\Opera Software\Opera Stable\NativeMessagingHosts\%HOST_NAME%"
) do (
  reg add %%K /ve /t REG_SZ /d "%HOST_JSON%" /f >nul
)

reg add "HKCU\Software\Mozilla\NativeMessagingHosts\%HOST_NAME%" /ve /t REG_SZ /d "%FF_JSON%" /f >nul

echo.
echo Готово. Перезапустите браузер и загрузите расширение:
echo   chrome://extensions -^> Режим разработчика -^> Загрузить распакованное
echo   каталог: %SCRIPT_DIR%..
echo.
echo Проверка host без браузера:
echo   %PYTHON_CMD% "%INSTALL_DIR%\cert_filter_host.py" --selftest

endlocal
