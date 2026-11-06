# Cert Filter — расширение для браузера

Расширение повторяет основную логику `cert_filter_ui.pyw`: по выбранному JSON-конфигу и номеру ключа находит CN сертификата, показывает совпавшие сертификаты и скрывает (архивирует) все остальные в хранилищах `MY` и `AddressBook` текущего пользователя.

## Как это работает

Браузер не имеет доступа к CryptoAPI/КриптоПро напрямую, поэтому используется стандартный механизм **Native Messaging**:

```
popup расширения  ->  background.js  ->  native host (Python)  ->  CryptoAPI
```

- `browser_extension/native/cert_filter_host.py` — локальный помощник. Он не открывает сетевых портов и принимает команды только от расширения с известным ID.
- `install.sh` / `install.bat` регистрируют этого помощника в браузере.
- Логика фильтра взята из `cert_filter_ui.pyw`:
  - регистронезависимый поиск CN по подстроке;
  - совпавшие сертификаты показываются;
  - все несовпавшие переводятся в архив (скрываются).

## Требования

### Linux
- Python 3.8+
- КриптоПро CSP с библиотеками:
  - `/opt/cprocsp/lib/amd64/libcapi20.so`
  - `/opt/cprocsp/lib/amd64/libcapi10.so`
- Chrome, Chromium, Chromium-GOST, Edge, Brave, Vivaldi, Yandex Browser или Opera
- PySide6 **не требуется**

### Windows
- Python 3.8+ (при установке включите «Add Python to PATH»)
- КриптоПро CSP или другой CryptoAPI-провайдер
- Chrome, Chromium, Chromium-GOST, Edge, Brave, Vivaldi, Yandex Browser или Opera
- PySide6 **не требуется**

## Установка на Linux

1. Перейдите в каталог проекта:

   ```bash
   cd /home/zurab/my_apps/software_for_certificates
   ```

2. Запустите установщик native host **от имени того же пользователя, под которым работает браузер** (без `sudo`):

   ```bash
   bash browser_extension/native/install.sh
   ```

   Скрипт:
   - копирует host в `~/.local/share/cert-filter-host` (или `$XDG_DATA_HOME/cert-filter-host`);
   - копирует `config_fl.json` и `config_ul.json` в `~/.local/share/cert-filter-host/configs`;
   - создаёт manifest native host;
   - регистрирует host для найденных браузеров:
     - `~/.config/google-chrome/NativeMessagingHosts/`
     - `~/.config/chromium/NativeMessagingHosts/`
     - `~/.config/chromium-gost/NativeMessagingHosts/`
     - `~/.config/microsoft-edge/NativeMessagingHosts/`
     - `~/.config/brave-browser/NativeMessagingHosts/`
     - `~/.config/vivaldi/NativeMessagingHosts/`
     - `~/.config/yandex-browser/NativeMessagingHosts/`
     - `~/.config/opera/NativeMessagingHosts/`
   - регистрирует host для Firefox в `~/.mozilla/native-messaging-hosts/`.

3. Полностью перезапустите браузер.

4. Загрузите расширение:

   - Chrome / Chromium / Chromium-GOST / Brave / Vivaldi: `chrome://extensions`
   - Yandex Browser: `browser://extensions`
   - Opera: `opera://extensions`
   - Edge: `edge://extensions`

   Включите **«Режим разработчика»**, нажмите **«Загрузить распакованное»** и выберите каталог:

   ```
   /home/zurab/my_apps/software_for_certificates/browser_extension
   ```

5. Нажмите на иконку расширения на панели браузера.

### Если браузер не был найден установщиком

Скопируйте manifest вручную в каталог нужного браузера:

```bash
cp ~/.local/share/cert-filter-host/com.certfilter.host.json \
   ~/.config/google-chrome/NativeMessagingHosts/com.certfilter.host.json
```

Для Chromium-GOST замените `google-chrome` на `chromium-gost`.

## Установка на Windows

1. Установите Python 3.8+ с [python.org](https://www.python.org/downloads/windows/) и включите опцию **«Add Python to PATH»**.

2. Убедитесь, что установлен КриптоПро CSP.

3. Запустите установщик:

   ```cmd
   cd C:\путь\к\software_for_certificates
   browser_extension\native\install.bat
   ```

   Можно также дважды кликнуть по `install.bat`.

   Скрипт:
   - копирует host в `%LOCALAPPDATA%\CertFilterHost`;
   - копирует `config_*.json` в `%LOCALAPPDATA%\CertFilterHost\configs`;
   - создаёт manifest native host;
   - прописывает ключи реестра для Chrome, Chromium, Chromium-GOST, Edge, Brave, Vivaldi, Yandex Browser, Opera и Firefox.

4. Полностью перезапустите браузер.

5. Загрузите расширение:

   - Chrome / Chromium / Chromium-GOST / Brave / Vivaldi: `chrome://extensions`
   - Yandex Browser: `browser://extensions`
   - Opera: `opera://extensions`
   - Edge: `edge://extensions`

   Включите **«Режим разработчика»**, нажмите **«Загрузить распакованное»** и выберите каталог:

   ```
   C:\путь\к\software_for_certificates\browser_extension
   ```

6. Нажмите на иконку расширения на панели браузера.

### Если Python не найден

- Откройте новое окно `cmd` после установки Python.
- Проверьте команды:

  ```cmd
  py -3 --version
  python --version
  ```

- Если `python` открывает Microsoft Store, используйте `py -3`. Установщик и `run_host.bat` уже пытаются использовать `py` в первую очередь.

## Установка в Firefox

Firefox использует отдельный manifest расширения.

1. Выполните установку native host для своей ОС (шаги выше). Для Linux host регистрируется в `~/.mozilla/native-messaging-hosts/`, для Windows — в реестре.

2. Создайте копию каталога расширения:

   ```bash
   cp -r browser_extension browser_extension_firefox
   cp browser_extension_firefox/manifest.firefox.json browser_extension_firefox/manifest.json
   ```

3. Откройте `about:debugging#/runtime/this-firefox`.

4. Нажмите **«Load Temporary Add-on»** и выберите `browser_extension_firefox/manifest.json`.

Временное дополнение исчезнет после перезапуска Firefox. Для постоянной установки расширение нужно подписать в Mozilla Add-ons либо использовать Firefox Developer Edition с отключённой проверкой подписей.

### Firefox из Snap

Snap-версия Firefox использует изолированный профиль. Если native host не находится, скопируйте manifest:

```bash
mkdir -p ~/snap/firefox/common/.mozilla/native-messaging-hosts
cp ~/.mozilla/native-messaging-hosts/com.certfilter.host.json \
   ~/snap/firefox/common/.mozilla/native-messaging-hosts/
```

## Использование

1. Нажмите на иконку расширения.
2. В поле **«Конфигурация (JSON)»** выберите `config_fl.json` или `config_ul.json`.
   - Кнопка **«загрузить»** позволяет открыть произвольный JSON-файл с компьютера.
3. Введите ключ, например `1` или `ддо1`.
4. Нажмите **OK** или клавишу Enter.
5. Результат отобразится в журнале:
   - `Видно: N` — столько сертификатов совпало;
   - `скрыто: M` — столько сертификатов переведено в архив.
6. Кнопки:
   - **«Показать все»** — снять архивный флаг со всех сертификатов;
   - **«Скрыть все»** — перевести все сертификаты в архив;
   - **«Обновить»** — перечитать список сертификатов.
7. В списке сертификатов:
   - поиск по CN;
   - кнопка `■` / `○` скрывает или показывает отдельный сертификат.

Фильтр не удаляет сертификаты и ключи. Он только меняет флаг архивности, как и `cert_filter_ui.pyw`.

## Конфигурации JSON

Формат файла:

```json
{
  "1": "Иванов Иван Иванович",
  "2": "Петров Пётр Петрович",
  "ддо1": "Название организации"
}
```

Ключ — то, что вы вводите в поле «КЛЮЧ». Значение — CN сертификата (или его часть).

При установке файлы `config_fl.json` и `config_ul.json` копируются в каталог host:

- Linux: `~/.local/share/cert-filter-host/configs/`
- Windows: `%LOCALAPPDATA%\CertFilterHost\configs\`

Если вы изменили JSON в каталоге проекта, повторно запустите установщик или скопируйте файлы в каталог `configs` вручную.

Можно указать свой каталог через переменную окружения `CERT_FILTER_CONFIG_DIR`. На Linux браузер должен быть запущен из терминала, чтобы увидеть переменную:

```bash
export CERT_FILTER_CONFIG_DIR=/путь/к/конфигам
google-chrome
```

## Проверка native host без браузера

### Linux

```bash
python3 ~/.local/share/cert-filter-host/cert_filter_host.py --selftest
```

### Windows

```cmd
py -3 "%LOCALAPPDATA%\CertFilterHost\cert_filter_host.py" --selftest
```

Команда выводит:
- каталог конфигов и найденные JSON;
- доступность CryptoAPI;
- количество сертификатов в хранилище.

## Диагностика

### «Native host не найден»

1. Убедитесь, что установщик завершился без ошибок.
2. Полностью закройте и снова откройте браузер.
3. Проверьте, что manifest существует и путь в нём правильный:
   - Linux: `~/.config/<браузер>/NativeMessagingHosts/com.certfilter.host.json`
   - Windows: `%LOCALAPPDATA%\CertFilterHost\com.certfilter.host.json`
4. Проверьте ID расширения. В `chrome://extensions` он должен быть:

   ```
   pmgabkmokgnookclibdbmkkfchobocek
   ```

   Этот ID задаётся полем `key` в `manifest.json`. Если поле удалить или изменить, ID изменится, и host перестанет принимать запросы. В этом случае либо верните `key`, либо обновите `allowed_origins` в manifest native host.
5. В Windows проверьте ключи реестра:

   ```cmd
   reg query "HKCU\Software\Google\Chrome\NativeMessagingHosts\com.certfilter.host"
   ```

### «CryptoAPI недоступен»

1. Проверьте, что установлен КриптоПро CSP.
2. На Linux проверьте наличие библиотек:

   ```bash
   ls -l /opt/cprocsp/lib/amd64/libcapi20.so
   ls -l /opt/cprocsp/lib/amd64/libcapi10.so
   ```

3. Запустите `--selftest` (см. выше).

### Пустой список конфигов

- Убедитесь, что `config_fl.json` и `config_ul.json` лежат в корне проекта перед запуском `install.sh` / `install.bat`.
- Либо скопируйте их вручную в каталог `configs` host.

### Пустой список сертификатов

Приложение работает с хранилищем **текущего пользователя** (`CURRENT_USER`), а не `LocalMachine`. Если сертификаты установлены только для всех пользователей или для другого пользователя, они не отобразятся.

### Журналы

- Linux: `~/.cache/cert-filter-host/host.log`
- Windows: `%LOCALAPPDATA%\CertFilterHost\host.log`
- Ошибки расширения: `chrome://extensions` → «Ошибки» / консоль service worker.

## Удаление

1. Удалите расширение со страницы `chrome://extensions` (или аналога).

2. Linux:

   ```bash
   rm -rf ~/.local/share/cert-filter-host
   rm -f ~/.config/google-chrome/NativeMessagingHosts/com.certfilter.host.json
   rm -f ~/.config/chromium/NativeMessagingHosts/com.certfilter.host.json
   rm -f ~/.config/chromium-gost/NativeMessagingHosts/com.certfilter.host.json
   rm -f ~/.config/microsoft-edge/NativeMessagingHosts/com.certfilter.host.json
   rm -f ~/.config/brave-browser/NativeMessagingHosts/com.certfilter.host.json
   rm -f ~/.config/vivaldi/NativeMessagingHosts/com.certfilter.host.json
   rm -f ~/.config/yandex-browser/NativeMessagingHosts/com.certfilter.host.json
   rm -f ~/.config/opera/NativeMessagingHosts/com.certfilter.host.json
   rm -f ~/.mozilla/native-messaging-hosts/com.certfilter.host.json
   ```

3. Windows:

   ```cmd
   rmdir /S /Q "%LOCALAPPDATA%\CertFilterHost"
   reg delete "HKCU\Software\Google\Chrome\NativeMessagingHosts\com.certfilter.host" /f
   reg delete "HKCU\Software\Chromium\NativeMessagingHosts\com.certfilter.host" /f
   reg delete "HKCU\Software\Chromium-GOST\NativeMessagingHosts\com.certfilter.host" /f
   reg delete "HKCU\Software\Microsoft\Edge\NativeMessagingHosts\com.certfilter.host" /f
   reg delete "HKCU\Software\BraveSoftware\Brave-Browser\NativeMessagingHosts\com.certfilter.host" /f
   reg delete "HKCU\Software\Vivaldi\NativeMessagingHosts\com.certfilter.host" /f
   reg delete "HKCU\Software\Yandex\YandexBrowser\NativeMessagingHosts\com.certfilter.host" /f
   reg delete "HKCU\Software\Opera Software\Opera Stable\NativeMessagingHosts\com.certfilter.host" /f
   reg delete "HKCU\Software\Mozilla\NativeMessagingHosts\com.certfilter.host" /f
   ```

## Структура проекта

```
browser_extension/
├── manifest.json              # Chrome / Chromium / Edge и другие Chromium-браузеры
├── manifest.firefox.json      # Firefox
├── popup.html                 # форма расширения
├── popup.css
├── popup.js
├── background.js              # связь popup с native host
├── icons/
└── native/
    ├── cert_filter_host.py    # работа с CryptoAPI
    ├── run_host.sh            # запуск host в Linux
    ├── run_host.bat           # запуск host в Windows
    ├── install.sh             # установка в Linux
    └── install.bat            # установка в Windows
```

## Безопасность

- Native host не слушает сетевые порты.
- Запросы принимаются только от расширения с ID `pmgabkmokgnookclibdbmkkfchobocek` (Chrome) или `cert-filter@local` (Firefox).
- Все операции выполняются в хранилище сертификатов текущего пользователя.
- Фильтрация и переключатели меняют только флаг архивности, но не удаляют сертификаты и закрытые ключи.
