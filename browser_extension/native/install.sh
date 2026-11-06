#!/usr/bin/env bash
# Установка native messaging host для расширения Cert Filter (Linux).
set -euo pipefail

HOST_NAME="com.certfilter.host"
EXT_ID="pmgabkmokgnookclibdbmkkfchobocek"
FIREFOX_ID="cert-filter@local"

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
INSTALL_DIR="${CERT_FILTER_INSTALL_DIR:-${XDG_DATA_HOME:-$HOME/.local/share}/cert-filter-host}"

PYTHON_BIN=""
if command -v python3 >/dev/null 2>&1; then
  PYTHON_BIN="$(command -v python3)"
elif command -v python >/dev/null 2>&1; then
  PYTHON_BIN="$(command -v python)"
else
  echo "Ошибка: python3 не найден в PATH." >&2
  exit 1
fi

echo "Python: $PYTHON_BIN"
echo "Каталог установки: $INSTALL_DIR"

mkdir -p "$INSTALL_DIR/configs"
install -m 755 "$SCRIPT_DIR/cert_filter_host.py" "$INSTALL_DIR/cert_filter_host.py"
install -m 755 "$SCRIPT_DIR/run_host.sh" "$INSTALL_DIR/run_host.sh"

copied=0
shopt -s nullglob
for file in "$PROJECT_ROOT"/config_*.json; do
  cp -f "$file" "$INSTALL_DIR/configs/"
  copied=$((copied + 1))
done
shopt -u nullglob

if [ "$copied" -eq 0 ]; then
  echo "Внимание: config_*.json не найдены в $PROJECT_ROOT" >&2
  echo "          Скопируйте JSON-конфиги в $INSTALL_DIR/configs/" >&2
else
  echo "Скопировано конфигов: $copied"
fi

HOST_MANIFEST="$INSTALL_DIR/$HOST_NAME.json"
cat > "$HOST_MANIFEST" <<EOF
{
  "name": "$HOST_NAME",
  "description": "Cert Filter native host",
  "path": "$INSTALL_DIR/run_host.sh",
  "type": "stdio",
  "allowed_origins": ["chrome-extension://$EXT_ID/"]
}
EOF
chmod 644 "$HOST_MANIFEST"

FIREFOX_MANIFEST="$INSTALL_DIR/$HOST_NAME.firefox.json"
cat > "$FIREFOX_MANIFEST" <<EOF
{
  "name": "$HOST_NAME",
  "description": "Cert Filter native host",
  "path": "$INSTALL_DIR/run_host.sh",
  "type": "stdio",
  "allowed_extensions": ["$FIREFOX_ID"]
}
EOF
chmod 644 "$FIREFOX_MANIFEST"

installed_chrome=0
for base in \
  "$HOME/.config/google-chrome" \
  "$HOME/.config/google-chrome-beta" \
  "$HOME/.config/chromium" \
  "$HOME/.config/chromium-gost" \
  "$HOME/.config/microsoft-edge" \
  "$HOME/.config/brave-browser" \
  "$HOME/.config/vivaldi" \
  "$HOME/.config/yandex-browser" \
  "$HOME/.config/opera"; do
  if [ -d "$base" ]; then
    mkdir -p "$base/NativeMessagingHosts"
    cp -f "$HOST_MANIFEST" "$base/NativeMessagingHosts/$HOST_NAME.json"
    echo "Chrome/Chromium: $base/NativeMessagingHosts/$HOST_NAME.json"
    installed_chrome=1
  fi
done

if [ "$installed_chrome" -eq 0 ]; then
  echo "Chrome/Chromium не найден. Manifest для ручной установки:"
  echo "  $HOST_MANIFEST"
fi

if [ -d "$HOME/.mozilla" ] || command -v firefox >/dev/null 2>&1; then
  mkdir -p "$HOME/.mozilla/native-messaging-hosts"
  cp -f "$FIREFOX_MANIFEST" "$HOME/.mozilla/native-messaging-hosts/$HOST_NAME.json"
  echo "Firefox: $HOME/.mozilla/native-messaging-hosts/$HOST_NAME.json"
fi

echo
echo "Готово. Перезапустите браузер и загрузите расширение:"
echo "  chrome://extensions -> Режим разработчика -> Загрузить распакованное"
echo "  каталог: $SCRIPT_DIR/.."
echo
echo "Проверка host без браузера:"
echo "  $PYTHON_BIN $INSTALL_DIR/cert_filter_host.py --selftest"
