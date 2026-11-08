const isFirefox =
  typeof globalThis.browser !== "undefined" &&
  !!globalThis.browser &&
  !!globalThis.browser.runtime;
const api = globalThis.browser || globalThis.chrome;

const els = {};
const STORAGE_KEY = "certFilterPopupState";
let hostReady = false;
let configData = null;
let configLabel = "";
let fileConfigs = [];
const FILE_VALUE_PREFIX = "__file__:";
let hiddenConfigs = [];
let certs = [];
let logs = [];

document.addEventListener("DOMContentLoaded", () => {
  [
    "hostDot",
    "banner",
    "refreshBtn",
    "configSelect",
    "configInfo",
    "fileInput",
    "deleteConfigBtn",
    "restoreConfigsBtn",
    "keyInput",
    "applyBtn",
    "resolved",
    "showAllBtn",
    "hideAllBtn",
    "reloadCertsBtn",
    "certSearch",
    "certCount",
    "certList",
    "log",
  ].forEach((id) => {
    els[id] = document.getElementById(id);
  });

  bindEvents();
  init().catch((error) => {
    setDot("err");
    showBanner(error.message || String(error));
    log(error.message || String(error), "bad");
  });
});

function bindEvents() {
  els.refreshBtn.addEventListener("click", refreshAll);
  els.configSelect.addEventListener("change", () => {
    const name = els.configSelect.value;
    updateDeleteButton();
    const fileEntry = findFileConfigByValue(name);
    if (fileEntry) {
      selectFileConfig(fileEntry);
      return;
    }
    if (name) {
      loadConfig(name)
        .catch((error) => log(error.message, "bad"))
        .finally(() => writeState());
    } else {
      configData = null;
      configLabel = "";
      els.configInfo.textContent = "Конфиг не выбран. Выберите JSON из списка.";
      els.configInfo.className = "hint";
      updateResolved();
      writeState();
    }
  });
  els.fileInput.addEventListener("change", onFileChosen);
  els.deleteConfigBtn.addEventListener("click", deleteCurrentConfig);
  els.restoreConfigsBtn.addEventListener("click", restoreHiddenConfigs);
  els.keyInput.addEventListener("input", () => {
    updateResolved();
    writeState();
  });
  els.keyInput.addEventListener("keydown", (event) => {
    if (event.key === "Enter") {
      event.preventDefault();
      applyFilter();
    }
  });
  els.applyBtn.addEventListener("click", applyFilter);
  els.showAllBtn.addEventListener("click", () => runSimpleAction("restore_all", "Все сертификаты показаны", "good"));
  els.hideAllBtn.addEventListener("click", () => runSimpleAction("hide_all", "Все сертификаты скрыты", "bad"));
  els.reloadCertsBtn.addEventListener("click", () => loadCerts());
  els.certSearch.addEventListener("input", () => {
    renderCerts();
    writeState();
  });
  window.addEventListener("pagehide", writeState);
}

async function init() {
  const saved = await readState();
  if (Array.isArray(saved.hidden)) {
    hiddenConfigs = saved.hidden.filter(
      (item) => typeof item === "string" && item
    );
  }
  if (typeof saved.key === "string") els.keyInput.value = saved.key;
  if (typeof saved.search === "string") els.certSearch.value = saved.search;
  loadSavedFileConfigs(saved);
  updateResolved();

  let restored = typeof saved.config === "string" ? saved.config : "";
  if (restored === "__file__") {
    restored = fileConfigs.length ? fileOptionValue(fileConfigs[0]) : "";
  }

  log("Подключение к native host...", "info");
  if (!(await connectHost())) {
    const restoredFile = findFileConfigByValue(restored);
    if (restoredFile) selectFileConfig(restoredFile);
    return;
  }
  await loadConfigs(restored);
  await loadCerts();
}

function makeFileId() {
  return `f${Date.now().toString(36)}${Math.random().toString(36).slice(2, 7)}`;
}

function normalizeFileConfig(item) {
  if (!item || !item.data || typeof item.data !== "object") return null;
  const data = {};
  for (const [key, value] of Object.entries(item.data)) {
    if (typeof value === "string") data[key] = value;
  }
  return {
    id: typeof item.id === "string" && item.id ? item.id : makeFileId(),
    name: typeof item.name === "string" && item.name ? item.name : "custom.json",
    data,
  };
}

function loadSavedFileConfigs(saved) {
  fileConfigs = [];
  const usedIds = new Set();
  const add = (item) => {
    const entry = normalizeFileConfig(item);
    if (!entry) return;
    if (usedIds.has(entry.id)) entry.id = makeFileId();
    usedIds.add(entry.id);
    fileConfigs.push(entry);
  };

  if (Array.isArray(saved.files)) {
    for (const item of saved.files) add(item);
  }
  if (!fileConfigs.length && saved.file) add(saved.file);
}

function fileOptionValue(entry) {
  return `${FILE_VALUE_PREFIX}${entry.id}`;
}

function findFileConfigByValue(value) {
  if (!value) return null;
  if (value === "__file__") return fileConfigs[0] || null;
  if (!value.startsWith(FILE_VALUE_PREFIX)) return null;
  const id = value.slice(FILE_VALUE_PREFIX.length);
  return fileConfigs.find((entry) => entry.id === id) || null;
}

async function refreshAll() {
  if (!(await connectHost())) return;
  await loadConfigs();
  await loadCerts();
}

async function connectHost() {
  try {
    const response = await sendBg({ action: "ping" });
    hostReady = true;
    if (response.crypto === false) {
      setDot("err");
      showBanner(
        `Native host запущен, но CryptoAPI недоступен: ${
          response.crypto_error || "неизвестная ошибка"
        }`
      );
      log("CryptoAPI недоступен", "bad");
    } else {
      setDot("ok");
      hideBanner();
      log("Native host подключён", "good");
    }
    return true;
  } catch (error) {
    hostReady = false;
    setDot("err");
    showBanner(
      "Native host не найден. Запустите native/install.sh (Linux) или native/install.bat (Windows), затем перезапустите браузер."
    );
    log("Native host недоступен", "bad");
    populateConfigs([]);
    return false;
  }
}

async function loadConfigs(preferred = "") {
  const previous = els.configSelect.value;
  try {
    const response = await sendBg({ action: "get_configs" });
    const allConfigs = Array.isArray(response.configs) ? response.configs : [];
    const list = allConfigs.filter((item) => {
      const name = typeof item === "string" ? item : item && item.name;
      return !!name && !hiddenConfigs.includes(name);
    });
    populateConfigs(list);

    const preferredFile = findFileConfigByValue(preferred);
    if (preferredFile) {
      selectFileConfig(preferredFile);
      log(`Загружен сохранённый JSON: ${preferredFile.name}`, "info");
      return;
    }
    if (!preferred) {
      const previousFile = findFileConfigByValue(previous);
      if (previousFile) {
        selectFileConfig(previousFile);
        return;
      }
    }

    if (list.length) {
      const names = list
        .map((item) => (typeof item === "string" ? item : item && item.name))
        .filter(Boolean);
      if (!names.length) return;
      const wanted = names.includes(preferred)
        ? preferred
        : names.includes(previous)
        ? previous
        : "";
      if (!wanted) {
        showNoConfigOption();
        configData = null;
        configLabel = "";
        els.configInfo.textContent = "Конфиг не выбран. Выберите JSON из списка.";
        els.configInfo.className = "hint";
        updateResolved();
        writeState();
        log(`Конфигов найдено: ${list.length}`, "info");
        return;
      }
      els.configSelect.value = wanted;
      await loadConfig(wanted);
      writeState();
      log(`Конфигов найдено: ${list.length}`, "info");
    } else {
      configData = null;
      configLabel = "";
      showNoConfigOption();
      els.configInfo.textContent = hiddenConfigs.length
        ? `Все конфиги скрыты (${hiddenConfigs.length}). Нажмите «вернуть», чтобы показать их снова.`
        : fileConfigs.length
        ? "Нет конфигов в каталоге. Выберите загруженный JSON из списка или загрузите новый."
        : "JSON-файлы не найдены. Загрузите файл вручную.";
      updateResolved();
      writeState();
    }
  } catch (error) {
    log(`Ошибка загрузки конфигов: ${error.message}`, "bad");
  }
}

function populateConfigs(list) {
  els.configSelect.replaceChildren();

  const option = document.createElement("option");
  option.value = "";
  option.textContent =
    list.length || fileConfigs.length
      ? "— выберите конфиг —"
      : hiddenConfigs.length
      ? "— все конфиги скрыты —"
      : "— нет доступных JSON —";
  els.configSelect.append(option);

  for (const item of list) {
    const name = typeof item === "string" ? item : item && item.name;
    if (!name) continue;
    const itemOption = document.createElement("option");
    itemOption.value = name;
    itemOption.textContent = name;
    if (item && typeof item.key_count === "number") {
      itemOption.dataset.keys = String(item.key_count);
    }
    els.configSelect.append(itemOption);
  }

  ensureFileOptions();
  updateDeleteButton();
}

function ensureFileOptions() {
  for (const entry of fileConfigs) {
    const value = fileOptionValue(entry);
    let existing = null;
    for (const option of els.configSelect.options) {
      if (option.value === value) {
        existing = option;
        break;
      }
    }
    if (existing) {
      existing.textContent = `📄 ${entry.name}`;
      continue;
    }
    const option = document.createElement("option");
    option.value = value;
    option.textContent = `📄 ${entry.name}`;
    els.configSelect.append(option);
  }
}

function selectFileConfig(entry) {
  if (!entry) return;
  ensureFileOptions();
  els.configSelect.value = fileOptionValue(entry);
  configData = entry.data;
  configLabel = entry.name;
  els.configInfo.textContent = `${entry.name} · ключей: ${
    Object.keys(entry.data).length
  }`;
  els.configInfo.className = "hint";
  updateResolved();
  writeState();
}

function updateDeleteButton() {
  if (els.deleteConfigBtn) {
    els.deleteConfigBtn.disabled = !els.configSelect.value;
  }
  if (els.restoreConfigsBtn) {
    els.restoreConfigsBtn.hidden = hiddenConfigs.length === 0;
    els.restoreConfigsBtn.textContent = `вернуть (${hiddenConfigs.length})`;
    els.restoreConfigsBtn.title = `Вернуть скрытые конфиги: ${hiddenConfigs.length}`;
  }
}

function restoreHiddenConfigs() {
  if (!hiddenConfigs.length) return;
  hiddenConfigs = [];
  log("Скрытые конфиги возвращены в список", "good");
  writeState();
  if (hostReady) {
    loadConfigs().catch((error) => log(error.message, "bad"));
  } else {
    els.configInfo.textContent = "Нет соединения с native host";
    els.configInfo.className = "hint bad";
  }
}

function deleteCurrentConfig() {
  const name = els.configSelect.value;
  const fileEntry = findFileConfigByValue(name);
  const isFile = !!fileEntry;
  if (!name && !configData && !fileConfigs.length) {
    log("Нет загруженного конфига", "bad");
    return;
  }

  const label = isFile ? fileEntry.name : configLabel || name;
  const message = isFile
    ? `Удалить сохранённую в расширении копию конфига «${label}»? Исходный файл на диске останется.`
    : `Удалить конфиг «${label}» из расширения? JSON-файл на диске останется без изменений.`;
  if (!window.confirm(message)) return;

  if (isFile) {
    fileConfigs = fileConfigs.filter((entry) => entry !== fileEntry);
  } else if (name && !hiddenConfigs.includes(name)) {
    hiddenConfigs.push(name);
  }
  configData = null;
  configLabel = "";

  for (const option of Array.from(els.configSelect.options)) {
    if (option.value === name) option.remove();
  }
  showNoConfigOption();
  els.configInfo.textContent = isFile
    ? "Сохранённая копия удалена из расширения. Исходный файл не изменён."
    : "Конфиг скрыт в расширении. JSON-файл на диске не изменён.";
  els.configInfo.className = "hint";
  updateResolved();
  writeState();
  log(
    isFile
      ? "Сохранённая копия конфига удалена из расширения"
      : `Конфиг «${label}» скрыт в расширении`,
    "good"
  );
}

function showNoConfigOption() {
  let placeholder = null;
  for (const option of els.configSelect.options) {
    if (option.value === "") {
      placeholder = option;
      break;
    }
  }
  if (!placeholder) {
    placeholder = document.createElement("option");
    placeholder.value = "";
    placeholder.textContent = "— конфиг не выбран —";
    els.configSelect.prepend(placeholder);
  }
  els.configSelect.value = "";
}

function readState() {
  return new Promise((resolve) => {
    try {
      const maybe = api.storage.local.get(STORAGE_KEY);
      if (maybe && typeof maybe.then === "function") {
        maybe
          .then((data) => resolve((data && data[STORAGE_KEY]) || {}))
          .catch(() => resolve({}));
        return;
      }
      api.storage.local.get(STORAGE_KEY, (data) => {
        resolve((data && data[STORAGE_KEY]) || {});
      });
    } catch (_) {
      resolve({});
    }
  });
}

function writeState() {
  updateDeleteButton();
  const state = {
    config: els.configSelect.value || "",
    key: els.keyInput.value || "",
    search: els.certSearch.value || "",
    files: fileConfigs.map((entry) => ({
      id: entry.id,
      name: entry.name,
      data: entry.data,
    })),
    hidden: hiddenConfigs,
  };
  try {
    const maybe = api.storage.local.set({ [STORAGE_KEY]: state });
    if (maybe && typeof maybe.catch === "function") maybe.catch(() => {});
  } catch (_) {
    /* ignore */
  }
}

async function loadConfig(name) {
  try {
    const response = await sendBg({ action: "get_config", name });
    const raw = response.config && typeof response.config === "object" ? response.config : {};
    configData = {};
    for (const [key, value] of Object.entries(raw)) {
      if (typeof value === "string") configData[key] = value;
    }
    configLabel = name;
    const count = Object.keys(configData).length;
    els.configInfo.textContent = `${name} · ключей: ${count}`;
    els.configInfo.className = "hint";
    updateResolved();
  } catch (error) {
    configData = null;
    configLabel = "";
    els.configInfo.textContent = `Не удалось загрузить ${name}: ${error.message}`;
    els.configInfo.className = "hint bad";
    updateResolved();
  }
}

async function onFileChosen() {
  const files = Array.from(els.fileInput.files || []);
  if (!files.length) return;

  const loaded = [];
  for (const file of files) {
    try {
      const text = await file.text();
      const parsed = JSON.parse(text);
      const clean = {};
      for (const [key, value] of Object.entries(parsed || {})) {
        if (typeof value === "string") clean[key] = value;
      }
      let entry = fileConfigs.find((item) => item.name === file.name);
      if (entry) {
        entry.data = clean;
      } else {
        entry = { id: makeFileId(), name: file.name, data: clean };
        fileConfigs.push(entry);
      }
      loaded.push(entry);
    } catch (error) {
      log(`Ошибка JSON (${file.name}): ${error.message}`, "bad");
    }
  }

  if (loaded.length) {
    ensureFileOptions();
    selectFileConfig(loaded[loaded.length - 1]);
    log(
      loaded.length > 1
        ? `Загружено JSON-файлов: ${loaded.length}`
        : `Загружен файл ${loaded[0].name}`,
      "info"
    );
  }
  els.fileInput.value = "";
}

function findValue(key) {
  if (!configData || !key) return null;
  if (Object.prototype.hasOwnProperty.call(configData, key)) return configData[key];
  const lower = key.toLowerCase();
  for (const [candidate, value] of Object.entries(configData)) {
    if (candidate.toLowerCase() === lower) return value;
  }
  return null;
}

function updateResolved() {
  const key = els.keyInput.value.trim();
  if (!configData) {
    els.resolved.textContent = "Конфиг не выбран";
    els.resolved.className = "hint";
    return;
  }
  if (!key) {
    els.resolved.textContent = `Ключей в конфиге: ${Object.keys(configData).length}`;
    els.resolved.className = "hint";
    return;
  }
  const value = findValue(key);
  if (value) {
    els.resolved.textContent = value;
    els.resolved.className = "hint good";
  } else {
    els.resolved.textContent = `Ключ «${key}» не найден`;
    els.resolved.className = "hint bad";
  }
}

async function applyFilter() {
  const key = els.keyInput.value.trim();
  if (!key) {
    els.keyInput.focus();
    log("Введите ключ", "bad");
    return;
  }
  const value = findValue(key);
  if (!value) {
    log(`Ключ «${key}» не найден в конфиге`, "bad");
    updateResolved();
    return;
  }
  if (!hostReady) {
    showBanner(
      "Native host не найден. Запустите native/install.sh (Linux) или native/install.bat (Windows), затем перезапустите браузер."
    );
    log("Нет соединения с native host", "bad");
    return;
  }

  els.applyBtn.disabled = true;
  log(`Фильтр: ${value}`, "info");
  try {
    const response = await sendBg({ action: "apply_filter", cn: value });
    log(`Готово. Видно: ${response.kept}, скрыто: ${response.hidden}`, "good");
    await loadCerts();
  } catch (error) {
    log(`Ошибка фильтра: ${error.message}`, "bad");
  } finally {
    els.applyBtn.disabled = false;
  }
}

async function runSimpleAction(action, successMessage, kind) {
  if (!hostReady) {
    showBanner(
      "Native host не найден. Запустите native/install.sh (Linux) или native/install.bat (Windows), затем перезапустите браузер."
    );
    log("Нет соединения с native host", "bad");
    return;
  }
  try {
    await sendBg({ action });
    log(successMessage, kind || "info");
    await loadCerts();
  } catch (error) {
    log(`Ошибка: ${error.message}`, "bad");
  }
}

async function loadCerts() {
  if (!hostReady) return;
  try {
    const response = await sendBg({ action: "get_certs" });
    certs = Array.isArray(response.certs) ? response.certs : [];
    hideBanner();
    renderCerts();
  } catch (error) {
    showBanner(`Не удалось получить сертификаты: ${error.message}`);
    log(`Ошибка списка сертификатов: ${error.message}`, "bad");
  }
}

function renderCerts() {
  const search = els.certSearch.value.trim().toLowerCase();
  const filtered = certs
    .filter((cert) => !search || String(cert.name || "").toLowerCase().includes(search))
    .sort((a, b) =>
      String(a.name || "").localeCompare(String(b.name || ""), "ru", {
        sensitivity: "base",
      })
    );

  const visibleCount = certs.filter((cert) => !cert.archived).length;
  els.certCount.textContent = `${visibleCount}/${certs.length}`;
  els.certList.replaceChildren();

  if (!filtered.length) {
    const empty = document.createElement("div");
    empty.className = "empty";
    empty.textContent = certs.length
      ? "Ничего не найдено"
      : hostReady
      ? "Сертификаты не найдены"
      : "Нет соединения с native host";
    els.certList.append(empty);
    return;
  }

  const fragment = document.createDocumentFragment();
  for (const cert of filtered) {
    fragment.append(buildCertRow(cert));
  }
  els.certList.append(fragment);
}

function buildCertRow(cert) {
  const row = document.createElement("div");
  row.className = "cert-row";

  const daysLeft = daysUntil(cert.not_after);
  if (daysLeft !== null && daysLeft < 0) row.classList.add("expired");
  else if (daysLeft !== null && daysLeft <= 10) row.classList.add("soon");
  if (cert.archived) row.classList.add("hidden-cert");

  const toggle = document.createElement("button");
  toggle.className = "toggle";
  toggle.textContent = cert.archived ? "■" : "○";
  toggle.title = cert.archived
    ? "Скрыт (нажмите, чтобы показать)"
    : "Виден (нажмите, чтобы скрыть)";
  toggle.addEventListener("click", async () => {
    toggle.disabled = true;
    try {
      await sendBg({ action: "toggle_cert", name: cert.name });
      log(
        `${cert.archived ? "Показан" : "Скрыт"}: ${cert.name}`,
        cert.archived ? "good" : "bad"
      );
      await loadCerts();
    } catch (error) {
      log(`Ошибка: ${error.message}`, "bad");
      toggle.disabled = false;
    }
  });

  const info = document.createElement("div");
  info.className = "cert-info";

  const name = document.createElement("div");
  name.className = "cert-name";
  name.textContent = cert.name || "Без имени";

  const meta = document.createElement("div");
  meta.className = "cert-meta";
  meta.textContent = formatMeta(cert, daysLeft);

  info.append(name, meta);

  const badge = document.createElement("span");
  badge.className = `badge ${cert.archived ? "badge-hidden" : "badge-visible"}`;
  badge.textContent = cert.archived ? "скрыт" : "виден";

  row.append(toggle, info, badge);
  return row;
}

function daysUntil(iso) {
  if (!iso) return null;
  const date = new Date(iso);
  if (Number.isNaN(date.getTime())) return null;
  return Math.floor((date.getTime() - Date.now()) / 86400000);
}

function formatMeta(cert, daysLeft) {
  const date = cert.not_after ? new Date(cert.not_after) : null;
  const valid = date && !Number.isNaN(date.getTime());
  const formatted = valid
    ? date.toLocaleDateString("ru-RU", {
        day: "2-digit",
        month: "2-digit",
        year: "numeric",
      })
    : "—";

  if (daysLeft !== null && daysLeft < 0) {
    return `⚠ истёк ${formatted}`;
  }
  if (daysLeft !== null && daysLeft <= 10) {
    return `⏳ ${daysLeft} дн. до ${formatted}`;
  }
  return `до ${formatted}`;
}

function sendBg(payload) {
  const message = { type: "native", payload };

  if (isFirefox) {
    return api.runtime
      .sendMessage(message)
      .then((response) => {
        if (!response) throw new Error("Нет ответа от background");
        if (response.ok === false) throw new Error(response.error || "Ошибка host");
        return response;
      })
      .catch((error) => {
        throw new Error(cleanNativeError(error));
      });
  }

  return new Promise((resolve, reject) => {
    try {
      api.runtime.sendMessage(message, (response) => {
        const error = api.runtime.lastError;
        if (error && error.message) {
          reject(new Error(cleanNativeError(error.message)));
          return;
        }
        if (!response) {
          reject(new Error("Нет ответа от background"));
          return;
        }
        if (response.ok === false) {
          reject(new Error(response.error || "Ошибка host"));
          return;
        }
        resolve(response);
      });
    } catch (error) {
      reject(new Error(cleanNativeError(error)));
    }
  });
}

function cleanNativeError(error) {
  const text = error && error.message ? error.message : String(error);
  if (/native messaging host|not found|Specified native|host.*not.*found/i.test(text)) {
    return (
      "Native host не найден. Установите его через native/install.sh или " +
      "native/install.bat и перезапустите браузер."
    );
  }
  return text;
}

function setDot(state) {
  els.hostDot.classList.remove("ok", "err");
  if (state) els.hostDot.classList.add(state);
}

function showBanner(text) {
  els.banner.textContent = text;
  els.banner.classList.remove("hidden");
}

function hideBanner() {
  els.banner.classList.add("hidden");
}

function log(message, kind) {
  const time = new Date().toLocaleTimeString("ru-RU", {
    hour: "2-digit",
    minute: "2-digit",
    second: "2-digit",
  });
  logs.push({ time, message, kind: kind || "" });
  logs = logs.slice(-6);

  els.log.replaceChildren();
  for (const entry of logs) {
    const line = document.createElement("div");
    const timeSpan = document.createElement("span");
    timeSpan.className = "t";
    timeSpan.textContent = `[${entry.time}] `;
    const body = document.createElement("span");
    body.className = entry.kind;
    body.textContent = entry.message;
    line.append(timeSpan, body);
    els.log.append(line);
  }
  els.log.scrollTop = els.log.scrollHeight;
}
