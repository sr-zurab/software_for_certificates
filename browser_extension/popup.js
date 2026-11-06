const isFirefox =
  typeof globalThis.browser !== "undefined" &&
  !!globalThis.browser &&
  !!globalThis.browser.runtime;
const api = globalThis.browser || globalThis.chrome;

const els = {};
let hostReady = false;
let configData = null;
let configLabel = "";
let fileConfigData = null;
let fileConfigName = "";
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
    if (name === "__file__") {
      if (fileConfigData) {
        configData = fileConfigData;
        configLabel = fileConfigName;
        els.configInfo.textContent = `${fileConfigName} · ключей: ${
          Object.keys(fileConfigData).length
        }`;
        els.configInfo.className = "hint";
        updateResolved();
      }
      return;
    }
    if (name) {
      loadConfig(name).catch((error) => log(error.message, "bad"));
    }
  });
  els.fileInput.addEventListener("change", onFileChosen);
  els.keyInput.addEventListener("input", updateResolved);
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
  els.certSearch.addEventListener("input", renderCerts);
}

async function init() {
  log("Подключение к native host...", "info");
  if (!(await connectHost())) return;
  await loadConfigs();
  await loadCerts();
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

async function loadConfigs() {
  try {
    const response = await sendBg({ action: "get_configs" });
    const list = Array.isArray(response.configs) ? response.configs : [];
    populateConfigs(list);
    if (list.length) {
      const names = list
        .map((item) => (typeof item === "string" ? item : item && item.name))
        .filter(Boolean);
      if (!names.length) return;
      const wanted = names.includes(els.configSelect.value)
        ? els.configSelect.value
        : names[0];
      els.configSelect.value = wanted;
      await loadConfig(wanted);
      log(`Конфигов найдено: ${list.length}`, "info");
    } else {
      configData = null;
      configLabel = "";
      els.configInfo.textContent = "JSON-файлы не найдены. Загрузите файл вручную.";
      updateResolved();
    }
  } catch (error) {
    log(`Ошибка загрузки конфигов: ${error.message}`, "bad");
  }
}

function populateConfigs(list) {
  els.configSelect.replaceChildren();
  if (!list.length) {
    const option = document.createElement("option");
    option.value = "";
    option.textContent = "— нет доступных JSON —";
    els.configSelect.append(option);
    return;
  }
  for (const item of list) {
    const name = typeof item === "string" ? item : item && item.name;
    if (!name) continue;
    const option = document.createElement("option");
    option.value = name;
    option.textContent = name;
    if (item && typeof item.key_count === "number") {
      option.dataset.keys = String(item.key_count);
    }
    els.configSelect.append(option);
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
  const file = els.fileInput.files && els.fileInput.files[0];
  if (!file) return;
  try {
    const text = await file.text();
    const parsed = JSON.parse(text);
    const clean = {};
    for (const [key, value] of Object.entries(parsed || {})) {
      if (typeof value === "string") clean[key] = value;
    }
    configData = clean;
    configLabel = file.name;
    fileConfigData = clean;
    fileConfigName = file.name;
    const count = Object.keys(clean).length;

    const option = document.createElement("option");
    option.value = "__file__";
    option.textContent = `📄 ${file.name}`;
    const existing = els.configSelect.querySelector('option[value="__file__"]');
    if (existing) existing.remove();
    els.configSelect.append(option);
    els.configSelect.value = "__file__";

    els.configInfo.textContent = `${file.name} · ключей: ${count}`;
    els.configInfo.className = "hint";
    log(`Загружен файл ${file.name}`, "info");
    updateResolved();
  } catch (error) {
    log(`Ошибка JSON: ${error.message}`, "bad");
  } finally {
    els.fileInput.value = "";
  }
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
  if (!key) {
    els.resolved.textContent = configData
      ? `Ключей в конфиге: ${Object.keys(configData).length}`
      : "";
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
