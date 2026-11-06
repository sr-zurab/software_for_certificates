const api = globalThis.browser || globalThis.chrome;
const HOST_NAME = "com.certfilter.host";
const REQUEST_TIMEOUT_MS = 60000;

let port = null;
let seq = 0;
const pending = new Map();

function rejectAll(message) {
  for (const [, entry] of pending) {
    clearTimeout(entry.timer);
    entry.reject(new Error(message));
  }
  pending.clear();
}

function connectHost() {
  if (port) return port;

  port = api.runtime.connectNative(HOST_NAME);

  port.onMessage.addListener((message) => {
    const id = message && message._id;
    const entry = id != null ? pending.get(id) : null;
    if (!entry) return;
    pending.delete(id);
    clearTimeout(entry.timer);
    entry.resolve(message);
  });

  port.onDisconnect.addListener(() => {
    const error = api.runtime.lastError;
    port = null;
    rejectAll(
      (error && error.message) ||
        "Нет соединения с native host. Установлен ли он?"
    );
  });

  return port;
}

api.runtime.onMessage.addListener((message, _sender, sendResponse) => {
  if (!message || message.type !== "native") return;

  let currentPort;
  try {
    currentPort = connectHost();
  } catch (error) {
    sendResponse({ ok: false, error: String(error) });
    return true;
  }

  const id = ++seq;
  const payload = Object.assign({}, message.payload, { _id: id });

  const timer = setTimeout(() => {
    if (!pending.has(id)) return;
    pending.delete(id);
    sendResponse({ ok: false, error: "Превышено время ожидания ответа от host" });
    try {
      currentPort.disconnect();
    } catch (_) {
      /* ignore */
    }
  }, REQUEST_TIMEOUT_MS);

  pending.set(id, {
    timer,
    resolve: (response) => {
      try {
        sendResponse(response);
      } catch (_) {
        /* popup could already be closed */
      }
    },
    reject: (error) => {
      try {
        sendResponse({ ok: false, error: error.message || String(error) });
      } catch (_) {
        /* ignore */
      }
    },
  });

  try {
    currentPort.postMessage(payload);
  } catch (error) {
    clearTimeout(timer);
    pending.delete(id);
    sendResponse({ ok: false, error: String(error) });
  }

  return true;
});
