#!/usr/bin/env python3
"""Native messaging host for the Cert Filter browser extension.

Принимает JSON-сообщения по протоколу Chrome/Firefox Native Messaging
(4 байта длины + JSON) и выполняет операции с хранилищем сертификатов
CryptoPro/CryptoAPI, повторяя логику cert_filter_ui.pyw.
"""

import ctypes
import json
import os
import struct
import sys
import traceback
from datetime import datetime, timedelta
from pathlib import Path

# ── CryptoAPI ─────────────────────────────────────────────────────────────────

crypt32 = None
advapi32 = None
CRYPTO_ERROR = None

CERT_STORE_PROV_SYSTEM = 10
CERT_STORE_PROV_MEMORY = 2
CERT_SYSTEM_STORE_CURRENT_USER = 0x00010000
CERT_STORE_OPEN_EXISTING_FLAG = 0x00004000
CERT_STORE_MAXIMUM_ALLOWED_FLAG = 0x00001000
CERT_STORE_ENUM_ARCHIVED_FLAG = 0x00000200
CERT_ARCHIVED_PROP_ID = 19
CERT_FRIENDLY_NAME_PROP_ID = 7
CERT_KEY_PROV_INFO_PROP_ID = 2
CERT_X500_NAME_STR = 3
CERT_STORE_ADD_REPLACE_EXISTING = 3

EXPORT_PRIVATE_KEYS = 0x00000004
REPORT_NOT_ABLE_TO_EXPORT_PRIVATE_KEY = 0x00000002
CRYPT_DELETEKEYSET = 0x00000010


class DATA_BLOB(ctypes.Structure):
    _fields_ = [("cbData", ctypes.c_ulong), ("pbData", ctypes.c_void_p)]


class CRYPT_KEY_PROV_INFO(ctypes.Structure):
    _fields_ = [
        ("pwszContainerName", ctypes.c_wchar_p),
        ("pwszProvName", ctypes.c_wchar_p),
        ("dwProvType", ctypes.c_uint32),
        ("dwFlags", ctypes.c_uint32),
        ("cProvParam", ctypes.c_uint32),
        ("rgProvParam", ctypes.c_void_p),
        ("dwKeySpec", ctypes.c_uint32),
    ]


class FILETIME(ctypes.Structure):
    _fields_ = [
        ("dwLowDateTime", ctypes.c_uint32),
        ("dwHighDateTime", ctypes.c_uint32),
    ]


class CRYPT_ALGORITHM_IDENTIFIER(ctypes.Structure):
    _fields_ = [("pszObjId", ctypes.c_void_p), ("Parameters", DATA_BLOB)]


class CERT_INFO(ctypes.Structure):
    _fields_ = [
        ("dwVersion", ctypes.c_uint32),
        ("SerialNumber", DATA_BLOB),
        ("SignatureAlgorithm", CRYPT_ALGORITHM_IDENTIFIER),
        ("Issuer", DATA_BLOB),
        ("NotBefore", FILETIME),
        ("NotAfter", FILETIME),
        ("Subject", DATA_BLOB),
    ]


class CERT_CONTEXT(ctypes.Structure):
    _fields_ = [
        ("dwCertEncodingType", ctypes.c_uint32),
        ("pbCertEncoded", ctypes.c_void_p),
        ("cbCertEncoded", ctypes.c_uint32),
        ("pCertInfo", ctypes.POINTER(CERT_INFO)),
        ("hCertStore", ctypes.c_void_p),
    ]


def _load_crypto():
    global crypt32, advapi32, CRYPTO_ERROR
    if crypt32 is not None:
        return
    if CRYPTO_ERROR is not None:
        raise RuntimeError(CRYPTO_ERROR)

    try:
        if sys.platform == "win32":
            crypt32 = ctypes.WinDLL("crypt32.dll")
            advapi32 = ctypes.WinDLL("advapi32.dll")
        else:
            candidates20 = []
            candidates10 = []
            for path in (
                "/opt/cprocsp/lib/amd64/libcapi20.so",
                "/opt/cprocsp/lib/x64/libcapi20.so",
                "/opt/cprocsp/lib/aarch64/libcapi20.so",
                "/opt/cprocsp/lib/arm64/libcapi20.so",
            ):
                candidates20.append(path)
            for path in (
                "/opt/cprocsp/lib/amd64/libcapi10.so",
                "/opt/cprocsp/lib/x64/libcapi10.so",
                "/opt/cprocsp/lib/aarch64/libcapi10.so",
                "/opt/cprocsp/lib/arm64/libcapi10.so",
            ):
                candidates10.append(path)
            try:
                candidates20.extend(
                    str(p) for p in Path("/opt/cprocsp/lib").glob("*/libcapi20.so")
                )
                candidates10.extend(
                    str(p) for p in Path("/opt/cprocsp/lib").glob("*/libcapi10.so")
                )
            except OSError:
                pass

            last_error = None
            for path in candidates20:
                try:
                    crypt32 = ctypes.CDLL(path)
                    break
                except OSError as error:
                    last_error = error
            if crypt32 is None:
                raise RuntimeError(
                    "Не найдена библиотека КриптоПро libcapi20.so "
                    f"({last_error})"
                )

            for path in candidates10:
                try:
                    advapi32 = ctypes.CDLL(path)
                    break
                except OSError as error:
                    last_error = error
            if advapi32 is None:
                raise RuntimeError(
                    "Не найдена библиотека КриптоПро libcapi10.so "
                    f"({last_error})"
                )

        crypt32.CertOpenStore.restype = ctypes.c_void_p
        crypt32.CertOpenStore.argtypes = [
            ctypes.c_void_p,
            ctypes.c_uint,
            ctypes.c_void_p,
            ctypes.c_uint,
            ctypes.c_wchar_p,
        ]
        crypt32.CertCloseStore.restype = ctypes.c_bool
        crypt32.CertCloseStore.argtypes = [ctypes.c_void_p, ctypes.c_uint]
        crypt32.CertEnumCertificatesInStore.restype = ctypes.c_void_p
        crypt32.CertEnumCertificatesInStore.argtypes = [ctypes.c_void_p, ctypes.c_void_p]
        crypt32.CertGetNameStringW.restype = ctypes.c_uint
        crypt32.CertGetNameStringW.argtypes = [
            ctypes.c_void_p,
            ctypes.c_uint,
            ctypes.c_uint,
            ctypes.c_void_p,
            ctypes.c_wchar_p,
            ctypes.c_uint,
        ]
        crypt32.CertGetCertificateContextProperty.restype = ctypes.c_bool
        crypt32.CertGetCertificateContextProperty.argtypes = [
            ctypes.c_void_p,
            ctypes.c_uint,
            ctypes.c_void_p,
            ctypes.POINTER(ctypes.c_uint32),
        ]
        crypt32.CertSetCertificateContextProperty.restype = ctypes.c_bool
        crypt32.CertSetCertificateContextProperty.argtypes = [
            ctypes.c_void_p,
            ctypes.c_uint,
            ctypes.c_uint,
            ctypes.c_void_p,
        ]
        crypt32.CertDuplicateCertificateContext.restype = ctypes.c_void_p
        crypt32.CertDuplicateCertificateContext.argtypes = [ctypes.c_void_p]
        crypt32.CertFreeCertificateContext.restype = ctypes.c_bool
        crypt32.CertFreeCertificateContext.argtypes = [ctypes.c_void_p]
        crypt32.CertNameToStrW.restype = ctypes.c_uint
        crypt32.CertNameToStrW.argtypes = [
            ctypes.c_uint,
            ctypes.c_void_p,
            ctypes.c_uint,
            ctypes.c_wchar_p,
            ctypes.c_uint,
        ]
        crypt32.CertDeleteCertificateFromStore.restype = ctypes.c_bool
        crypt32.CertDeleteCertificateFromStore.argtypes = [ctypes.c_void_p]
        crypt32.CertAddCertificateContextToStore.restype = ctypes.c_bool
        crypt32.CertAddCertificateContextToStore.argtypes = [
            ctypes.c_void_p,
            ctypes.c_void_p,
            ctypes.c_uint,
            ctypes.c_void_p,
        ]
        crypt32.PFXExportCertStoreEx.restype = ctypes.c_bool
        crypt32.PFXExportCertStoreEx.argtypes = [
            ctypes.c_void_p,
            ctypes.c_void_p,
            ctypes.c_wchar_p,
            ctypes.c_void_p,
            ctypes.c_uint,
        ]
        crypt32.PFXImportCertStore.restype = ctypes.c_void_p
        crypt32.PFXImportCertStore.argtypes = [
            ctypes.c_void_p,
            ctypes.c_wchar_p,
            ctypes.c_uint,
        ]

        advapi32.CryptAcquireContextW.restype = ctypes.c_bool
        advapi32.CryptAcquireContextW.argtypes = [
            ctypes.POINTER(ctypes.c_void_p),
            ctypes.c_wchar_p,
            ctypes.c_wchar_p,
            ctypes.c_uint,
            ctypes.c_uint,
        ]
        advapi32.CryptReleaseContext.restype = ctypes.c_bool
        advapi32.CryptReleaseContext.argtypes = [ctypes.c_void_p, ctypes.c_uint]
    except Exception as error:
        CRYPTO_ERROR = f"Не удалось загрузить CryptoAPI: {error}"
        raise RuntimeError(CRYPTO_ERROR) from error


def _ensure_crypto():
    _load_crypto()


# ── Работа с сертификатами (логика из cert_filter_ui.pyw) ────────────────────


def filetime_to_datetime(ft):
    win_ticks = (ft.dwHighDateTime << 32) + ft.dwLowDateTime
    if win_ticks == 0:
        return datetime(1970, 1, 1)
    try:
        return datetime(1601, 1, 1) + timedelta(microseconds=win_ticks // 10)
    except Exception:
        return datetime(1970, 1, 1)


def iter_certs(store):
    if not store:
        return
    cert = crypt32.CertEnumCertificatesInStore(store, None)
    while cert:
        yield cert
        cert = crypt32.CertEnumCertificatesInStore(store, cert)


def get_name(cert) -> str:
    size = crypt32.CertGetNameStringW(cert, 4, 0, None, None, 0)
    if size <= 1:
        return "Неизвестное имя"
    buf = ctypes.create_unicode_buffer(size)
    crypt32.CertGetNameStringW(cert, 4, 0, None, buf, size)
    return buf.value


def is_archived(cert) -> bool:
    size = ctypes.c_uint32(0)
    return bool(
        crypt32.CertGetCertificateContextProperty(
            cert, CERT_ARCHIVED_PROP_ID, None, ctypes.byref(size)
        )
    )


def set_archived(cert, archive: bool):
    current = is_archived(cert)
    if current == archive:
        return True
    if archive:
        blob = DATA_BLOB(0, None)
        return crypt32.CertSetCertificateContextProperty(
            cert, CERT_ARCHIVED_PROP_ID, 0, ctypes.byref(blob)
        )
    return crypt32.CertSetCertificateContextProperty(
        cert, CERT_ARCHIVED_PROP_ID, 0, None
    )


def get_cert_property(cert, prop_id):
    size = ctypes.c_uint32(0)
    if not crypt32.CertGetCertificateContextProperty(
        cert, prop_id, None, ctypes.byref(size)
    ):
        return ""
    buf = ctypes.create_string_buffer(size.value)
    if not crypt32.CertGetCertificateContextProperty(
        cert, prop_id, buf, ctypes.byref(size)
    ):
        return ""
    try:
        return buf.raw[: max(0, size.value - 2)].decode("utf-16le")
    except Exception:
        return ""


def set_cert_friendly_name(cert_name, new_friendly_name):
    _ensure_crypto()
    for store_name in ("MY", "AddressBook"):
        store = None
        try:
            flags = (
                CERT_SYSTEM_STORE_CURRENT_USER
                | CERT_STORE_OPEN_EXISTING_FLAG
                | CERT_STORE_MAXIMUM_ALLOWED_FLAG
                | CERT_STORE_ENUM_ARCHIVED_FLAG
            )
            store = crypt32.CertOpenStore(
                ctypes.c_void_p(CERT_STORE_PROV_SYSTEM),
                0,
                None,
                flags,
                ctypes.c_wchar_p(store_name),
            )
            if not store:
                continue
            for cert in iter_certs(store):
                if get_name(cert) == cert_name:
                    name_bytes = (new_friendly_name + "\0").encode("utf-16le")
                    blob = DATA_BLOB(
                        len(name_bytes),
                        ctypes.cast(
                            ctypes.create_string_buffer(name_bytes), ctypes.c_void_p
                        ),
                    )
                    return bool(
                        crypt32.CertSetCertificateContextProperty(
                            cert,
                            CERT_FRIENDLY_NAME_PROP_ID,
                            0,
                            ctypes.byref(blob),
                        )
                    )
        finally:
            if store:
                crypt32.CertCloseStore(store, 0)
    return False


def get_cert_details(name: str):
    _ensure_crypto()
    for store_name in ("MY", "AddressBook"):
        store = None
        try:
            flags = (
                CERT_SYSTEM_STORE_CURRENT_USER
                | CERT_STORE_OPEN_EXISTING_FLAG
                | CERT_STORE_ENUM_ARCHIVED_FLAG
            )
            store = crypt32.CertOpenStore(
                ctypes.c_void_p(CERT_STORE_PROV_SYSTEM),
                0,
                None,
                flags,
                ctypes.c_wchar_p(store_name),
            )
            if not store:
                continue
            for cert in iter_certs(store):
                if get_name(cert) != name:
                    continue
                friendly = get_cert_property(cert, CERT_FRIENDLY_NAME_PROP_ID)
                ctx = CERT_CONTEXT.from_address(cert)
                full_subject_str = ""
                if ctx.pCertInfo:
                    size = crypt32.CertNameToStrW(
                        1,
                        ctypes.byref(ctx.pCertInfo.contents.Subject),
                        CERT_X500_NAME_STR,
                        None,
                        0,
                    )
                    if size > 1:
                        buf = ctypes.create_unicode_buffer(size)
                        crypt32.CertNameToStrW(
                            1,
                            ctypes.byref(ctx.pCertInfo.contents.Subject),
                            CERT_X500_NAME_STR,
                            buf,
                            size,
                        )
                        full_subject_str = buf.value

                def get_str(c, typ):
                    size = crypt32.CertGetNameStringW(c, typ, 0, None, None, 0)
                    if size <= 1:
                        return ""
                    b = ctypes.create_unicode_buffer(size)
                    crypt32.CertGetNameStringW(c, typ, 0, None, b, size)
                    return b.value

                cn_val = get_str(cert, 3)
                subject_simple = get_str(cert, 1)
                issuer_val = get_str(cert, 4)

                serial_val = ""
                not_before = datetime(1970, 1, 1)
                not_after = datetime(1970, 1, 1)
                if ctx.pCertInfo:
                    s_blob = ctx.pCertInfo.contents.SerialNumber
                    p_data = ctypes.cast(s_blob.pbData, ctypes.POINTER(ctypes.c_ubyte))
                    serial_val = "".join(
                        f"{p_data[i]:02X}" for i in range(s_blob.cbData - 1, -1, -1)
                    )
                    not_before = filetime_to_datetime(ctx.pCertInfo.contents.NotBefore)
                    not_after = filetime_to_datetime(ctx.pCertInfo.contents.NotAfter)

                return {
                    "name": name,
                    "cn": cn_val,
                    "friendly": friendly,
                    "subject": subject_simple,
                    "issuer": issuer_val,
                    "serial": serial_val,
                    "not_before": not_before.isoformat(),
                    "not_after": not_after.isoformat(),
                    "full_subject": full_subject_str,
                }
        finally:
            if store:
                crypt32.CertCloseStore(store, 0)
    return None


def get_all_certs():
    _ensure_crypto()
    result = []
    for store_name in ("MY", "AddressBook"):
        store = None
        try:
            flags = (
                CERT_SYSTEM_STORE_CURRENT_USER
                | CERT_STORE_OPEN_EXISTING_FLAG
                | CERT_STORE_ENUM_ARCHIVED_FLAG
            )
            store = crypt32.CertOpenStore(
                ctypes.c_void_p(CERT_STORE_PROV_SYSTEM),
                0,
                None,
                flags,
                ctypes.c_wchar_p(store_name),
            )
            if not store:
                continue
            current = crypt32.CertEnumCertificatesInStore(store, None)
            while current:
                try:
                    name = get_name(current)
                    archived = is_archived(current)
                    not_before = datetime(1970, 1, 1)
                    not_after = datetime(1970, 1, 1)
                    serial = ""
                    ctx = CERT_CONTEXT.from_address(current)
                    if ctx.pCertInfo:
                        not_before = filetime_to_datetime(ctx.pCertInfo.contents.NotBefore)
                        not_after = filetime_to_datetime(ctx.pCertInfo.contents.NotAfter)
                        s_blob = ctx.pCertInfo.contents.SerialNumber
                        p_data = ctypes.cast(
                            s_blob.pbData, ctypes.POINTER(ctypes.c_ubyte)
                        )
                        serial = "".join(
                            f"{p_data[i]:02X}" for i in range(s_blob.cbData - 1, -1, -1)
                        )
                    result.append(
                        {
                            "name": name,
                            "archived": archived,
                            "not_before": not_before.isoformat(),
                            "not_after": not_after.isoformat(),
                            "store": store_name,
                            "serial": serial,
                        }
                    )
                except Exception:
                    pass
                current = crypt32.CertEnumCertificatesInStore(store, current)
        finally:
            if store:
                crypt32.CertCloseStore(store, 0)
    return result


def apply_filter(target_cn: str):
    _ensure_crypto()
    kept = hidden = 0
    clean_target = (target_cn or "").lower().replace('"', "").strip()
    if not clean_target:
        raise ValueError("Пустое значение CN")
    for store_name in ("MY", "AddressBook"):
        store = None
        try:
            flags = (
                CERT_SYSTEM_STORE_CURRENT_USER
                | CERT_STORE_OPEN_EXISTING_FLAG
                | CERT_STORE_MAXIMUM_ALLOWED_FLAG
                | CERT_STORE_ENUM_ARCHIVED_FLAG
            )
            store = crypt32.CertOpenStore(
                ctypes.c_void_p(CERT_STORE_PROV_SYSTEM),
                0,
                None,
                flags,
                ctypes.c_wchar_p(store_name),
            )
            if not store:
                continue
            for cert in iter_certs(store):
                name = get_name(cert).lower().replace('"', "").strip()
                if clean_target in name:
                    set_archived(cert, False)
                    kept += 1
                else:
                    set_archived(cert, True)
                    hidden += 1
        finally:
            if store:
                crypt32.CertCloseStore(store, 0)
    return kept, hidden


def restore_all():
    _ensure_crypto()
    for store_name in ("MY", "AddressBook"):
        store = None
        try:
            flags = (
                CERT_SYSTEM_STORE_CURRENT_USER
                | CERT_STORE_OPEN_EXISTING_FLAG
                | CERT_STORE_MAXIMUM_ALLOWED_FLAG
                | CERT_STORE_ENUM_ARCHIVED_FLAG
            )
            store = crypt32.CertOpenStore(
                ctypes.c_void_p(CERT_STORE_PROV_SYSTEM),
                0,
                None,
                flags,
                ctypes.c_wchar_p(store_name),
            )
            if not store:
                continue
            certs_to_process = []
            current = crypt32.CertEnumCertificatesInStore(store, None)
            while current:
                certs_to_process.append(
                    crypt32.CertDuplicateCertificateContext(current)
                )
                current = crypt32.CertEnumCertificatesInStore(store, current)
            for cert in certs_to_process:
                set_archived(cert, False)
                crypt32.CertFreeCertificateContext(cert)
        finally:
            if store:
                crypt32.CertCloseStore(store, 0)


def hide_all():
    _ensure_crypto()
    for store_name in ("MY", "AddressBook"):
        store = None
        try:
            flags = (
                CERT_SYSTEM_STORE_CURRENT_USER
                | CERT_STORE_OPEN_EXISTING_FLAG
                | CERT_STORE_MAXIMUM_ALLOWED_FLAG
                | CERT_STORE_ENUM_ARCHIVED_FLAG
            )
            store = crypt32.CertOpenStore(
                ctypes.c_void_p(CERT_STORE_PROV_SYSTEM),
                0,
                None,
                flags,
                ctypes.c_wchar_p(store_name),
            )
            if not store:
                continue
            certs_to_process = []
            current = crypt32.CertEnumCertificatesInStore(store, None)
            while current:
                certs_to_process.append(
                    crypt32.CertDuplicateCertificateContext(current)
                )
                current = crypt32.CertEnumCertificatesInStore(store, current)
            for cert in certs_to_process:
                set_archived(cert, True)
                crypt32.CertFreeCertificateContext(cert)
        finally:
            if store:
                crypt32.CertCloseStore(store, 0)


def toggle_cert_archive(name: str):
    _ensure_crypto()
    for store_name in ("MY", "AddressBook"):
        store = None
        try:
            flags = (
                CERT_SYSTEM_STORE_CURRENT_USER
                | CERT_STORE_OPEN_EXISTING_FLAG
                | CERT_STORE_MAXIMUM_ALLOWED_FLAG
                | CERT_STORE_ENUM_ARCHIVED_FLAG
            )
            store = crypt32.CertOpenStore(
                ctypes.c_void_p(CERT_STORE_PROV_SYSTEM),
                0,
                None,
                flags,
                ctypes.c_wchar_p(store_name),
            )
            if not store:
                continue
            for cert in iter_certs(store):
                if get_name(cert) == name:
                    set_archived(cert, not is_archived(cert))
                    return True
        finally:
            if store:
                crypt32.CertCloseStore(store, 0)
    return False


def get_cert_serial(cert) -> str:
    ctx = CERT_CONTEXT.from_address(cert)
    if not ctx.pCertInfo:
        return ""
    s_blob = ctx.pCertInfo.contents.SerialNumber
    p_data = ctypes.cast(s_blob.pbData, ctypes.POINTER(ctypes.c_ubyte))
    return "".join(f"{p_data[i]:02X}" for i in range(s_blob.cbData - 1, -1, -1))


def delete_cert_and_key(name: str, serial: str = ""):
    _ensure_crypto()
    for store_name in ("MY", "AddressBook"):
        store = None
        try:
            flags = (
                CERT_SYSTEM_STORE_CURRENT_USER
                | CERT_STORE_OPEN_EXISTING_FLAG
                | CERT_STORE_MAXIMUM_ALLOWED_FLAG
                | CERT_STORE_ENUM_ARCHIVED_FLAG
            )
            store = crypt32.CertOpenStore(
                ctypes.c_void_p(CERT_STORE_PROV_SYSTEM),
                0,
                None,
                flags,
                ctypes.c_wchar_p(store_name),
            )
            if not store:
                continue
            for cert in iter_certs(store):
                if get_name(cert) != name:
                    continue
                if serial and get_cert_serial(cert) != serial:
                    continue
                size = ctypes.c_uint32(0)
                if crypt32.CertGetCertificateContextProperty(
                    cert, CERT_KEY_PROV_INFO_PROP_ID, None, ctypes.byref(size)
                ):
                    buf = ctypes.create_string_buffer(size.value)
                    if crypt32.CertGetCertificateContextProperty(
                        cert, CERT_KEY_PROV_INFO_PROP_ID, buf, ctypes.byref(size)
                    ):
                        info = CRYPT_KEY_PROV_INFO.from_buffer(buf)
                        h_prov = ctypes.c_void_p()
                        advapi32.CryptAcquireContextW(
                            ctypes.byref(h_prov),
                            info.pwszContainerName,
                            info.pwszProvName,
                            info.dwProvType,
                            CRYPT_DELETEKEYSET,
                        )
                dup = crypt32.CertDuplicateCertificateContext(cert)
                return bool(crypt32.CertDeleteCertificateFromStore(dup))
        finally:
            if store:
                crypt32.CertCloseStore(store, 0)
    return False


# ── Конфигурации JSON ────────────────────────────────────────────────────────


def config_dir() -> Path:
    env = os.environ.get("CERT_FILTER_CONFIG_DIR")
    here = Path(__file__).resolve().parent
    candidates = []
    if env:
        candidates.append(Path(env).expanduser())
    candidates.extend(
        [
            here / "configs",
            here.parent.parent,
            here.parent,
            Path.cwd(),
        ]
    )

    seen = set()
    for candidate in candidates:
        try:
            resolved = candidate.resolve()
        except OSError:
            continue
        if resolved in seen:
            continue
        seen.add(resolved)
        if resolved.is_dir():
            try:
                next(resolved.glob("*.json"))
            except StopIteration:
                continue
            except OSError:
                continue
            return resolved
    return here / "configs"


def safe_config_path(name: str) -> Path:
    base = config_dir().resolve()
    filename = Path(str(name)).name
    if not filename.lower().endswith(".json"):
        raise ValueError("Ожидается файл .json")
    candidate = (base / filename).resolve()
    if candidate.parent != base:
        raise ValueError("Недопустимый путь к конфигу")
    if not candidate.is_file():
        raise FileNotFoundError(f"Файл не найден: {filename}")
    return candidate


def load_config_file(name: str):
    path = safe_config_path(name)
    with open(path, "r", encoding="utf-8") as handle:
        data = json.load(handle)
    if not isinstance(data, dict):
        raise ValueError("Корневой элемент JSON должен быть объектом")
    return data


def list_configs():
    base = config_dir()
    items = []
    try:
        paths = sorted(base.glob("*.json"), key=lambda p: p.name.lower())
    except OSError:
        paths = []
    for path in paths:
        key_count = 0
        try:
            with open(path, "r", encoding="utf-8") as handle:
                data = json.load(handle)
            if isinstance(data, dict):
                key_count = sum(1 for value in data.values() if isinstance(value, str))
        except Exception:
            key_count = 0
        items.append({"name": path.name, "key_count": key_count})
    return {"configs": items, "dir": str(base)}


# ── Native messaging protocol ────────────────────────────────────────────────


def read_message():
    raw = sys.stdin.buffer.read(4)
    if len(raw) < 4:
        return None
    length = struct.unpack("=I", raw)[0]
    if length <= 0:
        return None
    data = sys.stdin.buffer.read(length)
    if len(data) < length:
        return None
    return json.loads(data.decode("utf-8"))


def send_message(payload):
    data = json.dumps(payload, ensure_ascii=False).encode("utf-8")
    sys.stdout.buffer.write(struct.pack("=I", len(data)))
    sys.stdout.buffer.write(data)
    sys.stdout.buffer.flush()


def handle(message):
    action = message.get("action")

    if action == "ping":
        try:
            _ensure_crypto()
            return {"ok": True, "platform": sys.platform, "crypto": True}
        except Exception as error:
            return {
                "ok": True,
                "platform": sys.platform,
                "crypto": False,
                "crypto_error": str(error),
            }

    if action == "get_configs":
        result = list_configs()
        result["ok"] = True
        return result

    if action == "get_config":
        name = message.get("name")
        if not name:
            raise ValueError("Не указано имя конфига")
        return {"ok": True, "config": load_config_file(name)}

    if action == "apply_filter":
        kept, hidden = apply_filter(message.get("cn", ""))
        return {"ok": True, "kept": kept, "hidden": hidden}

    if action == "restore_all":
        restore_all()
        return {"ok": True}

    if action == "hide_all":
        hide_all()
        return {"ok": True}

    if action == "get_certs":
        return {"ok": True, "certs": get_all_certs()}

    if action == "toggle_cert":
        name = message.get("name")
        if not name:
            raise ValueError("Не указано имя сертификата")
        if not toggle_cert_archive(name):
            raise ValueError(f"Сертификат не найден: {name}")
        return {"ok": True}

    if action == "set_friendly_name":
        name = message.get("name")
        value = message.get("value", "")
        if not name:
            raise ValueError("Не указано имя сертификата")
        if not set_cert_friendly_name(name, value):
            raise ValueError("Не удалось изменить Friendly Name")
        return {"ok": True}

    if action == "cert_details":
        name = message.get("name")
        if not name:
            raise ValueError("Не указано имя сертификата")
        details = get_cert_details(name)
        if not details:
            raise ValueError(f"Сертификат не найден: {name}")
        return {"ok": True, "cert": details}

    if action == "delete_cert":
        name = message.get("name")
        serial = message.get("serial", "")
        if not name:
            raise ValueError("Не указано имя сертификата")
        deleted = delete_cert_and_key(name, serial)
        return {"ok": bool(deleted), "deleted": bool(deleted)}

    raise ValueError(f"Неизвестное действие: {action}")


def main():
    if sys.platform == "win32":
        import msvcrt

        msvcrt.setmode(sys.stdin.fileno(), os.O_BINARY)
        msvcrt.setmode(sys.stdout.fileno(), os.O_BINARY)

    while True:
        try:
            message = read_message()
        except Exception:
            print(traceback.format_exc(), file=sys.stderr)
            break
        if message is None:
            break
        if not isinstance(message, dict):
            continue

        request_id = message.get("_id")
        try:
            response = handle(message)
            if not isinstance(response, dict):
                response = {"ok": True, "result": response}
            response.setdefault("ok", True)
        except Exception as error:
            response = {"ok": False, "error": str(error)}
            print(traceback.format_exc(), file=sys.stderr)

        if request_id is not None:
            response["_id"] = request_id
        try:
            send_message(response)
        except Exception:
            print(traceback.format_exc(), file=sys.stderr)
            break


def selftest():
    print("platform:", sys.platform)
    print("config dir:", config_dir())
    try:
        info = list_configs()
        print("configs:", [item["name"] for item in info["configs"]])
    except Exception as error:
        print("configs error:", error)
    try:
        _ensure_crypto()
        print("crypto: OK")
        certs = get_all_certs()
        print("certificates:", len(certs))
        for cert in certs[:5]:
            print("  -", cert["name"], "hidden" if cert["archived"] else "visible")
    except Exception as error:
        print("crypto error:", error)


if __name__ == "__main__":
    if "--selftest" in sys.argv:
        selftest()
    else:
        main()
