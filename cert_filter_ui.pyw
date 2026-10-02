#!/usr/bin/env python3
"""
cert_filter_ui.py — Оптимизированный фильтр сертификатов
"""

import sys
import json
import ctypes
import os
import re
from pathlib import Path
from datetime import datetime

# ── PySide6 ─────────────────────────────────────────────────────────────────────
try:
    from PySide6.QtWidgets import (
        QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout,
        QLabel, QPushButton, QFrame, QScrollArea, QLineEdit, QComboBox,
        QMessageBox, QDialog, QFormLayout, QTextEdit, QFileDialog, QInputDialog,
        QCheckBox
    )
    from PySide6.QtCore import Qt, QThread, Signal, QTimer
    from PySide6.QtGui import QColor, QPalette
except ImportError:
    print("Установите PySide6: pip install PySide6")
    sys.exit(1)

# ── CryptoAPI (кроссплатформенная загрузка) ───────────────────────────────────
if sys.platform == "win32":
    crypt32 = ctypes.WinDLL("crypt32.dll")
    advapi32 = ctypes.WinDLL("advapi32.dll")
else:
    # КриптоПро CSP на Linux предоставляет CryptoAPI-совместимые .so библиотеки
    crypt32 = ctypes.CDLL("/opt/cprocsp/lib/amd64/libcapi20.so")
    advapi32 = ctypes.CDLL("/opt/cprocsp/lib/amd64/libcapi10.so")

crypt32.CertOpenStore.restype = ctypes.c_void_p
crypt32.CertOpenStore.argtypes = [ctypes.c_void_p, ctypes.c_uint, ctypes.c_void_p, ctypes.c_uint, ctypes.c_wchar_p]
crypt32.CertCloseStore.restype = ctypes.c_bool
crypt32.CertCloseStore.argtypes = [ctypes.c_void_p, ctypes.c_uint]
crypt32.CertEnumCertificatesInStore.restype = ctypes.c_void_p
crypt32.CertEnumCertificatesInStore.argtypes = [ctypes.c_void_p, ctypes.c_void_p]
crypt32.CertGetNameStringW.restype = ctypes.c_uint
crypt32.CertGetNameStringW.argtypes = [ctypes.c_void_p, ctypes.c_uint, ctypes.c_uint, ctypes.c_void_p, ctypes.c_wchar_p, ctypes.c_uint]
crypt32.CertGetCertificateContextProperty.restype = ctypes.c_bool
crypt32.CertGetCertificateContextProperty.argtypes = [ctypes.c_void_p, ctypes.c_uint, ctypes.c_void_p, ctypes.POINTER(ctypes.c_uint32)]
crypt32.CertSetCertificateContextProperty.restype = ctypes.c_bool
crypt32.CertSetCertificateContextProperty.argtypes = [ctypes.c_void_p, ctypes.c_uint, ctypes.c_uint, ctypes.c_void_p]
crypt32.CertDuplicateCertificateContext.restype = ctypes.c_void_p
crypt32.CertDuplicateCertificateContext.argtypes = [ctypes.c_void_p]
crypt32.CertFreeCertificateContext.restype = ctypes.c_bool
crypt32.CertFreeCertificateContext.argtypes = [ctypes.c_void_p]
crypt32.CertNameToStrW.restype = ctypes.c_uint
crypt32.CertNameToStrW.argtypes = [ctypes.c_uint, ctypes.c_void_p, ctypes.c_uint, ctypes.c_wchar_p, ctypes.c_uint]
crypt32.CertDeleteCertificateFromStore.restype = ctypes.c_bool
crypt32.CertDeleteCertificateFromStore.argtypes = [ctypes.c_void_p]
crypt32.CertAddCertificateContextToStore.restype = ctypes.c_bool
crypt32.CertAddCertificateContextToStore.argtypes = [ctypes.c_void_p, ctypes.c_void_p, ctypes.c_uint, ctypes.c_void_p]

crypt32.PFXExportCertStoreEx.restype = ctypes.c_bool
crypt32.PFXExportCertStoreEx.argtypes = [ctypes.c_void_p, ctypes.c_void_p, ctypes.c_wchar_p, ctypes.c_void_p, ctypes.c_uint]
crypt32.PFXImportCertStore.restype = ctypes.c_void_p
crypt32.PFXImportCertStore.argtypes = [ctypes.c_void_p, ctypes.c_wchar_p, ctypes.c_uint]

advapi32.CryptAcquireContextW.restype = ctypes.c_bool
advapi32.CryptAcquireContextW.argtypes = [ctypes.POINTER(ctypes.c_void_p), ctypes.c_wchar_p, ctypes.c_wchar_p, ctypes.c_uint, ctypes.c_uint]
advapi32.CryptReleaseContext.restype = ctypes.c_bool
advapi32.CryptReleaseContext.argtypes = [ctypes.c_void_p, ctypes.c_uint]

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
    _fields_ = [("dwLowDateTime", ctypes.c_uint32), ("dwHighDateTime", ctypes.c_uint32)]

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

def filetime_to_datetime(ft):
    import datetime as dt
    win_ticks = (ft.dwHighDateTime << 32) + ft.dwLowDateTime
    if win_ticks == 0:
        return dt.datetime(1970, 1, 1)
    try:
        return dt.datetime(1601, 1, 1) + dt.timedelta(microseconds=win_ticks // 10)
    except:
        return dt.datetime(1970, 1, 1)

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
    sz = ctypes.c_uint32(0)
    return bool(crypt32.CertGetCertificateContextProperty(cert, CERT_ARCHIVED_PROP_ID, None, ctypes.byref(sz)))

def set_archived(cert, archive: bool):
    current = is_archived(cert)
    if current == archive:
        return True 
    if archive:
        blob = DATA_BLOB(0, None)
        return crypt32.CertSetCertificateContextProperty(cert, CERT_ARCHIVED_PROP_ID, 0, ctypes.byref(blob))
    return crypt32.CertSetCertificateContextProperty(cert, CERT_ARCHIVED_PROP_ID, 0, None)

def get_cert_property(cert, prop_id):
    sz = ctypes.c_uint32(0)
    if not crypt32.CertGetCertificateContextProperty(cert, prop_id, None, ctypes.byref(sz)):
        return ""
    buf = ctypes.create_string_buffer(sz.value)
    if not crypt32.CertGetCertificateContextProperty(cert, prop_id, buf, ctypes.byref(sz)):
        return ""
    try:
        return buf.raw[:sz.value-2].decode('utf-16le')
    except:
        return ""

def set_cert_friendly_name(cert_name, new_friendly_name):
    stores = ["MY", "AddressBook"]
    for s_name in stores:
        store = None
        try:
            flags = (CERT_SYSTEM_STORE_CURRENT_USER | CERT_STORE_OPEN_EXISTING_FLAG | 
                     CERT_STORE_MAXIMUM_ALLOWED_FLAG | CERT_STORE_ENUM_ARCHIVED_FLAG)
            store = crypt32.CertOpenStore(ctypes.c_void_p(CERT_STORE_PROV_SYSTEM), 0, None, flags, ctypes.c_wchar_p(s_name))
            if not store:
                continue
            for cert in iter_certs(store):
                if get_name(cert) == cert_name:
                    name_bytes = (new_friendly_name + "\0").encode('utf-16le')
                    blob = DATA_BLOB(len(name_bytes), ctypes.cast(ctypes.create_string_buffer(name_bytes), ctypes.c_void_p))
                    return crypt32.CertSetCertificateContextProperty(cert, CERT_FRIENDLY_NAME_PROP_ID, 0, ctypes.byref(blob))
        finally:
            if store:
                crypt32.CertCloseStore(store, 0)
    return False

def get_cert_details(name: str):
    stores = ["MY", "AddressBook"]
    for s_name in stores:
        store = None
        try:
            flags = (CERT_SYSTEM_STORE_CURRENT_USER | CERT_STORE_OPEN_EXISTING_FLAG | CERT_STORE_ENUM_ARCHIVED_FLAG)
            store = crypt32.CertOpenStore(ctypes.c_void_p(CERT_STORE_PROV_SYSTEM), 0, None, flags, ctypes.c_wchar_p(s_name))
            if not store:
                continue
            for cert in iter_certs(store):
                if get_name(cert) == name:
                    friendly = get_cert_property(cert, CERT_FRIENDLY_NAME_PROP_ID)
                    ctx = CERT_CONTEXT.from_address(cert)
                    full_subject_str = ""
                    if ctx.pCertInfo:
                        size = crypt32.CertNameToStrW(1, ctypes.byref(ctx.pCertInfo.contents.Subject), CERT_X500_NAME_STR, None, 0)
                        if size > 1:
                            buf = ctypes.create_unicode_buffer(size)
                            crypt32.CertNameToStrW(1, ctypes.byref(ctx.pCertInfo.contents.Subject), CERT_X500_NAME_STR, buf, size)
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
                        serial_val = "".join(f"{p_data[i]:02X}" for i in range(s_blob.cbData - 1, -1, -1))
                        not_before = filetime_to_datetime(ctx.pCertInfo.contents.NotBefore)
                        not_after = filetime_to_datetime(ctx.pCertInfo.contents.NotAfter)

                    def find_oid(s, patterns):
                        for p in patterns:
                            m = re.search(p, s, re.IGNORECASE)
                            if m:
                                return m.group(1).replace('"', '').strip()
                        return ""

                    snils_val = find_oid(full_subject_str, [r"СНИЛС\s*=\s*([\d-]+)", r"SNILS\s*=\s*([\d-]+)", r"OID\.1\.2\.643\.100\.3\s*=\s*([\d-]+)"])
                    inn_val = find_oid(full_subject_str, [r"(?<!ЮЛ)ИНН\s*=\s*(\d+)", r"INN\s*=\s*(\d+)", r"OID\.1\.2\.643\.3\.131\.1\.1\s*=\s*(\d+)"])
                    inn_le_val = find_oid(full_subject_str, [r"ИНН\s*ЮЛ\s*=\s*(\d+)", r"ИНН\s+ЮЛ\s*=\s*(\d+)", r"OID\.1\.2\.643\.6\.3\.1\.4\.1\s*=\s*(\d+)"])
                    ogrn_val = find_oid(full_subject_str, [r"ОГРН\s*=\s*(\d+)", r"OGRN\s*=\s*(\d+)", r"OID\.1\.2\.643\.100\.1\s*=\s*(\d+)"])

                    return {
                        "name": name, "cn": cn_val, "friendly": friendly, "subject": subject_simple, "issuer": issuer_val,
                        "serial": serial_val, "snils": snils_val, "inn": inn_val, "inn_le": inn_le_val, "ogrn": ogrn_val,
                        "not_before": not_before, "not_after": not_after, "full_subject": full_subject_str
                    }
        finally:
            if store:
                crypt32.CertCloseStore(store, 0)
    return None

def delete_cert_and_key(name: str):
    stores = ["MY", "AddressBook"]
    for s_name in stores:
        store = None
        try:
            flags = (CERT_SYSTEM_STORE_CURRENT_USER | CERT_STORE_OPEN_EXISTING_FLAG | 
                     CERT_STORE_MAXIMUM_ALLOWED_FLAG | CERT_STORE_ENUM_ARCHIVED_FLAG)
            store = crypt32.CertOpenStore(ctypes.c_void_p(CERT_STORE_PROV_SYSTEM), 0, None, flags, ctypes.c_wchar_p(s_name))
            if not store:
                continue
            for cert in iter_certs(store):
                if get_name(cert) == name:
                    sz = ctypes.c_uint32(0)
                    if crypt32.CertGetCertificateContextProperty(cert, CERT_KEY_PROV_INFO_PROP_ID, None, ctypes.byref(sz)):
                        buf = ctypes.create_string_buffer(sz.value)
                        if crypt32.CertGetCertificateContextProperty(cert, CERT_KEY_PROV_INFO_PROP_ID, buf, ctypes.byref(sz)):
                            info = CRYPT_KEY_PROV_INFO.from_buffer(buf)
                            h_prov = ctypes.c_void_p()
                            advapi32.CryptAcquireContextW(ctypes.byref(h_prov), info.pwszContainerName, info.pwszProvName, 
                                                         info.dwProvType, CRYPT_DELETEKEYSET)
                    dup = crypt32.CertDuplicateCertificateContext(cert)
                    return crypt32.CertDeleteCertificateFromStore(dup)
        finally:
            if store:
                crypt32.CertCloseStore(store, 0)
    return False

def export_pfx(name: str, path: str, password: str):
    store_sys = None
    store_mem = None
    try:
        flags = (CERT_SYSTEM_STORE_CURRENT_USER | CERT_STORE_OPEN_EXISTING_FLAG | 
                 CERT_STORE_MAXIMUM_ALLOWED_FLAG | CERT_STORE_ENUM_ARCHIVED_FLAG)
        store_sys = crypt32.CertOpenStore(ctypes.c_void_p(CERT_STORE_PROV_SYSTEM), 0, None, flags, ctypes.c_wchar_p("MY"))
        store_mem = crypt32.CertOpenStore(ctypes.c_void_p(CERT_STORE_PROV_MEMORY), 0, None, 0, None)
        
        found = False
        for cert in iter_certs(store_sys):
            if get_name(cert) == name:
                crypt32.CertAddCertificateContextToStore(store_mem, cert, CERT_STORE_ADD_REPLACE_EXISTING, None)
                found = True
                break
        if not found:
            return False
        
        blob = DATA_BLOB(0, None)
        export_flags = EXPORT_PRIVATE_KEYS | REPORT_NOT_ABLE_TO_EXPORT_PRIVATE_KEY
        if crypt32.PFXExportCertStoreEx(store_mem, ctypes.byref(blob), password, None, export_flags):
            buf = ctypes.create_string_buffer(blob.cbData)
            blob.pbData = ctypes.cast(buf, ctypes.c_void_p)
            if crypt32.PFXExportCertStoreEx(store_mem, ctypes.byref(blob), password, None, export_flags):
                with open(path, "wb") as f:
                    f.write(buf.raw)
                return True
    finally:
        if store_sys:
            crypt32.CertCloseStore(store_sys, 0)
        if store_mem:
            crypt32.CertCloseStore(store_mem, 0)
    return False

def export_pfx_multi(names: list, path: str, password: str):
    """Экспорт нескольких сертификатов в один PFX файл."""
    store_sys = None
    store_mem = None
    try:
        flags = (CERT_SYSTEM_STORE_CURRENT_USER | CERT_STORE_OPEN_EXISTING_FLAG |
                 CERT_STORE_MAXIMUM_ALLOWED_FLAG | CERT_STORE_ENUM_ARCHIVED_FLAG)
        store_sys = crypt32.CertOpenStore(ctypes.c_void_p(CERT_STORE_PROV_SYSTEM), 0, None, flags, ctypes.c_wchar_p("MY"))
        store_mem = crypt32.CertOpenStore(ctypes.c_void_p(CERT_STORE_PROV_MEMORY), 0, None, 0, None)
        names_set = set(names)
        found_count = 0
        for cert in iter_certs(store_sys):
            if get_name(cert) in names_set:
                crypt32.CertAddCertificateContextToStore(store_mem, cert, CERT_STORE_ADD_REPLACE_EXISTING, None)
                found_count += 1
        if found_count == 0:
            return False, 0
        blob = DATA_BLOB(0, None)
        export_flags = EXPORT_PRIVATE_KEYS | REPORT_NOT_ABLE_TO_EXPORT_PRIVATE_KEY
        if crypt32.PFXExportCertStoreEx(store_mem, ctypes.byref(blob), password, None, export_flags):
            buf = ctypes.create_string_buffer(blob.cbData)
            blob.pbData = ctypes.cast(buf, ctypes.c_void_p)
            if crypt32.PFXExportCertStoreEx(store_mem, ctypes.byref(blob), password, None, export_flags):
                with open(path, "wb") as f:
                    f.write(buf.raw)
                return True, found_count
    finally:
        if store_sys:
            crypt32.CertCloseStore(store_sys, 0)
        if store_mem:
            crypt32.CertCloseStore(store_mem, 0)
    return False, 0

def export_cer(name: str, path: str) -> bool:
    """Экспорт сертификата в формате DER (.cer) без закрытого ключа."""
    stores = ["MY", "AddressBook"]
    for s_name in stores:
        store = None
        try:
            flags = (CERT_SYSTEM_STORE_CURRENT_USER | CERT_STORE_OPEN_EXISTING_FLAG |
                     CERT_STORE_MAXIMUM_ALLOWED_FLAG | CERT_STORE_ENUM_ARCHIVED_FLAG)
            store = crypt32.CertOpenStore(ctypes.c_void_p(CERT_STORE_PROV_SYSTEM), 0, None, flags, ctypes.c_wchar_p(s_name))
            if not store:
                continue
            for cert in iter_certs(store):
                if get_name(cert) == name:
                    ctx = CERT_CONTEXT.from_address(cert)
                    size = ctx.cbCertEncoded
                    if size == 0:
                        return False
                    raw = ctypes.string_at(ctx.pbCertEncoded, size)
                    with open(path, "wb") as f:
                        f.write(raw)
                    return True
        finally:
            if store:
                crypt32.CertCloseStore(store, 0)
    return False

def import_pfx(path: str, password: str):
    store_sys = None
    store_pfx = None
    try:
        with open(path, "rb") as f:
            data = f.read()
        blob = DATA_BLOB(len(data), ctypes.cast(ctypes.create_string_buffer(data), ctypes.c_void_p))
        store_pfx = crypt32.PFXImportCertStore(ctypes.byref(blob), password, 0x00001000)
        if not store_pfx:
            return False
        store_sys = crypt32.CertOpenStore(ctypes.c_void_p(CERT_STORE_PROV_SYSTEM), 0, None, 
                                         CERT_SYSTEM_STORE_CURRENT_USER | CERT_STORE_OPEN_EXISTING_FLAG, ctypes.c_wchar_p("MY"))
        success = False
        for cert in iter_certs(store_pfx):
            if crypt32.CertAddCertificateContextToStore(store_sys, cert, CERT_STORE_ADD_REPLACE_EXISTING, None):
                success = True
        return success
    finally:
        if store_sys:
            crypt32.CertCloseStore(store_sys, 0)
        if store_pfx:
            crypt32.CertCloseStore(store_pfx, 0)
    return False

def toggle_cert_archive(name: str):
    stores = ["MY", "AddressBook"]
    for s_name in stores:
        store = None
        try:
            flags = (CERT_SYSTEM_STORE_CURRENT_USER | CERT_STORE_OPEN_EXISTING_FLAG | 
                     CERT_STORE_MAXIMUM_ALLOWED_FLAG | CERT_STORE_ENUM_ARCHIVED_FLAG)
            store = crypt32.CertOpenStore(ctypes.c_void_p(CERT_STORE_PROV_SYSTEM), 0, None, flags, ctypes.c_wchar_p(s_name))
            if not store:
                continue
            for cert in iter_certs(store):
                if get_name(cert) == name:
                    set_archived(cert, not is_archived(cert))
                    return
        finally:
            if store:
                crypt32.CertCloseStore(store, 0)

def apply_filter(target_cn: str):
    stores = ["MY", "AddressBook"]
    kept = hidden = 0
    clean_target = target_cn.lower().replace('"', '').strip()
    for s_name in stores:
        store = None
        try:
            flags = (CERT_SYSTEM_STORE_CURRENT_USER | CERT_STORE_OPEN_EXISTING_FLAG | 
                     CERT_STORE_MAXIMUM_ALLOWED_FLAG | CERT_STORE_ENUM_ARCHIVED_FLAG)
            store = crypt32.CertOpenStore(ctypes.c_void_p(CERT_STORE_PROV_SYSTEM), 0, None, flags, ctypes.c_wchar_p(s_name))
            if not store:
                continue
            for cert in iter_certs(store):
                name = get_name(cert).lower().replace('"', '').strip()
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
    stores = ["MY", "AddressBook"]
    for s_name in stores:
        store = None
        try:
            flags = (CERT_SYSTEM_STORE_CURRENT_USER | CERT_STORE_OPEN_EXISTING_FLAG | 
                     CERT_STORE_MAXIMUM_ALLOWED_FLAG | CERT_STORE_ENUM_ARCHIVED_FLAG)
            store = crypt32.CertOpenStore(ctypes.c_void_p(CERT_STORE_PROV_SYSTEM), 0, None, flags, ctypes.c_wchar_p(s_name))
            if not store:
                continue
            certs_to_process = []
            curr = crypt32.CertEnumCertificatesInStore(store, None)
            while curr:
                certs_to_process.append(crypt32.CertDuplicateCertificateContext(curr))
                curr = crypt32.CertEnumCertificatesInStore(store, curr)
            for c in certs_to_process:
                set_archived(c, False)
                crypt32.CertFreeCertificateContext(c)
        finally:
            if store:
                crypt32.CertCloseStore(store, 0)

def hide_all():
    stores = ["MY", "AddressBook"]
    for s_name in stores:
        store = None
        try:
            flags = (CERT_SYSTEM_STORE_CURRENT_USER | CERT_STORE_OPEN_EXISTING_FLAG | 
                     CERT_STORE_MAXIMUM_ALLOWED_FLAG | CERT_STORE_ENUM_ARCHIVED_FLAG)
            store = crypt32.CertOpenStore(ctypes.c_void_p(CERT_STORE_PROV_SYSTEM), 0, None, flags, ctypes.c_wchar_p(s_name))
            if not store:
                continue
            certs_to_process = []
            curr = crypt32.CertEnumCertificatesInStore(store, None)
            while curr:
                certs_to_process.append(crypt32.CertDuplicateCertificateContext(curr))
                curr = crypt32.CertEnumCertificatesInStore(store, curr)
            for c in certs_to_process:
                set_archived(c, True)
                crypt32.CertFreeCertificateContext(c)
        finally:
            if store:
                crypt32.CertCloseStore(store, 0)

def get_all_certs():
    stores = ["MY", "AddressBook"]
    result = []
    for s_name in stores:
        store = None
        try:
            flags = (CERT_SYSTEM_STORE_CURRENT_USER | CERT_STORE_OPEN_EXISTING_FLAG | CERT_STORE_ENUM_ARCHIVED_FLAG)
            store = crypt32.CertOpenStore(ctypes.c_void_p(CERT_STORE_PROV_SYSTEM), 0, None, flags, ctypes.c_wchar_p(s_name))
            if not store:
                continue
            curr = crypt32.CertEnumCertificatesInStore(store, None)
            while curr:
                try:
                    name = get_name(curr)
                    archived = is_archived(curr)
                    not_before = datetime(1970, 1, 1)
                    not_after = datetime(1970, 1, 1)
                    ctx = CERT_CONTEXT.from_address(curr)
                    if ctx.pCertInfo:
                        not_before = filetime_to_datetime(ctx.pCertInfo.contents.NotBefore)
                        not_after = filetime_to_datetime(ctx.pCertInfo.contents.NotAfter)
                    result.append({"name": name, "archived": archived,
                                   "not_before": not_before, "not_after": not_after})
                except:
                    pass
                curr = crypt32.CertEnumCertificatesInStore(store, curr)
        finally:
            if store:
                crypt32.CertCloseStore(store, 0)
    return result

# ── UI ────────────────────────────────────────────────────────────────────────
BG, BG_PANEL, BG_CARD = "#0e1117", "#161b27", "#1c2333"
BORDER, ACCENT, ACCENT2, DANGER = "#2a3550", "#4f7bec", "#3ecf8e", "#f76f72"
TEXT, TEXT_DIM = "#e2e8f8", "#7b8db8"

def safe_filename(name: str, max_len: int = 80) -> str:
    """Убирает символы запрещённые в именах файлов Windows/Linux."""
    # Запрещённые в Windows: \ / : * ? " < > |  (и управляющие символы 0-31)
    result = re.sub(r'[\\/:*?"<>|\x00-\x1f]', '_', name)
    result = result.strip('. ')  # запрещены в начале/конце файла
    return result[:max_len] or "cert"

class CertWorker(QThread):
    done = Signal(int, int, str)
    def __init__(self, cn: str):
        super().__init__()
        self.cn = cn
    def run(self):
        k, h = apply_filter(self.cn)
        self.done.emit(k, h, self.cn)

class CertFilterApp(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Cert Filter Ultra PRO")
        self.resize(1100, 850)
        self.setMinimumSize(700, 500)
        self.setStyleSheet(f"background: {BG}; color: {TEXT};")
        self.config_data = {}
        self.log_lines = []
        self.sort_mode = "CN"
        self.selected_certs: dict[str, QCheckBox] = {}  # name -> checkbox

        central = QWidget()
        self.setCentralWidget(central)
        main_lay = QHBoxLayout(central)
        
        left = QWidget()
        left.setMinimumWidth(280)
        left.setMaximumWidth(420)
        self.left_lay = QVBoxLayout(left)
        
        self.combo_files = QComboBox()
        self.combo_files.setStyleSheet(f"background:{BG_PANEL}; border:1px solid {BORDER}; padding:8px; color:{TEXT};")
        self.combo_files.currentTextChanged.connect(self._load_selected_json)
        self.left_lay.addWidget(QLabel("ФАЙЛ:"))
        self.left_lay.addWidget(self.combo_files)

        self.input_key = QLineEdit()
        self.input_key.setPlaceholderText("Введите номер ключа...")
        self.input_key.setStyleSheet(f"background:{BG_PANEL}; border:1px solid {BORDER}; padding:8px; color:{TEXT};")
        self.input_key.returnPressed.connect(self._on_ok_clicked)
        self.left_lay.addSpacing(15)
        self.left_lay.addWidget(QLabel("КЛЮЧ:"))
        
        key_hbox = QHBoxLayout()
        key_hbox.addWidget(self.input_key)
        btn_ok = QPushButton("OK")
        btn_ok.setFixedSize(60, 35)
        btn_ok.clicked.connect(self._on_ok_clicked)
        btn_ok.setStyleSheet(f"background:{ACCENT}; border-radius:5px; font-weight:bold;")
        key_hbox.addWidget(btn_ok)
        self.left_lay.addLayout(key_hbox)

        self.input_search_keys = QLineEdit()
        self.input_search_keys.setPlaceholderText("Поиск по списку...")
        self.input_search_keys.setStyleSheet(f"background:{BG_PANEL}; border:1px solid {BORDER}; padding:8px; color:{TEXT};")
        self.input_search_keys.textChanged.connect(self._update_keys_list)
        self.left_lay.addSpacing(10)
        self.left_lay.addWidget(QLabel("ПОИСК В СПИСКЕ:"))
        self.left_lay.addWidget(self.input_search_keys)

        self.scroll_keys = QScrollArea()
        self.scroll_keys.setWidgetResizable(True)
        self.scroll_keys.setStyleSheet("border:none; background:transparent;")
        self.keys_cont = QWidget()
        self.keys_lay = QVBoxLayout(self.keys_cont)
        self.keys_lay.addStretch()
        self.scroll_keys.setWidget(self.keys_cont)
        self.left_lay.addWidget(QLabel("СПИСОК:"))
        self.left_lay.addWidget(self.scroll_keys)

        self.left_lay.addSpacing(10)
        self.left_lay.addWidget(QLabel("ДОБАВИТЬ В JSON:"))
        self.input_new_key = QLineEdit()
        self.input_new_key.setPlaceholderText("Новый ключ (например: 145ю)")
        self.input_new_key.setStyleSheet(f"background:{BG_PANEL}; border:1px solid {BORDER}; padding:8px; color:{TEXT};")
        self.left_lay.addWidget(self.input_new_key)
        self.input_new_val = QLineEdit()
        self.input_new_val.setPlaceholderText("Новое значение (CN сертификата)")
        self.input_new_val.setStyleSheet(f"background:{BG_PANEL}; border:1px solid {BORDER}; padding:8px; color:{TEXT};")
        self.left_lay.addWidget(self.input_new_val)
        self.btn_add_json = QPushButton("СОХРАНИТЬ В JSON")
        self.btn_add_json.clicked.connect(self._on_add_to_json)
        self.btn_add_json.setStyleSheet(f"background:{ACCENT2}; border-radius:5px; font-weight:bold; padding:8px; color:{BG};")
        self.left_lay.addWidget(self.btn_add_json)

        self.log_label = QLabel("Готов")
        self.log_label.setStyleSheet(f"background:{BG_PANEL}; border:1px solid {BORDER}; padding:10px; font-size:10px;")
        self.log_label.setWordWrap(True)
        self.log_label.setFixedHeight(120)
        self.left_lay.addWidget(self.log_label)

        right = QWidget()
        right_lay = QVBoxLayout(right)
        right_lay.setSpacing(4)
        hdr1 = QHBoxLayout()
        hdr1.setSpacing(4)

        # Общий стиль кнопок заголовка
        _hs = "font-size:10px; padding:3px 7px;"

        btn_sel_all = QPushButton("☑ Выбрать все")
        btn_sel_all.clicked.connect(lambda: self._on_select_all(True))
        btn_sel_all.setStyleSheet(f"color:{TEXT_DIM}; border:1px solid {BORDER}; {_hs}")
        hdr1.addWidget(btn_sel_all)

        btn_sel_none = QPushButton("☐ Снять все")
        btn_sel_none.clicked.connect(lambda: self._on_select_all(False))
        btn_sel_none.setStyleSheet(f"color:{TEXT_DIM}; border:1px solid {BORDER}; {_hs}")
        hdr1.addWidget(btn_sel_none)

        btn_exp_sel = QPushButton("Эксп. PFX")
        btn_exp_sel.clicked.connect(self._on_export_selected)
        btn_exp_sel.setStyleSheet(
            f"background:#2a3a6e; color:{ACCENT}; border:1px solid {ACCENT};"
            f"font-weight:bold; {_hs}"
        )
        btn_exp_sel.setToolTip("Экспорт выбранных сертификатов в PFX")
        hdr1.addWidget(btn_exp_sel)

        btn_del_sel = QPushButton("Удал. выбранные")
        btn_del_sel.clicked.connect(self._on_delete_selected)
        btn_del_sel.setStyleSheet(
            f"background:#3a1a1a; color:{DANGER}; border:1px solid {DANGER};"
            f"font-weight:bold; {_hs}"
        )
        btn_del_sel.setToolTip("Удалить выбранные сертификаты и ключи")
        hdr1.addWidget(btn_del_sel)

        btn_import = QPushButton("Импорт PFX")
        btn_import.clicked.connect(self._on_import_pfx)
        btn_import.setStyleSheet(f"color:{ACCENT}; border:1px solid {ACCENT}; font-weight:bold; {_hs}")
        hdr1.addWidget(btn_import)

        btn_all = QPushButton("Показать все")
        btn_all.clicked.connect(self._on_restore)
        btn_all.setStyleSheet(f"color:{ACCENT2}; border:1px solid {ACCENT2}; {_hs}")
        hdr1.addWidget(btn_all)

        btn_hide_all = QPushButton("Скрыть все")
        btn_hide_all.clicked.connect(self._on_hide_all)
        btn_hide_all.setStyleSheet(f"color:{DANGER}; border:1px solid {DANGER}; {_hs}")
        hdr1.addWidget(btn_hide_all)

        hdr1.addStretch()
        right_lay.addLayout(hdr1)

        hdr2 = QHBoxLayout()
        self.input_search_certs = QLineEdit()
        self.input_search_certs.setPlaceholderText("Поиск сертификата по CN...")
        self.input_search_certs.setStyleSheet(f"background:{BG_PANEL}; border:1px solid {BORDER}; padding:6px; color:{TEXT};")
        self.input_search_certs.textChanged.connect(self._load_certs)
        hdr2.addWidget(QLabel("ПОИСК:"))
        hdr2.addWidget(self.input_search_certs)
        hdr2.addSpacing(20)
        hdr2.addWidget(QLabel("СОРТИРОВКА:"))
        self.combo_sort = QComboBox()
        self.combo_sort.addItems([
            "По имени (CN)",
            "Дата начала (NotBefore)",
            "Дата окончания (NotAfter)",
            "Дата ок. ключа (NotAfter)",
        ])
        self.combo_sort.setMinimumWidth(180)
        self.combo_sort.setStyleSheet(
            f"QComboBox {{ background:{BG_PANEL}; border:1px solid {BORDER}; "
            f"padding:3px 5px; color:{TEXT}; font-size:10px; }}"
            f"QComboBox QAbstractItemView {{ background:{BG_PANEL}; color:{TEXT}; "
            f"selection-background-color:{ACCENT}; font-size:10px; }}"
        )
        self.combo_sort.currentIndexChanged.connect(self._on_sort_changed)
        hdr2.addWidget(self.combo_sort)
        right_lay.addLayout(hdr2)

        self.scroll_certs = QScrollArea()
        self.scroll_certs.setWidgetResizable(True)
        self.scroll_certs.setStyleSheet("border:none; background:transparent;")
        self.certs_cont = QWidget()
        self.certs_lay = QVBoxLayout(self.certs_cont)
        self.certs_lay.addStretch()
        self.scroll_certs.setWidget(self.certs_cont)
        right_lay.addWidget(self.scroll_certs)
        main_lay.addWidget(left)
        main_lay.addWidget(right)

        self._scan_jsons()
        self._load_certs()

    def _on_sort_changed(self, idx):
        modes = ["CN", "NOT_BEFORE", "NOT_AFTER", "KEY_DATE"]
        self.sort_mode = modes[idx] if idx < len(modes) else "CN"
        self._load_certs()

    def _scan_jsons(self):
        files = [f for f in os.listdir(".") if f.endswith(".json")]
        self.combo_files.addItems(files)

    def _load_selected_json(self, name):
        if not name:
            return
        try:
            with open(name, "r", encoding="utf-8") as f:
                self.config_data = json.load(f)
            self._update_keys_list()
            self._log(f"Загружено: {name}", ACCENT2)
        except Exception as e:
            self._log(f"Ошибка JSON: {e}", DANGER)

    def _update_keys_list(self):
        search_text = self.input_search_keys.text().lower()
        while self.keys_lay.count() > 1:
            w = self.keys_lay.takeAt(0).widget()
            if w:
                w.deleteLater()
        for k, v in self.config_data.items():
            if search_text and search_text not in k.lower() and search_text not in v.lower():
                continue
            row = QWidget()
            row_lay = QHBoxLayout(row)
            row_lay.setContentsMargins(0, 0, 0, 2)
            row_lay.setSpacing(2)
            btn = QPushButton(f"{k} : {v[:40]}...")
            btn.setToolTip(f"Ключ: {k}\nЗначение: {v}")
            btn.setStyleSheet(f"text-align:left; padding:8px; background:{BG_CARD}; border:1px solid {BORDER};")
            btn.clicked.connect(lambda ch, val=v: self._start_filter(val))
            btn_edit = QPushButton("✎")
            btn_edit.setFixedSize(30, 35)
            btn_edit.setStyleSheet(f"background:{BG_PANEL}; border:1px solid {BORDER}; color:{ACCENT2};")
            btn_edit.clicked.connect(lambda ch, key=k, val=v: self._on_edit_key(key, val))
            btn_del = QPushButton("🗑")
            btn_del.setFixedSize(30, 35)
            btn_del.setStyleSheet(f"background:{BG_PANEL}; border:1px solid {BORDER}; color:{DANGER};")
            btn_del.clicked.connect(lambda ch, key=k: self._on_delete_key(key))
            row_lay.addWidget(btn, 1)
            row_lay.addWidget(btn_edit)
            row_lay.addWidget(btn_del)
            self.keys_lay.insertWidget(self.keys_lay.count()-1, row)

    def _on_edit_key(self, key, val):
        self.input_new_key.setText(key)
        self.input_new_val.setText(val)
        self.input_new_val.setFocus()
        self._log(f"Редактирование: {key}", ACCENT)

    def _on_delete_key(self, key):
        filename = self.combo_files.currentText()
        if not filename:
            return
        reply = QMessageBox.question(self, 'Удаление', f"Удалить ключ '{key}' из {filename}?", QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No)
        if reply == QMessageBox.StandardButton.Yes:
            if key in self.config_data:
                del self.config_data[key]
                try:
                    with open(filename, "w", encoding="utf-8") as f:
                        json.dump(self.config_data, f, ensure_ascii=False, indent=2)
                    self._update_keys_list()
                    self._log(f"Удалено: {key}", DANGER)
                except Exception as e:
                    self._log(f"Ошибка удаления: {e}", DANGER)

    def _on_ok_clicked(self):
        key = self.input_key.text().strip()
        val = self.config_data.get(key)
        if val:
            self._start_filter(val)
        else:
            self._log(f"Ключ '{key}' не найден!", DANGER)

    def _on_add_to_json(self):
        key = self.input_new_key.text().strip()
        val = self.input_new_val.text().strip()
        filename = self.combo_files.currentText()
        if not key or not val:
            self._log("Ошибка: Ключ и значение пустые", DANGER)
            return
        if not filename:
            self._log("Ошибка: Файл не выбран", DANGER)
            return
        self.config_data[key] = val
        try:
            with open(filename, "w", encoding="utf-8") as f:
                json.dump(self.config_data, f, ensure_ascii=False, indent=2)
            self._update_keys_list()
            self.input_new_key.clear()
            self.input_new_val.clear()
            self._log(f"Добавлено: {key}", ACCENT2)
        except Exception as e:
            self._log(f"Ошибка: {e}", DANGER)

    def _start_filter(self, cn):
        self._log(f"Фильтр: {cn[:50]}...", ACCENT)
        self.setEnabled(False)
        self.worker = CertWorker(cn)
        self.worker.done.connect(self._on_done)
        self.worker.start()

    def _on_done(self, k, h, cn):
        self.setEnabled(True)
        self._log(f"Успех! Видно: {k}, Скрыто: {h}", ACCENT2)
        self._load_certs()

    def _load_certs(self):
        certs = get_all_certs()
        search_text = self.input_search_certs.text().lower()
        if search_text:
            certs = [c for c in certs if search_text in c["name"].lower()]
        if self.sort_mode == "CN":
            certs.sort(key=lambda x: x["name"].lower())
        elif self.sort_mode == "NOT_BEFORE":
            certs.sort(key=lambda x: x["not_before"])
        elif self.sort_mode == "NOT_AFTER":
            certs.sort(key=lambda x: x["not_after"])
        elif self.sort_mode == "KEY_DATE":
            # Срок закрытого ключа совпадает с окончанием сертификата
            certs.sort(key=lambda x: x["not_after"])
        else:
            certs.sort(key=lambda x: x["name"].lower())
        self.selected_certs.clear()
        while self.certs_lay.count() > 1:
            w = self.certs_lay.takeAt(0).widget()
            if w:
                w.deleteLater()
        now = datetime.now()
        for c in certs:
            row = QWidget()
            row_lay = QHBoxLayout(row)
            row_lay.setContentsMargins(5, 2, 5, 2)

            # Определяем статус срока
            days_left = (c['not_after'] - now).days
            is_expired = days_left < 0
            is_expiring_soon = 0 <= days_left <= 10

            # Чекбокс выбора
            chk = QCheckBox()
            chk.setFixedSize(24, 24)
            chk.setStyleSheet(
                f"QCheckBox::indicator {{ width:16px; height:16px; border:1px solid {BORDER};"
                f"border-radius:3px; background:{BG_PANEL}; }}"
                f"QCheckBox::indicator:checked {{ background:{ACCENT}; border:1px solid {ACCENT}; }}"
            )
            self.selected_certs[c['name']] = chk
            row_lay.addWidget(chk)

            btn_tgl = QPushButton('■' if c['archived'] else '○')
            btn_tgl.setFixedSize(36, 28)
            tgl_color = TEXT_DIM if c['archived'] else ACCENT2
            btn_tgl.setStyleSheet(f"border:1px solid {BORDER}; font-size:14px; font-weight:bold; background:{BG_PANEL}; color:{tgl_color};")
            btn_tgl.setToolTip('Скрыт (нажмите чтобы показать)' if c['archived'] else 'Виден (нажмите чтобы скрыть)')
            btn_tgl.clicked.connect(lambda ch, name=c['name']: self._on_toggle_manual(name))
            btn_edt = QPushButton("≡")
            btn_edit_style = f"background:{BG_PANEL}; border:1px solid {BORDER}; color:{ACCENT2}; font-size:15px; font-weight:bold;"
            btn_edt.setFixedSize(36, 28)
            btn_edt.setStyleSheet(btn_edit_style)
            btn_edt.setToolTip("Инфо / редактировать")
            btn_edt.clicked.connect(lambda ch, n=c['name']: self._on_edit_cert(n))
            btn_exp = QPushButton("PFX")
            btn_exp.setFixedSize(36, 28)
            btn_exp.setStyleSheet(f"background:{BG_PANEL}; border:1px solid {BORDER}; color:{ACCENT}; font-size:9px; font-weight:bold;")
            btn_exp.setToolTip("Экспорт PFX (с ключом)")
            btn_exp.clicked.connect(lambda ch, n=c['name']: self._on_export_cert(n))
            btn_cer = QPushButton("CER")
            btn_cer.setFixedSize(36, 28)
            btn_cer.setStyleSheet(f"background:{BG_PANEL}; border:1px solid {BORDER}; color:{ACCENT2}; font-size:9px; font-weight:bold;")
            btn_cer.setToolTip("Экспорт .cer (без закрытого ключа)")
            btn_cer.clicked.connect(lambda ch, n=c['name']: self._on_export_cer(n))
            btn_rm = QPushButton("DEL")
            btn_rm.setFixedSize(36, 28)
            btn_rm.setStyleSheet(f"background:{BG_PANEL}; border:1px solid {DANGER}; color:{DANGER}; font-size:9px; font-weight:bold;")
            btn_rm.clicked.connect(lambda ch, n=c['name']: self._on_remove_cert(n))
            btn_rm.setToolTip("Удалить сертификат и КЛЮЧ")

            # Цвет текста и фона строки в зависимости от срока
            if is_expired:
                info_color = "#ff4d4d"
                row_bg = "#2a1a1a"
                date_badge = f"<small style='color:#ff4d4d; font-weight:bold;'>⚠ ИСТЁК {c['not_after'].strftime('%d.%m.%Y')}</small>"
            elif is_expiring_soon:
                info_color = "#f0c040"
                row_bg = "#272010"
                date_badge = f"<small style='color:#f0c040; font-weight:bold;'>⏳ {days_left} дн. до {c['not_after'].strftime('%d.%m.%Y')}</small>"
            elif c['archived']:
                info_color = TEXT_DIM
                row_bg = BG
                date_badge = f"<small style='color:{TEXT_DIM}'>до {c['not_after'].strftime('%d.%m.%Y')}</small>"
            else:
                info_color = TEXT
                row_bg = BG_PANEL
                date_badge = f"<small style='color:{TEXT_DIM}'>до {c['not_after'].strftime('%d.%m.%Y')}</small>"

            info = QLabel(f"<span style='color:{info_color}'>{c['name']}</span> {date_badge}")
            row_lay.addWidget(btn_tgl)
            row_lay.addWidget(btn_edt)
            row_lay.addWidget(btn_exp)
            row_lay.addWidget(btn_cer)
            row_lay.addWidget(btn_rm)
            row_lay.addWidget(info, 1)
            row.setStyleSheet(f"background:{row_bg}; border-bottom:1px solid {BORDER};")
            self.certs_lay.insertWidget(self.certs_lay.count()-1, row)

    def _on_toggle_manual(self, name):
        toggle_cert_archive(name)
        self._load_certs()

    def _on_restore(self):
        self._log("Восстановление...", TEXT_DIM)
        restore_all()
        self._load_certs()
        self._log("Все открыты", ACCENT2)

    def _on_hide_all(self):
        self._log("Скрытие...", TEXT_DIM)
        hide_all()
        self._load_certs()
        self._log("Все скрыты", DANGER)

    def _on_edit_cert(self, name):
        d = get_cert_details(name)
        if not d:
            return
        dlg = QDialog(self)
        dlg.setWindowTitle(f"Данные: {name}")
        dlg.resize(750, 650)
        dlg.setStyleSheet(f"background:{BG}; color:{TEXT};")
        lay = QVBoxLayout(dlg)
        form = QFormLayout()
        form.setLabelAlignment(Qt.AlignmentFlag.AlignRight)
        def c_ro(t, h=40):
            e = QTextEdit()
            e.setPlainText(t or "не указано")
            e.setReadOnly(True)
            e.setFixedHeight(h)
            e.setStyleSheet(f"background:{BG_PANEL}; border:1px solid {BORDER}; color:{TEXT_DIM};")
            return e
        e_f = QLineEdit(d['friendly'])
        e_f.setStyleSheet(f"background:{BG_PANEL}; border:1px solid {BORDER}; padding:8px; color:{ACCENT2};")
        val = f"С {d['not_before'].strftime('%d.%m.%Y %H:%M:%S')}\nПО {d['not_after'].strftime('%d.%m.%Y %H:%M:%S')}"
        form.addRow("CN (Имя):", c_ro(d['cn']))
        form.addRow("СРОК ДЕЙСТВИЯ:", c_ro(val, 60))
        form.addRow("ИНН (Физлицо):", c_ro(d['inn']))
        form.addRow("ИНН ЮЛ (ИИН):", c_ro(d['inn_le']))
        form.addRow("СНИЛС:", c_ro(d['snils']))
        form.addRow("ОГРН:", c_ro(d['ogrn']))
        form.addRow("СЕРИЙНЫЙ НОМЕР:", c_ro(d['serial']))
        form.addRow("Friendly Name:", e_f)
        form.addRow("СУБЪЕКТ:", c_ro(d['subject'], 60))
        form.addRow("ИЗДАТЕЛЬ:", c_ro(d['issuer'], 60))
        form.addRow("ПОЛНЫЙ СУБЪЕКТ:", c_ro(d['full_subject'], 100))
        lay.addLayout(form)
        btns = QHBoxLayout()
        btn_s = QPushButton("СОХРАНИТЬ")
        btn_s.setStyleSheet(f"background:{ACCENT2}; color:{BG}; font-weight:bold; padding:12px;")
        btn_s.clicked.connect(dlg.accept)
        btn_c = QPushButton("ЗАКРЫТЬ")
        btn_c.setStyleSheet(f"background:{BG_PANEL}; padding:12px;")
        btn_c.clicked.connect(dlg.reject)
        btns.addWidget(btn_c)
        btns.addWidget(btn_s)
        lay.addLayout(btns)
        if dlg.exec():
            if set_cert_friendly_name(name, e_f.text().strip()):
                self._log(f"Обновлено: {name}", ACCENT2)
                self._load_certs()

    def _on_export_cert(self, name):
        default_name = safe_filename(name) + ".pfx"
        path, _ = QFileDialog.getSaveFileName(self, "Экспорт PFX", default_name, "PFX Files (*.pfx)")
        if not path:
            return
        # Гарантируем наличие расширения
        if not path.lower().endswith(".pfx"):
            path += ".pfx"
        pwd, ok = QInputDialog.getText(self, "Пароль PFX", "Введите пароль для защиты файла:", QLineEdit.EchoMode.Password)
        if ok:
            if export_pfx(name, path, pwd):
                QMessageBox.information(self, "Успех", "Сертификат и ключ экспортированы")
            else:
                QMessageBox.critical(self, "Ошибка", "Не удалось экспортировать. Возможно, ключ помечен как неэкспортируемый.")

    def _on_export_cer(self, name):
        """Экспорт сертификата в .cer (без закрытого ключа)."""
        default_name = safe_filename(name) + ".cer"
        path, _ = QFileDialog.getSaveFileName(
            self, "Экспорт сертификата .cer",
            default_name, "Certificate Files (*.cer *.crt);;All Files (*)"
        )
        if not path:
            return
        if not path.lower().endswith((".cer", ".crt")):
            path += ".cer"
        if export_cer(name, path):
            self._log(f".cer экспорт: {Path(path).name}", ACCENT2)
            QMessageBox.information(self, "Успех", f"Сертификат сохранён: {path}")
        else:
            QMessageBox.critical(self, "Ошибка", "Не удалось сохранить файл .cer.")



    def _on_select_all(self, state: bool):
        """Установить/снять все галочки."""
        for chk in self.selected_certs.values():
            chk.setChecked(state)

    def _on_export_selected(self):
        """Экспортировать все отмеченные сертификаты в один PFX."""
        names = [n for n, chk in self.selected_certs.items() if chk.isChecked()]
        if not names:
            QMessageBox.warning(self, "Нет выбранных", "Отметьте галочкой хотя бы один сертификат.")
            return
        path, _ = QFileDialog.getSaveFileName(
            self, "Экспорт выбранных в PFX",
            "export_selected.pfx", "PFX Files (*.pfx)"
        )
        if not path:
            return
        if not path.lower().endswith(".pfx"):
            path += ".pfx"
        pwd, ok = QInputDialog.getText(
            self, "Пароль PFX",
            f"Введите пароль для защиты PFX ({len(names)} сертиф.):",
            QLineEdit.EchoMode.Password
        )
        if not ok:
            return
        ok_exp, count = export_pfx_multi(names, path, pwd)
        if ok_exp:
            self._log(f"Экспортировано {count} сертификатов → {Path(path).name}", ACCENT2)
            QMessageBox.information(
                self, "Успех",
                f"Экспортировано: {count} из {len(names)} сертификатов.\n{path}"
            )
        else:
            QMessageBox.critical(self, "Ошибка", "Не удалось экспортировать выбранные сертификаты.")

    def _on_import_pfx(self):
        path, _ = QFileDialog.getOpenFileName(self, "Импорт PFX", "", "PFX Files (*.pfx *.p12)")
        if not path:
            return
        pwd, ok = QInputDialog.getText(self, "Пароль PFX", "Введите пароль от файла:", QLineEdit.EchoMode.Password)
        if ok:
            if import_pfx(path, pwd):
                self._log("PFX импортирован", ACCENT2)
                self._load_certs()
            else:
                QMessageBox.critical(self, "Ошибка", "Ошибка импорта. Проверьте пароль.")

    def _on_remove_cert(self, name):
        rep = QMessageBox.warning(self, "УДАЛЕНИЕ", f"Вы уверены, что хотите УДАЛИТЬ сертификат '{name}' и его ЗАКРЫТЫЙ КЛЮЧ?\nЭто действие необратимо!", 
                                  QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No)
        if rep == QMessageBox.StandardButton.Yes:
            if delete_cert_and_key(name):
                self._log(f"Удалено: {name}", DANGER)
                self._load_certs()
            else:
                self._log("Ошибка удаления", DANGER)

    def _on_delete_selected(self):
        """Удалить все отмеченные галочкой сертификаты и их закрытые ключи."""
        names = [n for n, chk in self.selected_certs.items() if chk.isChecked()]
        if not names:
            QMessageBox.warning(self, "Нет выбранных", "Отметьте галочкой хотя бы один сертификат.")
            return
        list_text = "\n".join(f"• {n}" for n in names)
        rep = QMessageBox.warning(
            self, "УДАЛЕНИЕ ВЫБРАННЫХ",
            f"Вы уверены, что хотите УДАЛИТЬ {len(names)} сертификат(а/ов) "
            f"и их ЗАКРЫТЫЕ КЛЮЧИ?\n\n{list_text}\n\nЭто действие необратимо!",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No
        )
        if rep != QMessageBox.StandardButton.Yes:
            return
        ok_count = 0
        fail_count = 0
        for name in names:
            if delete_cert_and_key(name):
                ok_count += 1
            else:
                fail_count += 1
        if ok_count:
            self._log(f"Удалено: {ok_count} серт.", DANGER)
        if fail_count:
            self._log(f"Ошибка удаления: {fail_count} серт.", DANGER)
        self._load_certs()

    def _log(self, m, c=TEXT_DIM):
        t = datetime.now().strftime("%H:%M:%S")
        self.log_lines.append(f"[{t}] <span style='color:{c}'>{m}</span>")
        self.log_label.setText("<br>".join(self.log_lines[-6:]))

if __name__ == "__main__":
    app = QApplication(sys.argv)
    win = CertFilterApp()
    win.show()
    sys.exit(app.exec())
