"""Windows DPAPI-backed credential storage."""
import ctypes
import json
import os
import platform
import re
import tempfile
from pathlib import Path


class CredentialStorageError(RuntimeError):
    pass


class _DataBlob(ctypes.Structure):
    _fields_ = [("cbData", ctypes.c_uint32), ("pbData", ctypes.POINTER(ctypes.c_ubyte))]


class SecureCredentialStore:
    ENTROPY = b"MACFinderPro|MerakiInspector|v1"

    def __init__(self, folder=None):
        root = os.environ.get("LOCALAPPDATA") or os.environ.get("APPDATA")
        base = Path(root) if root else Path.home() / ".local" / "share"
        self.folder = Path(folder) if folder else base / "MACFinderPro" / "credentials"
        self.folder.mkdir(parents=True, exist_ok=True)

    @staticmethod
    def _available():
        return platform.system().lower() == "windows" and hasattr(ctypes, "windll")

    def _path(self, name):
        safe = re.sub(r"[^A-Za-z0-9_.-]+", "_", str(name)).strip("._") or "credential"
        return self.folder / f"{safe}.dpapi"

    @staticmethod
    def _blob(data):
        buffer = ctypes.create_string_buffer(data, len(data))
        return _DataBlob(len(data), ctypes.cast(buffer, ctypes.POINTER(ctypes.c_ubyte))), buffer

    def _protect(self, data):
        crypt32 = ctypes.windll.crypt32
        source, source_buffer = self._blob(data)
        entropy, entropy_buffer = self._blob(self.ENTROPY)
        output = _DataBlob()
        if not crypt32.CryptProtectData(ctypes.byref(source), ctypes.c_wchar_p("MACFinderPro"),
                                        ctypes.byref(entropy), None, None, 0x1, ctypes.byref(output)):
            raise CredentialStorageError("Windows DPAPI ile kimlik bilgisi şifrelenemedi.")
        try:
            return ctypes.string_at(output.pbData, output.cbData)
        finally:
            ctypes.windll.kernel32.LocalFree(output.pbData)

    def _unprotect(self, data):
        crypt32 = ctypes.windll.crypt32
        source, source_buffer = self._blob(data)
        entropy, entropy_buffer = self._blob(self.ENTROPY)
        output = _DataBlob()
        description = ctypes.c_wchar_p()
        if not crypt32.CryptUnprotectData(ctypes.byref(source), ctypes.byref(description),
                                          ctypes.byref(entropy), None, None, 0x1,
                                          ctypes.byref(output)):
            raise CredentialStorageError("Şifreli kimlik bilgisi bu Windows kullanıcısıyla açılamadı.")
        try:
            return ctypes.string_at(output.pbData, output.cbData)
        finally:
            kernel32 = ctypes.windll.kernel32
            kernel32.LocalFree(output.pbData)
            if description.value:
                kernel32.LocalFree(description)

    def save(self, name, secret):
        value = str(secret or "").strip()
        if not value:
            self.delete(name)
            return
        if not self._available():
            raise CredentialStorageError("Kalıcı kimlik saklama yalnızca Windows DPAPI ile kullanılabilir.")
        encrypted = self._protect(value.encode("utf-8"))
        path = self._path(name)
        temporary = None
        try:
            with tempfile.NamedTemporaryFile(dir=self.folder, delete=False) as handle:
                temporary = Path(handle.name)
                handle.write(encrypted)
            os.chmod(temporary, 0o600)
            os.replace(temporary, path)
        finally:
            if temporary and temporary.exists():
                temporary.unlink()

    def load(self, name):
        path = self._path(name)
        if not path.exists():
            return ""
        if not self._available():
            raise CredentialStorageError("DPAPI bu platformda kullanılamıyor.")
        try:
            return self._unprotect(path.read_bytes()).decode("utf-8")
        except OSError as exc:
            raise CredentialStorageError(f"Kimlik dosyası okunamadı: {exc}") from exc

    def delete(self, name):
        path = self._path(name)
        if path.exists():
            path.unlink()

    def save_json(self, name, value):
        self.save(name, json.dumps(value, ensure_ascii=False, sort_keys=True))

    def load_json(self, name, default=None):
        raw = self.load(name)
        if not raw:
            return default
        try:
            return json.loads(raw)
        except json.JSONDecodeError as exc:
            raise CredentialStorageError("Şifreli ayar dosyası bozuk.") from exc
