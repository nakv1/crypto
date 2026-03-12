from __future__ import annotations

import base64
import ctypes
import json
import os
import stat
import threading
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Optional

from core.security import secure_zero_bytearray


@dataclass(frozen=True)
class KeyCacheConfig:
    idle_timeout_sec: int = 3600
    lock_when_inactive: bool = True
    use_memory_protection: bool = True

    def normalized(self) -> "KeyCacheConfig":
        timeout = max(60, min(int(self.idle_timeout_sec), 86400))
        return KeyCacheConfig(
            idle_timeout_sec=timeout,
            lock_when_inactive=bool(self.lock_when_inactive),
            use_memory_protection=bool(self.use_memory_protection),
        )


class SecureKeyCache:
    def __init__(self, config: Optional[KeyCacheConfig] = None):
        self.config = (config or KeyCacheConfig()).normalized()
        self.mutex = threading.Lock()
        self.key_data: Optional[bytearray] = None
        self.cached_at_ts: float = 0.0
        self.last_activity_ts: float = 0.0
        self.app_active: bool = True
        self.memory_protected: bool = False

    def set_config(self, config: KeyCacheConfig) -> None:
        with self.mutex:
            self.config = config.normalized()

    def cache_key(self, key: bytes) -> None:
        if not isinstance(key, (bytes, bytearray)) or len(key) == 0:
            raise ValueError("key не может быть пустым")
        with self.mutex:
            self.clear_key_locked("replace")
            self.key_data = bytearray(bytes(key))
            now_ts = time.monotonic()
            self.cached_at_ts = now_ts
            self.last_activity_ts = now_ts
            self.memory_protected = False
            if self.config.use_memory_protection:
                self.memory_protected = self.protect_memory_region(self.key_data)

    def get_key(self) -> Optional[bytes]:
        with self.mutex:
            if self.key_data is None:
                return None
            if self.is_expired_locked():
                self.clear_key_locked("expired")
                return None
            self.last_activity_ts = time.monotonic()
            return bytes(self.key_data)

    def has_key(self) -> bool:
        with self.mutex:
            if self.key_data is None:
                return False
            if self.is_expired_locked():
                self.clear_key_locked("expired")
                return False
            return True

    def touch_activity(self) -> None:
        with self.mutex:
            if self.key_data is not None:
                self.last_activity_ts = time.monotonic()

    def clear_key(self, reason: str = "manual") -> None:
        del reason
        with self.mutex:
            self.clear_key_locked("manual")

    def set_application_active(self, is_active: bool) -> None:
        with self.mutex:
            self.app_active = bool(is_active)
            if not self.app_active and self.config.lock_when_inactive:
                self.clear_key_locked("inactive")

    def is_expired(self) -> bool:
        with self.mutex:
            return self.is_expired_locked()

    def is_expired_locked(self) -> bool:
        if self.key_data is None:
            return True
        if not self.app_active and self.config.lock_when_inactive:
            return True
        now_ts = time.monotonic()
        idle = now_ts - self.last_activity_ts
        return idle >= float(self.config.idle_timeout_sec)

    def clear_key_locked(self, reason: str) -> None:
        del reason
        if self.key_data is not None:
            if self.memory_protected:
                self.unprotect_memory_region(self.key_data)
            secure_zero_bytearray(self.key_data)
            self.key_data = None
        self.cached_at_ts = 0.0
        self.last_activity_ts = 0.0
        self.memory_protected = False

    @staticmethod
    def protect_memory_region(buf: bytearray) -> bool:
        try:
            if len(buf) == 0:
                return False
            ptr = (ctypes.c_char * len(buf)).from_buffer(buf)
            addr = ctypes.addressof(ptr)
            size = ctypes.c_size_t(len(buf))

            if os.name == "nt":
                kernel32 = ctypes.windll.kernel32
                return bool(kernel32.VirtualLock(ctypes.c_void_p(addr), size))

            libc = ctypes.CDLL(None)
            return int(libc.mlock(ctypes.c_void_p(addr), size)) == 0
        except Exception:
            return False

    @staticmethod
    def unprotect_memory_region(buf: bytearray) -> bool:
        try:
            if len(buf) == 0:
                return False
            ptr = (ctypes.c_char * len(buf)).from_buffer(buf)
            addr = ctypes.addressof(ptr)
            size = ctypes.c_size_t(len(buf))

            if os.name == "nt":
                kernel32 = ctypes.windll.kernel32
                return bool(kernel32.VirtualUnlock(ctypes.c_void_p(addr), size))

            libc = ctypes.CDLL(None)
            return int(libc.munlock(ctypes.c_void_p(addr), size)) == 0
        except Exception:
            return False


class PlatformSecretStore:
    def __init__(self, service_name: str = "cryptosafe_manager", fallback_dir: Optional[Path] = None):
        self.service_name = service_name
        self.fallback_dir = fallback_dir or (Path.home() / ".cryptosafe_manager")
        self.fallback_file = self.fallback_dir / "secret_store.json"
        self.keyring_api = None
        self.keyring_available = False
        try:
            import keyring  # type: ignore

            self.keyring_api = keyring
            self.keyring_available = True
        except Exception:
            self.keyring_api = None
            self.keyring_available = False

    def set_secret(self, secret_name: str, value: bytes) -> None:
        if self.keyring_available and self.keyring_api is not None:
            try:
                payload = base64.b64encode(value).decode("utf-8")
                self.keyring_api.set_password(self.service_name, secret_name, payload)
                return
            except Exception:
                pass
        data = self.read_fallback_data()
        data[secret_name] = base64.b64encode(value).decode("utf-8")
        self.write_fallback_data(data)

    def get_secret(self, secret_name: str) -> Optional[bytes]:
        if self.keyring_available and self.keyring_api is not None:
            try:
                payload = self.keyring_api.get_password(self.service_name, secret_name)
                if payload:
                    return base64.b64decode(payload.encode("utf-8"))
            except Exception:
                pass
        data = self.read_fallback_data()
        payload = data.get(secret_name)
        if not isinstance(payload, str):
            return None
        try:
            return base64.b64decode(payload.encode("utf-8"))
        except Exception:
            return None

    def delete_secret(self, secret_name: str) -> None:
        if self.keyring_available and self.keyring_api is not None:
            try:
                self.keyring_api.delete_password(self.service_name, secret_name)
            except Exception:
                pass
        data = self.read_fallback_data()
        if secret_name in data:
            del data[secret_name]
            self.write_fallback_data(data)

    def read_fallback_data(self) -> dict[str, str]:
        if not self.fallback_file.exists():
            return {}
        try:
            raw = json.loads(self.fallback_file.read_text(encoding="utf-8"))
        except Exception:
            return {}
        if not isinstance(raw, dict):
            return {}
        out: dict[str, str] = {}
        for key, val in raw.items():
            if isinstance(key, str) and isinstance(val, str):
                out[key] = val
        return out

    def write_fallback_data(self, payload: dict[str, str]) -> None:
        self.fallback_dir.mkdir(parents=True, exist_ok=True)
        self.fallback_file.write_text(
            json.dumps(payload, ensure_ascii=False, indent=2),
            encoding="utf-8",
        )
        try:
            if os.name != "nt":
                os.chmod(self.fallback_file, stat.S_IRUSR | stat.S_IWUSR)
        except Exception:
            pass
