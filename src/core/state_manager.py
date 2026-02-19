from __future__ import annotations

import threading
from dataclasses import dataclass
from typing import Optional

from core.security import secure_zero_bytearray


@dataclass
class SessionState:
    unlocked: bool = False
    username: str = ""


class StateManager:
    def __init__(self):
        self._lock = threading.Lock()
        self._session = SessionState(unlocked=False)
        self._master_key: Optional[bytearray] = None

        # Заглушки будущих фич
        self.clipboard_value: str = ""
        self.clipboard_timeout_sec: int = 0
        self.inactivity_minutes: int = 0

    def is_unlocked(self) -> bool:
        with self._lock:
            return bool(self._session.unlocked)

    def unlock(self, master_key: bytes, username: str = "user") -> None:
        if not master_key:
            raise ValueError("master_key не может быть пустым")
        with self._lock:
            # Стираем старый ключ, если был.
            if self._master_key is not None:
                secure_zero_bytearray(self._master_key)
            self._master_key = bytearray(master_key)
            self._session = SessionState(unlocked=True, username=username)

    def lock(self) -> None:
        with self._lock:
            self._session = SessionState(unlocked=False, username="")
            if self._master_key is not None:
                secure_zero_bytearray(self._master_key)
                self._master_key = None

    def get_master_key(self) -> bytes:
        with self._lock:
            if not self._session.unlocked or self._master_key is None:
                raise RuntimeError("Хранилище заблокировано")
            return bytes(self._master_key)